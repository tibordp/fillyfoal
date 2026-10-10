//! WAVE chunks: `fmt ` (every `WAVEFORMATEX` variant we know the extra
//! bytes of, and WAVE_FORMAT_EXTENSIBLE), `fact`, `data`, Broadcast Wave
//! `bext` (with its UMID) and `levl`, `cue `, `plst`, `smpl`, `inst`,
//! `LIST adtl` (`labl`, `note`, `ltxt`, `file`), `LIST exif`, `PEAK`,
//! `acid`, `cart`, `DISP`, RF64/BW64 `ds64` and the ADM `chna`.
//!
//! The `fmt ` layout ([`wave_format`]) is shared with AVI audio streams,
//! DLS wave pools and Sony Wave64.

use crate::bytes::{u32_be, u32_le, u64_le};
use crate::cx::Cx;
use crate::dsl::{Record, emit_record};
use crate::error::Result;
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::audio::midi::{manufacturer, note_name};
use crate::formats::iff::{Chunk, Ctx, FourCc, find, scan};
use crate::formats::util::sound::{
    channels, clip, duration_of, fourcc, latin1_field, peek_text, table, text, trim_nul,
};
use crate::formats::util::vidutil::asc_summary;
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Guid, Value, flag, lookup};

/// `WAVE_FORMAT_*` tags (mmreg.h, with the names FFmpeg uses for the tags
/// it reads).
pub const FORMAT_TAG: EnumTable = &[
    (0x0000, "Unknown"),
    (0x0001, "PCM"),
    (0x0002, "Microsoft ADPCM"),
    (0x0003, "IEEE float"),
    (0x0004, "Compaq VSELP"),
    (0x0005, "IBM CVSD"),
    (0x0006, "A-law"),
    (0x0007, "µ-law"),
    (0x0008, "DTS"),
    (0x0009, "DRM"),
    (0x000a, "WMA Voice 9"),
    (0x000b, "WMA Voice 10"),
    (0x0010, "OKI ADPCM"),
    (0x0011, "IMA ADPCM"),
    (0x0012, "MediaSpace ADPCM"),
    (0x0013, "Sierra ADPCM"),
    (0x0014, "G.723 ADPCM"),
    (0x0015, "DSP Solutions DigiSTD"),
    (0x0016, "DSP Solutions DigiFIX"),
    (0x0017, "Dialogic OKI ADPCM"),
    (0x0018, "MediaVision ADPCM"),
    (0x0019, "HP CU codec"),
    (0x0020, "Yamaha ADPCM"),
    (0x0021, "Speech Compression Sonarc"),
    (0x0022, "DSP Group TrueSpeech"),
    (0x0023, "Echo Speech SC1"),
    (0x0024, "AudioFile AF36"),
    (0x0025, "APTX"),
    (0x0026, "AudioFile AF10"),
    (0x0027, "Prosody 1612"),
    (0x0028, "LRC"),
    (0x0030, "Dolby AC-2"),
    (0x0031, "GSM 6.10"),
    (0x0032, "MSN Audio"),
    (0x0033, "Antex ADPCME"),
    (0x0034, "Control Resources VQLPC"),
    (0x0035, "DSP Solutions DigiREAL"),
    (0x0036, "DSP Solutions DigiADPCM"),
    (0x0037, "Control Resources CR10"),
    (0x0038, "Natural MicroSystems VBXADPCM"),
    (0x0039, "Crystal IMA ADPCM"),
    (0x003a, "Echo Speech SC3"),
    (0x003b, "Rockwell ADPCM"),
    (0x003c, "Rockwell DigiTalk"),
    (0x003d, "Xebec"),
    (0x0040, "G.721 ADPCM"),
    (0x0041, "G.728 CELP"),
    (0x0042, "MSG723"),
    (0x0043, "Intel G.723.1"),
    (0x0044, "Intel G.729"),
    (0x0045, "G.726 ADPCM"),
    (0x0050, "MPEG audio"),
    (0x0052, "RT24"),
    (0x0053, "PAC"),
    (0x0055, "MPEG Layer III"),
    (0x0059, "Lucent G.723"),
    (0x0060, "Cirrus"),
    (0x0061, "Duck DK4 ADPCM"),
    (0x0062, "Duck DK3 ADPCM"),
    (0x0063, "Canopus ATRAC"),
    (0x0064, "G.726 ADPCM"),
    (0x0065, "G.722 ADPCM"),
    (0x0066, "DSAT"),
    (0x0067, "DSAT display"),
    (0x0069, "Voxware"),
    (0x0080, "Softsound"),
    (0x0092, "Dolby AC-3 SPDIF"),
    (0x00ff, "AAC"),
    (0x0100, "Rhetorex ADPCM"),
    (0x0130, "ACELP.net"),
    (0x0160, "WMA v1"),
    (0x0161, "WMA v2"),
    (0x0162, "WMA Pro"),
    (0x0163, "WMA Lossless"),
    (0x0164, "WMA SPDIF"),
    (0x0200, "Creative ADPCM"),
    (0x0202, "Creative FastSpeech 8"),
    (0x0203, "Creative FastSpeech 10"),
    (0x0270, "Sony ATRAC3"),
    (0x0300, "FM Towns SND"),
    (0x0401, "Intel Music Coder"),
    (0x1000, "Olivetti GSM"),
    (0x1600, "MPEG-2 AAC (ADTS)"),
    (0x1601, "MPEG-2 AAC (raw)"),
    (0x1602, "MPEG-4 AAC (LATM)"),
    (0x1610, "HE-AAC"),
    (0x2000, "AC-3"),
    (0x2001, "DTS"),
    (0x3313, "AVI AAC"),
    (0x4143, "Divio AAC"),
    (0x566f, "Vorbis"),
    (0x674f, "Ogg Vorbis (mode 1)"),
    (0x6750, "Ogg Vorbis (mode 2)"),
    (0x6751, "Ogg Vorbis (mode 3)"),
    (0x676f, "Ogg Vorbis (mode 1+)"),
    (0x6770, "Ogg Vorbis (mode 2+)"),
    (0x6771, "Ogg Vorbis (mode 3+)"),
    (0x704f, "Opus"),
    (0x706d, "AAC (FAAD)"),
    (0x7361, "AMR-NB"),
    (0x7362, "AMR-WB"),
    (0xa106, "AAC"),
    (0xa109, "Speex"),
    (0xf1ac, "FLAC"),
    (0xfffe, "Extensible"),
];

/// WAVE_FORMAT_EXTENSIBLE speaker positions (ksmedia.h `SPEAKER_*`).
const SPEAKERS: FlagTable = &[
    flag(0x1, "FRONT_LEFT"),
    flag(0x2, "FRONT_RIGHT"),
    flag(0x4, "FRONT_CENTER"),
    flag(0x8, "LOW_FREQUENCY"),
    flag(0x10, "BACK_LEFT"),
    flag(0x20, "BACK_RIGHT"),
    flag(0x40, "FRONT_LEFT_OF_CENTER"),
    flag(0x80, "FRONT_RIGHT_OF_CENTER"),
    flag(0x100, "BACK_CENTER"),
    flag(0x200, "SIDE_LEFT"),
    flag(0x400, "SIDE_RIGHT"),
    flag(0x800, "TOP_CENTER"),
    flag(0x1000, "TOP_FRONT_LEFT"),
    flag(0x2000, "TOP_FRONT_CENTER"),
    flag(0x4000, "TOP_FRONT_RIGHT"),
    flag(0x8000, "TOP_BACK_LEFT"),
    flag(0x10000, "TOP_BACK_CENTER"),
    flag(0x20000, "TOP_BACK_RIGHT"),
    flag(0x8000_0000, "ALL"),
];

/// Channel masks with a common name (as FFmpeg names them).
const LAYOUTS: &[(u32, &str)] = &[
    (0x4, "mono"),
    (0x3, "stereo"),
    (0xb, "2.1"),
    (0x7, "3.0"),
    (0x103, "3.0 (back)"),
    (0xf, "3.1"),
    (0x107, "4.0"),
    (0x33, "quad"),
    (0x603, "quad (side)"),
    (0x10f, "4.1"),
    (0x37, "5.0"),
    (0x607, "5.0 (side)"),
    (0x3f, "5.1"),
    (0x60f, "5.1 (side)"),
    (0x707, "6.0"),
    (0x137, "hexagonal"),
    (0x70f, "6.1"),
    (0x13f, "6.1 (back)"),
    (0x637, "7.0"),
    (0x737, "octagonal"),
    (0x63f, "7.1"),
    (0xff, "7.1 (wide)"),
    (0x6cf, "7.1 (wide-side)"),
    (0x560f, "5.1.2"),
    (0x2d60f, "5.1.4"),
    (0x563f, "7.1.2"),
    (0x2d63f, "7.1.4"),
];

/// A channel layout for summaries: "stereo", "5.1", "3 ch".
pub fn layout(count: u16, mask: Option<u32>) -> String {
    match mask.filter(|&m| m != 0) {
        Some(m) => LAYOUTS
            .iter()
            .find(|(k, _)| *k == m)
            .map_or_else(|| channels(count), |(_, n)| (*n).to_owned()),
        None => match count {
            1 => "mono".to_owned(),
            2 => "stereo".to_owned(),
            n => channels(n),
        },
    }
}

/// A sample rate in kHz without needless digits: "8 kHz", "44.1 kHz".
pub fn khz(rate: u32) -> String {
    if rate < 1000 {
        return format!("{rate} Hz");
    }
    let (whole, frac) = (rate / 1000, rate % 1000);
    if frac == 0 {
        format!("{whole} kHz")
    } else {
        let frac = format!("{frac:03}");
        format!("{whole}.{} kHz", frac.trim_end_matches('0'))
    }
}

/// A bit rate from bytes per second: "128 kb/s".
fn kbps(bytes_per_second: u32) -> String {
    let bits = u64::from(bytes_per_second).saturating_mul(8);
    format!("{} kb/s", bits.saturating_add(500) / 1000)
}

/// A decoded `WAVEFORMATEX`.
#[derive(Clone, Debug, Default)]
pub struct WaveFormat {
    pub tag: u16,
    pub channels: u16,
    pub rate: u32,
    pub avg_bytes: u32,
    pub align: u16,
    pub bits: u16,
    /// The format tag inside WAVE_FORMAT_EXTENSIBLE's subformat GUID.
    pub subformat: Option<u16>,
    /// A subformat GUID outside the format-tag family, by name.
    pub subformat_name: Option<&'static str>,
    /// WAVE_FORMAT_EXTENSIBLE's valid bits per sample and channel mask.
    pub valid_bits: Option<u16>,
    pub mask: Option<u32>,
}

impl WaveFormat {
    /// The effective format tag (the subformat for EXTENSIBLE).
    pub fn codec(&self) -> u16 {
        self.subformat.unwrap_or(self.tag)
    }

    pub fn codec_name(&self) -> String {
        if let Some(name) = self.subformat_name {
            return name.to_owned();
        }
        lookup(FORMAT_TAG, self.codec().into())
            .map_or_else(|| format!("format {:#06x}", self.codec()), str::to_owned)
    }

    /// Formats whose data is whole sample frames of `align` bytes.
    fn is_framed(&self) -> bool {
        (matches!(self.codec(), 1 | 3 | 6 | 7) || self.subformat_name.is_some()) && self.align > 0
    }

    /// "PCM, 44100 Hz, 2 ch, 16-bit".
    pub fn summary(&self) -> String {
        let mut s = format!(
            "{}, {} Hz, {}",
            self.codec_name(),
            self.rate,
            channels(self.channels)
        );
        if self.bits > 0 {
            s.push_str(&format!(", {}-bit", self.bits));
        }
        s
    }

    /// "PCM 24-bit, 48 kHz, stereo" ("MPEG Layer III, 44.1 kHz, stereo,
    /// 128 kb/s" for compressed formats).
    pub fn line(&self) -> String {
        let mut s = self.codec_name();
        match self.valid_bits {
            Some(v) if v > 0 && v < self.bits => {
                s.push_str(&format!(" {v}-bit (in {})", self.bits));
            }
            _ if self.bits > 0 => s.push_str(&format!(" {}-bit", self.bits)),
            _ => {}
        }
        s.push_str(&format!(
            ", {}, {}",
            khz(self.rate),
            layout(self.channels, self.mask)
        ));
        if !self.is_framed() && self.avg_bytes > 0 {
            s.push_str(&format!(", {}", kbps(self.avg_bytes)));
        }
        s
    }

    /// Sample frames in `bytes` of sample data (`samples` from `fact` for
    /// compressed formats).
    pub fn frames(&self, bytes: u64, samples: Option<u64>) -> Option<u64> {
        if self.is_framed() {
            bytes.checked_div(self.align.into())
        } else {
            samples
        }
    }

    /// Playing time of `bytes` of sample data (`samples` from `fact`, if
    /// known, for compressed formats).
    pub fn duration(&self, bytes: u64, samples: Option<u64>) -> Option<String> {
        match self.frames(bytes, samples) {
            Some(n) => duration_of(n, self.rate.into()),
            None => duration_of(bytes, self.avg_bytes.into()),
        }
    }
}

/// The KSDATAFORMAT_SUBTYPE GUIDs are `XXXXXXXX-0000-0010-8000-00aa00389b71`
/// with a format tag in the first field.
fn subformat_tag(g: &Guid) -> Option<u16> {
    (g.data2 == 0 && g.data3 == 0x10 && g.data4 == [0x80, 0, 0, 0xaa, 0, 0x38, 0x9b, 0x71])
        .then(|| u16::try_from(g.data1).ok())
        .flatten()
}

/// Subformat GUIDs outside the format-tag family (ksmedia.h).
fn subformat_special(g: &Guid) -> Option<&'static str> {
    const AMBISONIC: [u8; 8] = [0x86, 0x44, 0xc8, 0xc1, 0xca, 0, 0, 0];
    const IEC61937: [u8; 8] = [0x80, 0, 0, 0xaa, 0, 0x38, 0x9b, 0x71];
    if g.data2 == 0x0721 && g.data3 == 0x11d3 && g.data4 == AMBISONIC {
        return match g.data1 {
            1 => Some("Ambisonic B-format PCM"),
            3 => Some("Ambisonic B-format float"),
            _ => None,
        };
    }
    if g.data2 == 0x0cea && g.data3 == 0x0010 && g.data4 == IEC61937 {
        return match g.data1 {
            0x0a => Some("IEC 61937 Dolby Digital Plus"),
            0x0b => Some("IEC 61937 DTS-HD"),
            0x0c => Some("IEC 61937 Dolby MLP"),
            0x0d => Some("IEC 61937 DST"),
            _ => None,
        };
    }
    None
}

const MP3_ID: EnumTable = &[(0, "unknown"), (1, "MPEG"), (2, "constant frame size")];
const MP3_PADDING: EnumTable = &[(0, "ISO"), (1, "always"), (2, "never")];
const MPEG_LAYER: FlagTable = &[
    flag(0x1, "LAYER1"),
    flag(0x2, "LAYER2"),
    flag(0x4, "LAYER3"),
];
const MPEG_MODE: FlagTable = &[
    flag(0x1, "STEREO"),
    flag(0x2, "JOINT_STEREO"),
    flag(0x4, "DUAL_CHANNEL"),
    flag(0x8, "SINGLE_CHANNEL"),
];
const MPEG_EMPHASIS: EnumTable = &[
    (1, "none"),
    (2, "50/15 µs"),
    (3, "reserved"),
    (4, "CCITT J.17"),
];
const MPEG_FLAGS: FlagTable = &[
    flag(0x1, "PRIVATE_BIT"),
    flag(0x2, "COPYRIGHT"),
    flag(0x4, "ORIGINAL"),
    flag(0x8, "PROTECTION"),
    flag(0x10, "MPEG1"),
];

const AAC_PAYLOAD: EnumTable = &[(0, "raw"), (1, "ADTS"), (2, "ADIF"), (3, "LOAS")];

/// Coefficient pairs shown for Microsoft ADPCM (the standard set has 7).
const MAX_COEFFICIENTS: u64 = 256;

/// `WAVEFORMATEX` / `WAVEFORMATEXTENSIBLE`.
pub fn wave_format(f: &mut Fields<'_>, _: &()) -> Result<WaveFormat> {
    let mut w = WaveFormat {
        tag: f.u16("Format tag").enumeration(FORMAT_TAG).emit()?,
        channels: f.u16("Channels").emit()?,
        rate: f.u32("Sample rate").desc("Samples per second").emit()?,
        avg_bytes: f.u32("Average bytes per second").emit()?,
        align: f.u16("Block align").desc("Bytes per sample frame").emit()?,
        ..WaveFormat::default()
    };
    if f.remaining() >= 2 {
        w.bits = f.u16("Bits per sample").emit()?;
    }
    if f.remaining() >= 2 {
        let declared = f
            .u16("Extension size")
            .desc("Bytes of format-specific data that follow")
            .emit()?;
        let extra = u64::from(declared).min(f.remaining());
        let end = f.pos().saturating_add(extra);
        if w.tag == 0xfffe && extra >= 22 {
            extensible(f, &mut w)?;
        } else {
            extension(f, &w, extra)?;
        }
        if f.pos() < end {
            f.bytes("Extension data", end.saturating_sub(f.pos()))
                .emit()?;
        }
        f.seek(end);
    }
    Ok(w)
}

fn extensible(f: &mut Fields<'_>, w: &mut WaveFormat) -> Result<()> {
    let bits = w.bits;
    w.valid_bits = Some(
        f.u16("Valid bits per sample")
            .desc(if bits == 0 {
                "Samples per block (bits per sample is 0)"
            } else {
                "Bits of precision in each sample"
            })
            .emit()?,
    );
    let count = w.channels;
    w.mask = Some(
        f.u32("Channel mask")
            .flags(SPEAKERS)
            .with(|&m, n| n.summary(layout(count, Some(m))))
            .emit()?,
    );
    let guid = f
        .guid("Subformat")
        .with(|g, n| match (subformat_tag(g), subformat_special(g)) {
            (Some(tag), _) => n.summary(
                lookup(FORMAT_TAG, tag.into())
                    .map_or_else(|| format!("format {tag:#06x}"), str::to_owned),
            ),
            (None, Some(name)) => n.summary(name),
            (None, None) => n,
        })
        .emit()?;
    w.subformat = subformat_tag(&guid);
    w.subformat_name = subformat_special(&guid);
    Ok(())
}

/// The format-specific bytes after `cbSize`, for the tags whose layout is
/// documented.
fn extension(f: &mut Fields<'_>, w: &WaveFormat, extra: u64) -> Result<()> {
    match w.tag {
        // ADPCMWAVEFORMAT
        0x0002 if extra >= 4 => {
            f.u16("Samples per block").emit()?;
            let count = f.u16("Coefficient pairs").emit()?;
            let shown = u64::from(count)
                .min(extra.saturating_sub(4) / 4)
                .min(MAX_COEFFICIENTS);
            for i in 0..shown {
                let at = f.peek_span(4);
                let a = f.int::<i16>("Coefficient 1").get()?;
                let b = f.int::<i16>("Coefficient 2").get()?;
                f.node(
                    Node::new(format!("Coefficient pair {i}"))
                        .span(at)
                        .summary(format!("{a}, {b}")),
                );
            }
        }
        // IMAADPCMWAVEFORMAT, GSM610WAVEFORMAT
        0x0011 | 0x0031 if extra >= 2 => {
            f.u16("Samples per block").emit()?;
        }
        // MPEGLAYER3WAVEFORMAT
        0x0055 if extra >= 12 => {
            f.u16("MPEG ID").enumeration(MP3_ID).emit()?;
            f.u32("Padding").enumeration(MP3_PADDING).emit()?;
            f.u16("Block size").desc("Bytes per block").emit()?;
            f.u16("Frames per block").emit()?;
            f.u16("Codec delay")
                .desc("Encoder delay in samples")
                .emit()?;
        }
        // MPEG1WAVEFORMAT
        0x0050 if extra >= 22 => {
            f.u16("Layer").flags(MPEG_LAYER).emit()?;
            f.u32("Bit rate")
                .desc("Bits per second, 0 = variable")
                .emit()?;
            f.u16("Mode").flags(MPEG_MODE).emit()?;
            f.u16("Mode extension").hex().emit()?;
            f.u16("Emphasis").enumeration(MPEG_EMPHASIS).emit()?;
            f.u16("Flags").flags(MPEG_FLAGS).emit()?;
            f.u32("PTS (low)").emit()?;
            f.u32("PTS (high)").emit()?;
        }
        // HEAACWAVEINFO / raw AAC: an AudioSpecificConfig follows.
        0x00ff | 0x1601 | 0x706d | 0xa106 if extra >= 2 => {
            f.bytes("AudioSpecificConfig", extra)
                .with(|b, n| match asc_summary(b) {
                    Some(s) => n.summary(s),
                    None => n,
                })
                .emit()?;
        }
        0x1610 if extra >= 12 => {
            f.u16("Payload type").enumeration(AAC_PAYLOAD).emit()?;
            f.u16("Profile and level").hex().emit()?;
            f.u8("Structure type").emit()?;
            f.bytes("Reserved", 7).emit()?;
            let rest = extra.saturating_sub(12);
            if rest > 0 {
                f.bytes("AudioSpecificConfig", rest)
                    .with(|b, n| match asc_summary(b) {
                        Some(s) => n.summary(s),
                        None => n,
                    })
                    .emit()?;
            }
        }
        // WMAUDIO1WAVEFORMAT, WMAUDIO2WAVEFORMAT
        0x0160 if extra >= 4 => {
            f.u16("Samples per block").emit()?;
            f.u16("Encode options").hex().emit()?;
        }
        0x0161 if extra >= 10 => {
            f.u32("Samples per block").emit()?;
            f.u16("Encode options").hex().emit()?;
            f.u32("Super block align").emit()?;
        }
        _ => {}
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Fixed records

record! {
    pub struct CuePoint {
        id: u32 "Identifier",
        position: u32 "Position" .desc("Sample position in play order"),
        chunk: ascii[4] "Data chunk ID",
        chunk_start: u32 "Chunk start" .desc("Offset of the chunk holding the cue (0 without a wavl list)"),
        block_start: u32 "Block start" .desc("Offset of the block holding the cue, for compressed data"),
        offset: u32 "Sample offset" .desc("Sample frame within the block"),
    }
}

const SMPTE_FORMAT: EnumTable = &[
    (0, "none"),
    (24, "24 fps"),
    (25, "25 fps"),
    (29, "30 fps drop-frame"),
    (30, "30 fps"),
];

record! {
    pub struct Sampler {
        manufacturer: u32 "Manufacturer" .hex() .with(|&v, n| n.summary(mma_manufacturer(v)))
            .desc("MIDI manufacturer: ID length in the high byte, ID in the low bytes"),
        product: u32 "Product" .hex(),
        period: u32 "Sample period" .desc("Nanoseconds per sample")
            .with(|&v, n| if v > 0 { n.summary(format!("{:.1} Hz", 1e9 / f64::from(v))) } else { n }),
        unity_note: u32 "MIDI unity note" .with(|&v, n| n.summary(note32(v)))
            .desc("The note played at the original pitch"),
        pitch_fraction: u32 "MIDI pitch fraction" .hex()
            .with(|&v, n| n.summary(format!("+{:.2} cents", f64::from(v) * 100.0 / 4_294_967_296.0))),
        smpte_format: u32 "SMPTE format" .enumeration(SMPTE_FORMAT),
        smpte_offset: u32 "SMPTE offset" .hex() .with(|&v, n| n.summary(smpte(v))),
        loops: u32 "Sample loops",
        sampler_data: u32 "Sampler data size",
    }
}

const LOOP_TYPE: EnumTable = &[(0, "forward"), (1, "alternating"), (2, "backward")];

record! {
    pub struct SampleLoop {
        id: u32 "Cue point ID",
        kind: u32 "Type" .enumeration(LOOP_TYPE),
        start: u32 "Start" .desc("First sample frame of the loop"),
        end: u32 "End" .desc("Last sample frame of the loop (inclusive)"),
        fraction: u32 "Fraction" .hex(),
        count: u32 "Play count" .desc("0 = infinite"),
    }
}

fn loop_summary(l: &SampleLoop) -> String {
    let kind = lookup(LOOP_TYPE, l.kind.into()).unwrap_or("?");
    let times = if l.count == 0 {
        "infinite".to_owned()
    } else {
        format!("{}×", l.count)
    };
    format!("{kind}, {}..{}, {times}", l.start, l.end)
}

record! {
    pub struct Instrument {
        note: u8 "Unshifted note" .with(|&v, n| n.summary(note_name(v))),
        fine_tune: i8 "Fine tune (cents)",
        gain: i8 "Gain (dB)",
        low_note: u8 "Low note" .with(|&v, n| n.summary(note_name(v))),
        high_note: u8 "High note" .with(|&v, n| n.summary(note_name(v))),
        low_velocity: u8 "Low velocity",
        high_velocity: u8 "High velocity",
    }
}

record! {
    pub struct Ds64 {
        riff_size: u64 "RIFF size" .desc("Size of the RF64 chunk"),
        data_size: u64 "data size",
        samples: u64 "Sample count" .desc("Replaces the fact chunk's count"),
        table: u32 "Table length" .desc("Entries for other chunks over 4 GiB"),
    }
}

record! {
    pub struct Ds64Entry {
        id: ascii[4] "Chunk ID",
        size: u64 "Size",
    }
}

record! {
    pub struct Segment {
        id: u32 "Cue point ID",
        length: u32 "Length" .desc("Sample frames"),
        repeats: u32 "Repeats",
    }
}

record! {
    /// Audio Definition Model track UID (ITU-R BS.2076 `chna`).
    pub struct ChnaEntry {
        track: u16 "Track index" .desc("1-based; 0 = unused entry"),
        uid: ascii[12] "Track UID",
        track_ref: ascii[14] "Track format reference",
        pack_ref: ascii[11] "Pack format reference",
        _pad: u8 "Padding",
    }
}

const ACID_FLAGS: FlagTable = &[
    flag(0x1, "ONE_SHOT"),
    flag(0x2, "ROOT_NOTE_SET"),
    flag(0x4, "STRETCH"),
    flag(0x8, "DISK_BASED"),
    flag(0x10, "HIGH_OCTAVE"),
];

record! {
    pub struct Acid {
        flags: u32 "Flags" .flags(ACID_FLAGS),
        root_note: u16 "Root note" .with(|&v, n| n.summary(note32(v.into()))),
        _unknown1: u16 "Unknown",
        _unknown2: f32 "Unknown",
        beats: u32 "Beats",
        meter_denominator: u16 "Meter denominator",
        meter_numerator: u16 "Meter numerator",
        tempo: f32 "Tempo (BPM)",
    }
}

fn note32(v: u32) -> String {
    u8::try_from(v)
        .ok()
        .filter(|&n| n < 128)
        .map_or_else(|| "?".to_owned(), note_name)
}

/// The `smpl` manufacturer: 1 or 3 MIDI ID bytes, their count in the top
/// byte.
fn mma_manufacturer(v: u32) -> String {
    let [count, _, hi, lo] = v.to_be_bytes();
    let id: &[u8] = match count {
        1 => &[lo],
        3 => &[0, hi, lo],
        _ => &[],
    };
    if v == 0 {
        return "none".to_owned();
    }
    manufacturer(id).map_or_else(|| "unknown".to_owned(), str::to_owned)
}

/// A SMPTE offset `0xhhmmssff` (hours signed).
fn smpte(v: u32) -> String {
    let [h, m, s, f] = v.to_be_bytes();
    format!("{:+03}:{m:02}:{s:02}:{f:02}", h as i8)
}

const DISP_TYPE: EnumTable = &[
    (1, "CF_TEXT"),
    (2, "CF_BITMAP"),
    (3, "CF_METAFILEPICT"),
    (8, "CF_DIB"),
    (14, "CF_ENHMETAFILE"),
];

const LEVL_FORMAT: EnumTable = &[(1, "8-bit"), (2, "16-bit")];
const LEVL_POINTS: EnumTable = &[(1, "positive peaks"), (2, "positive and negative peaks")];

// ---------------------------------------------------------------------------
// Chunk names

pub fn describe_id(id: &FourCc) -> Option<&'static str> {
    Some(match id {
        b"fmt " => "Sample format",
        b"data" => "Sample data",
        b"fact" => "Sample count (for compressed formats)",
        b"cue " => "Cue points",
        b"plst" => "Playlist",
        b"smpl" => "Sampler parameters and loops",
        b"inst" => "Instrument parameters",
        b"bext" => "Broadcast Wave extension (EBU Tech 3285)",
        b"levl" => "Peak envelope (EBU Tech 3285 supplement 3)",
        b"ds64" => "64-bit sizes (RF64/BW64)",
        b"chna" => "ADM channel allocation (ITU-R BS.2076)",
        b"axml" => "XML metadata (ADM, EBU Core)",
        b"iXML" => "iXML production metadata",
        b"PEAK" => "Peak levels",
        b"cart" => "Broadcast cart chunk (AES46)",
        b"acid" => "ACID loop information",
        b"DISP" => "Clipboard display data",
        b"slnt" => "Silence",
        b"labl" => "Cue point label",
        b"note" => "Cue point note",
        b"ltxt" => "Labelled text",
        b"file" => "Embedded file",
        b"umid" => "SMPTE unique material identifier",
        b"IARL" => "Archival location",
        b"ICMS" => "Commissioned by",
        b"ICRP" => "Cropped",
        b"IDIM" => "Dimensions",
        b"IDPI" => "Dots per inch",
        b"ILGT" => "Lightness",
        b"IMED" => "Medium",
        b"IPLT" => "Palette setting",
        b"ISHP" => "Sharpness",
        b"ISRF" => "Source form",
        b"IDIT" => "Digitization time",
        b"ISMP" => "SMPTE time code",
        b"IENC" => "Encoded by",
        b"IWRI" => "Written by",
        b"IPRO" => "Produced by",
        b"IMUS" => "Music by",
        b"ISTR" => "Starring",
        b"IEDT" => "Edited by",
        b"ICNM" => "Cinematographer",
        b"IPDS" => "Production designer",
        b"ICDS" => "Costume designer",
        b"ISTD" => "Production studio",
        b"IDST" => "Distributed by",
        b"ICNT" => "Country",
        b"IRTD" => "Rating",
        b"ISGN" => "Secondary genre",
        b"IRIP" => "Ripped by",
        b"IBSU" => "Base URL",
        b"ever" => "Exif version",
        b"erel" => "Related image file",
        b"etim" => "Creation time",
        b"ecor" => "Manufacturer",
        b"emdl" => "Model",
        b"emnt" => "Maker note",
        b"eucm" => "User comment",
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Lookups across chunks

async fn fmt_of(cx: &Cx, chunk: &Chunk) -> Option<WaveFormat> {
    let fmt = find(cx, &chunk.ctx, chunk.parent, b"fmt ").await.ok()??;
    parse(cx, fmt.data, chunk.endian(), &(), wave_format)
        .await
        .ok()
}

fn word(endian: Endian, data: &[u8]) -> Option<u32> {
    match endian {
        Endian::Little => u32_le(data, 0),
        Endian::Big => u32_be(data, 0),
    }
}

/// The `ds64` sample count of an RF64/BW64 file.
async fn ds64_samples(cx: &Cx, ctx: &Ctx) -> Option<u64> {
    if ctx.sizes.is_empty() {
        return None;
    }
    let file = ctx.input.span;
    let raw = cx.read_avail(file.sub(12, 32)).await.ok()?;
    raw.starts_with(b"ds64").then(|| u64_le(&raw, 24))?
}

/// The `fact` sample count, resolving RF64's 0xffffffff through `ds64`.
async fn fact_value(cx: &Cx, ctx: &Ctx, data: Span) -> Option<u64> {
    let n = word(ctx.endian, &cx.read_avail(data.sub(0, 4)).await.ok()?)?;
    if n == u32::MAX
        && let Some(n) = ds64_samples(cx, ctx).await
    {
        return Some(n);
    }
    Some(n.into())
}

async fn fact_samples(cx: &Cx, chunk: &Chunk) -> Option<u64> {
    let fact = find(cx, &chunk.ctx, chunk.parent, b"fact").await.ok()??;
    fact_value(cx, &chunk.ctx, fact.data).await
}

/// A sample count as a time of day: `06:00:00.000`.
fn clock(samples: u64, rate: u32) -> Option<String> {
    let rate = u64::from(rate);
    let secs = samples.checked_div(rate)?;
    let ms = samples
        .checked_rem(rate)?
        .saturating_mul(1000)
        .checked_div(rate)?;
    Some(format!(
        "{:02}:{:02}:{:02}.{ms:03}",
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    ))
}

// ---------------------------------------------------------------------------
// Summaries

pub async fn summary(cx: &Cx, chunk: &Chunk) -> Result<Option<String>> {
    let e = chunk.endian();
    let data = chunk.data;
    Ok(match &chunk.id {
        b"fmt " => Some(parse(cx, data, e, &(), wave_format).await?.line()),
        b"data" => {
            let mut s = format!("{} bytes", chunk.size);
            if let Some(fmt) = fmt_of(cx, chunk).await {
                let samples = fact_samples(cx, chunk).await;
                if let Some(d) = fmt.duration(chunk.size, samples) {
                    s.push_str(&format!(", {d}"));
                }
            }
            Some(s)
        }
        b"fact" => fact_value(cx, &chunk.ctx, data)
            .await
            .map(|n| format!("{n} samples")),
        b"cue " => {
            let n = word(e, &cx.read(data.sub(0, 4)).await?).unwrap_or(0);
            Some(format!("{n} cue points"))
        }
        b"plst" => {
            let n = word(e, &cx.read(data.sub(0, 4)).await?).unwrap_or(0);
            Some(format!("{n} segments"))
        }
        b"bext" => {
            let head = cx.read_avail(data.sub(0, 288)).await?;
            let description = trim_nul(head.get(..256).unwrap_or_default());
            let originator = trim_nul(head.get(256..288).unwrap_or_default());
            let pick = if description.is_empty() {
                originator
            } else {
                description
            };
            (!pick.is_empty()).then(|| clip(&crate::text::latin1(pick), 60))
        }
        b"smpl" => {
            let s = crate::dsl::read_record::<Sampler>(cx, data.sub(0, Sampler::SIZE), e).await?;
            Some(format!(
                "unity note {}, {} loop{}",
                note32(s.unity_note),
                s.loops,
                if s.loops == 1 { "" } else { "s" }
            ))
        }
        b"inst" => {
            let i =
                crate::dsl::read_record::<Instrument>(cx, data.sub(0, Instrument::SIZE), e).await?;
            Some(format!(
                "note {}, keys {}–{}, velocity {}–{}",
                note_name(i.note),
                note_name(i.low_note),
                note_name(i.high_note),
                i.low_velocity,
                i.high_velocity
            ))
        }
        b"acid" => {
            let a = crate::dsl::read_record::<Acid>(cx, data.sub(0, Acid::SIZE), e).await?;
            Some(format!(
                "{:.2} BPM, {} beats, {}/{}{}",
                a.tempo,
                a.beats,
                a.meter_numerator,
                a.meter_denominator,
                if a.flags & 1 != 0 { ", one-shot" } else { "" }
            ))
        }
        b"ds64" => {
            let d = crate::dsl::read_record::<Ds64>(cx, data.sub(0, Ds64::SIZE), e).await?;
            Some(format!("data {} bytes, {} samples", d.data_size, d.samples))
        }
        b"chna" => {
            let h = cx.read(data.sub(0, 4)).await?;
            let tracks = crate::bytes::u16_le(&h, 0).unwrap_or(0);
            let uids = crate::bytes::u16_le(&h, 2).unwrap_or(0);
            Some(format!("{tracks} tracks, {uids} track UIDs"))
        }
        b"levl" => {
            let h = cx.read(data.sub(0, 24)).await?;
            let block = u32_le(&h, 12).unwrap_or(0);
            let channels = u32_le(&h, 16).unwrap_or(0);
            let frames = u32_le(&h, 20).unwrap_or(0);
            Some(format!(
                "{frames} peak frames of {block} samples, {channels} ch"
            ))
        }
        b"PEAK" => Some(format!("{} channels", data.len.saturating_sub(8) / 8)),
        b"cart" => {
            let title = peek_text(cx, data.sub(4, 64), 64).await?;
            let artist = peek_text(cx, data.sub(68, 64), 64).await?;
            match (title.is_empty(), artist.is_empty()) {
                (false, false) => Some(clip(&format!("{artist} – {title}"), 60)),
                (false, true) => Some(clip(&title, 60)),
                (true, false) => Some(clip(&artist, 60)),
                (true, true) => None,
            }
        }
        b"labl" | b"note" if &chunk.list == b"adtl" => {
            let id = word(e, &cx.read(data.sub(0, 4)).await?).unwrap_or(0);
            let text = peek_text(cx, data.tail(4), 120).await?;
            Some(format!("cue {id}: {}", clip(&text, 60)))
        }
        b"ltxt" if &chunk.list == b"adtl" => {
            let head = cx.read(data.sub(0, 12)).await?;
            let id = word(e, &head).unwrap_or(0);
            let len = word(e, head.get(4..).unwrap_or_default()).unwrap_or(0);
            let purpose = fourcc(head.get(8..12).unwrap_or_default());
            let text = peek_text(cx, data.tail(20), 120).await?;
            let mut s = format!("cue {id}, {len} samples, {purpose}");
            if !text.is_empty() {
                s.push_str(&format!(": {}", clip(&text, 50)));
            }
            Some(s)
        }
        b"slnt" => {
            let n = word(e, &cx.read(data.sub(0, 4)).await?).unwrap_or(0);
            Some(format!("{n} samples of silence"))
        }
        _ if &chunk.list == b"exif" => Some(clip(&peek_text(cx, data, 120).await?, 60)),
        _ => None,
    })
}

// ---------------------------------------------------------------------------
// Expansion

pub async fn chunk(cx: &Cx, chunk: &Chunk) -> Result<bool> {
    let e = chunk.endian();
    let data = chunk.data;
    match &chunk.id {
        b"fmt " => {
            let block = cx.block(data).await?;
            let mut f = Fields::emitting(cx, &block, e);
            wave_format(&mut f, &())?;
            if f.remaining() > 0 {
                cx.emit(
                    Node::new("Unused")
                        .span(data.tail(f.pos()))
                        .desc("Bytes after the declared extension"),
                );
            }
        }
        b"data" => {
            let mut node = Node::new("Samples").span(data);
            if let Some(fmt) = fmt_of(cx, chunk).await {
                let samples = fact_samples(cx, chunk).await;
                let mut parts = Vec::new();
                if let Some(n) = fmt.frames(chunk.size, samples) {
                    parts.push(format!("{n} frames"));
                }
                if let Some(d) = fmt.duration(chunk.size, samples) {
                    parts.push(d);
                }
                if !parts.is_empty() {
                    node = node.summary(parts.join(", "));
                }
            }
            cx.emit(node);
        }
        b"fact" => {
            let block = cx.block(data.sub(0, 4)).await?;
            let rf64 = ds64_samples(cx, &chunk.ctx).await;
            Fields::emitting(cx, &block, e)
                .u32("Sample length")
                .desc("Samples per channel")
                .with(|&v, n| match rf64 {
                    Some(s) if v == u32::MAX => n.summary(format!("see ds64: {s} samples")),
                    _ => n,
                })
                .emit()?;
        }
        b"ds64" => {
            let d = emit_record::<Ds64>(cx, data.sub(0, Ds64::SIZE), e).await?;
            let rest = data.tail(Ds64::SIZE);
            let len = u64::from(d.table)
                .saturating_mul(Ds64Entry::SIZE)
                .min(rest.len);
            if len > 0 {
                cx.emit(table::<Ds64Entry>(
                    "Size table",
                    rest.sub(0, len),
                    e,
                    "Entry",
                    Some(|t| format!("{}: {} bytes", t.id, t.size)),
                ));
            }
            if rest.len > len {
                cx.emit(Node::new("Unused").span(rest.tail(len)));
            }
        }
        b"bext" => {
            let rate = fmt_of(cx, chunk).await.map_or(0, |f| f.rate);
            let block = cx.block(data.sub(0, 602)).await?;
            bext(&mut Fields::emitting(cx, &block, e), rate)?;
            let history = data.tail(602);
            if !history.is_empty() {
                let t = peek_text(cx, history, history.len.min(1 << 16)).await?;
                cx.emit(
                    Node::new("Coding history")
                        .span(history)
                        .value(text(t))
                        .desc("EBU R 98 coding history, one line per processing step"),
                );
            }
        }
        b"levl" => {
            let block = cx.block(data.sub(0, 120)).await?;
            let mut f = Fields::emitting(cx, &block, e);
            f.u32("Version").emit()?;
            f.u32("Format").enumeration(LEVL_FORMAT).emit()?;
            f.u32("Points per value").enumeration(LEVL_POINTS).emit()?;
            f.u32("Block size")
                .desc("Audio samples per peak frame")
                .emit()?;
            let ch = f.u32("Peak channels").emit()?;
            let frames = f.u32("Peak frames").emit()?;
            f.u32("Position of peak of peaks")
                .with(|&v, n| {
                    if v == u32::MAX {
                        n.summary("unknown")
                    } else {
                        n
                    }
                })
                .desc("Sample frame of the highest peak; 0xffffffff = unknown")
                .emit()?;
            let offset = f
                .u32("Offset to peaks")
                .desc("From the start of the chunk header")
                .emit()?;
            latin1_field(&mut f, "Timestamp", 28).emit()?;
            f.bytes("Reserved", 60).emit()?;
            let peaks = data.tail(u64::from(offset).saturating_sub(8).max(120));
            cx.emit(
                Node::new("Peak data")
                    .span(peaks)
                    .summary(format!("{frames} frames × {ch} channels")),
            );
        }
        b"cue " => {
            let block = cx.block(data.sub(0, 4)).await?;
            let count = Fields::emitting(cx, &block, e).u32("Cue points").emit()?;
            let points = data.sub(4, u64::from(count).saturating_mul(CuePoint::SIZE));
            cx.emit(table::<CuePoint>(
                "Points",
                points,
                e,
                "Cue",
                Some(|c| format!("#{} at sample {}", c.id, c.position)),
            ));
        }
        b"plst" => {
            let block = cx.block(data.sub(0, 4)).await?;
            let count = Fields::emitting(cx, &block, e).u32("Segments").emit()?;
            let segments = data.sub(4, u64::from(count).saturating_mul(Segment::SIZE));
            cx.emit(table::<Segment>(
                "Play order",
                segments,
                e,
                "Segment",
                Some(|s| format!("cue {}, {} samples, {}×", s.id, s.length, s.repeats)),
            ));
        }
        b"smpl" => {
            let s = emit_record::<Sampler>(cx, data.sub(0, Sampler::SIZE), e).await?;
            let rest = data.tail(Sampler::SIZE);
            let loops = u64::from(s.loops)
                .saturating_mul(SampleLoop::SIZE)
                .min(rest.len);
            if loops > 0 {
                cx.emit(table::<SampleLoop>(
                    "Loops",
                    rest.sub(0, loops),
                    e,
                    "Loop",
                    Some(loop_summary),
                ));
            }
            let extra = rest.tail(loops);
            if !extra.is_empty() {
                let declared = u64::from(s.sampler_data).min(extra.len);
                if declared > 0 {
                    cx.emit(
                        Node::new("Sampler data")
                            .span(extra.sub(0, declared))
                            .desc("Manufacturer-specific"),
                    );
                }
                if extra.len > declared {
                    cx.emit(Node::new("Unused").span(extra.tail(declared)));
                }
            }
        }
        b"inst" => {
            emit_record::<Instrument>(cx, data, e).await?;
        }
        b"acid" => {
            emit_record::<Acid>(cx, data, e).await?;
        }
        b"chna" => {
            let block = cx.block(data.sub(0, 4)).await?;
            let mut f = Fields::emitting(cx, &block, e);
            f.u16("Tracks").emit()?;
            let uids = f.u16("Track UIDs").emit()?;
            let entries = data
                .tail(4)
                .sub(0, u64::from(uids).saturating_mul(ChnaEntry::SIZE));
            cx.emit(table::<ChnaEntry>(
                "Track UIDs",
                entries,
                e,
                "Track",
                Some(|c| format!("track {}: {}, {}", c.track, c.uid, c.track_ref)),
            ));
        }
        b"cart" => {
            let block = cx.block(data.sub(0, 2048)).await?;
            cart(cx, &mut Fields::emitting(cx, &block, e))?;
            let tags = data.tail(2048);
            if !tags.is_empty() {
                let t = peek_text(cx, tags, tags.len.min(1 << 16)).await?;
                cx.emit(
                    Node::new("Tag text")
                        .span(tags)
                        .value(text(t))
                        .desc("Free-form text, often XML"),
                );
            }
        }
        b"DISP" => {
            let block = cx.block(data.sub(0, 4)).await?;
            let kind = Fields::emitting(cx, &block, e)
                .u32("Type")
                .enumeration(DISP_TYPE)
                .emit()?;
            let body = data.tail(4);
            if kind == 1 {
                let t = peek_text(cx, body, body.len.min(1 << 16)).await?;
                cx.emit(Node::new("Text").span(body).value(text(t)));
            } else {
                cx.emit(Node::new("Data").span(body));
            }
        }
        b"slnt" => {
            let block = cx.block(data.sub(0, 4)).await?;
            Fields::emitting(cx, &block, e)
                .u32("Silent samples")
                .emit()?;
        }
        b"umid" => {
            let block = cx.block(data).await?;
            umid(&mut Fields::emitting(cx, &block, e), &())?;
        }
        b"labl" | b"note" if &chunk.list == b"adtl" => {
            let block = cx.block(data.sub(0, 4)).await?;
            Fields::emitting(cx, &block, e).u32("Cue point ID").emit()?;
            let t = peek_text(cx, data.tail(4), data.len).await?;
            cx.emit(Node::new("Text").span(data.tail(4)).value(text(t)));
        }
        b"ltxt" if &chunk.list == b"adtl" => {
            let block = cx.block(data.sub(0, 20)).await?;
            let mut f = Fields::emitting(cx, &block, e);
            f.u32("Cue point ID").emit()?;
            f.u32("Sample length").emit()?;
            f.bytes("Purpose", 4)
                .with(|b, n| {
                    let n = n.value(text(fourcc(b)));
                    match b.as_slice() {
                        b"rgn " => n.summary("region"),
                        _ => n,
                    }
                })
                .emit()?;
            f.u16("Country").emit()?;
            f.u16("Language").emit()?;
            f.u16("Dialect").emit()?;
            f.u16("Code page").emit()?;
            let rest = data.tail(20);
            if !rest.is_empty() {
                let t = peek_text(cx, rest, rest.len).await?;
                cx.emit(Node::new("Text").span(rest).value(text(t)));
            }
        }
        b"file" if &chunk.list == b"adtl" => {
            let block = cx.block(data.sub(0, 8)).await?;
            let mut f = Fields::emitting(cx, &block, e);
            f.u32("Cue point ID").emit()?;
            f.bytes("Media type", 4)
                .with(|b, n| n.value(text(fourcc(b))))
                .emit()?;
            cx.emit(crate::formats::embedded(
                "File",
                chunk.input().nested(data.tail(8)),
            ));
        }
        _ if &chunk.list == b"exif" => {
            let t = peek_text(cx, data, data.len.min(1 << 16)).await?;
            cx.emit(Node::new("Text").span(data).value(text(t)));
        }
        b"PEAK" => {
            let block = cx.block(data).await?;
            let mut f = Fields::emitting(cx, &block, e);
            f.u32("Version").emit()?;
            f.u32("Timestamp").timestamp().emit()?;
            let mut i = 0u32;
            while f.remaining() >= 8 {
                cx.checkpoint().await;
                let at = f.peek_span(8);
                let value = f.f32("Peak value").get()?;
                let position = f.u32("Peak position").get()?;
                let db = if value > 0.0 {
                    format!("{:.1} dBFS", 20.0 * f64::from(value).log10())
                } else {
                    "silent".to_owned()
                };
                cx.emit(
                    Node::new(format!("Channel {i}"))
                        .span(at)
                        .value(Value::Float(value.into()))
                        .summary(format!("{db} at sample {position}"))
                        .lazy(peak, (at, e)),
                );
                i = i.saturating_add(1);
            }
        }
        _ => return Ok(false),
    }
    Ok(true)
}

async fn peak(cx: Cx, (span, e): (Span, Endian)) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, e);
    f.f32("Value").desc("Linear, 1.0 = full scale").emit()?;
    f.u32("Position").desc("Sample frame").emit()?;
    Ok(())
}

/// The fixed part of `bext` (602 bytes), versions 0 to 2.
pub fn bext(f: &mut Fields<'_>, rate: u32) -> Result<()> {
    latin1_field(f, "Description", 256).emit()?;
    latin1_field(f, "Originator", 32).emit()?;
    latin1_field(f, "Originator reference", 32).emit()?;
    latin1_field(f, "Origination date", 10)
        .desc("yyyy-mm-dd")
        .emit()?;
    latin1_field(f, "Origination time", 8)
        .desc("hh:mm:ss")
        .emit()?;
    let at = f.peek_span(8);
    let low = f.u32("Time reference (low)").get()?;
    let high = f.u32("Time reference (high)").get()?;
    let reference = (u64::from(high) << 32) | u64::from(low);
    let mut node = Node::new("Time reference")
        .span(at)
        .value(crate::formats::util::sound::uint(reference, 64))
        .desc("Sample frames since midnight at the first sample");
    if let Some(t) = clock(reference, rate) {
        node = node.summary(t);
    }
    f.node(node);
    let version = f.u16("Version").emit()?;
    if version == 0 {
        f.bytes("Reserved", 254).emit()?;
        return Ok(());
    }
    let at = f.peek_span(64);
    let raw = f.bytes("UMID", 64).get()?;
    let kind = match raw.get(12) {
        Some(0x13) => "basic UMID",
        Some(0x33) => "extended UMID",
        _ => "UMID",
    };
    if raw.iter().all(|&b| b == 0) {
        f.node(Node::new("UMID").span(at).summary("not set"));
    } else {
        f.node(struct_node("UMID", at, Endian::Big, (), umid).summary(kind));
    }
    if version >= 2 {
        for (name, unit) in [
            ("Loudness value", "LUFS"),
            ("Loudness range", "LU"),
            ("Max true peak level", "dBTP"),
            ("Max momentary loudness", "LUFS"),
            ("Max short-term loudness", "LUFS"),
        ] {
            f.int::<i16>(name)
                .with(|&v, n| {
                    if v == 0x7fff {
                        n.summary("not set")
                    } else {
                        n.summary(format!("{:.2} {unit}", f64::from(v) / 100.0))
                    }
                })
                .emit()?;
        }
        f.bytes("Reserved", 180).emit()?;
    } else {
        f.bytes("Reserved", 190).emit()?;
    }
    Ok(())
}

/// A SMPTE 330M UMID (32-byte basic or 64-byte extended).
pub fn umid(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.bytes("Universal label", 12)
        .desc("06 0A 2B 34 01 01 01 xx 01 01 xx xx")
        .emit()?;
    let len = f
        .u8("Length")
        .with(|&l, n| match l {
            0x13 => n.summary("basic UMID"),
            0x33 => n.summary("extended UMID"),
            _ => n,
        })
        .emit()?;
    f.bytes("Instance number", 3).emit()?;
    f.bytes("Material number", 16).emit()?;
    if len == 0x33 {
        f.bytes("Time/date", 8).emit()?;
        f.bytes("Spatial coordinates", 12).emit()?;
        latin1_field(f, "Country", 4).emit()?;
        latin1_field(f, "Organization", 4).emit()?;
        latin1_field(f, "User", 4).emit()?;
    } else if f.remaining() > 0 {
        f.bytes("Unused", f.remaining()).emit()?;
    }
    Ok(())
}

/// The fixed part of the AES46 `cart` chunk (2048 bytes).
fn cart(cx: &Cx, f: &mut Fields<'_>) -> Result<()> {
    latin1_field(f, "Version", 4).desc("e.g. 0101").emit()?;
    for name in [
        "Title",
        "Artist",
        "Cut ID",
        "Client ID",
        "Category",
        "Classification",
        "Out cue",
    ] {
        latin1_field(f, name, 64).emit()?;
    }
    latin1_field(f, "Start date", 10).emit()?;
    latin1_field(f, "Start time", 8).emit()?;
    latin1_field(f, "End date", 10).emit()?;
    latin1_field(f, "End time", 8).emit()?;
    latin1_field(f, "Producer application", 64).emit()?;
    latin1_field(f, "Producer application version", 64).emit()?;
    latin1_field(f, "User defined", 64).emit()?;
    f.i32("Level reference")
        .desc("Sample value of 0 dB reference")
        .emit()?;
    for i in 0..8u8 {
        let at = f.peek_span(8);
        let usage = f.bytes("Usage", 4).get()?;
        let value = f.u32("Value").get()?;
        if usage.iter().all(|&b| b == 0) {
            continue;
        }
        cx.emit(
            Node::new(format!("Post timer {i}"))
                .span(at)
                .value(crate::formats::util::sound::uint(value, 32))
                .summary(fourcc(&usage)),
        );
    }
    f.bytes("Reserved", 276).emit()?;
    latin1_field(f, "URL", 1024).emit()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// The file

pub async fn describe(cx: &Cx, ctx: &Ctx, region: Span) -> Result<Option<String>> {
    let chunks = scan(cx, ctx, region, 64).await?;
    let Some(fmt) = chunks.iter().find(|c| &c.id == b"fmt ") else {
        return Ok(None);
    };
    let fmt = parse(cx, fmt.data, ctx.endian, &(), wave_format).await?;
    let magic = cx.read_avail(ctx.input.span.sub(0, 4)).await?;
    let kind = match magic.as_slice() {
        b"RF64" => "RF64",
        b"BW64" => "BW64",
        b"RIFX" => "WAV (big-endian)",
        _ => "WAV",
    };
    let mut line = format!("{kind} {}", fmt.line());
    let samples = match chunks.iter().find(|c| &c.id == b"fact") {
        Some(fact) => fact_value(cx, ctx, fact.data).await,
        None => None,
    };
    if let Some(data) = chunks.iter().find(|c| &c.id == b"data")
        && let Some(d) = fmt.duration(data.size, samples)
    {
        line.push_str(&format!(", {d}"));
    }
    if let Some(bext) = chunks.iter().find(|c| &c.id == b"bext") {
        let raw = cx.read_avail(bext.data.sub(256, 32)).await?;
        let originator = crate::text::latin1(trim_nul(&raw));
        if originator.is_empty() {
            line.push_str(", Broadcast Wave");
        } else {
            line.push_str(&format!(
                ", Broadcast Wave (originator {})",
                clip(&originator, 32)
            ));
        }
    }
    Ok(Some(line))
}

/// A lazy node for a `WAVEFORMATEX` at `span` (used by AVI and DLS).
pub fn format_node(name: &'static str, span: Span, endian: Endian) -> Node {
    struct_node(name, span, endian, (), wave_format)
}
