//! Dolby AC-3 and E-AC-3 elementary streams: sync frames starting with
//! `0B 77`, each self-describing its size, sample rate and channel mode.
//!
//! Each frame shows its sync information and bit stream information (BSI):
//! for AC-3 (A/52) mix levels, dialogue normalisation, compression, language,
//! production information, time codes and (bsid 6) the extended BSI; for
//! E-AC-3 (Annex E) the stream type and substream (independent, dependent
//! with its channel map, converted from AC-3), mixing and informational
//! metadata. The CRCs are checked.

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::arcutil::human_size;
use crate::formats::util::sound::{
    Bits, CRC16_BUYPASS, FrameRef, FrameSyntax, bits_node, duration, frames_node, hex, leaf,
};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::{SourceId, Span};
use crate::value::{EnumTable, FlagTable, flag, lookup};

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
    (3, "3/0 (L, C, R)"),
    (4, "2/1 (L, R, S)"),
    (5, "3/1 (L, C, R, S)"),
    (6, "2/2 (L, R, SL, SR)"),
    (7, "3/2 (L, C, R, SL, SR)"),
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
const STRMTYP: EnumTable = &[
    (0, "independent"),
    (1, "dependent"),
    (2, "converted from AC-3"),
    (3, "reserved"),
];
const CMIXLEV: EnumTable = &[
    (0, "−3.0 dB"),
    (1, "−4.5 dB"),
    (2, "−6.0 dB"),
    (3, "reserved"),
];
const SURMIXLEV: EnumTable = &[(0, "−3 dB"), (1, "−6 dB"), (2, "off"), (3, "reserved")];
const DSURMOD: EnumTable = &[
    (0, "not indicated"),
    (1, "not Dolby Surround encoded"),
    (2, "Dolby Surround encoded"),
    (3, "reserved"),
];
const DSUREXMOD: EnumTable = &[
    (0, "not indicated"),
    (1, "not Dolby Surround EX encoded"),
    (2, "Dolby Surround EX encoded"),
    (3, "Dolby Pro Logic IIz encoded"),
];
const DHEADPHONMOD: EnumTable = &[
    (0, "not indicated"),
    (1, "not Dolby Headphone encoded"),
    (2, "Dolby Headphone encoded"),
    (3, "reserved"),
];
const ADCONVTYP: EnumTable = &[(0, "standard"), (1, "HDCD")];
const ROOMTYP: EnumTable = &[
    (0, "not indicated"),
    (1, "large room, X curve"),
    (2, "small room, flat"),
    (3, "reserved"),
];
const DMIXMOD: EnumTable = &[
    (0, "not indicated"),
    (1, "Lt/Rt preferred"),
    (2, "Lo/Ro preferred"),
    (3, "Pro Logic II preferred"),
];
const MIXLEV_3: EnumTable = &[
    (0, "+3.0 dB"),
    (1, "+1.5 dB"),
    (2, "0.0 dB"),
    (3, "−1.5 dB"),
    (4, "−3.0 dB"),
    (5, "−4.5 dB"),
    (6, "−6.0 dB"),
    (7, "−∞ dB"),
];

/// E-AC-3 dependent substream channel map, by bit (bit 0 is the MSB).
const CHANMAP: FlagTable = &[
    flag(0x8000, "L"),
    flag(0x4000, "C"),
    flag(0x2000, "R"),
    flag(0x1000, "LS"),
    flag(0x0800, "RS"),
    flag(0x0400, "LC_RC"),
    flag(0x0200, "LRS_RRS"),
    flag(0x0100, "CS"),
    flag(0x0080, "TS"),
    flag(0x0040, "LSD_RSD"),
    flag(0x0020, "LW_RW"),
    flag(0x0010, "VHL_VHR"),
    flag(0x0008, "VHC"),
    flag(0x0004, "LTS_RTS"),
    flag(0x0002, "LFE2"),
    flag(0x0001, "LFE"),
];

/// Channels a channel map names: pairs count twice.
fn chanmap_channels(map: u64) -> u32 {
    const PAIRS: u64 = 0x0400 | 0x0200 | 0x0040 | 0x0020 | 0x0010 | 0x0004;
    (map.count_ones()).saturating_add((map & PAIRS).count_ones())
}

fn acmod_name(acmod: u64, lfe: bool) -> String {
    let n = CHANNELS.get(to_usize(acmod)).copied().unwrap_or(0);
    if lfe {
        format!("{n}.1 ch")
    } else {
        format!("{n} ch")
    }
}

/// What a frame's header says.
#[derive(Clone, Copy, Debug, Default)]
struct Info {
    eac3: bool,
    /// Bytes.
    len: u64,
    rate: u32,
    kbps: u64,
    acmod: u64,
    lfe: bool,
    /// 256-sample audio blocks per frame.
    blocks: u64,
    strmtyp: u64,
    substream: u64,
    chanmap: Option<u64>,
    bsmod: Option<u64>,
    dialnorm: u64,
}

impl Info {
    fn describe(&self) -> String {
        let mut s = if self.eac3 {
            match self.strmtyp {
                1 => format!("E-AC-3 dependent substream {}", self.substream),
                2 => "E-AC-3 (converted from AC-3)".to_owned(),
                _ if self.substream > 0 => {
                    format!("E-AC-3 independent substream {}", self.substream)
                }
                _ => "E-AC-3".to_owned(),
            }
        } else {
            "AC-3".to_owned()
        };
        s.push_str(&format!(", {} kbps, {} Hz, ", self.kbps, self.rate));
        match self.chanmap {
            Some(map) => s.push_str(&format!("{} ch (channel map)", chanmap_channels(map))),
            None => s.push_str(&acmod_name(self.acmod, self.lfe)),
        }
        if let Some(name) = self
            .bsmod
            .filter(|&m| m != 0)
            .and_then(|m| lookup(BSMOD, m))
        {
            s.push_str(&format!(", {name}"));
        }
        s
    }
}

/// Reads the sync information and BSI (emitting them if `b` emits).
fn header(b: &mut Bits<'_>) -> Result<Info> {
    // The bitstream ID (bits 40..45) tells AC-3 from E-AC-3.
    b.seek(40);
    let bsid = b.read(5).unwrap_or(0);
    b.seek(0);
    b.field("Sync word", 16).hex().emit()?;
    match bsid {
        0..=10 => ac3_bsi(b),
        11..=16 => eac3_bsi(b),
        _ => Err(Diagnostic::unsupported(format!("bitstream ID {bsid}"))),
    }
}

/// The second program (dual mono) repeats some fields.
fn program(b: &mut Bits<'_>, two: bool, eac3: bool) -> Result<u64> {
    let dialnorm = b
        .field(
            if two {
                "Dialogue normalisation 2"
            } else {
                "Dialogue normalisation"
            },
            5,
        )
        .with(|v, n| n.summary(format!("−{} dB", if v == 0 { 31 } else { v })))
        .emit()?;
    if b.field(
        if two {
            "Compression gain 2 present"
        } else {
            "Compression gain present"
        },
        1,
    )
    .flag()
    .emit()?
        != 0
    {
        b.field(
            if two {
                "Compression gain 2"
            } else {
                "Compression gain"
            },
            8,
        )
        .emit()?;
    }
    if !eac3 {
        if b.field(
            if two {
                "Language code 2 present"
            } else {
                "Language code present"
            },
            1,
        )
        .flag()
        .emit()?
            != 0
        {
            b.field(
                if two {
                    "Language code 2"
                } else {
                    "Language code"
                },
                8,
            )
            .emit()?;
        }
        if b.field(
            if two {
                "Production info 2 present"
            } else {
                "Production info present"
            },
            1,
        )
        .flag()
        .emit()?
            != 0
        {
            b.field(
                if two {
                    "Mixing level 2"
                } else {
                    "Mixing level"
                },
                5,
            )
            .with(|v, n| n.summary(format!("{} dB SPL", v.saturating_add(80))))
            .emit()?;
            b.field(if two { "Room type 2" } else { "Room type" }, 2)
                .enumeration(ROOMTYP)
                .emit()?;
        }
    }
    Ok(if dialnorm == 0 { 31 } else { dialnorm })
}

fn ac3_bsi(b: &mut Bits<'_>) -> Result<Info> {
    b.field("CRC1", 16)
        .hex()
        .desc("Of the first 5/8 of the frame")
        .emit()?;
    let fscod = b
        .field("Sample rate code", 2)
        .with(|v, n| {
            n.summary(match v {
                0 => "48 kHz",
                1 => "44.1 kHz",
                2 => "32 kHz",
                _ => "reserved",
            })
        })
        .emit()?;
    let code = b
        .field("Frame size code", 6)
        .with(|v, n| match BITRATES.get(to_usize(v / 2)) {
            Some(k) => n.summary(format!("{k} kbps")),
            None => n.diag(Diagnostic::malformed("invalid frame size code")),
        })
        .emit()?;
    let bsid = b
        .field("Bitstream ID", 5)
        .with(|v, n| {
            n.summary(if v == 6 {
                "A/52 Annex D (extended BSI)"
            } else {
                "A/52"
            })
        })
        .emit()?;
    let bsmod = b.field("Bitstream mode", 3).enumeration(BSMOD).emit()?;
    let acmod = b.field("Audio coding mode", 3).enumeration(ACMOD).emit()?;
    if acmod & 1 != 0 && acmod != 1 {
        b.field("Centre mix level", 2).enumeration(CMIXLEV).emit()?;
    }
    if acmod & 4 != 0 {
        b.field("Surround mix level", 2)
            .enumeration(SURMIXLEV)
            .emit()?;
    }
    if acmod == 2 {
        b.field("Dolby Surround mode", 2)
            .enumeration(DSURMOD)
            .emit()?;
    }
    let lfe = b.field("LFE on", 1).flag().emit()? != 0;
    let dialnorm = program(b, false, false)?;
    if acmod == 0 {
        program(b, true, false)?;
    }
    b.field("Copyright", 1).flag().emit()?;
    b.field("Original bitstream", 1).flag().emit()?;
    let words = match fscod {
        0 => BITRATES
            .get(to_usize(code / 2))
            .map(|&k| u64::from(k).saturating_mul(2)),
        1 => WORDS_44K.get(to_usize(code)).map(|&w| u64::from(w)),
        2 => BITRATES
            .get(to_usize(code / 2))
            .map(|&k| u64::from(k).saturating_mul(3)),
        _ => None,
    };
    ac3_tail(b, bsid)?;
    Ok(Info {
        eac3: false,
        len: words.unwrap_or(0).saturating_mul(2),
        rate: [48000, 44100, 32000]
            .get(to_usize(fscod))
            .copied()
            .unwrap_or(0),
        kbps: BITRATES.get(to_usize(code / 2)).map_or(0, |&k| k.into()),
        acmod,
        lfe,
        blocks: 6,
        strmtyp: 0,
        substream: 0,
        chanmap: None,
        bsmod: Some(bsmod),
        dialnorm,
    })
}

fn eac3_bsi(b: &mut Bits<'_>) -> Result<Info> {
    let strmtyp = b.field("Stream type", 2).enumeration(STRMTYP).emit()?;
    let substream = b.field("Substream ID", 3).emit()?;
    let frmsiz = b
        .field("Frame size − 1", 11)
        .desc("In 16-bit words")
        .with(|v, n| n.summary(format!("{} bytes", v.saturating_add(1).saturating_mul(2))))
        .emit()?;
    let fscod = b
        .field("Sample rate code", 2)
        .with(|v, n| {
            n.summary(match v {
                0 => "48 kHz",
                1 => "44.1 kHz",
                2 => "32 kHz",
                _ => "reduced rate (code 2 follows)",
            })
        })
        .emit()?;
    let (rate, blocks) = if fscod == 3 {
        let code = b
            .field("Sample rate code 2", 2)
            .with(|v, n| {
                n.summary(match v {
                    0 => "24 kHz",
                    1 => "22.05 kHz",
                    2 => "16 kHz",
                    _ => "reserved",
                })
            })
            .emit()?;
        (
            [24000, 22050, 16000]
                .get(to_usize(code))
                .copied()
                .unwrap_or(0),
            6,
        )
    } else {
        let code = b
            .field("Blocks per frame code", 2)
            .with(|v, n| {
                n.summary(format!(
                    "{} blocks of 256 samples",
                    [1, 2, 3, 6].get(to_usize(v)).copied().unwrap_or(0)
                ))
            })
            .emit()?;
        (
            [48000, 44100, 32000]
                .get(to_usize(fscod))
                .copied()
                .unwrap_or(0),
            [1u64, 2, 3, 6].get(to_usize(code)).copied().unwrap_or(6),
        )
    };
    let acmod = b.field("Audio coding mode", 3).enumeration(ACMOD).emit()?;
    let lfe = b.field("LFE on", 1).flag().emit()? != 0;
    b.field("Bitstream ID", 5)
        .with(|v, n| {
            n.summary(if v == 16 {
                "E-AC-3 (Annex E)"
            } else {
                "E-AC-3 (reserved ID)"
            })
        })
        .emit()?;
    let dialnorm = program(b, false, true)?;
    if acmod == 0 {
        program(b, true, true)?;
    }
    let mut chanmap = None;
    if strmtyp == 1 && b.field("Channel map present", 1).flag().emit()? != 0 {
        chanmap = Some(
            b.field("Channel map", 16)
                .flags(CHANMAP)
                .with(|v, n| n.summary(format!("{} channels", chanmap_channels(v))))
                .emit()?,
        );
    }
    if b.field("Mixing metadata present", 1).flag().emit()? != 0 {
        mixing_metadata(b, strmtyp, acmod, lfe, blocks)?;
    }
    let mut bsmod = None;
    if b.field("Informational metadata present", 1).flag().emit()? != 0 {
        bsmod = Some(b.field("Bitstream mode", 3).enumeration(BSMOD).emit()?);
        b.field("Copyright", 1).flag().emit()?;
        b.field("Original bitstream", 1).flag().emit()?;
        if acmod == 2 {
            b.field("Dolby Surround mode", 2)
                .enumeration(DSURMOD)
                .emit()?;
            b.field("Dolby Headphone mode", 2)
                .enumeration(DHEADPHONMOD)
                .emit()?;
        }
        if acmod >= 6 {
            b.field("Dolby Surround EX mode", 2)
                .enumeration(DSUREXMOD)
                .emit()?;
        }
        let programs = if acmod == 0 { 2 } else { 1 };
        for name in ["Production info present", "Production info 2 present"]
            .into_iter()
            .take(programs)
        {
            if b.field(name, 1).flag().emit()? != 0 {
                b.field("Mixing level", 5)
                    .with(|v, n| n.summary(format!("{} dB SPL", v.saturating_add(80))))
                    .emit()?;
                b.field("Room type", 2).enumeration(ROOMTYP).emit()?;
                b.field("A/D converter type", 1)
                    .with(|v, n| n.summary(if v == 0 { "standard" } else { "HDCD" }))
                    .emit()?;
            }
        }
        if fscod < 3 {
            b.field("Source sample rate", 1)
                .with(|v, n| n.summary(if v == 0 { "same" } else { "twice the rate" }))
                .emit()?;
        }
    }
    if strmtyp == 0 && blocks != 6 {
        b.field("Converter sync", 1)
            .flag()
            .desc("Marks the first frame of a set of six blocks")
            .emit()?;
    }
    if strmtyp == 2 {
        let present = blocks == 6 || b.field("AC-3 frame size code present", 1).flag().emit()? != 0;
        if present {
            b.field("AC-3 frame size code", 6).emit()?;
        }
    }
    additional_bsi(b)?;
    let bytes = frmsiz.saturating_add(1).saturating_mul(2);
    Ok(Info {
        eac3: true,
        len: bytes,
        rate,
        kbps: bytes
            .saturating_mul(8)
            .saturating_mul(rate.into())
            .checked_div(blocks.saturating_mul(256).saturating_mul(1000))
            .unwrap_or(0),
        acmod,
        lfe,
        blocks,
        strmtyp,
        substream,
        chanmap,
        bsmod,
        dialnorm,
    })
}

fn mixing_metadata(
    b: &mut Bits<'_>,
    strmtyp: u64,
    acmod: u64,
    lfe: bool,
    blocks: u64,
) -> Result<()> {
    if acmod > 2 {
        b.field("Preferred downmix", 2)
            .enumeration(DMIXMOD)
            .emit()?;
        if acmod & 1 != 0 {
            b.field("Lt/Rt centre mix level", 3)
                .enumeration(MIXLEV_3)
                .emit()?;
            b.field("Lo/Ro centre mix level", 3)
                .enumeration(MIXLEV_3)
                .emit()?;
        }
        if acmod & 4 != 0 {
            b.field("Lt/Rt surround mix level", 3)
                .enumeration(MIXLEV_3)
                .emit()?;
            b.field("Lo/Ro surround mix level", 3)
                .enumeration(MIXLEV_3)
                .emit()?;
        }
    }
    if lfe && b.field("LFE mix level present", 1).flag().emit()? != 0 {
        b.field("LFE mix level", 5)
            .with(|v, n| {
                n.summary(format!(
                    "{} dB",
                    10i64.saturating_sub(i64::try_from(v).unwrap_or(0))
                ))
            })
            .emit()?;
    }
    if strmtyp != 0 {
        return Ok(());
    }
    let programs = if acmod == 0 { 2 } else { 1 };
    for _ in 0..programs {
        if b.field("Program scale factor present", 1).flag().emit()? != 0 {
            b.field("Program scale factor", 6).emit()?;
        }
    }
    if b.field("External program scale factor present", 1)
        .flag()
        .emit()?
        != 0
    {
        b.field("External program scale factor", 6).emit()?;
    }
    let mixdef = b.field("Mix control type", 2).emit()?;
    match mixdef {
        1 => {
            b.field("Mix control", 5).hex().emit()?;
        }
        2 => {
            b.field("Mix control", 12).hex().emit()?;
        }
        3 => {
            let len = b.field("Mix control length", 5).emit()?;
            b.skip(len.saturating_add(2).saturating_mul(8));
        }
        _ => {}
    }
    if acmod < 2 {
        for _ in 0..programs {
            if b.field("Pan information present", 1).flag().emit()? != 0 {
                b.field("Pan mean direction", 8).emit()?;
                b.field("Pan information", 6).emit()?;
            }
        }
    }
    if b.field("Mixing configuration present", 1).flag().emit()? != 0 {
        for _ in 0..blocks {
            if blocks == 1
                || b.field("Block mixing configuration present", 1)
                    .flag()
                    .emit()?
                    != 0
            {
                b.field("Block mixing configuration", 5).emit()?;
            }
        }
    }
    Ok(())
}

/// Time codes (AC-3) or, for bitstream ID 6 (Annex D), the extended BSI
/// that replaces them; then additional BSI.
fn ac3_tail(b: &mut Bits<'_>, bsid: u64) -> Result<()> {
    if bsid == 6 {
        if b.field("Extended BSI 1 present", 1).flag().emit()? != 0 {
            b.field("Preferred downmix", 2)
                .enumeration(DMIXMOD)
                .emit()?;
            b.field("Lt/Rt centre mix level", 3)
                .enumeration(MIXLEV_3)
                .emit()?;
            b.field("Lt/Rt surround mix level", 3)
                .enumeration(MIXLEV_3)
                .emit()?;
            b.field("Lo/Ro centre mix level", 3)
                .enumeration(MIXLEV_3)
                .emit()?;
            b.field("Lo/Ro surround mix level", 3)
                .enumeration(MIXLEV_3)
                .emit()?;
        }
        if b.field("Extended BSI 2 present", 1).flag().emit()? != 0 {
            b.field("Dolby Surround EX mode", 2)
                .enumeration(DSUREXMOD)
                .emit()?;
            b.field("Dolby Headphone mode", 2)
                .enumeration(DHEADPHONMOD)
                .emit()?;
            b.field("A/D converter type", 1)
                .enumeration(ADCONVTYP)
                .emit()?;
            b.field("Extended BSI 2", 8).hex().emit()?;
            b.field("Encoder information", 1).emit()?;
        }
    } else {
        for (present, name) in [
            ("Time code 1 present", "Time code 1"),
            ("Time code 2 present", "Time code 2"),
        ] {
            if b.field(present, 1).flag().emit()? != 0 {
                b.field(name, 14).hex().emit()?;
            }
        }
    }
    additional_bsi(b)
}

fn additional_bsi(b: &mut Bits<'_>) -> Result<()> {
    if b.field("Additional BSI present", 1).flag().emit()? != 0 {
        let len = b.field("Additional BSI length − 1", 6).emit()?;
        b.skip(len.saturating_add(1).saturating_mul(8));
    }
    Ok(())
}

/// The whole header (sync information and BSI).
fn layout(b: &mut Bits<'_>) -> Result<()> {
    header(b).map(|_| ())
}

/// Parses the header of the frame at the start of `d`.
fn info(d: &[u8]) -> Option<Info> {
    if d.get(..2)? != [0x0b, 0x77] {
        return None;
    }
    let mut b = Bits::new(d, Span::new(SourceId::ZEROS, 0, to_u64(d.len())));
    let info = header(&mut b).ok()?;
    (info.len >= 8 && info.rate > 0).then_some(info)
}

fn parse(d: &[u8]) -> Option<(u64, String)> {
    let i = info(d)?;
    Some((i.len, i.describe()))
}

fn header_len(d: &[u8]) -> u64 {
    let mut b = Bits::new(d, Span::new(SourceId::ZEROS, 0, to_u64(d.len())));
    if layout(&mut b).is_err() {
        return 8;
    }
    b.pos().div_ceil(8)
}

static SYNTAX: FrameSyntax = FrameSyntax {
    peek: 160,
    sync: &[0x0b],
    parse,
    header: header_len,
    layout,
    expand: Some(crate::expander!(frame: FrameRef)),
};

async fn frame(cx: Cx, f: FrameRef) -> Result<()> {
    cx.emit(bits_node(
        "Sync information and BSI",
        f.header,
        layout,
        false,
    ));
    let data = if f.span.len <= cx.limits().max_read {
        cx.read_avail(f.span).await?
    } else {
        Vec::new()
    };
    let complete = to_u64(data.len()) == f.span.len && !data.is_empty();
    let eac3 = data.get(5).is_some_and(|b| b >> 3 > 10);
    let crc_at = f.span.len.saturating_sub(2);
    let blocks = f
        .span
        .sub(f.header.len, crc_at.saturating_sub(f.header.len));
    cx.emit(
        Node::new("Audio blocks")
            .span(blocks)
            .summary(human_size(blocks.len))
            .desc("Exponents, bit allocation and mantissas, then auxiliary data"),
    );
    let stored = crate::bytes::u16_be(&data, to_usize(crc_at)).unwrap_or(0);
    let mut node = leaf(
        if eac3 { "CRC" } else { "CRC2" },
        f.span.sub(crc_at, 2),
        hex(stored, 16),
    )
    .desc(if eac3 {
        "Of the frame after the sync word"
    } else {
        "Of the last 3/8 of the frame"
    });
    if complete {
        let len = to_usize(f.span.len);
        // AC-3 checks the first 5/8 (CRC1) and the rest (CRC2); E-AC-3
        // the whole frame after the sync word. A correct CRC leaves no
        // remainder.
        let five_eighths = ((len >> 2).saturating_add(len >> 4)) << 1;
        let ranges = if eac3 {
            vec![(2, len)]
        } else {
            vec![(2, five_eighths), (five_eighths, len)]
        };
        let mut bad = Vec::new();
        for (i, (from, to)) in ranges.into_iter().enumerate() {
            let part = data.get(from..to).unwrap_or_default();
            if CRC16_BUYPASS.checksum(part) != 0 {
                bad.push(if eac3 {
                    "CRC"
                } else if i == 0 {
                    "CRC1"
                } else {
                    "CRC2"
                });
            }
        }
        node = if bad.is_empty() {
            node.summary(if eac3 { "valid" } else { "valid (CRC1 too)" })
        } else {
            node.diag(Diagnostic::warning(format!(
                "{} mismatch",
                bad.join(" and ")
            )))
        };
    }
    cx.emit(node);
    Ok(())
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let window = cx.read_avail(file.sub(0, 0x10000)).await?;
    if let Some(first) = info(&window) {
        // Count the frames of the first independent substream; note what
        // else is multiplexed with it.
        let mut at = 0usize;
        let (mut frames, mut bytes) = (0u64, 0u64);
        let mut dependent: Option<Info> = None;
        let mut substreams = 0u64;
        while let Some(i) = window.get(at..).and_then(info) {
            let end = at.saturating_add(to_usize(i.len));
            if end > window.len() {
                break;
            }
            if i.strmtyp != 1 && i.substream == 0 {
                frames = frames.saturating_add(1);
            } else if i.strmtyp == 1 {
                dependent = dependent.or(Some(i));
            } else {
                substreams = substreams.max(i.substream);
            }
            bytes = bytes.saturating_add(i.len);
            at = end;
        }
        let total = if to_u64(window.len()) >= file.len || bytes == 0 {
            frames as f64
        } else {
            frames as f64 * file.len as f64 / bytes as f64
        };
        let seconds = if first.rate > 0 {
            total * first.blocks.saturating_mul(256) as f64 / f64::from(first.rate)
        } else {
            0.0
        };
        let mut line = format!(
            "{}, {} kbps, {} Hz, {}",
            if first.eac3 { "E-AC-3" } else { "AC-3" },
            if seconds > 0.0 {
                (file.len as f64 * 8.0 / seconds / 1000.0).round() as u64
            } else {
                first.kbps
            },
            first.rate,
            acmod_name(first.acmod, first.lfe)
        );
        if let Some(d) = dependent {
            let extra = d.chanmap.map_or_else(
                || acmod_name(d.acmod, d.lfe),
                |m| format!("{} ch", chanmap_channels(m)),
            );
            line.push_str(&format!(" + dependent substream ({extra})"));
        }
        if substreams > 0 {
            line.push_str(&format!(" + {substreams} more independent substreams"));
        }
        if let Some(name) = first
            .bsmod
            .filter(|&m| m != 0)
            .and_then(|m| lookup(BSMOD, m))
        {
            line.push_str(&format!(", {name}"));
        }
        line.push_str(&format!(
            ", dialnorm −{} dB, {}",
            first.dialnorm,
            duration(seconds)
        ));
        cx.annotate(line);
    }
    cx.emit(frames_node(file, &SYNTAX));
    Ok(())
}
