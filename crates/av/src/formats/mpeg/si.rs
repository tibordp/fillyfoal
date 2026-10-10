//! Program-specific information (ISO/IEC 13818-1 2.4.4) and DVB service
//! information (ETSI EN 300 468) carried in transport stream sections:
//! PAT, CAT, PMT, NIT, SDT, EIT, TDT and TOT, SCTE-35 splice information,
//! and the descriptors inside them. Sections arrive here reassembled.

use crate::bytes::{u16_be, u32_be};
use crate::formats::util::fmt::plural;
use crate::formats::util::vidutil::bitwalk::Walker;
use crate::formats::util::vidutil::nal::group;
use crate::formats::util::vidutil::{self, lookup_or};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Value};

pub const STREAM_TYPES: EnumTable = &[
    (0x01, "MPEG-1 video"),
    (0x02, "MPEG-2 video"),
    (0x03, "MPEG-1 audio"),
    (0x04, "MPEG-2 audio"),
    (0x05, "private sections"),
    (0x06, "PES private data"),
    (0x07, "MHEG"),
    (0x08, "DSM-CC"),
    (0x09, "H.222.1"),
    (0x0a, "DSM-CC multiprotocol encapsulation"),
    (0x0b, "DSM-CC U-N messages"),
    (0x0c, "DSM-CC stream descriptors"),
    (0x0d, "DSM-CC sections"),
    (0x0e, "auxiliary"),
    (0x0f, "AAC (ADTS)"),
    (0x10, "MPEG-4 Visual"),
    (0x11, "AAC (LATM)"),
    (0x12, "MPEG-4 SL (PES)"),
    (0x13, "MPEG-4 SL (sections)"),
    (0x14, "DSM-CC synchronized download"),
    (0x15, "metadata (PES)"),
    (0x16, "metadata (sections)"),
    (0x17, "metadata (data carousel)"),
    (0x18, "metadata (object carousel)"),
    (0x19, "metadata (synchronized download)"),
    (0x1a, "IPMP"),
    (0x1b, "H.264"),
    (0x1c, "MPEG-4 audio (raw)"),
    (0x1d, "MPEG-4 text"),
    (0x1e, "MPEG-4 auxiliary video"),
    (0x1f, "H.264 SVC"),
    (0x20, "H.264 MVC"),
    (0x21, "JPEG 2000"),
    (0x22, "MPEG-2 video (stereo additional view)"),
    (0x23, "H.264 (stereo additional view)"),
    (0x24, "HEVC"),
    (0x25, "HEVC temporal subset"),
    (0x26, "H.264 MVCD"),
    (0x27, "timeline and external media information"),
    (0x28, "HEVC enhancement (G)"),
    (0x29, "HEVC temporal enhancement (G)"),
    (0x2a, "HEVC enhancement (H)"),
    (0x2b, "HEVC temporal enhancement (H)"),
    (0x2c, "green access units"),
    (0x2d, "MPEG-H 3D audio"),
    (0x2e, "MPEG-H 3D audio (auxiliary)"),
    (0x2f, "quality access units"),
    (0x30, "media orchestration"),
    (0x31, "HEVC motion-constrained tile sets"),
    (0x32, "JPEG XS"),
    (0x33, "VVC"),
    (0x34, "VVC temporal subset"),
    (0x35, "EVC"),
    (0x36, "LCEVC"),
    (0x42, "AVS"),
    (0x7f, "IPMP"),
    (0x80, "LPCM (Blu-ray)"),
    (0x81, "AC-3"),
    (0x82, "DTS"),
    (0x83, "Dolby TrueHD"),
    (0x84, "E-AC-3 (Blu-ray)"),
    (0x85, "DTS-HD High Resolution"),
    (0x86, "SCTE-35 / DTS-HD Master Audio"),
    (0x87, "E-AC-3"),
    (0x90, "PGS subtitles"),
    (0x91, "interactive graphics"),
    (0x92, "text subtitles"),
    (0xa1, "E-AC-3 secondary audio"),
    (0xa2, "DTS-HD secondary audio"),
    (0xd1, "Dirac"),
    (0xd2, "AVS2"),
    (0xd4, "AVS3"),
    (0xea, "VC-1"),
];

/// Whether a stream of this type carries sections rather than PES.
pub fn carries_sections(kind: u8, scte35: bool) -> bool {
    matches!(kind, 0x05 | 0x0b | 0x0c | 0x0d | 0x13 | 0x16) || (kind == 0x86 && scte35)
}

/// The name of a table ID.
pub fn table_name(id: u8) -> String {
    match id {
        0x00 => "Program association table",
        0x01 => "Conditional access table",
        0x02 => "Program map table",
        0x03 => "Transport stream description table",
        0x04 => "Scene description",
        0x05 => "Object descriptor",
        0x06 => "Metadata",
        0x07 => "IPMP control information",
        0x3a..=0x3f => "DSM-CC section",
        0x40 => "Network information table (actual network)",
        0x41 => "Network information table (other network)",
        0x42 => "Service description table (actual stream)",
        0x46 => "Service description table (other stream)",
        0x4a => "Bouquet association table",
        0x4e => "Event information table (present/following, actual)",
        0x4f => "Event information table (present/following, other)",
        0x50..=0x5f => "Event information table (schedule, actual)",
        0x60..=0x6f => "Event information table (schedule, other)",
        0x70 => "Time and date table",
        0x71 => "Running status table",
        0x72 => "Stuffing table",
        0x73 => "Time offset table",
        0x74 => "Application information table",
        0x7e => "Discontinuity information table",
        0x7f => "Selection information table",
        0xc7 => "Master guide table (ATSC)",
        0xc8 => "Terrestrial virtual channel table (ATSC)",
        0xc9 => "Cable virtual channel table (ATSC)",
        0xcd => "System time table (ATSC)",
        0xfc => "SCTE-35 splice information",
        0xff => "Stuffing",
        _ => return format!("Table {id:#04x}"),
    }
    .to_owned()
}

/// A short name of a table ID for summaries ("SDT", "EIT").
pub fn table_short(id: u8) -> &'static str {
    match id {
        0x00 => "PAT",
        0x01 => "CAT",
        0x02 => "PMT",
        0x03 => "TSDT",
        0x40 | 0x41 => "NIT",
        0x42 | 0x46 => "SDT",
        0x4a => "BAT",
        0x4e..=0x6f => "EIT",
        0x70 => "TDT",
        0x71 => "RST",
        0x73 => "TOT",
        0x74 => "AIT",
        0xc7 => "MGT",
        0xc8 | 0xc9 => "VCT",
        0xcd => "STT",
        0xfc => "SCTE-35",
        _ => "section",
    }
}

pub const SERVICE_TYPES: EnumTable = &[
    (0x01, "digital television"),
    (0x02, "digital radio sound"),
    (0x03, "teletext"),
    (0x04, "NVOD reference"),
    (0x05, "NVOD time-shifted"),
    (0x06, "mosaic"),
    (0x07, "FM radio"),
    (0x0a, "advanced codec digital radio sound"),
    (0x0b, "advanced codec mosaic"),
    (0x0c, "data broadcast"),
    (0x10, "DVB MHP"),
    (0x11, "MPEG-2 HD digital television"),
    (0x16, "advanced codec SD digital television"),
    (0x17, "advanced codec SD NVOD time-shifted"),
    (0x18, "advanced codec SD NVOD reference"),
    (0x19, "advanced codec HD digital television"),
    (0x1a, "advanced codec HD NVOD time-shifted"),
    (0x1b, "advanced codec HD NVOD reference"),
    (0x1c, "advanced codec frame-compatible 3D HD television"),
    (0x1f, "HEVC digital television"),
    (0x20, "HEVC UHD digital television"),
];

const RUNNING_STATUS: EnumTable = &[
    (0, "undefined"),
    (1, "not running"),
    (2, "starts in a few seconds"),
    (3, "pausing"),
    (4, "running"),
    (5, "service off-air"),
];

const AUDIO_TYPES: EnumTable = &[
    (0, "undefined"),
    (1, "clean effects"),
    (2, "hearing impaired"),
    (3, "visual impaired commentary"),
];

const ALIGNMENT_TYPES: EnumTable = &[
    (1, "slice or access unit"),
    (2, "access unit"),
    (3, "GOP or sequence"),
    (4, "sequence"),
];

const TELETEXT_TYPES: EnumTable = &[
    (1, "initial teletext page"),
    (2, "teletext subtitle page"),
    (3, "additional information page"),
    (4, "programme schedule page"),
    (5, "teletext subtitle page for the hearing impaired"),
];

const SPLICE_COMMANDS: EnumTable = &[
    (0x00, "splice_null"),
    (0x04, "splice_schedule"),
    (0x05, "splice_insert"),
    (0x06, "time_signal"),
    (0x07, "bandwidth_reservation"),
    (0xff, "private_command"),
];

const CONTENT_NIBBLES: [&str; 12] = [
    "undefined",
    "movie/drama",
    "news/current affairs",
    "show/game show",
    "sports",
    "children's/youth",
    "music/ballet/dance",
    "arts/culture",
    "social/political/economics",
    "education/science/factual",
    "leisure hobbies",
    "special characteristics",
];

/// The name of a descriptor tag (MPEG-2 systems 0x00–0x3f, DVB 0x40–0x7f,
/// and common private ones).
pub fn descriptor_name(tag: u8) -> &'static str {
    match tag {
        0x02 => "Video stream descriptor",
        0x03 => "Audio stream descriptor",
        0x04 => "Hierarchy descriptor",
        0x05 => "Registration descriptor",
        0x06 => "Data stream alignment descriptor",
        0x07 => "Target background grid descriptor",
        0x08 => "Video window descriptor",
        0x09 => "Conditional access descriptor",
        0x0a => "ISO 639 language descriptor",
        0x0b => "System clock descriptor",
        0x0c => "Multiplex buffer utilization descriptor",
        0x0d => "Copyright descriptor",
        0x0e => "Maximum bitrate descriptor",
        0x0f => "Private data indicator descriptor",
        0x10 => "Smoothing buffer descriptor",
        0x11 => "STD descriptor",
        0x12 => "IBP descriptor",
        0x1b => "MPEG-4 video descriptor",
        0x1c => "MPEG-4 audio descriptor",
        0x1d => "IOD descriptor",
        0x1e => "SL descriptor",
        0x1f => "FMC descriptor",
        0x20 => "External ES ID descriptor",
        0x21 => "MuxCode descriptor",
        0x22 => "FmxBufferSize descriptor",
        0x23 => "Multiplex buffer descriptor",
        0x24 => "Content labeling descriptor",
        0x25 => "Metadata pointer descriptor",
        0x26 => "Metadata descriptor",
        0x27 => "Metadata STD descriptor",
        0x28 => "AVC video descriptor",
        0x29 => "IPMP descriptor",
        0x2a => "AVC timing and HRD descriptor",
        0x2b => "MPEG-2 AAC audio descriptor",
        0x2c => "FlexMux timing descriptor",
        0x2d => "MPEG-4 text descriptor",
        0x2e => "MPEG-4 audio extension descriptor",
        0x2f => "Auxiliary video stream descriptor",
        0x30 => "SVC extension descriptor",
        0x31 => "MVC extension descriptor",
        0x32 => "J2K video descriptor",
        0x33 => "MVC operation point descriptor",
        0x34 => "MPEG-2 stereoscopic video format descriptor",
        0x35 => "Stereoscopic program info descriptor",
        0x36 => "Stereoscopic video info descriptor",
        0x37 => "Transport profile descriptor",
        0x38 => "HEVC video descriptor",
        0x39 => "VVC video descriptor",
        0x3a => "EVC video descriptor",
        0x3f => "Extension descriptor",
        0x40 => "Network name descriptor",
        0x41 => "Service list descriptor",
        0x42 => "Stuffing descriptor",
        0x43 => "Satellite delivery system descriptor",
        0x44 => "Cable delivery system descriptor",
        0x45 => "VBI data descriptor",
        0x46 => "VBI teletext descriptor",
        0x47 => "Bouquet name descriptor",
        0x48 => "Service descriptor",
        0x49 => "Country availability descriptor",
        0x4a => "Linkage descriptor",
        0x4b => "NVOD reference descriptor",
        0x4c => "Time shifted service descriptor",
        0x4d => "Short event descriptor",
        0x4e => "Extended event descriptor",
        0x4f => "Time shifted event descriptor",
        0x50 => "Component descriptor",
        0x51 => "Mosaic descriptor",
        0x52 => "Stream identifier descriptor",
        0x53 => "CA identifier descriptor",
        0x54 => "Content descriptor",
        0x55 => "Parental rating descriptor",
        0x56 => "Teletext descriptor",
        0x57 => "Telephone descriptor",
        0x58 => "Local time offset descriptor",
        0x59 => "Subtitling descriptor",
        0x5a => "Terrestrial delivery system descriptor",
        0x5b => "Multilingual network name descriptor",
        0x5c => "Multilingual bouquet name descriptor",
        0x5d => "Multilingual service name descriptor",
        0x5e => "Multilingual component descriptor",
        0x5f => "Private data specifier descriptor",
        0x60 => "Service move descriptor",
        0x61 => "Short smoothing buffer descriptor",
        0x62 => "Frequency list descriptor",
        0x63 => "Partial transport stream descriptor",
        0x64 => "Data broadcast descriptor",
        0x65 => "Scrambling descriptor",
        0x66 => "Data broadcast ID descriptor",
        0x67 => "Transport stream descriptor",
        0x68 => "DSNG descriptor",
        0x69 => "PDC descriptor",
        0x6a => "AC-3 descriptor",
        0x6b => "Ancillary data descriptor",
        0x6c => "Cell list descriptor",
        0x6d => "Cell frequency link descriptor",
        0x6e => "Announcement support descriptor",
        0x6f => "Application signalling descriptor",
        0x70 => "Adaptation field data descriptor",
        0x71 => "Service identifier descriptor",
        0x72 => "Service availability descriptor",
        0x73 => "Default authority descriptor",
        0x74 => "Related content descriptor",
        0x75 => "TVA ID descriptor",
        0x76 => "Content identifier descriptor",
        0x77 => "Time slice FEC identifier descriptor",
        0x78 => "ECM repetition rate descriptor",
        0x79 => "S2 satellite delivery system descriptor",
        0x7a => "Enhanced AC-3 descriptor",
        0x7b => "DTS descriptor",
        0x7c => "AAC descriptor",
        0x7d => "XAIT location descriptor",
        0x7e => "FTA content management descriptor",
        0x7f => "DVB extension descriptor",
        0x81 => "AC-3 audio descriptor (ATSC)",
        0x83 => "Logical channel number descriptor",
        0x86 => "Caption service descriptor (ATSC)",
        0x8a => "Cue identifier descriptor (SCTE-35)",
        0xa0 => "Extended channel name descriptor (ATSC)",
        _ => "Descriptor",
    }
}

/// DVB text (EN 300 468 Annex A): an optional character table selector,
/// then the text; control codes are dropped, `0x8a` is a line break.
pub fn dvb_text(b: &[u8]) -> String {
    let Some(&first) = b.first() else {
        return String::new();
    };
    let (label, rest): (Option<&str>, &[u8]) = match first {
        0x01 => (Some("iso-8859-5"), b.get(1..).unwrap_or_default()),
        0x02 => (Some("iso-8859-6"), b.get(1..).unwrap_or_default()),
        0x03 => (Some("iso-8859-7"), b.get(1..).unwrap_or_default()),
        0x04 => (Some("iso-8859-8"), b.get(1..).unwrap_or_default()),
        0x05 => (Some("iso-8859-9"), b.get(1..).unwrap_or_default()),
        0x06 => (Some("iso-8859-10"), b.get(1..).unwrap_or_default()),
        0x07 => (Some("iso-8859-11"), b.get(1..).unwrap_or_default()),
        0x09 => (Some("iso-8859-13"), b.get(1..).unwrap_or_default()),
        0x0a => (Some("iso-8859-14"), b.get(1..).unwrap_or_default()),
        0x0b => (Some("iso-8859-15"), b.get(1..).unwrap_or_default()),
        0x10 => {
            let n = b.get(2).copied().unwrap_or(1);
            let label = match n {
                1 => "iso-8859-1",
                2 => "iso-8859-2",
                3 => "iso-8859-3",
                4 => "iso-8859-4",
                5 => "iso-8859-5",
                6 => "iso-8859-6",
                7 => "iso-8859-7",
                8 => "iso-8859-8",
                9 => "iso-8859-9",
                10 => "iso-8859-10",
                11 => "iso-8859-11",
                13 => "iso-8859-13",
                14 => "iso-8859-14",
                15 => "iso-8859-15",
                _ => "iso-8859-1",
            };
            (Some(label), b.get(3..).unwrap_or_default())
        }
        0x11 => (Some("utf-16be"), b.get(1..).unwrap_or_default()),
        0x13 => (Some("gb2312"), b.get(1..).unwrap_or_default()),
        0x14 => (Some("big5"), b.get(1..).unwrap_or_default()),
        0x15 => (Some("utf-8"), b.get(1..).unwrap_or_default()),
        0x1f => (None, b.get(2..).unwrap_or_default()),
        _ => (None, b),
    };
    // Drop emphasis and other control codes; map the CR/LF code.
    let cleaned: Vec<u8> = if label == Some("utf-16be") || label == Some("utf-8") {
        rest.to_vec()
    } else {
        rest.iter()
            .filter_map(|&c| match c {
                0x8a => Some(b'\n'),
                0x80..=0x9f => None,
                _ => Some(c),
            })
            .collect()
    };
    match label {
        Some(l) => crate::codec::charset::decode_label(l, &cleaned)
            .unwrap_or_else(|| String::from_utf8_lossy(&cleaned).into_owned()),
        None => iso6937(&cleaned),
    }
}

/// ISO/IEC 6937 (the DVB default table): ASCII, with non-spacing
/// diacritics `0xc1`–`0xcf` before the letter they modify.
fn iso6937(b: &[u8]) -> String {
    const MARKS: [char; 15] = [
        '\u{300}', '\u{301}', '\u{302}', '\u{303}', '\u{304}', '\u{306}', '\u{307}', '\u{308}',
        '\u{308}', '\u{30a}', '\u{327}', '\u{332}', '\u{30b}', '\u{328}', '\u{30c}',
    ];
    let mut out = String::new();
    let mut pending: Option<char> = None;
    for &c in b {
        if (0xc1..=0xcf).contains(&c) {
            pending = MARKS.get(usize::from(c.saturating_sub(0xc1))).copied();
            continue;
        }
        let ch = match c {
            0x00..=0x7f => char::from(c),
            0xa4 => '$',
            0xa6 => '#',
            0xa8 => '¤',
            0xd0 => '―',
            0xd1 => '¹',
            0xd2 => '®',
            0xd3 => '©',
            0xd4 => '™',
            0xe0 => 'Ω',
            0xe1 => 'Æ',
            0xe2 => 'Đ',
            0xe8 => 'Ł',
            0xe9 => 'Ø',
            0xea => 'Œ',
            0xec => 'Þ',
            0xf1 => 'æ',
            0xf2 => 'đ',
            0xf3 => 'ð',
            0xf5 => 'ı',
            0xf8 => 'ł',
            0xf9 => 'ø',
            0xfa => 'œ',
            0xfb => 'ß',
            0xfc => 'þ',
            _ => char::from(c),
        };
        match pending.take() {
            Some(m) => match compose(ch, m) {
                Some(c) => out.push(c),
                None => {
                    out.push(ch);
                    out.push(m);
                }
            },
            None => out.push(ch),
        }
    }
    out
}

/// A precomposed letter for a base letter and a combining mark, for the
/// common Latin letters.
fn compose(base: char, mark: char) -> Option<char> {
    const TABLE: &[(char, &str, &str)] = &[
        ('\u{300}', "AEIOUaeiou", "ÀÈÌÒÙàèìòù"),
        ('\u{301}', "AEIOUYaeiouyCcNnSsZz", "ÁÉÍÓÚÝáéíóúýĆćŃńŚśŹź"),
        ('\u{302}', "AEIOUaeiou", "ÂÊÎÔÛâêîôû"),
        ('\u{303}', "ANOano", "ÃÑÕãñõ"),
        ('\u{308}', "AEIOUaeiouy", "ÄËÏÖÜäëïöüÿ"),
        ('\u{30a}', "AUau", "ÅŮåů"),
        ('\u{327}', "CSTcst", "ÇŞŢçşţ"),
        ('\u{30c}', "CDENRSTZcdenrstz", "ČĎĚŇŘŠŤŽčďěňřšťž"),
        ('\u{30b}', "OUou", "ŐŰőű"),
        ('\u{328}', "AEae", "ĄĘąę"),
        ('\u{307}', "EZez", "ĖŻėż"),
    ];
    let (_, bases, composed) = TABLE.iter().find(|(m, _, _)| *m == mark)?;
    let i = bases.chars().position(|c| c == base)?;
    composed.chars().nth(i)
}

/// A DVB text field: a length byte (already read as `n`) and `n` bytes.
fn text_field(w: &mut Walker, name: &'static str, n: u64) -> Option<String> {
    let start = w.pos();
    let b = w.read_bytes(usize::try_from(n).ok()?)?;
    let s = dvb_text(&b);
    w.text(name, start, s.clone());
    Some(s)
}

fn bcd(b: u64) -> u64 {
    ((b >> 4) & 15).saturating_mul(10).saturating_add(b & 15)
}

/// A 40-bit MJD + BCD UTC time as Unix seconds.
fn mjd_time(v: u64) -> Option<i64> {
    let mjd = i64::try_from(v >> 24).ok()?;
    let h = i64::try_from(bcd((v >> 16) & 0xff)).ok()?;
    let m = i64::try_from(bcd((v >> 8) & 0xff)).ok()?;
    let s = i64::try_from(bcd(v & 0xff)).ok()?;
    mjd.checked_sub(40587)?
        .checked_mul(86400)?
        .checked_add(h.checked_mul(3600)?)?
        .checked_add(m.checked_mul(60)?)?
        .checked_add(s)
}

fn utc_time(w: &mut Walker, name: &'static str) -> Option<i64> {
    let start = w.pos();
    let v = w.read(40)?;
    let t = mjd_time(v);
    match t {
        Some(t) => w.record(name, start, Value::Timestamp { unix_seconds: t }),
        None => w.record(
            name,
            start,
            Value::UInt {
                value: v,
                bits: 40,
                radix: crate::value::Radix::Hex,
            },
        ),
    }
    t
}

fn bcd_duration(w: &mut Walker, name: &'static str) -> Option<u64> {
    let start = w.pos();
    let v = w.read(24)?;
    let secs = bcd(v >> 16)
        .saturating_mul(3600)
        .saturating_add(bcd((v >> 8) & 0xff).saturating_mul(60))
        .saturating_add(bcd(v & 0xff));
    w.text(name, start, vidutil::seconds_ms(secs.saturating_mul(1000)));
    Some(secs)
}

fn lang(w: &mut Walker, name: &'static str) -> Option<String> {
    let start = w.pos();
    let b = w.read_bytes(3)?;
    let s = String::from_utf8_lossy(&b).into_owned();
    w.text(name, start, s.clone());
    Some(s)
}

/// Decodes one descriptor body (the walker holds exactly its bytes).
/// Returns a summary.
fn descriptor_body(w: &mut Walker, tag: u8, len: usize) -> Option<String> {
    match tag {
        0x02 => {
            w.flag("multiple_frame_rate_flag")?;
            w.u("frame_rate_code", 4)?;
            let mpeg1 = w.flag("MPEG_1_only_flag")?;
            w.flag("constrained_parameter_flag")?;
            w.flag("still_picture_flag")?;
            if !mpeg1 && len >= 3 {
                w.x("profile_and_level_indication", 8)?;
                w.u("chroma_format", 2)?;
                w.flag("frame_rate_extension_flag")?;
                w.u("reserved", 5)?;
            }
            None
        }
        0x03 => {
            w.flag("free_format_flag")?;
            w.u("ID", 1)?;
            let layer = w.u("layer", 2)?;
            w.flag("variable_rate_audio_indicator")?;
            Some(format!("layer {layer}"))
        }
        0x05 => {
            let start = w.pos();
            let id = w.read_bytes(4)?;
            let s = vidutil::fourcc(&id);
            w.text("format_identifier", start, s.clone());
            if len > 4 {
                w.bytes("additional_identification_info", len.saturating_sub(4))?;
            }
            Some(s)
        }
        0x06 => {
            let t = w.en("alignment_type", 8, ALIGNMENT_TYPES)?;
            Some(lookup_or(ALIGNMENT_TYPES, t))
        }
        0x09 => {
            let system = w.x("CA_system_ID", 16)?;
            w.u("reserved", 3)?;
            let pid = w.x("CA_PID", 13)?;
            if len > 4 {
                w.bytes("private_data", len.saturating_sub(4))?;
            }
            Some(format!("system {system:#06x}, PID {pid:#06x}"))
        }
        0x0a => {
            let mut langs = Vec::new();
            for _ in 0..len / 4 {
                let l = lang(w, "ISO_639_language_code")?;
                let t = w.en("audio_type", 8, AUDIO_TYPES)?;
                langs.push(if t == 0 {
                    l
                } else {
                    format!("{l} ({})", lookup_or(AUDIO_TYPES, t))
                });
            }
            Some(langs.join(", "))
        }
        0x0e => {
            w.u("reserved", 2)?;
            let rate = w.u("maximum_bitrate", 22)?;
            let bps = rate.saturating_mul(400);
            w.summary(|| format!("{} kb/s", bps / 1000));
            Some(format!("{} kb/s", bps / 1000))
        }
        0x1b | 0x1c => {
            let p = w.x("profile_and_level", 8)?;
            Some(format!("profile and level {p:#04x}"))
        }
        0x28 => {
            let profile = w.en("profile_idc", 8, vidutil::H264_PROFILES)?;
            w.x("constraint_flags", 8)?;
            let level = w.u("level_idc", 8)?;
            w.flag("AVC_still_present")?;
            w.flag("AVC_24_hour_picture_flag")?;
            w.flag("frame_packing_SEI_not_present_flag")?;
            w.u("reserved", 5)?;
            Some(format!(
                "{}@L{}.{}",
                lookup_or(vidutil::H264_PROFILES, profile),
                level / 10,
                level % 10
            ))
        }
        0x2b => {
            w.x("MPEG-2_AAC_profile", 8)?;
            let ch = w.u("MPEG-2_AAC_channel_configuration", 8)?;
            w.x("MPEG-2_AAC_additional_information", 8)?;
            Some(format!("channel configuration {ch}"))
        }
        0x38 => {
            w.u("profile_space", 2)?;
            w.flag("tier_flag")?;
            let profile = w.en("profile_idc", 5, vidutil::HEVC_PROFILES)?;
            w.x("profile_compatibility_indication", 32)?;
            w.flag("progressive_source_flag")?;
            w.flag("interlaced_source_flag")?;
            w.flag("non_packed_constraint_flag")?;
            w.flag("frame_only_constraint_flag")?;
            w.x("copied_44bits", 44)?;
            let level = u8::try_from(w.u("level_idc", 8)?).ok()?;
            let subset = w.flag("temporal_layer_subset_flag")?;
            w.flag("HEVC_still_present_flag")?;
            w.flag("HEVC_24hr_picture_present_flag")?;
            w.flag("sub_pic_hrd_params_not_present_flag")?;
            w.u("reserved", 2)?;
            w.u("HDR_WCG_idc", 2)?;
            if subset && len >= 15 {
                w.u("temporal_id_min", 3)?;
                w.u("reserved", 5)?;
                w.u("temporal_id_max", 3)?;
                w.u("reserved", 5)?;
            }
            Some(format!(
                "{}@L{}",
                lookup_or(vidutil::HEVC_PROFILES, profile),
                vidutil::tables::hevc_level_name(level)
            ))
        }
        0x40 | 0x47 => {
            let s = text_field(
                w,
                if tag == 0x40 {
                    "network_name"
                } else {
                    "bouquet_name"
                },
                crate::bytes::to_u64(len),
            )?;
            Some(s)
        }
        0x41 => {
            for _ in 0..len / 3 {
                w.x("service_id", 16)?;
                w.en("service_type", 8, SERVICE_TYPES)?;
            }
            Some(plural(crate::bytes::to_u64(len / 3), "service"))
        }
        0x48 => {
            let t = w.en("service_type", 8, SERVICE_TYPES)?;
            let n = w.u("service_provider_name_length", 8)?;
            let provider = text_field(w, "service_provider_name", n)?;
            let n = w.u("service_name_length", 8)?;
            let name = text_field(w, "service_name", n)?;
            Some(format!(
                "{name} ({provider}), {}",
                lookup_or(SERVICE_TYPES, t)
            ))
        }
        0x4d => {
            let l = lang(w, "ISO_639_language_code")?;
            let n = w.u("event_name_length", 8)?;
            let name = text_field(w, "event_name", n)?;
            let n = w.u("text_length", 8)?;
            text_field(w, "text", n)?;
            Some(format!("{name} [{l}]"))
        }
        0x4e => {
            w.u("descriptor_number", 4)?;
            w.u("last_descriptor_number", 4)?;
            lang(w, "ISO_639_language_code")?;
            let items = w.u("length_of_items", 8)?;
            if items > 0 {
                w.skip_as("items", usize::try_from(items).ok()?.checked_mul(8)?)?;
            }
            let n = w.u("text_length", 8)?;
            let s = text_field(w, "text", n)?;
            Some(s.chars().take(64).collect())
        }
        0x50 => {
            w.u("stream_content_ext", 4)?;
            w.u("stream_content", 4)?;
            w.x("component_type", 8)?;
            w.u("component_tag", 8)?;
            let l = lang(w, "ISO_639_language_code")?;
            let rest = len.saturating_sub(6);
            if rest > 0 {
                text_field(w, "text", crate::bytes::to_u64(rest))?;
            }
            Some(l)
        }
        0x52 => {
            let t = w.u("component_tag", 8)?;
            Some(format!("component tag {t}"))
        }
        0x53 => {
            for _ in 0..len / 2 {
                w.x("CA_system_id", 16)?;
            }
            None
        }
        0x54 => {
            let mut genres = Vec::new();
            for _ in 0..len / 2 {
                let n1 = w.u("content_nibble_level_1", 4)?;
                w.u("content_nibble_level_2", 4)?;
                w.x("user_byte", 8)?;
                if let Some(g) = CONTENT_NIBBLES.get(usize::try_from(n1).ok()?) {
                    genres.push(*g);
                }
            }
            Some(genres.join(", "))
        }
        0x55 => {
            let mut out = Vec::new();
            for _ in 0..len / 4 {
                let c = lang(w, "country_code")?;
                let r = w.u("rating", 8)?;
                w.summary(|| {
                    if (1..=0x0f).contains(&r) {
                        format!("minimum age {}", r.saturating_add(3))
                    } else {
                        "undefined".to_owned()
                    }
                });
                out.push(format!("{c} {r}"));
            }
            Some(out.join(", "))
        }
        0x56 | 0x46 => {
            let mut out = Vec::new();
            for _ in 0..len / 5 {
                let l = lang(w, "ISO_639_language_code")?;
                let t = w.en("teletext_type", 5, TELETEXT_TYPES)?;
                let mag = w.u("teletext_magazine_number", 3)?;
                let page = w.x("teletext_page_number", 8)?;
                let mag = if mag == 0 { 8 } else { mag };
                out.push(format!(
                    "{l} page {mag}{page:02x} ({})",
                    lookup_or(TELETEXT_TYPES, t)
                ));
            }
            Some(out.join(", "))
        }
        0x58 => {
            for _ in 0..len / 13 {
                w.begin("Local time offset");
                let c = lang(w, "country_code")?;
                w.u("country_region_id", 6)?;
                w.u("reserved", 1)?;
                let neg = w.flag("local_time_offset_polarity")?;
                let off = w.x("local_time_offset", 16)?;
                utc_time(w, "time_of_change")?;
                w.x("next_time_offset", 16)?;
                w.end_summary(|| {
                    format!(
                        "{c} UTC{}{:02}:{:02}",
                        if neg { "−" } else { "+" },
                        bcd(off >> 8),
                        bcd(off & 0xff)
                    )
                });
            }
            None
        }
        0x59 => {
            let mut out = Vec::new();
            for _ in 0..len / 8 {
                let l = lang(w, "ISO_639_language_code")?;
                w.x("subtitling_type", 8)?;
                w.u("composition_page_id", 16)?;
                w.u("ancillary_page_id", 16)?;
                out.push(l);
            }
            Some(out.join(", "))
        }
        0x5f => {
            let v = w.x("private_data_specifier", 32)?;
            Some(format!("{v:#010x}"))
        }
        0x6a | 0x7a => {
            let start = w.pos();
            let flags = w.read(8)?;
            let names: &[&str] = if tag == 0x6a {
                &["component_type", "bsid", "mainid", "asvc"]
            } else {
                &[
                    "component_type",
                    "bsid",
                    "mainid",
                    "asvc",
                    "mixinfoexists",
                    "substream1",
                    "substream2",
                    "substream3",
                ]
            };
            w.record(
                "Flags",
                start,
                Value::UInt {
                    value: flags,
                    bits: 8,
                    radix: crate::value::Radix::Hex,
                },
            );
            for (i, name) in names.iter().enumerate() {
                if flags & (0x80 >> i) != 0 && *name != "mixinfoexists" && w.bits_left() >= 8 {
                    w.x(*name, 8)?;
                }
            }
            if w.bits_left() >= 8 {
                w.skip_as("additional_info", w.bits_left())?;
            }
            None
        }
        0x7c => {
            w.x("profile_and_level", 8)?;
            if len > 1 {
                let flag = w.flag("AAC_type_flag")?;
                w.flag("SAOC_DE_flag")?;
                w.u("reserved", 6)?;
                if flag {
                    w.x("AAC_type", 8)?;
                }
            }
            None
        }
        0x7f | 0x3f => {
            let t = w.x("descriptor_tag_extension", 8)?;
            if len > 1 {
                w.bytes("selector_byte", len.saturating_sub(1))?;
            }
            Some(format!("extension {t:#04x}"))
        }
        0x8a => {
            let t = w.en(
                "cue_stream_type",
                8,
                &[
                    (0, "splice_insert, splice_null, splice_schedule"),
                    (1, "all commands"),
                    (2, "segmentation"),
                    (3, "tiered splicing"),
                    (4, "tiered segmentation"),
                ],
            )?;
            Some(format!("cue stream type {t}"))
        }
        _ => {
            if len > 0 {
                w.bytes("data", len)?;
            }
            None
        }
    }
}

/// `len` bytes of descriptors at the walker's position, each as a node.
/// Returns (tag, body) pairs.
pub fn descriptor_loop(w: &mut Walker, len: usize) -> Option<Vec<(u8, Vec<u8>)>> {
    let end = w.pos().checked_add(len.checked_mul(8)?)?;
    if end > w.len_bits() {
        return None;
    }
    let mut out = Vec::new();
    while w.pos().saturating_add(16) <= end {
        let start = w.pos();
        let tag = u8::try_from(w.read(8)?).ok()?;
        let n = usize::try_from(w.read(8)?).ok()?;
        let body_at = w.pos();
        if body_at.saturating_add(n.saturating_mul(8)) > end {
            w.seek(start);
            return None;
        }
        let body = w.read_bytes(n)?;
        if w.emitting() {
            let mut sub = w.sub(body_at >> 3, n);
            let summary = descriptor_body(&mut sub, tag, n);
            let complete = summary.is_some() || sub.bits_left() == 0;
            let mut children = vec![
                Node::new("descriptor_tag")
                    .span(w.span_bits(start, start.saturating_add(8)))
                    .value(Value::UInt {
                        value: tag.into(),
                        bits: 8,
                        radix: crate::value::Radix::Hex,
                    }),
                Node::new("descriptor_length")
                    .span(w.span_bits(start.saturating_add(8), body_at))
                    .value(Value::UInt {
                        value: crate::bytes::to_u64(n),
                        bits: 8,
                        radix: crate::value::Radix::Dec,
                    }),
            ];
            children.extend(sub.finish(complete));
            let mut node = group(descriptor_name(tag), w.since(start), children);
            node = node.summary(match summary {
                Some(s) if !s.is_empty() => s,
                _ => format!(
                    "tag {tag:#04x}, {}",
                    plural(crate::bytes::to_u64(n), "byte")
                ),
            });
            w.push(node);
        }
        out.push((tag, body));
    }
    Some(out)
}

/// Reads a reserved field and a 12-bit length.
fn length12(w: &mut Walker, reserved: u32, name: &'static str) -> Option<usize> {
    w.u("reserved", reserved)?;
    usize::try_from(w.u(name, 12)?).ok()
}

/// What a PMT says.
#[derive(Clone, Debug, Default)]
pub struct Pmt {
    pub pcr_pid: u16,
    pub program_info: Vec<(u8, Vec<u8>)>,
    pub streams: Vec<PmtStream>,
}

#[derive(Clone, Debug, Default)]
pub struct PmtStream {
    pub kind: u8,
    pub pid: u16,
    pub descriptors: Vec<(u8, Vec<u8>)>,
    /// Offset and length of the entry in the section.
    pub offset: usize,
    pub len: usize,
}

/// A service from an SDT.
#[derive(Clone, Debug, Default)]
pub struct Service {
    pub id: u16,
    pub kind: u8,
    pub name: String,
    pub provider: String,
}

/// What a decoded section yields for the stream summary.
#[derive(Clone, Debug, Default)]
pub struct Decoded {
    pub summary: Option<String>,
    pub pat: Vec<(u16, u16)>,
    pub pmt: Option<Pmt>,
    pub services: Vec<Service>,
    pub network: Option<String>,
}

/// Decodes a whole section (header, table body, CRC). `d` holds the
/// section, whose bytes are at `span`.
pub fn section(d: &[u8], span: Span, emit: bool) -> (Decoded, Vec<Node>) {
    let mut w = Walker::new(d, span, false, emit);
    let mut out = Decoded::default();
    let ok = section_walk(&mut w, d, &mut out).is_some();
    (out, w.finish(ok))
}

fn section_walk(w: &mut Walker, d: &[u8], out: &mut Decoded) -> Option<()> {
    let table = u8::try_from(w.x("table_id", 8)?).ok()?;
    w.summary(|| table_name(table));
    let syntax = w.flag("section_syntax_indicator")?;
    if table == 0xfc {
        w.flag("private_indicator")?;
        w.u("sap_type", 2)?;
    } else {
        w.flag("private_indicator")?;
        w.u("reserved", 2)?;
    }
    let len = usize::try_from(w.u("section_length", 12)?).ok()?;
    let total = len.checked_add(3)?;
    let crc_present = syntax || matches!(table, 0x73 | 0xfc);
    let body_end = if crc_present {
        total.checked_sub(4)?
    } else {
        total
    };
    if total > d.len() {
        return None;
    }
    if syntax {
        let ext = w.x(
            match table {
                0x00 => "transport_stream_id",
                0x02 => "program_number",
                0x40 | 0x41 => "network_id",
                0x42 | 0x46 => "transport_stream_id",
                0x4a => "bouquet_id",
                0x4e..=0x6f => "service_id",
                _ => "table_id_extension",
            },
            16,
        )?;
        let _ = ext;
        w.u("reserved", 2)?;
        w.u("version_number", 5)?;
        w.flag("current_next_indicator")?;
        w.u("section_number", 8)?;
        w.u("last_section_number", 8)?;
    }
    let body_bits = body_end.checked_mul(8)?;
    match table {
        0x00 => {
            let mut n = 0u64;
            while w.pos().saturating_add(32) <= body_bits {
                let start = w.pos();
                let number = u16::try_from(w.read(16)?).ok()?;
                w.read(3)?;
                let pid = u16::try_from(w.read(13)?).ok()?;
                if w.emitting() {
                    let name = if number == 0 {
                        "Network PID".to_owned()
                    } else {
                        format!("Program {number}")
                    };
                    w.record(
                        name,
                        start,
                        Value::UInt {
                            value: pid.into(),
                            bits: 13,
                            radix: crate::value::Radix::Hex,
                        },
                    );
                    w.summary(|| if number == 0 { "NIT" } else { "PMT PID" }.to_owned());
                }
                out.pat.push((number, pid));
                n = n.saturating_add(1);
            }
            out.summary = Some(plural(n, "program"));
        }
        0x01 | 0x03 => {
            let n = body_end.saturating_sub(w.pos() >> 3);
            descriptor_loop(w, n)?;
        }
        0x02 => {
            let mut pmt = Pmt::default();
            w.u("reserved", 3)?;
            pmt.pcr_pid = u16::try_from(w.x("PCR_PID", 13)?).ok()?;
            let info = length12(w, 4, "program_info_length")?;
            if info > 0 {
                w.begin("Program info");
                pmt.program_info = descriptor_loop(w, info)?;
                w.end();
            }
            while w.pos().saturating_add(40) <= body_bits {
                let start = w.pos();
                w.begin("Elementary stream");
                let kind = u8::try_from(w.en("stream_type", 8, STREAM_TYPES)?).ok()?;
                w.u("reserved", 3)?;
                let pid = u16::try_from(w.x("elementary_PID", 13)?).ok()?;
                let n = length12(w, 4, "ES_info_length")?;
                let descriptors = descriptor_loop(w, n)?;
                w.rename(format!("Stream PID {pid:#06x}"));
                w.end_summary(|| lookup_or(STREAM_TYPES, kind.into()));
                pmt.streams.push(PmtStream {
                    kind,
                    pid,
                    descriptors,
                    offset: start >> 3,
                    len: (w.pos() >> 3).saturating_sub(start >> 3),
                });
            }
            out.summary = Some(plural(crate::bytes::to_u64(pmt.streams.len()), "stream"));
            out.pmt = Some(pmt);
        }
        0x40 | 0x41 => {
            let n = length12(w, 4, "network_descriptors_length")?;
            w.begin("Network descriptors");
            let ds = descriptor_loop(w, n)?;
            w.end();
            out.network = ds
                .iter()
                .find(|(t, _)| *t == 0x40)
                .map(|(_, b)| dvb_text(b));
            let n = length12(w, 4, "transport_stream_loop_length")?;
            let end = w.pos().saturating_add(n.saturating_mul(8)).min(body_bits);
            while w.pos().saturating_add(48) <= end {
                w.begin("Transport stream");
                let ts = w.x("transport_stream_id", 16)?;
                w.x("original_network_id", 16)?;
                let n = length12(w, 4, "transport_descriptors_length")?;
                descriptor_loop(w, n)?;
                w.end_summary(|| format!("transport stream {ts:#06x}"));
            }
            out.summary = out.network.clone();
        }
        0x42 | 0x46 => {
            w.x("original_network_id", 16)?;
            w.u("reserved_future_use", 8)?;
            while w.pos().saturating_add(40) <= body_bits {
                w.begin("Service");
                let id = u16::try_from(w.x("service_id", 16)?).ok()?;
                w.u("reserved_future_use", 6)?;
                w.flag("EIT_schedule_flag")?;
                w.flag("EIT_present_following_flag")?;
                w.en("running_status", 3, RUNNING_STATUS)?;
                w.flag("free_CA_mode")?;
                let n = usize::try_from(w.u("descriptors_loop_length", 12)?).ok()?;
                let ds = descriptor_loop(w, n)?;
                let mut service = Service {
                    id,
                    ..Service::default()
                };
                if let Some((_, b)) = ds.iter().find(|(t, _)| *t == 0x48) {
                    service.kind = b.first().copied().unwrap_or(0);
                    let pn = usize::from(b.get(1).copied().unwrap_or(0));
                    let provider = b.get(2..2usize.saturating_add(pn)).unwrap_or_default();
                    let at = 2usize.saturating_add(pn);
                    let sn = usize::from(b.get(at).copied().unwrap_or(0));
                    let start = at.saturating_add(1);
                    let name = b.get(start..start.saturating_add(sn)).unwrap_or_default();
                    service.provider = dvb_text(provider);
                    service.name = dvb_text(name);
                }
                let text = if service.name.is_empty() {
                    format!("service {id}")
                } else {
                    format!("{} ({})", service.name, service.provider)
                };
                w.end_summary(|| text);
                out.services.push(service);
            }
            out.summary = Some(
                out.services
                    .iter()
                    .map(|s| s.name.clone())
                    .collect::<Vec<_>>()
                    .join(", "),
            );
        }
        0x4e..=0x6f => {
            w.x("transport_stream_id", 16)?;
            w.x("original_network_id", 16)?;
            w.u("segment_last_section_number", 8)?;
            w.x("last_table_id", 8)?;
            let mut events = Vec::new();
            while w.pos().saturating_add(96) <= body_bits {
                w.begin("Event");
                let id = w.u("event_id", 16)?;
                let start = utc_time(w, "start_time")?;
                let dur = bcd_duration(w, "duration")?;
                w.en("running_status", 3, RUNNING_STATUS)?;
                w.flag("free_CA_mode")?;
                let n = usize::try_from(w.u("descriptors_loop_length", 12)?).ok()?;
                let ds = descriptor_loop(w, n)?;
                let title = ds.iter().find(|(t, _)| *t == 0x4d).and_then(|(_, b)| {
                    let n = usize::from(*b.get(3)?);
                    Some(dvb_text(b.get(4..4usize.saturating_add(n))?))
                });
                let _ = start;
                let text = match &title {
                    Some(t) => format!("{t}, {}", vidutil::seconds_ms(dur.saturating_mul(1000))),
                    None => format!(
                        "event {id}, {}",
                        vidutil::seconds_ms(dur.saturating_mul(1000))
                    ),
                };
                w.end_summary(|| text);
                if let Some(t) = title {
                    events.push(t);
                }
            }
            out.summary = Some(events.join("; "));
        }
        0x70 => {
            let t = utc_time(w, "UTC_time")?;
            out.summary = Some(format!("UTC {}", time_text(t)));
        }
        0x73 => {
            let t = utc_time(w, "UTC_time")?;
            let n = length12(w, 4, "descriptors_loop_length")?;
            descriptor_loop(w, n)?;
            out.summary = Some(format!("UTC {}", time_text(t)));
        }
        0xfc => {
            out.summary = splice_info(w, body_bits);
            out.summary.as_ref()?;
        }
        _ => {
            let n = body_end.saturating_sub(w.pos() >> 3);
            if n > 0 {
                w.skip_as("Table data", n.saturating_mul(8))?;
            }
        }
    }
    // The CRC covers everything before it.
    if crc_present {
        w.seek(body_bits);
        let start = w.pos();
        let crc = u32::try_from(w.read(32)?).ok()?;
        let computed = crc32_mpeg(d.get(..body_end).unwrap_or_default());
        let mut node = Node::new("CRC_32").span(w.since(start)).value(Value::UInt {
            value: crc.into(),
            bits: 32,
            radix: crate::value::Radix::Hex,
        });
        node = if computed == crc {
            node.summary("valid")
        } else {
            node.diag(crate::error::Diagnostic::warning(format!(
                "CRC mismatch: computed {computed:#010x}"
            )))
        };
        w.push(node);
    }
    Some(())
}

/// Whether the CRC of a section with syntax (or TOT/SCTE-35) checks out.
pub fn crc_ok(d: &[u8]) -> Option<bool> {
    let len = usize::from(u16_be(d, 1)? & 0x0fff).checked_add(3)?;
    let table = *d.first()?;
    let syntax = d.get(1)? & 0x80 != 0;
    if !(syntax || matches!(table, 0x73 | 0xfc)) {
        return None;
    }
    let end = len.checked_sub(4)?;
    let crc = u32_be(d, end)?;
    Some(crc32_mpeg(d.get(..end)?) == crc)
}

fn time_text(t: i64) -> String {
    let days = t.div_euclid(86400);
    let secs = t.rem_euclid(86400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days.saturating_add(719_468);
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe
        .saturating_sub(doe / 1460)
        .saturating_add(doe / 36524)
        .saturating_sub(doe / 146_096))
        / 365;
    let y = yoe.saturating_add(era.saturating_mul(400));
    let doy = doe.saturating_sub(
        yoe.saturating_mul(365)
            .saturating_add(yoe / 4)
            .saturating_sub(yoe / 100),
    );
    let mp = (doy.saturating_mul(5).saturating_add(2)) / 153;
    let d = doy
        .saturating_sub((mp.saturating_mul(153).saturating_add(2)) / 5)
        .saturating_add(1);
    let m = if mp < 10 {
        mp.saturating_add(3)
    } else {
        mp.saturating_sub(9)
    };
    let y = if m <= 2 { y.saturating_add(1) } else { y };
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}",
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    )
}

/// CRC-32/MPEG-2.
pub fn crc32_mpeg(data: &[u8]) -> u32 {
    u32::try_from(crate::codec::crc::CRC32_MPEG2.checksum(data)).unwrap_or(0)
}

/// `splice_time()`: returns the PTS if specified.
fn splice_time(w: &mut Walker) -> Option<Option<u64>> {
    if w.flag("time_specified_flag")? {
        w.u("reserved", 6)?;
        let pts = w.u("pts_time", 33)?;
        w.summary(|| super::seconds_90k(pts));
        Some(Some(pts))
    } else {
        w.u("reserved", 7)?;
        Some(None)
    }
}

/// `splice_info_section()` after the section length (SCTE 35 9.6).
fn splice_info(w: &mut Walker, crc_at: usize) -> Option<String> {
    w.u("protocol_version", 8)?;
    let encrypted = w.flag("encrypted_packet")?;
    w.u("encryption_algorithm", 6)?;
    let adj = w.u("pts_adjustment", 33)?;
    w.summary(|| super::seconds_90k(adj));
    w.u("cw_index", 8)?;
    w.x("tier", 12)?;
    let cmd_len = w.u("splice_command_length", 12)?;
    let cmd = w.en("splice_command_type", 8, SPLICE_COMMANDS)?;
    if encrypted {
        return Some("encrypted".to_owned());
    }
    let start = w.pos();
    w.begin(lookup_or(SPLICE_COMMANDS, cmd));
    let summary = match cmd {
        0x05 => {
            let id = w.x("splice_event_id", 32)?;
            let cancel = w.flag("splice_event_cancel_indicator")?;
            w.u("reserved", 7)?;
            if cancel {
                format!("splice_insert {id:#x} cancelled")
            } else {
                let out = w.flag("out_of_network_indicator")?;
                let program = w.flag("program_splice_flag")?;
                let has_duration = w.flag("duration_flag")?;
                let immediate = w.flag("splice_immediate_flag")?;
                w.u("reserved", 4)?;
                let mut at = None;
                if program && !immediate {
                    at = splice_time(w)?;
                }
                if !program {
                    let n = w.u("component_count", 8)?;
                    for _ in 0..n {
                        w.u("component_tag", 8)?;
                        if !immediate {
                            splice_time(w)?;
                        }
                    }
                }
                let mut duration = None;
                if has_duration {
                    w.flag("auto_return")?;
                    w.u("reserved", 6)?;
                    let d = w.u("duration", 33)?;
                    w.summary(|| super::seconds_90k(d));
                    duration = Some(d);
                }
                w.u("unique_program_id", 16)?;
                w.u("avail_num", 8)?;
                w.u("avails_expected", 8)?;
                let mut s = format!(
                    "splice_insert {id:#x}, {}",
                    if out {
                        "out of network"
                    } else {
                        "return to network"
                    }
                );
                if immediate {
                    s.push_str(", immediate");
                }
                if let Some(t) = at {
                    s.push_str(&format!(" at {}", super::seconds_90k(t)));
                }
                if let Some(d) = duration {
                    s.push_str(&format!(" for {}", super::seconds_90k(d)));
                }
                s
            }
        }
        0x06 => match splice_time(w)? {
            Some(t) => format!("time_signal at {}", super::seconds_90k(t)),
            None => "time_signal".to_owned(),
        },
        _ => lookup_or(SPLICE_COMMANDS, cmd),
    };
    let s = summary.clone();
    w.end_summary(|| s);
    if cmd_len != 0xfff {
        w.seek(start.saturating_add(usize::try_from(cmd_len).ok()?.saturating_mul(8)));
    }
    let n = usize::try_from(w.u("descriptor_loop_length", 16)?).ok()?;
    if n > 0 {
        w.begin("Splice descriptors");
        let end = w.pos().saturating_add(n.saturating_mul(8));
        while w.pos().saturating_add(48) <= end {
            w.begin("Splice descriptor");
            let tag = w.en(
                "splice_descriptor_tag",
                8,
                &[
                    (0, "avail_descriptor"),
                    (1, "DTMF_descriptor"),
                    (2, "segmentation_descriptor"),
                    (3, "time_descriptor"),
                    (4, "audio_descriptor"),
                ],
            )?;
            let len = w.u("descriptor_length", 8)?;
            let body_end = w
                .pos()
                .saturating_add(usize::try_from(len).ok()?.saturating_mul(8));
            w.x("identifier", 32)?;
            if tag == 2 && body_end >= w.pos().saturating_add(40) {
                w.x("segmentation_event_id", 32)?;
                w.flag("segmentation_event_cancel_indicator")?;
            }
            w.seek(body_end.min(end));
            w.end();
        }
        w.end();
        w.seek(end);
    }
    if w.pos() < crc_at {
        w.skip_as(
            "alignment_stuffing / E_CRC_32",
            crc_at.saturating_sub(w.pos()),
        )?;
    }
    Some(summary)
}
