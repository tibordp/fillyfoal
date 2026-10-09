//! Sample entries (`stsd` children) and the codec configuration boxes they
//! carry: `avcC`, `hvcC`, `av1C`, `vpcC`, `esds`, `dOps`, `dfLa`, `dac3`,
//! `dec3`, `alac`, `pcmC`, `colr`, `pasp`, `clap`, `btrt`, `mdcv`, `clli`,
//! ...; plus what a whole entry says about its codec ([`CodecInfo`]).

use crate::bytes::{to_u64, to_usize, u16_be, u32_be, u64_be};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::Result;
use crate::fields::{Fields, struct_node};
use crate::formats::Input;
use crate::formats::embedded;
use crate::formats::util::sound::{BitLayout, bits_node};
use crate::formats::util::vidutil::{
    self, COLOUR_PRIMARIES, H264_PROFILES, HEVC_NAL_TYPES, HEVC_PROFILES, MATRIX_COEFFICIENTS,
    TRANSFER_CHARACTERISTICS, enumerated, fixed16, flag_node, fourcc, h264_level, hevc_level,
    lookup_or, num, uint,
};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, flag};

use super::boxes::bitrate;
use super::codec::{self, Ac3, Asc, HevcConfig, bits_at, channel_count, chroma_name, khz};
use super::{BE, BoxState, Brand, children, full_box, read_header, small};

/// What kind of sample entry a FourCC is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum EntryKind {
    Visual,
    Audio,
    #[default]
    Other,
}

const VISUAL: &[&[u8; 4]] = &[
    b"avc1", b"avc2", b"avc3", b"avc4", b"hvc1", b"hev1", b"dvh1", b"dvhe", b"dva1", b"dvav",
    b"av01", b"vp08", b"vp09", b"vvc1", b"vvi1", b"mp4v", b"s263", b"h263", b"jpeg", b"mjpa",
    b"mjpb", b"mjp2", b"apch", b"apcn", b"apcs", b"apco", b"ap4h", b"ap4x", b"encv", b"png ",
    b"rle ", b"SVQ3", b"cvid", b"mp2v", b"xdvc", b"hdv1", b"dvc ", b"dvcp", b"raw ", b"CRAW",
    b"j2ki", b"hvt1", b"lhv1", b"lhe1", b"dav1", b"avs3", b"uncv", b"m2v1", b"mx5p", b"AVdn",
    b"AVdh", b"v210", b"2vuy",
];

const AUDIO: &[&[u8; 4]] = &[
    b"mp4a", b".mp3", b"ac-3", b"ec-3", b"ac-4", b"Opus", b"fLaC", b"alac", b"samr", b"sawb",
    b"sowt", b"twos", b"lpcm", b"ipcm", b"fpcm", b"in24", b"in32", b"fl32", b"fl64", b"ulaw",
    b"alaw", b"ima4", b"enca", b"dtsc", b"dtsh", b"dtsl", b"dtse", b"mha1", b"mhm1", b"NONE",
    b"sac3", b"mp3 ", b"raw ", b"MAC3", b"MAC6", b"Qclp", b"QDM2", b"QDMC", b"agsm", b"spex",
    b"dtsx", b"mhm2", b"mha2", b"iamf",
];

pub fn entry_kind(kind: &[u8; 4], handler: &[u8; 4]) -> EntryKind {
    if handler == b"vide" || handler == b"pict" || handler == b"auxv" {
        return EntryKind::Visual;
    }
    if handler == b"soun" {
        return EntryKind::Audio;
    }
    if VISUAL.contains(&kind) {
        EntryKind::Visual
    } else if AUDIO.contains(&kind) {
        EntryKind::Audio
    } else {
        EntryKind::Other
    }
}

record! {
    pub struct VisualEntry {
        pre_defined: u16 "Version" .desc("QuickTime; 0 in ISO files"),
        reserved: u16 "Revision",
        vendor: ascii[4] "Vendor",
        temporal: u32 "Temporal quality",
        spatial: u32 "Spatial quality",
        width: u16 "Width",
        height: u16 "Height",
        hres: u32 "Horizontal resolution" .with(|&v, n| n.summary(format!("{} dpi", num(fixed16(v))))),
        vres: u32 "Vertical resolution" .with(|&v, n| n.summary(format!("{} dpi", num(fixed16(v))))),
        data_size: u32 "Data size",
        frame_count: u16 "Frame count" .desc("Frames per sample"),
        compressor: bytes[32] "Compressor name" .with(|v, n| n.summary(pascal(v))),
        depth: u16 "Depth" .hex() .with(|&v, n| n.summary(depth_name(v))),
        color_table: i16 "Color table ID" .with(|&v, n| if v == -1 { n.summary("none") } else { n }),
    }
}

record! {
    pub struct AudioEntry {
        version: u16 "Version" .desc("QuickTime sound description version; 0 in ISO files"),
        revision: u16 "Revision",
        vendor: ascii[4] "Vendor",
        channels: u16 "Channel count",
        sample_size: u16 "Sample size" .desc("Bits per sample"),
        compression: i16 "Compression ID",
        packet_size: u16 "Packet size",
        rate: u32 "Sample rate" .with(|&v, n| n.summary(format!("{} Hz", num(fixed16(v))))),
    }
}

record! {
    pub struct AudioV1 {
        samples_per_packet: u32 "Samples per packet",
        bytes_per_packet: u32 "Bytes per packet",
        bytes_per_frame: u32 "Bytes per frame",
        bytes_per_sample: u32 "Bytes per sample",
    }
}

record! {
    pub struct AudioV2 {
        struct_size: u32 "Size of struct",
        rate: f64 "Sample rate",
        channels: u32 "Channel count",
        reserved: u32 "Reserved" .hex(),
        bits: u32 "Bits per channel",
        flags: u32 "Format-specific flags" .flags(LPCM_FLAGS),
        bytes_per_packet: u32 "Bytes per audio packet",
        frames_per_packet: u32 "LPCM frames per packet",
    }
}

const LPCM_FLAGS: FlagTable = &[
    flag(0x1, "FLOAT"),
    flag(0x2, "BIG_ENDIAN"),
    flag(0x4, "SIGNED_INTEGER"),
    flag(0x8, "PACKED"),
    flag(0x10, "ALIGNED_HIGH"),
    flag(0x20, "NON_INTERLEAVED"),
    flag(0x40, "NON_MIXABLE"),
];

const TMCD_FLAGS: FlagTable = &[
    flag(0x1, "DROP_FRAME"),
    flag(0x2, "MAX_24_HOURS"),
    flag(0x4, "NEGATIVE_TIMES_OK"),
    flag(0x8, "COUNTER"),
];

record! {
    pub struct TimecodeEntry {
        reserved: u32 "Reserved",
        flags: u32 "Flags" .flags(TMCD_FLAGS),
        timescale: u32 "Timescale",
        frame_duration: u32 "Frame duration"
            .with(|&d, n| if d > 0 { n.summary(format!("{} fps", super::tables::fps(f64::from(timescale) / f64::from(d)))) } else { n }),
        frames: u8 "Number of frames" .desc("Frames per second, rounded (the timecode's frame count base)"),
        reserved2: u8 "Reserved",
    }
}

/// A Pascal string in a fixed field.
fn pascal(v: &[u8]) -> String {
    let len = usize::from(v.first().copied().unwrap_or(0));
    let text = v
        .get(1..len.saturating_add(1).min(v.len()))
        .unwrap_or_default();
    String::from_utf8_lossy(text).into_owned()
}

fn depth_name(v: u16) -> String {
    match v {
        1 | 2 | 4 | 8 | 16 => format!("{v}-bit colour"),
        24 => "24-bit colour".to_owned(),
        32 => "colour with alpha".to_owned(),
        33..=40 => format!("{}-bit greyscale", v.saturating_sub(32)),
        _ => format!("{v}"),
    }
}

/// Length of the fixed audio fields after the 8 common bytes: 20, plus
/// QuickTime sound description version 1 (16) or 2 (36).
fn audio_fields_len(brand: Brand, data: &[u8]) -> u64 {
    let version = u16_be(data, 8).unwrap_or(0);
    let boxes_at = |at: usize| {
        u32_be(data, at).is_some_and(|s| {
            s >= 8 && to_u64(data.len()) >= u64::from(s).saturating_add(to_u64(at))
        }) && data
            .get(at.saturating_add(4)..at.saturating_add(8))
            .is_some_and(|k| {
                k.iter()
                    .all(|&b| b.is_ascii_alphanumeric() || b == b' ' || b == b'-' || b == b'.')
            })
    };
    let plain = to_u64(data.len()) == 28 || boxes_at(28);
    match version {
        1 if brand == Brand::Mov || (!plain && (to_u64(data.len()) == 44 || boxes_at(44))) => 36,
        2 if brand == Brand::Mov || (!plain && (to_u64(data.len()) == 64 || boxes_at(64))) => 56,
        _ => 20,
    }
}

/// Expands a sample entry in `stsd`.
pub async fn entry(cx: &Cx, st: &BoxState) -> Result<()> {
    let body = st.body();
    let kind = st.header.kind;
    let ctx = st.ctx;
    let block = cx.block(body.sub(0, 0x10000)).await?;
    let mut f = Fields::emitting(cx, &block, BE);
    f.bytes("Reserved", 6).emit()?;
    f.u16("Data reference index").emit()?;
    match &kind {
        b"tmcd" => {
            TimecodeEntry::read(&mut f)?;
        }
        b"text" if ctx.brand == Brand::Mov || &ctx.handler == b"text" => qt_text(&mut f)?,
        b"tx3g" => tx3g(&mut f)?,
        b"stpp" => {
            f.cstr("Namespace").emit()?;
            f.cstr("Schema location").emit()?;
            if f.remaining() > 0 && !looks_like_boxes(cx, body.tail(f.pos())).await {
                f.cstr("Auxiliary MIME types").emit()?;
            }
        }
        b"mett" => {
            f.cstr("Content encoding").emit()?;
            f.cstr("MIME format").emit()?;
        }
        b"metx" => {
            f.cstr("Content encoding").emit()?;
            f.cstr("Namespace").emit()?;
            f.cstr("Schema location").emit()?;
        }
        b"wvtt" | b"c608" | b"c708" | b"mp4s" => {}
        _ => match entry_kind(&kind, &ctx.handler) {
            EntryKind::Visual => {
                VisualEntry::read(&mut f)?;
            }
            EntryKind::Audio => {
                AudioEntry::read(&mut f)?;
                match audio_fields_len(ctx.brand, &block.data) {
                    36 => {
                        AudioV1::read(&mut f)?;
                    }
                    56 => {
                        AudioV2::read(&mut f)?;
                    }
                    _ => {}
                }
            }
            EntryKind::Other => {}
        },
    }
    let at = f.pos();
    let rest = body.tail(at);
    if rest.is_empty() {
        return Ok(());
    }
    let child = ctx.child(kind, rest);
    if looks_like_boxes(cx, rest).await {
        children(cx, st.input, rest, child).await
    } else {
        cx.emit(
            Node::new(if rest.len < 8 { "Reserved" } else { "Data" })
                .span(rest)
                .summary(format!("{} bytes", rest.len)),
        );
        Ok(())
    }
}

fn qt_text(f: &mut Fields<'_>) -> Result<()> {
    f.u32("Display flags").hex().emit()?;
    f.i32("Text justification").emit()?;
    for name in ["Background red", "Background green", "Background blue"] {
        f.u16(name).hex().emit()?;
    }
    for name in ["Box top", "Box left", "Box bottom", "Box right"] {
        f.int::<i16>(name).emit()?;
    }
    f.bytes("Reserved", 8).emit()?;
    f.u16("Font number").emit()?;
    f.u16("Font face").hex().emit()?;
    f.u8("Reserved").emit()?;
    f.u16("Reserved").emit()?;
    for name in ["Foreground red", "Foreground green", "Foreground blue"] {
        f.u16(name).hex().emit()?;
    }
    if f.remaining() > 0 {
        let n = f.u8("Text name length").emit()?;
        if n > 0 {
            f.ascii("Text name", n.into()).emit()?;
        }
    }
    Ok(())
}

fn tx3g(f: &mut Fields<'_>) -> Result<()> {
    f.u32("Display flags").hex().emit()?;
    f.int::<i8>("Horizontal justification").emit()?;
    f.int::<i8>("Vertical justification").emit()?;
    f.u32("Background color (RGBA)").hex().emit()?;
    for name in ["Box top", "Box left", "Box bottom", "Box right"] {
        f.int::<i16>(name).emit()?;
    }
    f.u16("Style start char").emit()?;
    f.u16("Style end char").emit()?;
    f.u16("Font ID").emit()?;
    f.u8("Face style flags").hex().emit()?;
    f.u8("Font size").emit()?;
    f.u32("Text color (RGBA)").hex().emit()?;
    Ok(())
}

/// Whether `span` plausibly starts with a box.
async fn looks_like_boxes(cx: &Cx, span: Span) -> bool {
    match read_header(cx, span, 0).await {
        Ok(Some(h)) => {
            h.size <= span.len
                && h.kind
                    .iter()
                    .all(|&b| b.is_ascii_alphanumeric() || b == b' ' || b == 0xa9 || b == b'-')
        }
        _ => false,
    }
}

/// Codec summary of a sample entry, for the box list.
pub async fn describe(cx: &Cx, st: &BoxState) -> Option<String> {
    let data = small(cx, st.body()).await.ok()?;
    let info = codec_info(&st.header.kind, &st.ctx.handler, st.ctx.brand, &data);
    Some(info.describe())
}

// ---------------------------------------------------------------------------
// What an entry says about its codec

/// The timing of a timecode track (`tmcd` entry).
#[derive(Clone, Copy, Debug, Default)]
pub struct Timecode {
    pub flags: u32,
    pub timescale: u32,
    pub frame_duration: u32,
    pub frames: u8,
}

impl Timecode {
    /// Formats a frame number as `hh:mm:ss:ff` (`;` before the frames
    /// for drop-frame).
    pub fn format(&self, frame: u32) -> String {
        let fps = u64::from(self.frames.max(1));
        let drop = self.flags & 1 != 0;
        let mut n = u64::from(frame);
        if drop {
            // Frames per ten minutes and per minute (minus the dropped
            // frame numbers), as in SMPTE 12M.
            let (dropped, per10, per1) = match fps {
                30 => (2u64, 17982u64, 1798u64),
                60 => (4, 35964, 3596),
                _ => (0, 0, 0),
            };
            if let (Some(d), Some(m)) = (n.checked_div(per10), n.checked_rem(per10)) {
                let extra = if m < dropped {
                    0
                } else {
                    dropped.saturating_mul(m.saturating_sub(dropped).checked_div(per1).unwrap_or(0))
                };
                n = n
                    .saturating_add(dropped.saturating_mul(9).saturating_mul(d))
                    .saturating_add(extra);
            }
        }
        let ff = n.checked_rem(fps).unwrap_or(0);
        let secs = n.checked_div(fps).unwrap_or(0);
        let hh = (secs / 3600) % 24;
        format!(
            "{hh:02}:{:02}:{:02}{}{ff:02}",
            (secs / 60) % 60,
            secs % 60,
            if drop { ';' } else { ':' }
        )
    }

    pub fn rate(&self) -> String {
        if self.frame_duration == 0 {
            return format!("{} fps", self.frames);
        }
        let rate = f64::from(self.timescale) / f64::from(self.frame_duration);
        format!(
            "{} fps{}",
            super::tables::fps(rate),
            if self.flags & 1 != 0 {
                " drop-frame"
            } else {
                ""
            }
        )
    }
}

/// What a sample entry and its configuration boxes say.
#[derive(Clone, Debug, Default)]
pub struct CodecInfo {
    pub fourcc: [u8; 4],
    pub kind: EntryKind,
    pub name: String,
    pub profile: Option<String>,
    pub codec_string: Option<String>,
    pub width: u32,
    pub height: u32,
    pub depth: Option<u64>,
    pub chroma: Option<&'static str>,
    pub colour: Option<String>,
    pub channels: u64,
    pub layout: Option<String>,
    pub rate: u64,
    pub bits: Option<u64>,
    /// Average bitrate the entry declares (`btrt`, `esds`, `dec3`).
    pub bitrate: Option<u64>,
    /// The protection scheme of an encrypted entry (`schm`).
    pub scheme: Option<String>,
    pub timecode: Option<Timecode>,
}

impl CodecInfo {
    /// Codec and profile: "H.264 High@L4.0", "HE-AACv2".
    pub fn label(&self) -> String {
        match &self.profile {
            Some(p) if p.contains(self.name.as_str()) => p.clone(),
            Some(p) => format!("{} {p}", self.name),
            None => self.name.clone(),
        }
    }

    /// "48 kHz stereo"-style audio details.
    fn audio_details(&self) -> Vec<String> {
        let mut parts = Vec::new();
        if let Some(l) = &self.layout {
            parts.push(l.clone());
        } else if self.channels > 0 {
            parts.push(channel_count(self.channels));
        }
        if self.rate > 0 {
            parts.push(khz(self.rate));
        }
        if let Some(b) = self.bits
            && !self.label().contains("-bit")
        {
            parts.push(format!("{b}-bit"));
        }
        parts
    }

    /// The entry's summary line.
    pub fn describe(&self) -> String {
        let mut parts = vec![self.label()];
        match self.kind {
            EntryKind::Visual => {
                if self.width > 0 || self.height > 0 {
                    parts.push(format!("{}×{}", self.width, self.height));
                }
                match (self.depth, self.chroma) {
                    (Some(d), Some(c)) => parts.push(format!("{d}-bit {c}")),
                    (Some(d), None) => parts.push(format!("{d}-bit")),
                    _ => {}
                }
                if let Some(c) = &self.colour {
                    parts.push(c.clone());
                }
            }
            EntryKind::Audio => parts.extend(self.audio_details()),
            EntryKind::Other => {
                if let Some(t) = &self.timecode {
                    parts.push(t.rate());
                }
            }
        }
        if let Some(s) = &self.scheme {
            parts.push(format!("encrypted ({s})"));
        }
        let mut s = parts.join(", ");
        if let Some(c) = &self.codec_string {
            s = format!("{s} [{c}]");
        }
        s
    }

    /// The short form for the file summary: "H.264 1920×1080",
    /// "AAC-LC stereo 48 kHz".
    pub fn short(&self) -> String {
        match self.kind {
            EntryKind::Visual if self.width > 0 && self.height > 0 => {
                format!("{} {}×{}", self.name, self.width, self.height)
            }
            EntryKind::Audio => {
                let mut parts = vec![self.label()];
                parts.extend(
                    self.audio_details()
                        .into_iter()
                        .filter(|p| !p.ends_with("-bit")),
                );
                parts.join(" ")
            }
            _ => self.name.clone(),
        }
    }
}

/// The child boxes of an in-memory region: (type, body).
fn child_boxes(d: &[u8], start: usize) -> Vec<([u8; 4], &[u8])> {
    let mut out = Vec::new();
    let mut at = start;
    while out.len() < 64 {
        let Some(size) = u32_be(d, at) else { break };
        let Some(kind) = crate::bytes::array::<4>(d, at.saturating_add(4)) else {
            break;
        };
        let (header, size) = match size {
            0 => (8usize, d.len().saturating_sub(at)),
            1 => match u64_be(d, at.saturating_add(8)) {
                Some(s) => (16, to_usize(s)),
                None => break,
            },
            s => (8, to_usize(s.into())),
        };
        if size < header {
            break;
        }
        let end = at.saturating_add(size).min(d.len());
        out.push((
            kind,
            d.get(at.saturating_add(header)..end).unwrap_or_default(),
        ));
        at = at.saturating_add(size);
    }
    out
}

/// Profiles distinguished by constraint flags (checked in order).
const CONSTRAINED: &[(u8, u8, &str)] = &[
    (66, 0x40, "Constrained Baseline"),
    (100, 0x0c, "Constrained High"),
    (100, 0x08, "Progressive High"),
];

/// Decodes a sample entry body (`data`, after the box header).
pub fn codec_info(kind: &[u8; 4], handler: &[u8; 4], brand: Brand, data: &[u8]) -> CodecInfo {
    let mut info = CodecInfo {
        fourcc: *kind,
        kind: entry_kind(kind, handler),
        name: match kind {
            b"text" => "QuickTime text".to_owned(),
            b"mett" | b"metx" => "timed metadata".to_owned(),
            b"mebx" => "QuickTime metadata".to_owned(),
            _ => vidutil::codec_name(kind).map_or_else(|| fourcc(kind), str::to_owned),
        },
        ..CodecInfo::default()
    };
    let current = info.kind;
    let start = match current {
        _ if kind == b"tmcd" => {
            info.kind = EntryKind::Other;
            info.timecode = Some(Timecode {
                flags: u32_be(data, 12).unwrap_or(0),
                timescale: u32_be(data, 16).unwrap_or(0),
                frame_duration: u32_be(data, 20).unwrap_or(0),
                frames: data.get(24).copied().unwrap_or(0),
            });
            26
        }
        EntryKind::Visual => {
            info.width = u16_be(data, 24).unwrap_or(0).into();
            info.height = u16_be(data, 26).unwrap_or(0).into();
            78
        }
        EntryKind::Audio => {
            info.channels = u16_be(data, 16).unwrap_or(0).into();
            // Compressed formats carry a placeholder sample size.
            if is_pcm(kind) {
                info.bits = u16_be(data, 18).map(u64::from).filter(|&b| b > 0);
            }
            info.rate = (u32_be(data, 24).unwrap_or(0) >> 16).into();
            let extra = audio_fields_len(brand, data);
            if extra == 56 {
                // QuickTime v2: the real values follow.
                if let Some(rate) = u64_be(data, 32) {
                    let rate = f64::from_bits(rate);
                    if rate.is_finite() && rate > 0.0 && rate < 1e7 {
                        info.rate = rate as u64;
                    }
                }
                info.channels = u32_be(data, 40).unwrap_or(0).into();
                let bits = u32_be(data, 48).unwrap_or(0);
                let flags = u32_be(data, 52).unwrap_or(0);
                if is_pcm(kind) && bits > 0 {
                    info.bits = Some(bits.into());
                    info.profile = Some(format!(
                        "{bits}-bit {} {}",
                        if flags & 1 != 0 { "float" } else { "integer" },
                        if flags & 2 != 0 {
                            "big-endian"
                        } else {
                            "little-endian"
                        }
                    ));
                }
            }
            to_usize(8u64.saturating_add(extra))
        }
        EntryKind::Other => match kind {
            b"tx3g" => 38,
            _ => data.len(),
        },
    };
    let boxes = child_boxes(data, start);
    // Encrypted entries: the original format comes first.
    for (k, b) in &boxes {
        if k != b"sinf" {
            continue;
        }
        for (k, b) in child_boxes(b, 0) {
            match &k {
                b"frma" => {
                    if let Some(o) = crate::bytes::array::<4>(b, 0) {
                        if let Some(name) = vidutil::codec_name(&o) {
                            info.name = name.to_owned();
                        }
                        info.fourcc = o;
                    }
                }
                b"schm" => info.scheme = b.get(4..8).map(fourcc),
                _ => {}
            }
        }
    }
    for (k, b) in &boxes {
        match k {
            b"sinf" => {}
            b"wave" => {
                for (k, b) in child_boxes(b, 0) {
                    configure(&mut info, &k, b);
                }
            }
            _ => configure(&mut info, k, b),
        }
    }
    if is_pcm(&info.fourcc) && info.profile.is_none() {
        info.profile = pcm_profile(&info.fourcc, info.bits);
    }
    info
}

fn is_pcm(kind: &[u8; 4]) -> bool {
    matches!(
        kind,
        b"sowt"
            | b"twos"
            | b"lpcm"
            | b"ipcm"
            | b"fpcm"
            | b"in24"
            | b"in32"
            | b"fl32"
            | b"fl64"
            | b"raw "
            | b"NONE"
    )
}

fn pcm_profile(kind: &[u8; 4], bits: Option<u64>) -> Option<String> {
    Some(match kind {
        b"sowt" => format!("{}-bit little-endian", bits.unwrap_or(16)),
        b"twos" => format!("{}-bit big-endian", bits.unwrap_or(16)),
        b"in24" => "24-bit integer".to_owned(),
        b"in32" => "32-bit integer".to_owned(),
        b"fl32" => "32-bit float".to_owned(),
        b"fl64" => "64-bit float".to_owned(),
        b"raw " => "8-bit unsigned".to_owned(),
        _ => return None,
    })
}

/// Applies what one configuration box says.
fn configure(info: &mut CodecInfo, kind: &[u8; 4], b: &[u8]) {
    let fcc = fourcc(&info.fourcc);
    match kind {
        b"avcC" => {
            info.codec_string = codec::avc_codec_string(&fcc, b);
            let profile = b.get(1).copied().unwrap_or(0);
            let compat = b.get(2).copied().unwrap_or(0);
            let level = b.get(3).copied().unwrap_or(0);
            let name = CONSTRAINED
                .iter()
                .find(|(p, mask, _)| *p == profile && compat & mask == *mask)
                .map_or_else(
                    || lookup_or(H264_PROFILES, profile.into()),
                    |(_, _, n)| (*n).to_owned(),
                );
            info.profile = Some(format!("{name}@L{}", h264_level(level)));
            if let Some(sps) = codec::avcc_sps(b).and_then(vidutil::h264_sps) {
                info.depth = Some(sps.bit_depth);
                info.chroma = Some(chroma_name(sps.chroma_format));
            }
        }
        b"hvcC" => {
            if let Some(c) = codec::hevc_config(b) {
                info.codec_string = Some(c.codec_string(&fcc));
                info.profile = Some(hevc_profile(&c));
                info.depth = Some(c.luma_depth);
                info.chroma = Some(chroma_name(c.chroma));
            }
        }
        b"av1C" => {
            if let Some(c) = codec::av1c(b) {
                info.codec_string = Some(c.codec_string());
                info.profile = Some(format!(
                    "{}@L{}",
                    lookup_or(codec::AV1_PROFILES, c.profile),
                    codec::av1_level(c.level)
                ));
                info.depth = Some(c.depth);
                info.chroma = Some(c.chroma());
            }
        }
        b"vpcC" => {
            if b.first().copied().unwrap_or(0) >= 1 {
                let profile = b.get(4).copied().unwrap_or(0);
                let level = b.get(5).copied().unwrap_or(0);
                let bits = b.get(6).copied().unwrap_or(0);
                info.profile = Some(format!("Profile {profile}"));
                info.depth = Some((bits >> 4).into());
                info.chroma = Some(vp9_chroma((bits >> 1) & 7));
                info.codec_string = Some(format!("{fcc}.{profile:02}.{level:02}.{:02}", bits >> 4));
                if let (Some(p), Some(t), Some(m)) = (b.get(7), b.get(8), b.get(9)) {
                    info.colour = colour_name(u64::from(*p), u64::from(*t), u64::from(*m));
                }
            }
        }
        b"colr" => {
            if let (Some(b"nclx" | b"nclc"), Some(p), Some(t), Some(m)) =
                (b.get(..4), u16_be(b, 4), u16_be(b, 6), u16_be(b, 8))
            {
                info.colour = colour_name(p.into(), t.into(), m.into());
            }
        }
        b"esds" => {
            let Some((oti, asc, avg)) = esds_info(b.get(4..).unwrap_or_default()) else {
                return;
            };
            if avg > 0 {
                info.bitrate = Some(avg.into());
            }
            info.codec_string = Some(format!("{fcc}.{oti:02x}"));
            if let Some(name) = object_type_codec(oti) {
                info.name = name.to_owned();
            }
            if matches!(oti, 0x40 | 0x66 | 0x67 | 0x68)
                && let Some(asc) = asc.and_then(codec::asc)
            {
                info.codec_string = Some(format!("{fcc}.{oti:02x}.{}", asc.signalled));
                apply_asc(info, &asc);
            }
        }
        b"dOps" => {
            let channels = b.get(1).copied().unwrap_or(0);
            let family = b.get(10).copied().unwrap_or(0);
            info.channels = channels.into();
            info.rate = 48000;
            info.layout = Some(opus_layout(channels, family));
            info.codec_string = Some("opus".to_owned());
        }
        b"dfLa" => {
            // FullBox, then metadata blocks; STREAMINFO comes first.
            if let Some(si) = b.get(8..) {
                let mut r = vidutil::Bits::new(si.get(10..18).unwrap_or_default());
                if let (Some(rate), Some(ch), Some(bits)) = (r.bits(20), r.bits(3), r.bits(5)) {
                    info.rate = rate;
                    info.channels = ch.saturating_add(1);
                    info.layout = Some(channel_count(info.channels));
                    info.bits = Some(bits.saturating_add(1));
                }
            }
            info.codec_string = Some("flac".to_owned());
        }
        b"dac3" | b"dec3" => {
            let parsed = if kind == b"dac3" {
                codec::dac3_layout(&mut crate::formats::util::sound::Bits::new(
                    b,
                    codec::nowhere(b.len()),
                ))
            } else {
                codec::dec3_layout(&mut crate::formats::util::sound::Bits::new(
                    b,
                    codec::nowhere(b.len()),
                ))
            };
            if let Ok(a) = parsed {
                apply_ac3(info, &a);
            }
            info.codec_string = Some(fcc.clone());
        }
        b"alac" => {
            // FullBox, then ALACSpecificConfig.
            info.bits = b.get(9).map(|&v| u64::from(v));
            info.channels = b.get(13).map_or(info.channels, |&v| u64::from(v));
            if let Some(r) = u32_be(b, 24) {
                info.rate = r.into();
            }
            info.codec_string = Some("alac".to_owned());
        }
        b"pcmC" => {
            let little = b.get(4).is_some_and(|f| f & 1 != 0);
            let bits = b.get(5).copied().unwrap_or(0);
            info.bits = Some(bits.into());
            info.profile = Some(format!(
                "{bits}-bit {}{}",
                if &info.fourcc == b"fpcm" {
                    "float "
                } else {
                    ""
                },
                if little {
                    "little-endian"
                } else {
                    "big-endian"
                }
            ));
        }
        b"btrt" => {
            // Declared codec rates (dac3, dec3, esds) take precedence.
            if info.bitrate.is_none()
                && let Some(avg) = u32_be(b, 8).filter(|&v| v > 0)
            {
                info.bitrate = Some(avg.into());
            }
        }
        _ => {}
    }
}

fn apply_asc(info: &mut CodecInfo, asc: &Asc) {
    info.profile = Some(asc.profile());
    info.rate = asc.output_rate();
    let ch = asc.channels();
    if ch > 0 {
        info.channels = ch;
    }
    info.layout = Some(asc.layout());
}

fn apply_ac3(info: &mut CodecInfo, a: &Ac3) {
    info.rate = a.rate;
    info.channels = a.channels();
    info.layout = Some(a.layout());
    if a.kbps > 0 {
        info.bitrate = Some(a.kbps.saturating_mul(1000));
    }
    if a.atmos {
        info.profile = Some("Dolby Atmos (JOC)".to_owned());
    }
}

fn hevc_profile(c: &HevcConfig) -> String {
    format!(
        "{}@L{}{}",
        lookup_or(HEVC_PROFILES, c.profile.into()),
        hevc_level(c.level),
        if c.tier == 1 { " High tier" } else { "" }
    )
}

fn vp9_chroma(v: u8) -> &'static str {
    match v {
        0 | 1 => "4:2:0",
        2 => "4:2:2",
        3 => "4:4:4",
        _ => "?",
    }
}

/// "BT.709", "BT.2020 PQ" from colour code points; `None` if unspecified.
fn colour_name(p: u64, t: u64, m: u64) -> Option<String> {
    let name =
        |table: EnumTable, v: u64| crate::value::lookup(table, v).filter(|n| *n != "unspecified");
    let primaries = name(COLOUR_PRIMARIES, p);
    let transfer = name(TRANSFER_CHARACTERISTICS, t);
    let matrix = name(MATRIX_COEFFICIENTS, m);
    match (primaries, transfer, matrix) {
        (None, None, None) => None,
        (Some(p), Some(t), Some(m)) if p == t && t == m => Some(p.to_owned()),
        (Some(p), Some(t), _)
            if p == "BT.2020" && (t.starts_with("PQ") || t.starts_with("HLG")) =>
        {
            Some(format!("BT.2020 {}", t.split(' ').next().unwrap_or(t)))
        }
        (Some(p), Some(t), Some(m)) => Some(format!("{p}/{t}/{m}")),
        (p, t, m) => Some(
            [(p, "primaries"), (t, "transfer"), (m, "matrix")]
                .iter()
                .filter_map(|(v, role)| v.map(|v| format!("{v} {role}")))
                .collect::<Vec<_>>()
                .join(", "),
        ),
    }
}

fn opus_layout(channels: u8, family: u8) -> String {
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

/// The codec an MPEG-4 objectTypeIndication names.
fn object_type_codec(oti: u8) -> Option<&'static str> {
    Some(match oti {
        0x20 => "MPEG-4 Visual",
        0x21 => "H.264",
        0x23 => "HEVC",
        0x40 | 0x66..=0x68 => "AAC",
        0x60..=0x65 => "MPEG-2 video",
        0x69 | 0x6b => "MP3",
        0x6a => "MPEG-1 video",
        0x6c => "JPEG",
        0x6d => "PNG",
        0x6e => "JPEG 2000",
        0xa3 => "VC-1",
        0xa4 => "Dirac",
        0xa5 => "AC-3",
        0xa6 => "E-AC-3",
        0xa9..=0xac => "DTS",
        0xad => "Opus",
        0xb1 => "VP9",
        0xdd => "Vorbis",
        0xe1 => "QCELP",
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Configuration boxes

const CHROMA: EnumTable = &[(0, "monochrome"), (1, "4:2:0"), (2, "4:2:2"), (3, "4:4:4")];

const VP9_CHROMA: EnumTable = &[
    (0, "4:2:0 vertical"),
    (1, "4:2:0 colocated"),
    (2, "4:2:2"),
    (3, "4:4:4"),
];

const PARALLELISM: EnumTable = &[
    (0, "mixed or unknown"),
    (1, "slice-based"),
    (2, "tile-based"),
    (3, "wavefront"),
];

const AVC_CONSTRAINTS: FlagTable = &[
    flag(0x80, "CONSTRAINT_SET0"),
    flag(0x40, "CONSTRAINT_SET1"),
    flag(0x20, "CONSTRAINT_SET2"),
    flag(0x10, "CONSTRAINT_SET3"),
    flag(0x08, "CONSTRAINT_SET4"),
    flag(0x04, "CONSTRAINT_SET5"),
];

const OBJECT_TYPES: EnumTable = &[
    (0x01, "Systems (14496-1)"),
    (0x02, "Systems (14496-1) v2"),
    (0x20, "MPEG-4 Visual"),
    (0x21, "H.264"),
    (0x22, "H.264 parameter sets"),
    (0x23, "HEVC"),
    (0x40, "MPEG-4 Audio"),
    (0x60, "MPEG-2 Visual Simple"),
    (0x61, "MPEG-2 Visual Main"),
    (0x62, "MPEG-2 Visual SNR"),
    (0x63, "MPEG-2 Visual Spatial"),
    (0x64, "MPEG-2 Visual High"),
    (0x65, "MPEG-2 Visual 4:2:2"),
    (0x66, "MPEG-2 AAC Main"),
    (0x67, "MPEG-2 AAC LC"),
    (0x68, "MPEG-2 AAC SSR"),
    (0x69, "MPEG-2 Audio (MP3)"),
    (0x6a, "MPEG-1 Visual"),
    (0x6b, "MPEG-1 Audio (MP3)"),
    (0x6c, "JPEG"),
    (0x6d, "PNG"),
    (0x6e, "JPEG 2000"),
    (0xa3, "VC-1"),
    (0xa4, "Dirac"),
    (0xa5, "AC-3"),
    (0xa6, "E-AC-3"),
    (0xa9, "DTS"),
    (0xaa, "DTS-HD High Resolution"),
    (0xab, "DTS-HD Master Audio"),
    (0xac, "DTS Express"),
    (0xad, "Opus"),
    (0xb1, "VP9"),
    (0xdd, "Vorbis"),
    (0xe1, "QCELP"),
];

const STREAM_TYPES: EnumTable = &[
    (1, "ObjectDescriptor"),
    (2, "ClockReference"),
    (3, "SceneDescription"),
    (4, "Visual"),
    (5, "Audio"),
    (6, "MPEG-7"),
    (7, "IPMP"),
    (8, "OCI"),
    (9, "MPEG-J"),
    (10, "Interaction"),
    (11, "IPMP tool"),
    (32, "Text (3GPP)"),
];

const DESCRIPTOR_TAGS: EnumTable = &[
    (0x01, "ObjectDescriptor"),
    (0x02, "InitialObjectDescriptor"),
    (0x03, "ES_Descriptor"),
    (0x04, "DecoderConfigDescriptor"),
    (0x05, "DecoderSpecificInfo"),
    (0x06, "SLConfigDescriptor"),
    (0x0e, "ES_ID_Inc"),
    (0x0f, "ES_ID_Ref"),
    (0x10, "MP4_IOD"),
    (0x11, "MP4_OD"),
];

const SL_PREDEFINED: EnumTable = &[
    (0, "custom"),
    (1, "null SL packet header"),
    (2, "MP4 (reserved for ISO files)"),
];

const FIELD_ORDERS: EnumTable = &[
    (0, "unknown / progressive"),
    (1, "top field first, separated"),
    (6, "bottom field first, separated"),
    (9, "top field first, interleaved"),
    (14, "bottom field first, interleaved"),
];

const OPUS_FAMILIES: EnumTable = &[
    (0, "mono/stereo"),
    (1, "Vorbis channel order"),
    (2, "ambisonics"),
    (3, "ambisonics with demixing"),
    (255, "discrete"),
];

const FLAC_BLOCKS: EnumTable = &[
    (0, "STREAMINFO"),
    (1, "PADDING"),
    (2, "APPLICATION"),
    (3, "SEEKTABLE"),
    (4, "VORBIS_COMMENT"),
    (5, "CUESHEET"),
    (6, "PICTURE"),
];

const CHANNEL_LAYOUTS: EnumTable = &[
    (0, "use channel descriptions"),
    (1, "use channel bitmap"),
    (100, "mono"),
    (101, "stereo"),
    (102, "stereo headphones"),
    (103, "matrix stereo"),
    (104, "mid/side"),
    (105, "XY"),
    (106, "binaural"),
    (107, "ambisonic B-format"),
    (108, "quadraphonic"),
    (109, "pentagonal"),
    (110, "hexagonal"),
    (111, "octagonal"),
    (112, "cube"),
    (113, "MPEG 3.0 A (L R C)"),
    (114, "MPEG 3.0 B (C L R)"),
    (115, "MPEG 4.0 A (L R C Cs)"),
    (116, "MPEG 4.0 B (C L R Cs)"),
    (117, "MPEG 5.0 A (L R C Ls Rs)"),
    (118, "MPEG 5.0 B (L R Ls Rs C)"),
    (119, "MPEG 5.0 C (L C R Ls Rs)"),
    (120, "MPEG 5.0 D (C L R Ls Rs)"),
    (121, "MPEG 5.1 A (L R C LFE Ls Rs)"),
    (122, "MPEG 5.1 B (L R Ls Rs C LFE)"),
    (123, "MPEG 5.1 C (L C R Ls Rs LFE)"),
    (124, "MPEG 5.1 D (C L R Ls Rs LFE)"),
    (125, "MPEG 6.1 A"),
    (126, "MPEG 7.1 A"),
    (127, "MPEG 7.1 B"),
    (128, "MPEG 7.1 C"),
    (129, "Emagic default 7.1"),
    (130, "SMPTE DTV"),
    (131, "ITU 2.1"),
    (132, "ITU 2.2"),
    (147, "AAC 3.0"),
    (148, "AAC quadraphonic"),
    (149, "AAC 4.0"),
    (150, "AAC 5.0"),
    (151, "AAC 5.1"),
    (152, "AAC 6.0"),
    (153, "AAC 6.1"),
    (154, "AAC 7.0"),
    (155, "AAC octagonal"),
    (156, "TMH 10.2 std"),
    (157, "TMH 10.2 full"),
    (158, "AC-3 1.0.1"),
    (159, "AC-3 3.0"),
    (160, "AC-3 3.1"),
    (161, "AC-3 3.0.1"),
    (162, "AC-3 2.1.1"),
    (163, "AC-3 3.1.1"),
    (164, "EAC 6.0 A"),
    (165, "EAC 7.0 A"),
    (166, "EAC3 6.1 A"),
    (190, "Atmos 5.1.2"),
    (191, "Atmos 5.1.4"),
    (192, "Atmos 7.1.2"),
    (193, "Atmos 7.1.4"),
    (194, "Atmos 9.1.6"),
];

async fn emit_fields(
    cx: &Cx,
    span: Span,
    layout: impl FnOnce(&mut Fields<'_>) -> Result<()>,
) -> Result<()> {
    let block = cx.block(span.sub(0, 0x10000)).await?;
    layout(&mut Fields::emitting(cx, &block, BE))
}

/// Emits a bit layout over `span` directly as children.
async fn emit_bits<R>(cx: &Cx, span: Span, layout: BitLayout<R>) -> Result<R> {
    let data = cx.read_avail(span.sub(0, 0x10000)).await?;
    let mut b = crate::formats::util::sound::Bits::emitting(cx, &data, span);
    layout(&mut b)
}

/// Decodes codec configuration boxes. Returns `false` for other types.
pub async fn decode_config(cx: &Cx, st: &BoxState) -> Result<bool> {
    let body = st.body();
    match &st.header.kind {
        b"avcC" => avcc(cx, body).await?,
        b"hvcC" | b"lhvC" => hvcc(cx, body).await?,
        b"av1C" => {
            emit_bits(cx, body.sub(0, 4), codec::av1c_layout).await?;
            let obus = body.tail(4);
            if !obus.is_empty() {
                cx.emit(
                    Node::new("Configuration OBUs")
                        .span(obus)
                        .lazy(expand_obus, obus),
                );
            }
        }
        b"vpcC" => vpcc(cx, body).await?,
        b"esds" | b"iods" => {
            emit_fields(cx, body.sub(0, 4), |f| full_box(f).map(|_| ())).await?;
            descriptors(cx, st.input, body.tail(4), 0).await?;
        }
        b"dOps" => emit_fields(cx, body, dops).await?,
        b"dfLa" => dfla(cx, body).await?,
        b"dac3" => {
            emit_bits(cx, body, codec::dac3_layout).await?;
        }
        b"dec3" => {
            emit_bits(cx, body, codec::dec3_layout).await?;
        }
        b"alac" => emit_fields(cx, body, alac).await?,
        b"pcmC" => {
            emit_fields(cx, body, |f| {
                full_box(f)?;
                f.u8("Format flags")
                    .hex()
                    .with(|&v, n| {
                        n.summary(if v & 1 != 0 {
                            "little-endian"
                        } else {
                            "big-endian"
                        })
                    })
                    .emit()?;
                f.u8("PCM sample size")
                    .with(|&v, n| n.summary(format!("{v} bits")))
                    .emit()?;
                Ok(())
            })
            .await?;
        }
        b"chan" => emit_fields(cx, body, chan).await?,
        b"enda" => {
            emit_fields(cx, body, |f| {
                f.u16("Little endian")
                    .with(|&v, n| n.summary(if v != 0 { "yes" } else { "no" }))
                    .emit()?;
                Ok(())
            })
            .await?;
        }
        b"colr" => colr(cx, st, body).await?,
        b"pasp" => {
            emit_fields(cx, body, |f| {
                f.u32("Horizontal spacing").emit()?;
                f.u32("Vertical spacing").emit()?;
                Ok(())
            })
            .await?;
        }
        b"clap" => {
            emit_fields(cx, body, |f| {
                f.u32("Clean aperture width N").emit()?;
                f.u32("Clean aperture width D").emit()?;
                f.u32("Clean aperture height N").emit()?;
                f.u32("Clean aperture height D").emit()?;
                f.i32("Horizontal offset N").emit()?;
                f.u32("Horizontal offset D").emit()?;
                f.i32("Vertical offset N").emit()?;
                f.u32("Vertical offset D").emit()?;
                Ok(())
            })
            .await?;
        }
        b"btrt" => {
            emit_fields(cx, body, |f| {
                f.u32("Buffer size")
                    .desc("Decoding buffer size in bytes")
                    .emit()?;
                f.u32("Max bitrate")
                    .with(|&v, n| n.summary(bitrate(v.into())))
                    .emit()?;
                f.u32("Average bitrate")
                    .with(|&v, n| n.summary(bitrate(v.into())))
                    .emit()?;
                Ok(())
            })
            .await?;
        }
        b"fiel" => {
            emit_fields(cx, body, |f| {
                f.u8("Field count")
                    .with(|&v, n| n.summary(if v == 2 { "interlaced" } else { "progressive" }))
                    .emit()?;
                f.u8("Field ordering").enumeration(FIELD_ORDERS).emit()?;
                Ok(())
            })
            .await?;
        }
        b"gama" => {
            emit_fields(cx, body, |f| {
                f.u32("Gamma")
                    .with(|&v, n| n.summary(num(fixed16(v))))
                    .emit()?;
                Ok(())
            })
            .await?;
        }
        b"clli" | b"CoLL" => {
            let full = &st.header.kind == b"CoLL";
            emit_fields(cx, body, |f| {
                if full {
                    full_box(f)?;
                }
                f.u16("Max content light level")
                    .with(|&v, n| n.summary(format!("{v} cd/m²")))
                    .emit()?;
                f.u16("Max frame-average light level")
                    .with(|&v, n| n.summary(format!("{v} cd/m²")))
                    .emit()?;
                Ok(())
            })
            .await?;
        }
        b"mdcv" => {
            emit_fields(cx, body, |f| {
                for name in [
                    "Primary 0 (green) x",
                    "Primary 0 (green) y",
                    "Primary 1 (blue) x",
                    "Primary 1 (blue) y",
                    "Primary 2 (red) x",
                    "Primary 2 (red) y",
                    "White point x",
                    "White point y",
                ] {
                    f.u16(name)
                        .with(|&v, n| n.summary(format!("{:.5}", f64::from(v) * 0.00002)))
                        .emit()?;
                }
                f.u32("Max luminance")
                    .with(|&v, n| n.summary(format!("{} cd/m²", num(f64::from(v) / 10000.0))))
                    .emit()?;
                f.u32("Min luminance")
                    .with(|&v, n| n.summary(format!("{} cd/m²", f64::from(v) / 10000.0)))
                    .emit()?;
                Ok(())
            })
            .await?;
        }
        b"SmDm" => {
            emit_fields(cx, body, |f| {
                full_box(f)?;
                for name in [
                    "Red x",
                    "Red y",
                    "Green x",
                    "Green y",
                    "Blue x",
                    "Blue y",
                    "White point x",
                    "White point y",
                ] {
                    f.u16(name)
                        .with(|&v, n| n.summary(format!("{:.5}", f64::from(v) / 65536.0)))
                        .emit()?;
                }
                f.u32("Max luminance")
                    .with(|&v, n| n.summary(format!("{} cd/m²", num(f64::from(v) / 256.0))))
                    .emit()?;
                f.u32("Min luminance")
                    .with(|&v, n| n.summary(format!("{} cd/m²", f64::from(v) / 16384.0)))
                    .emit()?;
                Ok(())
            })
            .await?;
        }
        b"damr" => {
            emit_fields(cx, body, |f| {
                f.ascii("Vendor", 4).emit()?;
                f.u8("Decoder version").emit()?;
                f.u16("Mode set").hex().emit()?;
                f.u8("Mode change period").emit()?;
                f.u8("Frames per sample").emit()?;
                Ok(())
            })
            .await?;
        }
        b"d263" => {
            emit_fields(cx, body, |f| {
                f.ascii("Vendor", 4).emit()?;
                f.u8("Decoder version").emit()?;
                f.u8("Level").emit()?;
                f.u8("Profile").emit()?;
                Ok(())
            })
            .await?;
        }
        b"dvcC" | b"dvvC" | b"dvwC" => {
            emit_fields(cx, body, |f| {
                f.u8("Version major").emit()?;
                f.u8("Version minor").emit()?;
                f.u16("Profile / level / flags")
                    .hex()
                    .with(|&v, n| {
                        n.summary(format!(
                            "profile {}, level {}{}{}{}",
                            v >> 9,
                            (v >> 3) & 0x3f,
                            if v & 4 != 0 { ", RPU" } else { "" },
                            if v & 2 != 0 { ", EL" } else { "" },
                            if v & 1 != 0 { ", BL" } else { "" }
                        ))
                    })
                    .emit()?;
                f.u8("BL signal compatibility")
                    .with(|&v, n| n.summary(format!("{}", v >> 4)))
                    .emit()?;
                Ok(())
            })
            .await?;
        }
        b"vttC" | b"vlab" => {
            emit_fields(cx, body, |f| {
                let n = f.remaining();
                f.ascii(
                    if &st.header.kind == b"vttC" {
                        "Configuration"
                    } else {
                        "Source label"
                    },
                    n,
                )
                .emit()?;
                Ok(())
            })
            .await?;
        }
        b"ftab" => {
            emit_fields(cx, body, |f| {
                let n = f.u16("Entry count").emit()?;
                for _ in 0..n {
                    if f.remaining() < 3 {
                        break;
                    }
                    f.u16("Font ID").emit()?;
                    let len = f.u8("Font name length").emit()?;
                    f.ascii("Font name", len.into()).emit()?;
                }
                Ok(())
            })
            .await?;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

async fn expand_obus(cx: Cx, span: Span) -> Result<()> {
    codec::obus(&cx, span).await
}

/// Summaries of configuration boxes for the box list.
pub async fn describe_config(cx: &Cx, st: &BoxState) -> Option<String> {
    let kind = &st.header.kind;
    if !matches!(
        kind,
        b"avcC"
            | b"hvcC"
            | b"av1C"
            | b"vpcC"
            | b"esds"
            | b"dOps"
            | b"dfLa"
            | b"dac3"
            | b"dec3"
            | b"colr"
            | b"pasp"
            | b"btrt"
            | b"clap"
            | b"clli"
            | b"mdcv"
            | b"fiel"
            | b"pcmC"
            | b"chan"
            | b"alac"
    ) {
        return None;
    }
    let d = small(cx, st.body().sub(0, 0x10000)).await.ok()?;
    match kind {
        b"avcC" => {
            let mut info = CodecInfo {
                name: "H.264".to_owned(),
                fourcc: *b"avc1",
                ..CodecInfo::default()
            };
            configure(&mut info, kind, &d);
            let mut s = info.label();
            if let Some(sps) = codec::avcc_sps(&d).and_then(vidutil::h264_sps) {
                s = format!("{s}, {}×{}", sps.width, sps.height);
            }
            if let (Some(depth), Some(c)) = (info.depth, info.chroma) {
                s = format!("{s}, {depth}-bit {c}");
            }
            Some(s)
        }
        b"hvcC" => {
            let c = codec::hevc_config(&d)?;
            let mut s = hevc_profile(&c);
            if let Some(sps) = vidutil::hvcc_sps(&d).and_then(vidutil::hevc_sps) {
                s = format!("{s}, {}×{}", sps.width, sps.height);
            }
            Some(format!(
                "{s}, {}-bit {}",
                c.luma_depth,
                chroma_name(c.chroma)
            ))
        }
        b"av1C" => codec::av1c(&d).map(|c| c.summary()),
        b"vpcC" => {
            if d.first().copied().unwrap_or(0) == 0 {
                return Some(format!("profile {}, level {}", d.get(4)?, d.get(5)?));
            }
            let level = d.get(5)?;
            Some(format!(
                "profile {}, level {}.{}, {}-bit {}",
                d.get(4)?,
                level / 10,
                level % 10,
                d.get(6)? >> 4,
                vp9_chroma((d.get(6)? >> 1) & 7)
            ))
        }
        b"esds" => esds_summary(d.get(4..)?),
        b"dOps" => Some(format!(
            "{}, input {}, pre-skip {}",
            opus_layout(*d.get(1)?, *d.get(10)?),
            khz(u32_be(&d, 4)?.into()),
            u16_be(&d, 2)?
        )),
        b"dfLa" => flac_streaminfo(d.get(8..)?),
        b"dac3" => codec::dac3_layout(&mut crate::formats::util::sound::Bits::new(
            &d,
            codec::nowhere(d.len()),
        ))
        .ok()
        .map(|a| a.summary()),
        b"dec3" => codec::dec3_layout(&mut crate::formats::util::sound::Bits::new(
            &d,
            codec::nowhere(d.len()),
        ))
        .ok()
        .map(|a| a.summary()),
        b"colr" => colr_summary(&d),
        b"pasp" => {
            let (h, v) = (u32_be(&d, 0)?, u32_be(&d, 4)?);
            Some(if h == v {
                "1:1 (square pixels)".to_owned()
            } else {
                format!("{h}:{v}")
            })
        }
        b"btrt" => Some(format!(
            "max {}, average {}",
            bitrate(u32_be(&d, 4)?.into()),
            bitrate(u32_be(&d, 8)?.into())
        )),
        b"clap" => {
            let frac = |at: usize| -> Option<f64> {
                let n = f64::from(u32_be(&d, at)? as i32);
                let den = f64::from(u32_be(&d, at.saturating_add(4))?);
                Some(if den == 0.0 { 0.0 } else { n / den })
            };
            Some(format!(
                "{}×{}, offset {}, {}",
                num(frac(0)?),
                num(frac(8)?),
                num(frac(16)?),
                num(frac(24)?)
            ))
        }
        b"clli" => Some(format!(
            "MaxCLL {} cd/m², MaxFALL {} cd/m²",
            u16_be(&d, 0)?,
            u16_be(&d, 2)?
        )),
        b"mdcv" => Some(format!(
            "{}–{} cd/m²",
            f64::from(u32_be(&d, 20)?) / 10000.0,
            num(f64::from(u32_be(&d, 16)?) / 10000.0)
        )),
        b"fiel" => Some(if *d.first()? == 2 {
            format!(
                "interlaced, {}",
                lookup_or(FIELD_ORDERS, (*d.get(1)?).into())
            )
        } else {
            "progressive".to_owned()
        }),
        b"pcmC" => Some(format!(
            "{}-bit {}",
            d.get(5)?,
            if d.get(4)? & 1 != 0 {
                "little-endian"
            } else {
                "big-endian"
            }
        )),
        b"chan" => {
            let tag = u32_be(&d, 4)?;
            Some(match tag >> 16 {
                0 => format!("{} channel descriptions", u32_be(&d, 12)?),
                1 => format!("channel bitmap {:#x}", u32_be(&d, 8)?),
                id => format!(
                    "{}, {} ch",
                    lookup_or(CHANNEL_LAYOUTS, id.into()),
                    tag & 0xffff
                ),
            })
        }
        b"alac" => Some(format!(
            "{}-bit, {}, {}",
            d.get(9)?,
            channel_count((*d.get(13)?).into()),
            khz(u32_be(&d, 24)?.into())
        )),
        _ => None,
    }
}

async fn avcc(cx: &Cx, body: Span) -> Result<()> {
    let block = cx.block(body.sub(0, 0x10000)).await?;
    let mut f = Fields::emitting(cx, &block, BE);
    f.u8("Configuration version").emit()?;
    let profile = f.u8("Profile").enumeration(H264_PROFILES).emit()?;
    f.u8("Profile compatibility")
        .flags(AVC_CONSTRAINTS)
        .desc("The constraint_set flags of the SPS")
        .emit()?;
    f.u8("Level")
        .with(|&l, n| n.summary(h264_level(l)))
        .emit()?;
    let mut b = bits_at(Some(cx), &mut f, 1);
    b.field("Reserved", 6).emit()?;
    b.field("Length size minus one", 2)
        .with(|v, n| n.summary(format!("{}-byte NAL lengths", v.saturating_add(1))))
        .emit()?;
    let mut b = bits_at(Some(cx), &mut f, 1);
    b.field("Reserved", 3).emit()?;
    let sps = b.field("SPS count", 5).emit()?;
    for _ in 0..sps {
        let len = f.u16("SPS length").emit()?;
        nal(&mut f, len.into(), false)?;
    }
    let pps = f.u8("PPS count").emit()?;
    for _ in 0..pps {
        let len = f.u16("PPS length").emit()?;
        nal(&mut f, len.into(), false)?;
    }
    if !matches!(profile, 66 | 77 | 88) && f.remaining() >= 4 {
        let mut b = bits_at(Some(cx), &mut f, 4);
        b.field("Reserved", 6).emit()?;
        b.field("Chroma format", 2).enumeration(CHROMA).emit()?;
        b.field("Reserved", 5).emit()?;
        b.field("Luma bit depth minus 8", 3)
            .with(|v, n| n.summary(format!("{} bits", v.saturating_add(8))))
            .emit()?;
        b.field("Reserved", 5).emit()?;
        b.field("Chroma bit depth minus 8", 3)
            .with(|v, n| n.summary(format!("{} bits", v.saturating_add(8))))
            .emit()?;
        let ext = b.field("SPS extension count", 8).emit()?;
        for _ in 0..ext {
            let len = f.u16("SPS extension length").emit()?;
            nal(&mut f, len.into(), false)?;
        }
    }
    let rest = f.remaining();
    if rest > 0 {
        f.bytes("Extension", rest).emit()?;
    }
    Ok(())
}

/// Emits a NAL unit of `len` bytes as an expandable node.
fn nal(f: &mut Fields<'_>, len: u64, hevc: bool) -> Result<()> {
    let span = f.peek_span(len);
    let start = to_usize(f.pos());
    let data = f
        .block()
        .data
        .get(start..start.saturating_add(to_usize(len)))
        .unwrap_or_default();
    let (name, summary) = if hevc {
        let kind = data.first().map_or(0, |b| (b >> 1) & 0x3f);
        (nal_name(kind, true), codec::hevc_nal_summary(data))
    } else {
        let kind = data.first().map_or(0, |b| b & 0x1f);
        (nal_name(kind, false), codec::avc_nal_summary(data))
    };
    // Check the bytes are there before emitting.
    f.bytes("NAL unit", len).get()?;
    let mut node = struct_node(name, span, BE, hevc, nal_layout);
    if let Some(s) = summary {
        node = node.summary(s);
    }
    f.node(node);
    Ok(())
}

fn nal_name(kind: u8, hevc: bool) -> &'static str {
    match (hevc, kind) {
        (true, 32) => "Video parameter set",
        (true, 33) | (false, 7) => "Sequence parameter set",
        (true, 34) | (false, 8) => "Picture parameter set",
        (true, 39) => "SEI (prefix)",
        (true, 40) => "SEI (suffix)",
        (false, 6) => "SEI",
        (false, 13) => "SPS extension",
        _ => "NAL unit",
    }
}

fn nal_layout(f: &mut Fields<'_>, hevc: &bool) -> Result<()> {
    if *hevc {
        let span = f.peek_span(2);
        let h = f.u16("NAL unit header").get()?;
        f.node(flag_node("Forbidden zero bit", span, h & 0x8000 != 0));
        f.node(enumerated(
            "NAL unit type",
            span,
            ((h >> 9) & 0x3f).into(),
            6,
            HEVC_NAL_TYPES,
        ));
        f.node(uint("Layer ID", span, ((h >> 3) & 0x3f).into(), 6));
        f.node(uint("Temporal ID plus one", span, (h & 7).into(), 3));
    } else {
        let span = f.peek_span(1);
        let h = f.u8("NAL unit header").get()?;
        f.node(flag_node("Forbidden zero bit", span, h & 0x80 != 0));
        f.node(uint("NAL ref IDC", span, ((h >> 5) & 3).into(), 2));
        f.node(enumerated(
            "NAL unit type",
            span,
            (h & 0x1f).into(),
            5,
            vidutil::H264_NAL_TYPES,
        ));
    }
    let rest = f.remaining();
    if rest > 0 {
        f.bytes("Payload", rest)
            .desc("RBSP with emulation-prevention bytes")
            .emit()?;
    }
    Ok(())
}

async fn hvcc(cx: &Cx, body: Span) -> Result<()> {
    let block = cx.block(body.sub(0, 0x10000)).await?;
    let mut f = Fields::emitting(cx, &block, BE);
    let mut b = bits_at(Some(cx), &mut f, 22);
    b.field("Configuration version", 8).emit()?;
    b.field("General profile space", 2)
        .enumeration(codec::HEVC_PROFILE_SPACES)
        .emit()?;
    b.field("General tier", 1)
        .with(|v, n| n.summary(if v == 1 { "High" } else { "Main" }))
        .emit()?;
    b.field("General profile IDC", 5)
        .enumeration(HEVC_PROFILES)
        .emit()?;
    b.field("General profile compatibility flags", 32)
        .hex()
        .emit()?;
    b.field("General constraint indicator flags", 48)
        .hex()
        .emit()?;
    b.field("General level IDC", 8)
        .with(|v, n| {
            n.summary(format!(
                "level {}",
                hevc_level(u8::try_from(v).unwrap_or(0))
            ))
        })
        .emit()?;
    b.field("Reserved", 4).emit()?;
    b.field("Min spatial segmentation", 12).emit()?;
    b.field("Reserved", 6).emit()?;
    b.field("Parallelism type", 2)
        .enumeration(PARALLELISM)
        .emit()?;
    b.field("Reserved", 6).emit()?;
    b.field("Chroma format", 2).enumeration(CHROMA).emit()?;
    b.field("Reserved", 5).emit()?;
    b.field("Luma bit depth minus 8", 3)
        .with(|v, n| n.summary(format!("{} bits", v.saturating_add(8))))
        .emit()?;
    b.field("Reserved", 5).emit()?;
    b.field("Chroma bit depth minus 8", 3)
        .with(|v, n| n.summary(format!("{} bits", v.saturating_add(8))))
        .emit()?;
    b.field("Average frame rate", 16)
        .with(|v, n| {
            if v == 0 {
                n.summary("unspecified")
            } else {
                n.summary(format!("{} fps", super::tables::fps(v as f64 / 256.0)))
            }
        })
        .desc("In frames per 256 seconds")
        .emit()?;
    b.field("Constant frame rate", 2).emit()?;
    b.field("Temporal layers", 3).emit()?;
    b.field("Temporal ID nested", 1).flag().emit()?;
    b.field("Length size minus one", 2)
        .with(|v, n| n.summary(format!("{}-byte NAL lengths", v.saturating_add(1))))
        .emit()?;
    let arrays = f.u8("Array count").emit()?;
    for _ in 0..arrays {
        if f.remaining() < 3 {
            break;
        }
        let start = f.pos();
        let d = &block.data;
        let at = to_usize(start);
        let kind = d.get(at).map_or(0, |b| b & 0x3f);
        let n = u16_be(d, at.saturating_add(1)).unwrap_or(0);
        let mut end = at.saturating_add(3);
        let mut first = None;
        for _ in 0..n {
            let Some(len) = u16_be(d, end) else { break };
            let s = end.saturating_add(2);
            let e = s.saturating_add(usize::from(len));
            if first.is_none() {
                first = d.get(s..e.min(d.len()));
            }
            end = e;
        }
        let len = to_u64(end.saturating_sub(at));
        let name = match kind {
            32 => "VPS array".to_owned(),
            33 => "SPS array".to_owned(),
            34 => "PPS array".to_owned(),
            39 => "Prefix SEI array".to_owned(),
            40 => "Suffix SEI array".to_owned(),
            k => format!("{} array", lookup_or(HEVC_NAL_TYPES, k.into())),
        };
        let mut summary = vidutil::plural(n, "NAL unit");
        if let Some(s) = first.and_then(codec::hevc_nal_summary) {
            summary = format!("{summary}: {s}");
        }
        f.node(struct_node(name, f.peek_span(len), BE, (), hvcc_array).summary(summary));
        f.skip(len);
    }
    Ok(())
}

fn hvcc_array(f: &mut Fields<'_>, _: &()) -> Result<()> {
    let span = f.peek_span(1);
    let v = f.u8("Array header").get()?;
    f.node(flag_node("Array completeness", span, v & 0x80 != 0));
    f.node(uint("Reserved", span, ((v >> 6) & 1).into(), 1));
    f.node(enumerated(
        "NAL unit type",
        span,
        (v & 0x3f).into(),
        6,
        HEVC_NAL_TYPES,
    ));
    let n = f.u16("NAL unit count").emit()?;
    for _ in 0..n {
        let len = f.u16("NAL unit length").emit()?;
        nal(f, len.into(), true)?;
    }
    Ok(())
}

async fn vpcc(cx: &Cx, body: Span) -> Result<()> {
    let block = cx.block(body.sub(0, 0x10000)).await?;
    let mut f = Fields::emitting(cx, &block, BE);
    let (v, _) = full_box(&mut f)?;
    f.u8("Profile").emit()?;
    f.u8("Level")
        .with(|&l, n| n.summary(format!("{}.{}", l / 10, l % 10)))
        .emit()?;
    if v == 0 {
        let mut b = bits_at(Some(cx), &mut f, 3);
        b.field("Bit depth", 4).emit()?;
        b.field("Colour space", 4).emit()?;
        b.field("Chroma subsampling", 4)
            .enumeration(VP9_CHROMA)
            .emit()?;
        b.field("Transfer function", 4).emit()?;
        b.field("Full range", 1).flag().emit()?;
        b.field("Reserved", 7).emit()?;
    } else {
        let mut b = bits_at(Some(cx), &mut f, 1);
        b.field("Bit depth", 4).emit()?;
        b.field("Chroma subsampling", 3)
            .enumeration(VP9_CHROMA)
            .emit()?;
        b.field("Full range", 1).flag().emit()?;
        f.u8("Colour primaries")
            .enumeration(COLOUR_PRIMARIES)
            .emit()?;
        f.u8("Transfer characteristics")
            .enumeration(TRANSFER_CHARACTERISTICS)
            .emit()?;
        f.u8("Matrix coefficients")
            .enumeration(MATRIX_COEFFICIENTS)
            .emit()?;
    }
    let n = f.u16("Codec initialization data size").emit()?;
    if n > 0 {
        f.bytes("Codec initialization data", n.into()).emit()?;
    }
    Ok(())
}

fn dops(f: &mut Fields<'_>) -> Result<()> {
    f.u8("Version").emit()?;
    let channels = f.u8("Output channel count").emit()?;
    f.u16("Pre-skip")
        .with(|&v, n| n.summary(format!("{} ms at 48 kHz", num(f64::from(v) / 48.0))))
        .desc("Samples to discard from the start of the decoded output")
        .emit()?;
    f.u32("Input sample rate")
        .with(|&v, n| n.summary(khz(v.into())))
        .desc("The original rate; Opus always decodes at 48 kHz")
        .emit()?;
    f.int::<i16>("Output gain")
        .with(|&v, n| n.summary(format!("{} dB", num(f64::from(v) / 256.0))))
        .emit()?;
    let family = f
        .u8("Channel mapping family")
        .enumeration(OPUS_FAMILIES)
        .emit()?;
    if family != 0 {
        f.u8("Stream count").emit()?;
        f.u8("Coupled count").emit()?;
        f.bytes("Channel mapping", channels.into()).emit()?;
    }
    Ok(())
}

async fn dfla(cx: &Cx, body: Span) -> Result<()> {
    let block = cx.block(body.sub(0, 0x10000)).await?;
    let mut f = Fields::emitting(cx, &block, BE);
    full_box(&mut f)?;
    while f.remaining() >= 4 {
        let start = f.pos();
        let header = u32_be(&block.data, to_usize(start)).unwrap_or(0);
        let kind = (header >> 24) & 0x7f;
        let len = u64::from(header & 0x00ff_ffff);
        let span = body.sub(start, len.saturating_add(4));
        let data = block
            .data
            .get(to_usize(start.saturating_add(4))..)
            .unwrap_or_default();
        let mut node = Node::new(lookup_or(FLAC_BLOCKS, kind.into()))
            .span(span)
            .summary(format!(
                "{} bytes{}",
                len,
                if header >> 31 == 1 { ", last" } else { "" }
            ))
            .lazy(flac_block, (span, kind));
        if kind == 0
            && let Some(s) = flac_streaminfo(data)
        {
            node = node.summary(s);
        }
        f.node(node);
        f.skip(len.saturating_add(4));
        if header >> 31 == 1 {
            break;
        }
    }
    Ok(())
}

async fn flac_block(cx: Cx, (span, kind): (Span, u32)) -> Result<()> {
    let data = cx.read_avail(span.sub(0, 0x10000)).await?;
    let mut b = crate::formats::util::sound::Bits::emitting(&cx, &data, span);
    b.field("Last block", 1).flag().emit()?;
    b.field("Block type", 7).enumeration(FLAC_BLOCKS).emit()?;
    let len = b.field("Length", 24).emit()?;
    if kind == 0 {
        b.field("Min block size", 16).emit()?;
        b.field("Max block size", 16).emit()?;
        b.field("Min frame size", 24).emit()?;
        b.field("Max frame size", 24).emit()?;
        b.field("Sample rate", 20)
            .with(|v, n| n.summary(khz(v)))
            .emit()?;
        b.field("Channels minus one", 3)
            .with(|v, n| n.summary(channel_count(v.saturating_add(1))))
            .emit()?;
        b.field("Bits per sample minus one", 5)
            .with(|v, n| n.summary(format!("{} bits", v.saturating_add(1))))
            .emit()?;
        b.field("Total samples", 36).emit()?;
        b.bytes("MD5 signature", 16).emit()?;
    } else if len > 0 {
        cx.emit(Node::new("Data").span(span.tail(4)));
    }
    Ok(())
}

pub fn flac_streaminfo(d: &[u8]) -> Option<String> {
    let mut b = vidutil::Bits::new(d.get(10..18)?);
    let rate = b.bits(20)?;
    let channels = b.bits(3)?.saturating_add(1);
    let bits = b.bits(5)?.saturating_add(1);
    let samples = b.bits(36)?;
    let mut s = format!("{}, {}, {bits}-bit", khz(rate), channel_count(channels));
    if rate > 0 && samples > 0 {
        s = format!("{s}, {}", vidutil::duration(samples, rate));
    }
    Some(s)
}

fn alac(f: &mut Fields<'_>) -> Result<()> {
    full_box(f)?;
    f.u32("Frame length").desc("Samples per frame").emit()?;
    f.u8("Compatible version").emit()?;
    f.u8("Bit depth").emit()?;
    f.u8("Rice history mult").emit()?;
    f.u8("Rice initial history").emit()?;
    f.u8("Rice limit").emit()?;
    f.u8("Channels").emit()?;
    f.u16("Max run").emit()?;
    f.u32("Max frame bytes").emit()?;
    f.u32("Average bit rate")
        .with(|&v, n| n.summary(bitrate(v.into())))
        .emit()?;
    f.u32("Sample rate")
        .with(|&v, n| n.summary(format!("{v} Hz")))
        .emit()?;
    Ok(())
}

fn chan(f: &mut Fields<'_>) -> Result<()> {
    full_box(f)?;
    f.u32("Layout tag")
        .hex()
        .with(|&t, n| {
            n.summary(format!(
                "{}, {} ch",
                lookup_or(CHANNEL_LAYOUTS, (t >> 16).into()),
                t & 0xffff
            ))
        })
        .emit()?;
    f.u32("Channel bitmap").hex().emit()?;
    let n = f.u32("Channel descriptions").emit()?;
    for _ in 0..n.min(64) {
        if f.remaining() < 20 {
            break;
        }
        f.u32("Channel label").emit()?;
        f.u32("Channel flags").hex().emit()?;
        f.f32("Coordinate 0").emit()?;
        f.f32("Coordinate 1").emit()?;
        f.f32("Coordinate 2").emit()?;
    }
    Ok(())
}

fn colr_summary(d: &[u8]) -> Option<String> {
    let kind = d.get(..4)?;
    match kind {
        b"nclx" | b"nclc" => {
            let p = u16_be(d, 4)?;
            let t = u16_be(d, 6)?;
            let m = u16_be(d, 8)?;
            let mut s = format!(
                "{}: {} / {} / {}",
                fourcc(kind),
                lookup_or(COLOUR_PRIMARIES, p.into()),
                lookup_or(TRANSFER_CHARACTERISTICS, t.into()),
                lookup_or(MATRIX_COEFFICIENTS, m.into())
            );
            if kind == b"nclx" {
                let full = d.get(10).is_some_and(|b| b & 0x80 != 0);
                s.push_str(if full {
                    ", full range"
                } else {
                    ", limited range"
                });
            }
            Some(s)
        }
        b"rICC" | b"prof" => Some(format!(
            "{}: ICC profile, {} bytes",
            fourcc(kind),
            d.len().saturating_sub(4)
        )),
        _ => Some(fourcc(kind)),
    }
}

async fn colr(cx: &Cx, st: &BoxState, body: Span) -> Result<()> {
    let kind = cx.read_avail(body.sub(0, 4)).await?;
    let block = cx.block(body.sub(0, 0x10000)).await?;
    let mut f = Fields::emitting(cx, &block, BE);
    f.ascii("Colour type", 4)
        .with(|t, n| {
            n.summary(match t.as_str() {
                "nclx" => "code points (ISO/IEC 23091-2)",
                "nclc" => "code points (QuickTime)",
                "rICC" => "restricted ICC profile",
                "prof" => "unrestricted ICC profile",
                _ => "",
            })
        })
        .emit()?;
    if kind == b"nclx" || kind == b"nclc" {
        f.u16("Colour primaries")
            .enumeration(COLOUR_PRIMARIES)
            .emit()?;
        f.u16("Transfer characteristics")
            .enumeration(TRANSFER_CHARACTERISTICS)
            .emit()?;
        f.u16("Matrix coefficients")
            .enumeration(MATRIX_COEFFICIENTS)
            .emit()?;
        if kind == b"nclx" {
            let mut b = bits_at(Some(cx), &mut f, 1);
            b.field("Full range", 1)
                .with(|v, n| n.summary(if v == 1 { "full" } else { "limited" }))
                .emit()?;
            b.field("Reserved", 7).emit()?;
        }
    }
    if kind == b"rICC" || kind == b"prof" {
        cx.emit(embedded("ICC profile", st.input.nested(body.tail(4))));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// MPEG-4 descriptors (esds, iods)

#[derive(Clone, Copy, Debug)]
struct Descriptor {
    input: Input,
    span: Span,
    header_len: u64,
    tag: u8,
    /// objectTypeIndication of the enclosing DecoderConfigDescriptor.
    object_type: u8,
}

/// Parses a descriptor header: tag and expandable size.
fn descriptor_header(d: &[u8]) -> Option<(u8, u64, u64)> {
    let tag = d.first().copied()?;
    let mut size = 0u64;
    for i in 1..5usize {
        let b = d.get(i).copied()?;
        size = (size << 7) | u64::from(b & 0x7f);
        if b & 0x80 == 0 {
            return Some((tag, size, to_u64(i.saturating_add(1))));
        }
    }
    None
}

async fn descriptors(cx: &Cx, input: Input, span: Span, object_type: u8) -> Result<()> {
    let mut pos = 0u64;
    let mut count = 0u32;
    while pos < span.len {
        let head = cx.read_avail(span.sub(pos, 5)).await?;
        let Some((tag, size, header_len)) = descriptor_header(&head) else {
            cx.emit(Node::new("Data").span(span.tail(pos)));
            break;
        };
        let total = header_len.saturating_add(size);
        let d = Descriptor {
            input,
            span: span.sub(pos, total),
            header_len,
            tag,
            object_type,
        };
        let name = crate::value::lookup(DESCRIPTOR_TAGS, tag.into())
            .map_or_else(|| format!("Descriptor {tag:#04x}"), str::to_owned);
        let mut node = Node::new(name).span(d.span);
        if let Some(s) = descriptor_summary(cx, &d).await {
            node = node.summary(s);
        }
        cx.push(node.lazy(crate::expander!(self::descriptor: Descriptor), d))
            .await;
        pos = pos.saturating_add(total);
        count = count.saturating_add(1);
        if count > 4096 {
            break;
        }
    }
    Ok(())
}

async fn descriptor_summary(cx: &Cx, d: &Descriptor) -> Option<String> {
    let body = d.span.tail(d.header_len);
    let data = cx.read_avail(body.sub(0, 64)).await.ok()?;
    match d.tag {
        0x04 => {
            let oti = data.first().copied()?;
            let mut s = lookup_or(OBJECT_TYPES, oti.into());
            if let Some(avg) = u32_be(&data, 9).filter(|&v| v > 0) {
                s = format!("{s}, {}", bitrate(avg.into()));
            }
            Some(s)
        }
        0x05 if is_aac(d.object_type) => codec::asc(&data).map(|a| a.summary()),
        0x03 => Some(format!("ES_ID {}", u16_be(&data, 0)?)),
        0x06 => Some(lookup_or(SL_PREDEFINED, (*data.first()?).into())),
        _ => None,
    }
}

fn is_aac(oti: u8) -> bool {
    matches!(oti, 0x40 | 0x66 | 0x67 | 0x68)
}

async fn descriptor(cx: Cx, d: Descriptor) -> Result<()> {
    let header = d.span.sub(0, d.header_len);
    cx.emit(enumerated(
        "Tag",
        header.sub(0, 1),
        d.tag.into(),
        8,
        DESCRIPTOR_TAGS,
    ));
    cx.emit(
        uint(
            "Size",
            header.tail(1),
            d.span.len.saturating_sub(d.header_len),
            32,
        )
        .desc("Expandable: 7 bits per byte, high bit set on all but the last"),
    );
    let body = d.span.tail(d.header_len);
    let block = cx.block(body.sub(0, 0x10000)).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    match d.tag {
        0x03 => {
            f.u16("ES_ID").emit()?;
            let mut b = bits_at(Some(&cx), &mut f, 1);
            let depends = b.field("Stream dependence", 1).flag().emit()?;
            let url = b.field("URL", 1).flag().emit()?;
            let ocr = b.field("OCR stream", 1).flag().emit()?;
            b.field("Stream priority", 5).emit()?;
            if depends == 1 {
                f.u16("Depends on ES_ID").emit()?;
            }
            if url == 1 {
                let len = f.u8("URL length").emit()?;
                f.ascii("URL string", len.into()).emit()?;
            }
            if ocr == 1 {
                f.u16("OCR ES_ID").emit()?;
            }
            let at = f.pos();
            descriptors(&cx, d.input, body.tail(at), d.object_type).await?;
        }
        0x04 => {
            let oti = f
                .u8("Object type indication")
                .enumeration(OBJECT_TYPES)
                .emit()?;
            let mut b = bits_at(Some(&cx), &mut f, 1);
            b.field("Stream type", 6).enumeration(STREAM_TYPES).emit()?;
            b.field("Upstream", 1).flag().emit()?;
            b.field("Reserved", 1).emit()?;
            let mut b = bits_at(Some(&cx), &mut f, 3);
            b.field("Buffer size", 24)
                .with(|v, n| n.summary(format!("{v} bytes")))
                .emit()?;
            f.u32("Max bitrate")
                .with(|&v, n| n.summary(bitrate(v.into())))
                .emit()?;
            f.u32("Average bitrate")
                .with(|&v, n| {
                    n.summary(if v == 0 {
                        "variable".to_owned()
                    } else {
                        bitrate(v.into())
                    })
                })
                .emit()?;
            let at = f.pos();
            descriptors(&cx, d.input, body.tail(at), oti).await?;
        }
        0x05 => {
            if is_aac(d.object_type) {
                let mut node = bits_node("AudioSpecificConfig", body, codec::asc_layout, false);
                if let Some(a) = codec::asc(&block.data) {
                    node = node.summary(a.summary());
                }
                cx.emit(node);
            } else if matches!(
                d.object_type,
                0x20 | 0x60..=0x65 | 0x6a | 0x6c | 0x6d | 0x6e
            ) {
                cx.emit(embedded("Decoder specific info", d.input.nested(body)));
            } else {
                let len = f.remaining();
                f.bytes("Decoder specific info", len).emit()?;
            }
        }
        0x06 => {
            f.u8("Predefined").enumeration(SL_PREDEFINED).emit()?;
            let rest = f.remaining();
            if rest > 0 {
                f.bytes("SL config", rest).emit()?;
            }
        }
        0x0e => {
            f.u32("Track ID").emit()?;
        }
        0x02 | 0x10 => {
            let mut b = bits_at(Some(&cx), &mut f, 2);
            b.field("Object descriptor ID", 10).emit()?;
            let url = b.field("URL", 1).flag().emit()?;
            b.field("Include inline profile level", 1).flag().emit()?;
            b.field("Reserved", 4).emit()?;
            if url == 1 {
                let len = f.u8("URL length").emit()?;
                f.ascii("URL string", len.into()).emit()?;
            } else {
                for name in [
                    "OD profile level",
                    "Scene profile level",
                    "Audio profile level",
                    "Visual profile level",
                    "Graphics profile level",
                ] {
                    f.u8(name).hex().emit()?;
                }
            }
            let at = f.pos();
            descriptors(&cx, d.input, body.tail(at), d.object_type).await?;
        }
        _ => {
            if !body.is_empty() {
                cx.emit(Node::new("Data").span(body));
            }
        }
    }
    Ok(())
}

/// Codec description from an `esds` body (after the FullBox header).
pub fn esds_summary(d: &[u8]) -> Option<String> {
    let (oti, asc, avg) = esds_info(d)?;
    let mut s = if is_aac(oti)
        && let Some(asc) = asc.and_then(codec::asc)
    {
        asc.summary()
    } else {
        lookup_or(OBJECT_TYPES, oti.into())
    };
    if avg > 0 {
        s = format!("{s}, {}", bitrate(avg.into()));
    }
    Some(s)
}

/// (objectTypeIndication, decoder specific info, average bitrate) from an
/// `esds` body.
pub fn esds_info(d: &[u8]) -> Option<(u8, Option<&[u8]>, u32)> {
    let mut at = 0usize;
    let mut oti = None;
    let mut avg = 0u32;
    // Walk ES_Descriptor → DecoderConfigDescriptor → DecoderSpecificInfo.
    for _ in 0..8 {
        let (tag, size, hl) = descriptor_header(d.get(at..)?)?;
        let body = at.saturating_add(usize::try_from(hl).ok()?);
        match tag {
            0x03 => {
                let flags = d.get(body.saturating_add(2)).copied()?;
                let mut skip = 3usize;
                if flags & 0x80 != 0 {
                    skip = skip.saturating_add(2);
                }
                if flags & 0x40 != 0 {
                    let len = d.get(body.saturating_add(skip)).copied()?;
                    skip = skip.saturating_add(1).saturating_add(len.into());
                }
                if flags & 0x20 != 0 {
                    skip = skip.saturating_add(2);
                }
                at = body.saturating_add(skip);
            }
            0x04 => {
                oti = Some(d.get(body).copied()?);
                avg = u32_be(d, body.saturating_add(9)).unwrap_or(0);
                at = body.saturating_add(13);
            }
            0x05 => {
                let end = body.saturating_add(usize::try_from(size).ok()?);
                return Some((oti?, d.get(body..end.min(d.len())), avg));
            }
            _ => return oti.map(|o| (o, None, avg)),
        }
    }
    oti.map(|o| (o, None, avg))
}
