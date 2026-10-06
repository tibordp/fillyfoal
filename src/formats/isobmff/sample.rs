//! Sample entries (`stsd` children) and the codec configuration boxes they
//! carry: `avcC`, `hvcC`, `av1C`, `vpcC`, `esds`, `dOps`, `dfLa`, `dac3`,
//! `dec3`, `colr`, `pasp`, `btrt`, ...

use crate::bytes::{u16_be, u32_be};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::Result;
use crate::fields::Fields;
use crate::formats::embedded;
use crate::formats::vidutil::{
    self, COLOUR_PRIMARIES, H264_PROFILES, HEVC_NAL_TYPES, MATRIX_COEFFICIENTS,
    TRANSFER_CHARACTERISTICS, asc_summary, fixed16, fourcc, h264_level, h264_sps, hevc_level,
    hevc_sps, lookup_or, num, uint,
};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::EnumTable;

use super::{BE, BoxState, Brand, Ctx, children, full_box, read_header, small};

/// What kind of sample entry a FourCC is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    Visual,
    Audio,
    Other,
}

const VISUAL: &[&[u8; 4]] = &[
    b"avc1", b"avc2", b"avc3", b"avc4", b"hvc1", b"hev1", b"dvh1", b"dvhe", b"dva1", b"dvav",
    b"av01", b"vp08", b"vp09", b"vvc1", b"vvi1", b"mp4v", b"s263", b"h263", b"jpeg", b"mjpa",
    b"mjpb", b"mjp2", b"apch", b"apcn", b"apcs", b"apco", b"ap4h", b"ap4x", b"encv", b"png ",
    b"rle ", b"SVQ3", b"cvid", b"mp2v", b"xdvc", b"hdv1", b"dvc ", b"dvcp", b"raw ", b"CRAW",
    b"j2ki", b"hvt1", b"lhv1", b"lhe1",
];

const AUDIO: &[&[u8; 4]] = &[
    b"mp4a", b".mp3", b"ac-3", b"ec-3", b"ac-4", b"Opus", b"fLaC", b"alac", b"samr", b"sawb",
    b"sowt", b"twos", b"lpcm", b"ipcm", b"fpcm", b"in24", b"in32", b"fl32", b"fl64", b"ulaw",
    b"alaw", b"ima4", b"enca", b"dtsc", b"dtsh", b"dtsl", b"dtse", b"mha1", b"mhm1", b"NONE",
    b"sac3", b"mp3 ",
];

pub fn entry_kind(kind: &[u8; 4], handler: &[u8; 4]) -> EntryKind {
    if VISUAL.contains(&kind) {
        EntryKind::Visual
    } else if AUDIO.contains(&kind) {
        EntryKind::Audio
    } else if handler == b"vide" || handler == b"pict" || handler == b"auxv" {
        EntryKind::Visual
    } else if handler == b"soun" {
        EntryKind::Audio
    } else {
        EntryKind::Other
    }
}

record! {
    pub struct VisualEntry {
        pre_defined: u16 "Version",
        reserved: u16 "Revision",
        vendor: bytes[4] "Vendor",
        temporal: u32 "Temporal quality",
        spatial: u32 "Spatial quality",
        width: u16 "Width",
        height: u16 "Height",
        hres: u32 "Horizontal resolution" .with(|&v, n| n.summary(format!("{} dpi", num(fixed16(v))))),
        vres: u32 "Vertical resolution" .with(|&v, n| n.summary(format!("{} dpi", num(fixed16(v))))),
        data_size: u32 "Data size",
        frame_count: u16 "Frame count",
        compressor: bytes[32] "Compressor name" .with(|v, n| n.summary(pascal(v))),
        depth: u16 "Depth" .hex(),
        color_table: i16 "Color table ID",
    }
}

record! {
    pub struct AudioEntry {
        version: u16 "Version",
        revision: u16 "Revision",
        vendor: bytes[4] "Vendor",
        channels: u16 "Channel count",
        sample_size: u16 "Sample size",
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
        flags: u32 "Format-specific flags" .hex(),
        bytes_per_packet: u32 "Bytes per audio packet",
        frames_per_packet: u32 "LPCM frames per packet",
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

/// Expands a sample entry in `stsd`.
pub async fn entry(cx: &Cx, st: &BoxState) -> Result<()> {
    let body = st.body();
    let kind = st.header.kind;
    let ctx = st.ctx;
    let block = cx.block(body.sub(0, 8 + 70 + 52)).await?;
    let mut f = Fields::emitting(cx, &block, BE);
    f.bytes("Reserved", 6).emit()?;
    f.u16("Data reference index").emit()?;
    let mut at = 8u64;
    match entry_kind(&kind, &ctx.handler) {
        EntryKind::Visual => {
            VisualEntry::read(&mut f)?;
            at = f.pos();
        }
        EntryKind::Audio => {
            let a = AudioEntry::read(&mut f)?;
            // QuickTime sound description versions 1 and 2 extend the
            // entry; ISO files always use version 0.
            if a.version == 1 && ctx.brand == Brand::Mov {
                AudioV1::read(&mut f)?;
            } else if a.version == 2 && ctx.brand == Brand::Mov {
                AudioV2::read(&mut f)?;
            }
            at = f.pos();
        }
        EntryKind::Other => {}
    }
    let rest = body.tail(at);
    if rest.is_empty() {
        return Ok(());
    }
    let child = ctx.child_of(kind, rest);
    if looks_like_boxes(cx, rest).await {
        children(cx, st.input, rest, child).await
    } else {
        cx.emit(Node::new("Data").span(rest));
        Ok(())
    }
}

impl Ctx {
    pub fn child_of(self, parent: [u8; 4], siblings: Span) -> Ctx {
        Ctx {
            parent,
            depth: self.depth.saturating_add(1),
            siblings,
            ..self
        }
    }
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

/// Codec summary of a sample entry, for the box list and track summaries.
pub async fn describe(cx: &Cx, st: &BoxState) -> Option<String> {
    let data = small(cx, st.body().sub(0, 64)).await.ok()?;
    let info = entry_info(&st.header.kind, &st.ctx.handler, &data);
    Some(info.describe())
}

#[derive(Clone, Debug, Default)]
pub struct EntryInfo {
    pub fourcc: String,
    pub codec: Option<&'static str>,
    pub width: u16,
    pub height: u16,
    pub channels: u16,
    pub rate: u32,
}

impl EntryInfo {
    pub fn describe(&self) -> String {
        let mut s = self
            .codec
            .map_or_else(|| self.fourcc.clone(), str::to_owned);
        if self.width > 0 || self.height > 0 {
            s = format!("{s} {}×{}", self.width, self.height);
        }
        if self.channels > 0 {
            s = format!("{s}, {} ch, {} Hz", self.channels, self.rate);
        }
        s
    }
}

/// Decodes the start of a sample entry body (`data`).
pub fn entry_info(kind: &[u8; 4], handler: &[u8; 4], data: &[u8]) -> EntryInfo {
    let mut info = EntryInfo {
        fourcc: fourcc(kind),
        codec: vidutil::codec_name(kind),
        ..EntryInfo::default()
    };
    match entry_kind(kind, handler) {
        EntryKind::Visual => {
            info.width = u16_be(data, 24).unwrap_or(0);
            info.height = u16_be(data, 26).unwrap_or(0);
        }
        EntryKind::Audio => {
            info.channels = u16_be(data, 16).unwrap_or(0);
            info.rate = u32_be(data, 24).unwrap_or(0) >> 16;
        }
        EntryKind::Other => {}
    }
    info
}

// ---------------------------------------------------------------------------
// Configuration boxes

const CHROMA: EnumTable = &[(0, "monochrome"), (1, "4:2:0"), (2, "4:2:2"), (3, "4:4:4")];

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

const AC3_ACMOD: [&str; 8] = ["1+1", "1/0", "2/0", "3/0", "2/1", "3/1", "2/2", "3/2"];
const AC3_RATES: [u32; 3] = [48000, 44100, 32000];
const AC3_BITRATES: [u32; 19] = [
    32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 448, 512, 576, 640,
];

async fn emit_fields(
    cx: &Cx,
    span: Span,
    layout: impl FnOnce(&mut Fields<'_>) -> Result<()>,
) -> Result<()> {
    let block = cx.block(span.sub(0, 0x10000)).await?;
    layout(&mut Fields::emitting(cx, &block, BE))
}

/// Decodes codec configuration boxes. Returns `false` for other types.
pub async fn decode_config(cx: &Cx, st: &BoxState) -> Result<bool> {
    let body = st.body();
    match &st.header.kind {
        b"avcC" => emit_fields(cx, body, avcc).await?,
        b"hvcC" | b"lhvC" => emit_fields(cx, body, hvcc).await?,
        b"av1C" => emit_fields(cx, body, av1c).await?,
        b"vpcC" => emit_fields(cx, body, vpcc).await?,
        b"esds" | b"iods" => {
            emit_fields(cx, body.sub(0, 4), |f| full_box(f).map(|_| ())).await?;
            descriptors(cx, body.tail(4), 0).await?;
        }
        b"dOps" => emit_fields(cx, body, dops).await?,
        b"dfLa" => emit_fields(cx, body, dfla).await?,
        b"dac3" => {
            emit_fields(cx, body, |f| {
                f.bytes("AC-3 specific", 3)
                    .with(|v, n| match dac3_summary(v) {
                        Some(s) => n.summary(s),
                        None => n,
                    })
                    .emit()?;
                Ok(())
            })
            .await?;
        }
        b"dec3" => {
            emit_fields(cx, body, |f| {
                f.u16("Data rate / substreams")
                    .hex()
                    .with(|&v, n| {
                        n.summary(format!(
                            "{} kb/s, {} independent substreams",
                            v >> 3,
                            (v & 7).saturating_add(1)
                        ))
                    })
                    .emit()?;
                let rest = f.remaining();
                f.bytes("Substreams", rest).emit()?;
                Ok(())
            })
            .await?;
        }
        b"alac" => emit_fields(cx, body, alac).await?,
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
                for name in [
                    "Clean aperture width N",
                    "Clean aperture width D",
                    "Clean aperture height N",
                    "Clean aperture height D",
                    "Horizontal offset N",
                    "Horizontal offset D",
                    "Vertical offset N",
                    "Vertical offset D",
                ] {
                    f.u32(name).emit()?;
                }
                Ok(())
            })
            .await?;
        }
        b"btrt" => {
            emit_fields(cx, body, |f| {
                f.u32("Buffer size").emit()?;
                f.u32("Max bitrate").emit()?;
                f.u32("Average bitrate").emit()?;
                Ok(())
            })
            .await?;
        }
        b"fiel" => {
            emit_fields(cx, body, |f| {
                f.u8("Field count").emit()?;
                f.u8("Field ordering").emit()?;
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
            emit_fields(cx, body, |f| {
                if &st.header.kind == b"CoLL" {
                    full_box(f)?;
                }
                f.u16("Max content light level").emit()?;
                f.u16("Max frame-average light level").emit()?;
                Ok(())
            })
            .await?;
        }
        b"mdcv" => {
            emit_fields(cx, body, |f| {
                for name in [
                    "Primary 0 x",
                    "Primary 0 y",
                    "Primary 1 x",
                    "Primary 1 y",
                    "Primary 2 x",
                    "Primary 2 y",
                    "White point x",
                    "White point y",
                ] {
                    f.u16(name).emit()?;
                }
                f.u32("Max luminance").emit()?;
                f.u32("Min luminance").emit()?;
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
        _ => return Ok(false),
    }
    Ok(true)
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
            | b"dac3"
            | b"colr"
            | b"pasp"
            | b"btrt"
    ) {
        return None;
    }
    let d = small(cx, st.body().sub(0, 1024)).await.ok()?;
    match kind {
        b"avcC" => vidutil::avcc_summary(&d),
        b"hvcC" => vidutil::hvcc_summary(&d),
        b"av1C" => {
            let b1 = d.get(1).copied()?;
            let b2 = d.get(2).copied()?;
            Some(format!(
                "profile {}, level index {}, {}-bit",
                b1 >> 5,
                b1 & 0x1f,
                av1_bit_depth(b2)
            ))
        }
        b"vpcC" => Some(format!(
            "profile {}, level {}, {}-bit",
            d.get(4)?,
            d.get(5)?,
            d.get(6)? >> 4
        )),
        b"esds" => esds_summary(d.get(4..)?),
        b"dOps" => Some(format!("{} ch, input {} Hz", d.get(1)?, u32_be(&d, 4)?)),
        b"dac3" => dac3_summary(d.get(..3)?),
        b"colr" => colr_summary(&d),
        b"pasp" => Some(format!("{}:{}", u32_be(&d, 0)?, u32_be(&d, 4)?)),
        b"btrt" => Some(format!("average {} b/s", u32_be(&d, 8)?)),
        _ => None,
    }
}

fn av1_bit_depth(b2: u8) -> u8 {
    match (b2 & 0x40 != 0, b2 & 0x20 != 0) {
        (true, true) => 12,
        (true, false) => 10,
        _ => 8,
    }
}

fn avcc(f: &mut Fields<'_>) -> Result<()> {
    f.u8("Configuration version").emit()?;
    f.u8("Profile").enumeration(H264_PROFILES).emit()?;
    f.u8("Profile compatibility").hex().emit()?;
    f.u8("Level")
        .with(|&l, n| n.summary(h264_level(l)))
        .emit()?;
    f.u8("Length size")
        .hex()
        .with(|&v, n| n.summary(format!("{} bytes", (v & 3).saturating_add(1))))
        .emit()?;
    let sps = f
        .u8("SPS count")
        .with(|&v, n| n.summary(format!("{}", v & 0x1f)))
        .emit()?;
    for _ in 0..(sps & 0x1f) {
        let len = f.u16("SPS length").emit()?;
        f.bytes("Sequence parameter set", len.into())
            .with(|nal, n| match h264_sps(nal) {
                Some(s) => n.summary(s.h264_summary()),
                None => n,
            })
            .emit()?;
    }
    let pps = f.u8("PPS count").emit()?;
    for _ in 0..pps {
        let len = f.u16("PPS length").emit()?;
        f.bytes("Picture parameter set", len.into()).emit()?;
    }
    let rest = f.remaining();
    if rest > 0 {
        f.bytes("Extension", rest).emit()?;
    }
    Ok(())
}

fn hvcc(f: &mut Fields<'_>) -> Result<()> {
    f.u8("Configuration version").emit()?;
    f.u8("Profile space / tier / profile")
        .hex()
        .with(|&v, n| {
            n.summary(format!(
                "{}, {} tier",
                lookup_or(vidutil::HEVC_PROFILES, (v & 0x1f).into()),
                if v & 0x20 != 0 { "High" } else { "Main" }
            ))
        })
        .emit()?;
    f.u32("Profile compatibility flags").hex().emit()?;
    f.bytes("Constraint indicator flags", 6).emit()?;
    f.u8("Level")
        .with(|&l, n| n.summary(hevc_level(l)))
        .emit()?;
    f.u16("Min spatial segmentation")
        .with(|&v, n| n.summary(format!("{}", v & 0x0fff)))
        .emit()?;
    f.u8("Parallelism type")
        .with(|&v, n| n.summary(format!("{}", v & 3)))
        .emit()?;
    f.u8("Chroma format")
        .with(|&v, n| n.summary(lookup_or(CHROMA, (v & 3).into())))
        .emit()?;
    f.u8("Luma bit depth")
        .with(|&v, n| n.summary(format!("{}", (v & 7).saturating_add(8))))
        .emit()?;
    f.u8("Chroma bit depth")
        .with(|&v, n| n.summary(format!("{}", (v & 7).saturating_add(8))))
        .emit()?;
    f.u16("Average frame rate").emit()?;
    f.u8("Frame rate / layers / length size")
        .hex()
        .with(|&v, n| {
            n.summary(format!(
                "{} temporal layers, length size {}",
                (v >> 3) & 7,
                (v & 3).saturating_add(1)
            ))
        })
        .emit()?;
    let arrays = f.u8("Array count").emit()?;
    for _ in 0..arrays {
        let kind = f
            .u8("NAL unit type")
            .with(|&v, n| n.summary(lookup_or(HEVC_NAL_TYPES, (v & 0x3f).into())))
            .emit()?
            & 0x3f;
        let count = f.u16("NAL unit count").emit()?;
        for _ in 0..count {
            let len = f.u16("NAL unit length").emit()?;
            let name = match kind {
                32 => "Video parameter set",
                33 => "Sequence parameter set",
                34 => "Picture parameter set",
                _ => "NAL unit",
            };
            f.bytes(name, len.into())
                .with(|nal, n| match (kind, hevc_sps(nal)) {
                    (33, Some(s)) => n.summary(s.hevc_summary()),
                    _ => n,
                })
                .emit()?;
        }
    }
    Ok(())
}

fn av1c(f: &mut Fields<'_>) -> Result<()> {
    f.u8("Marker / version")
        .hex()
        .with(|&v, n| n.summary(format!("version {}", v & 0x7f)))
        .emit()?;
    f.u8("Profile / level")
        .hex()
        .with(|&v, n| {
            n.summary(format!(
                "seq_profile {}, seq_level_idx {}",
                v >> 5,
                v & 0x1f
            ))
        })
        .emit()?;
    f.u8("Tier / depth / chroma")
        .hex()
        .with(|&v, n| {
            n.summary(format!(
                "tier {}, {}-bit{}, subsampling {}{}",
                v >> 7,
                av1_bit_depth(v),
                if v & 0x10 != 0 { ", monochrome" } else { "" },
                (v >> 3) & 1,
                (v >> 2) & 1
            ))
        })
        .emit()?;
    f.u8("Initial presentation delay").hex().emit()?;
    let rest = f.remaining();
    if rest > 0 {
        f.bytes("Configuration OBUs", rest).emit()?;
    }
    Ok(())
}

fn vpcc(f: &mut Fields<'_>) -> Result<()> {
    full_box(f)?;
    f.u8("Profile").emit()?;
    f.u8("Level").emit()?;
    f.u8("Bit depth / chroma / range")
        .hex()
        .with(|&v, n| {
            n.summary(format!(
                "{}-bit, chroma subsampling {}, {} range",
                v >> 4,
                (v >> 1) & 7,
                if v & 1 != 0 { "full" } else { "limited" }
            ))
        })
        .emit()?;
    f.u8("Colour primaries")
        .enumeration(COLOUR_PRIMARIES)
        .emit()?;
    f.u8("Transfer characteristics")
        .enumeration(TRANSFER_CHARACTERISTICS)
        .emit()?;
    f.u8("Matrix coefficients")
        .enumeration(MATRIX_COEFFICIENTS)
        .emit()?;
    let n = f.u16("Codec initialization data size").emit()?;
    if n > 0 {
        f.bytes("Codec initialization data", n.into()).emit()?;
    }
    Ok(())
}

fn dops(f: &mut Fields<'_>) -> Result<()> {
    f.u8("Version").emit()?;
    let channels = f.u8("Output channel count").emit()?;
    f.u16("Pre-skip").emit()?;
    f.u32("Input sample rate").emit()?;
    f.int::<i16>("Output gain").emit()?;
    let family = f.u8("Channel mapping family").emit()?;
    if family != 0 {
        f.u8("Stream count").emit()?;
        f.u8("Coupled count").emit()?;
        f.bytes("Channel mapping", channels.into()).emit()?;
    }
    Ok(())
}

const FLAC_BLOCKS: EnumTable = &[
    (0, "STREAMINFO"),
    (1, "PADDING"),
    (2, "APPLICATION"),
    (3, "SEEKTABLE"),
    (4, "VORBIS_COMMENT"),
    (5, "CUESHEET"),
    (6, "PICTURE"),
];

fn dfla(f: &mut Fields<'_>) -> Result<()> {
    full_box(f)?;
    while f.remaining() >= 4 {
        let header = f
            .u32("Metadata block header")
            .hex()
            .with(|&v, n| {
                n.summary(format!(
                    "{}{}, {} bytes",
                    lookup_or(FLAC_BLOCKS, ((v >> 24) & 0x7f).into()),
                    if v >> 31 == 1 { " (last)" } else { "" },
                    v & 0x00ff_ffff
                ))
            })
            .emit()?;
        let len = u64::from(header & 0x00ff_ffff);
        let name = if (header >> 24) & 0x7f == 0 {
            "STREAMINFO"
        } else {
            "Metadata block"
        };
        f.bytes(name, len)
            .with(|d, n| match flac_streaminfo(d) {
                Some(s) if name == "STREAMINFO" => n.summary(s),
                _ => n,
            })
            .emit()?;
        if header >> 31 == 1 {
            break;
        }
    }
    Ok(())
}

pub fn flac_streaminfo(d: &[u8]) -> Option<String> {
    let mut b = vidutil::Bits::new(d.get(10..18)?);
    let rate = b.bits(20)?;
    let channels = b.bits(3)?.saturating_add(1);
    let bits = b.bits(5)?.saturating_add(1);
    let samples = b.bits(36)?;
    Some(format!(
        "{rate} Hz, {channels} ch, {bits}-bit, {samples} samples"
    ))
}

fn alac(f: &mut Fields<'_>) -> Result<()> {
    full_box(f)?;
    f.u32("Frame length").emit()?;
    f.u8("Compatible version").emit()?;
    f.u8("Bit depth").emit()?;
    f.u8("Rice history mult").emit()?;
    f.u8("Rice initial history").emit()?;
    f.u8("Rice limit").emit()?;
    f.u8("Channels").emit()?;
    f.u16("Max run").emit()?;
    f.u32("Max frame bytes").emit()?;
    f.u32("Average bit rate").emit()?;
    f.u32("Sample rate").emit()?;
    Ok(())
}

fn dac3_summary(d: &[u8]) -> Option<String> {
    let mut b = vidutil::Bits::new(d);
    let fscod = b.bits(2)?;
    b.bits(5)?;
    b.bits(3)?;
    let acmod = b.bits(3)?;
    let lfe = b.bit()?;
    let rate = b.bits(5)?;
    Some(format!(
        "{} Hz, {}{}, {} kb/s",
        AC3_RATES.get(vidutil::us(fscod)).copied().unwrap_or(0),
        AC3_ACMOD.get(vidutil::us(acmod)).copied().unwrap_or("?"),
        if lfe == 1 { ".1" } else { "" },
        AC3_BITRATES.get(vidutil::us(rate)).copied().unwrap_or(0)
    ))
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
        b"rICC" | b"prof" => Some(format!("{}: ICC profile", fourcc(kind))),
        _ => Some(fourcc(kind)),
    }
}

async fn colr(cx: &Cx, st: &BoxState, body: Span) -> Result<()> {
    let kind = cx.read_avail(body.sub(0, 4)).await?;
    emit_fields(cx, body, |f| {
        f.ascii("Colour type", 4).emit()?;
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
                f.u8("Full range flag")
                    .with(|&v, n| n.summary(if v & 0x80 != 0 { "full" } else { "limited" }))
                    .emit()?;
            }
        }
        Ok(())
    })
    .await?;
    if kind == b"rICC" || kind == b"prof" {
        cx.emit(embedded("ICC profile", st.input.nested(body.tail(4))));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// MPEG-4 descriptors (esds, iods)

#[derive(Clone, Copy, Debug)]
struct Descriptor {
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
            return Some((tag, size, crate::bytes::to_u64(i.saturating_add(1))));
        }
    }
    None
}

async fn descriptors(cx: &Cx, span: Span, object_type: u8) -> Result<()> {
    let mut pos = 0u64;
    while pos < span.len {
        let head = cx.read_avail(span.sub(pos, 5)).await?;
        let Some((tag, size, header_len)) = descriptor_header(&head) else {
            cx.emit(Node::new("Data").span(span.tail(pos)));
            break;
        };
        let total = header_len.saturating_add(size);
        let d = Descriptor {
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
    }
    Ok(())
}

async fn descriptor_summary(cx: &Cx, d: &Descriptor) -> Option<String> {
    let body = d.span.tail(d.header_len);
    let data = cx.read_avail(body.sub(0, 16)).await.ok()?;
    match d.tag {
        0x04 => Some(lookup_or(OBJECT_TYPES, data.first().copied()?.into())),
        0x05 if matches!(d.object_type, 0x40 | 0x66 | 0x67 | 0x68) => asc_summary(&data),
        0x03 => Some(format!("ES_ID {}", u16_be(&data, 0)?)),
        _ => None,
    }
}

async fn descriptor(cx: Cx, d: Descriptor) -> Result<()> {
    let header = d.span.sub(0, d.header_len);
    cx.emit(vidutil::enumerated(
        "Tag",
        header.sub(0, 1),
        d.tag.into(),
        8,
        DESCRIPTOR_TAGS,
    ));
    cx.emit(uint(
        "Size",
        header.tail(1),
        d.span.len.saturating_sub(d.header_len),
        32,
    ));
    let body = d.span.tail(d.header_len);
    let block = cx.block(body.sub(0, 0x10000)).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    match d.tag {
        0x03 => {
            f.u16("ES_ID").emit()?;
            let flags = f
                .u8("Flags / stream priority")
                .hex()
                .with(|&v, n| n.summary(format!("priority {}", v & 0x1f)))
                .emit()?;
            if flags & 0x80 != 0 {
                f.u16("Depends on ES_ID").emit()?;
            }
            if flags & 0x40 != 0 {
                let len = f.u8("URL length").emit()?;
                f.ascii("URL", len.into()).emit()?;
            }
            if flags & 0x20 != 0 {
                f.u16("OCR ES_ID").emit()?;
            }
            let at = f.pos();
            descriptors(&cx, body.tail(at), d.object_type).await?;
        }
        0x04 => {
            let oti = f
                .u8("Object type indication")
                .enumeration(OBJECT_TYPES)
                .emit()?;
            f.u8("Stream type / flags")
                .hex()
                .with(|&v, n| {
                    n.summary(format!(
                        "{}{}",
                        lookup_or(STREAM_TYPES, (v >> 2).into()),
                        if v & 2 != 0 { ", upstream" } else { "" }
                    ))
                })
                .emit()?;
            f.bytes("Buffer size", 3).emit()?;
            f.u32("Max bitrate").emit()?;
            f.u32("Average bitrate").emit()?;
            let at = f.pos();
            descriptors(&cx, body.tail(at), oti).await?;
        }
        0x05 => {
            let len = f.remaining();
            let aac = matches!(d.object_type, 0x40 | 0x66 | 0x67 | 0x68);
            f.bytes("Decoder specific info", len)
                .with(|v, n| match asc_summary(v) {
                    Some(s) if aac => n.summary(s),
                    _ => n,
                })
                .emit()?;
        }
        0x06 => {
            f.u8("Predefined").emit()?;
            let rest = f.remaining();
            if rest > 0 {
                f.bytes("SL config", rest).emit()?;
            }
        }
        0x0e => {
            f.u32("Track ID").emit()?;
        }
        0x02 | 0x10 => {
            f.u16("Object descriptor ID / flags").hex().emit()?;
            for name in [
                "OD profile level",
                "Scene profile level",
                "Audio profile level",
                "Visual profile level",
                "Graphics profile level",
            ] {
                f.u8(name).hex().emit()?;
            }
            let at = f.pos();
            descriptors(&cx, body.tail(at), d.object_type).await?;
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
    let (oti, asc) = esds_info(d)?;
    if matches!(oti, 0x40 | 0x66 | 0x67 | 0x68)
        && let Some(asc) = asc
        && let Some(s) = asc_summary(asc)
    {
        return Some(s);
    }
    Some(lookup_or(OBJECT_TYPES, oti.into()))
}

/// (objectTypeIndication, decoder specific info) from an `esds` body.
pub fn esds_info(d: &[u8]) -> Option<(u8, Option<&[u8]>)> {
    let mut at = 0usize;
    let mut oti = None;
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
                at = body.saturating_add(13);
            }
            0x05 => {
                let end = body.saturating_add(usize::try_from(size).ok()?);
                return Some((oti?, d.get(body..end)));
            }
            _ => return oti.map(|o| (o, None)),
        }
    }
    oti.map(|o| (o, None))
}
