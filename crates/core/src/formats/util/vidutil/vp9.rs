//! VP8 and VP9 frame headers: the VP8 frame tag and key frame start (RFC
//! 6386 section 9.1), the VP9 uncompressed header (VP9 bitstream
//! specification section 6.2) up to the frame size, the VP9 superframe
//! index, and the `vpcC` codec configuration record.

use super::bitwalk::Walker;
use crate::value::EnumTable;

pub const VP9_COLOR_SPACES: EnumTable = &[
    (0, "unknown"),
    (1, "BT.601"),
    (2, "BT.709"),
    (3, "SMPTE 170"),
    (4, "SMPTE 240"),
    (5, "BT.2020"),
    (6, "reserved"),
    (7, "sRGB"),
];

const FRAME_TYPES: EnumTable = &[(0, "key frame"), (1, "non-key frame")];

/// What a VP9 frame header says.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Vp9Frame {
    pub profile: u64,
    pub key: bool,
    pub shown: bool,
    pub show_existing: bool,
    pub intra_only: bool,
    pub bit_depth: u64,
    pub color_space: u64,
    pub full_range: bool,
    pub subsampling: (u64, u64),
    pub width: u64,
    pub height: u64,
}

impl Vp9Frame {
    pub fn format(&self) -> String {
        let chroma = match self.subsampling {
            (1, 1) => "4:2:0",
            (1, 0) => "4:2:2",
            (0, 1) => "4:4:0",
            _ => "4:4:4",
        };
        format!("{chroma} {}-bit", self.bit_depth)
    }

    pub fn describe(&self) -> String {
        if self.show_existing {
            return "show existing frame".to_owned();
        }
        let mut s = format!(
            "profile {}, {}",
            self.profile,
            if self.key {
                "key frame"
            } else if self.intra_only {
                "intra-only frame"
            } else {
                "inter frame"
            }
        );
        if self.width > 0 {
            s.push_str(&format!(
                ", {}×{}, {}",
                self.width,
                self.height,
                self.format()
            ));
            if self.color_space != 0 {
                s.push_str(&format!(
                    ", {}",
                    super::tables::lookup_or(VP9_COLOR_SPACES, self.color_space)
                ));
            }
        }
        if !self.shown {
            s.push_str(", hidden");
        }
        s
    }
}

fn color_config(w: &mut Walker, f: &mut Vp9Frame) -> Option<()> {
    w.begin("Color config");
    f.bit_depth = if f.profile >= 2 {
        if w.flag("ten_or_twelve_bit")? { 12 } else { 10 }
    } else {
        8
    };
    f.color_space = w.en("color_space", 3, VP9_COLOR_SPACES)?;
    if f.color_space != 7 {
        f.full_range = w.flag("color_range")?;
        if f.profile == 1 || f.profile == 3 {
            f.subsampling.0 = w.u("subsampling_x", 1)?;
            f.subsampling.1 = w.u("subsampling_y", 1)?;
            w.u("reserved_zero", 1)?;
        } else {
            f.subsampling = (1, 1);
        }
    } else {
        f.full_range = true;
        if f.profile == 1 || f.profile == 3 {
            f.subsampling = (0, 0);
            w.u("reserved_zero", 1)?;
        }
    }
    let s = f.format();
    w.end_summary(|| s);
    Some(())
}

fn frame_size(w: &mut Walker, f: &mut Vp9Frame) -> Option<()> {
    f.width = w.u("frame_width_minus_1", 16)?.saturating_add(1);
    f.height = w.u("frame_height_minus_1", 16)?.saturating_add(1);
    if w.flag("render_and_frame_size_different")? {
        w.u("render_width_minus_1", 16)?;
        w.u("render_height_minus_1", 16)?;
    }
    Some(())
}

/// `uncompressed_header()` of a VP9 frame, up to the frame size.
pub fn vp9_header(w: &mut Walker) -> Option<Vp9Frame> {
    let mut f = Vp9Frame::default();
    let marker = w.u("frame_marker", 2)?;
    if marker != 2 {
        return None;
    }
    let low = w.u("profile_low_bit", 1)?;
    let high = w.u("profile_high_bit", 1)?;
    f.profile = (high << 1) | low;
    if f.profile == 3 {
        w.u("reserved_zero", 1)?;
    }
    f.show_existing = w.flag("show_existing_frame")?;
    if f.show_existing {
        w.u("frame_to_show_map_idx", 3)?;
        f.shown = true;
        return Some(f);
    }
    f.key = w.en("frame_type", 1, FRAME_TYPES)? == 0;
    f.shown = w.flag("show_frame")?;
    let error_resilient = w.flag("error_resilient_mode")?;
    if f.key {
        w.x("frame_sync_code", 24)?;
        color_config(w, &mut f)?;
        frame_size(w, &mut f)?;
    } else {
        f.intra_only = if f.shown {
            false
        } else {
            w.flag("intra_only")?
        };
        if !error_resilient {
            w.u("reset_frame_context", 2)?;
        }
        if f.intra_only {
            w.x("frame_sync_code", 24)?;
            if f.profile > 0 {
                color_config(w, &mut f)?;
            } else {
                f.bit_depth = 8;
                f.color_space = 1;
                f.subsampling = (1, 1);
            }
            w.x("refresh_frame_flags", 8)?;
            frame_size(w, &mut f)?;
        } else {
            w.x("refresh_frame_flags", 8)?;
        }
    }
    w.push(
        crate::node::Node::new("Remaining fields")
            .desc("The rest of the uncompressed header is not decoded"),
    );
    Some(f)
}

/// Frame sizes from a VP9 superframe index at the end of `d`, if any.
pub fn vp9_superframe(d: &[u8]) -> Option<Vec<u64>> {
    let marker = *d.last()?;
    if marker & 0xe0 != 0xc0 {
        return None;
    }
    let bytes = usize::from((marker >> 3) & 3).saturating_add(1);
    let frames = usize::from(marker & 7).saturating_add(1);
    let index = bytes.saturating_mul(frames).saturating_add(2);
    let start = d.len().checked_sub(index)?;
    if d.get(start) != Some(&marker) {
        return None;
    }
    let mut sizes = Vec::with_capacity(frames);
    for i in 0..frames {
        let at = start
            .saturating_add(1)
            .saturating_add(i.saturating_mul(bytes));
        let mut v = 0u64;
        for k in 0..bytes {
            let b = u64::from(*d.get(at.saturating_add(k))?);
            v |= b.checked_shl(u32::try_from(k.saturating_mul(8)).ok()?)?;
        }
        sizes.push(v);
    }
    Some(sizes)
}

/// The VP8 frame tag and, for key frames, the start code and dimensions.
pub fn vp8_header(w: &mut Walker) -> Option<String> {
    let start = w.pos();
    let tag = w.read(24)?;
    // The tag is little-endian.
    let tag = ((tag & 0xff) << 16) | (tag & 0xff00) | (tag >> 16);
    let key = tag & 1 == 0;
    let version = (tag >> 1) & 7;
    let shown = (tag >> 4) & 1 == 1;
    let first = tag >> 5;
    if w.emitting() {
        let end = w.pos();
        w.seek(start);
        w.begin("Frame tag");
        w.seek(end);
        let span = w.span_bits(start, start.saturating_add(24));
        for (name, value) in [
            ("frame_type (0 = key frame)", u64::from(!key)),
            ("version", version),
            ("show_frame", u64::from(shown)),
            ("first_part_size", first),
        ] {
            w.push(super::uint(name, span, value, 32));
        }
        w.end_summary(|| {
            format!(
                "{}, version {version}, first partition {first} bytes",
                if key { "key frame" } else { "inter frame" }
            )
        });
    }
    if !key {
        return Some(format!(
            "inter frame{}",
            if shown { "" } else { ", hidden" }
        ));
    }
    let code = w.x("start_code", 24)?;
    if code != 0x9d012a {
        return None;
    }
    let start = w.pos();
    let width = w.read(16)?;
    let width = ((width & 0xff) << 8) | (width >> 8);
    let span = w.span_bits(start, start.saturating_add(16));
    w.push(super::uint("width", span, width & 0x3fff, 14));
    w.push(super::uint("horizontal_scale", span, width >> 14, 2));
    let start = w.pos();
    let height = w.read(16)?;
    let height = ((height & 0xff) << 8) | (height >> 8);
    let span = w.span_bits(start, start.saturating_add(16));
    w.push(super::uint("height", span, height & 0x3fff, 14));
    w.push(super::uint("vertical_scale", span, height >> 14, 2));
    Some(format!("key frame, {}×{}", width & 0x3fff, height & 0x3fff))
}

/// `VPCodecConfigurationRecord` (the body of `vpcC` after its version and
/// flags).
pub fn vpcc(w: &mut Walker) -> Option<String> {
    let profile = w.u("profile", 8)?;
    let level = w.u("level", 8)?;
    w.summary(|| format!("{}.{}", level / 10, level % 10));
    let depth = w.u("bitDepth", 4)?;
    let sub = w.en("chromaSubsampling", 3, CHROMA_SUBSAMPLING)?;
    w.flag("videoFullRangeFlag")?;
    let p = w.en("colourPrimaries", 8, super::tables::COLOUR_PRIMARIES)?;
    let t = w.en(
        "transferCharacteristics",
        8,
        super::tables::TRANSFER_CHARACTERISTICS,
    )?;
    let m = w.en("matrixCoefficients", 8, super::tables::MATRIX_COEFFICIENTS)?;
    init_data(w)?;
    let mut s = vpcc_summary(profile, level, sub, depth);
    if let Some(c) = super::params::colour_summary(p, t, m) {
        s = format!("{s}, {c}");
    }
    Some(s)
}

const CHROMA_SUBSAMPLING: EnumTable = &[
    (0, "4:2:0 vertical"),
    (1, "4:2:0 colocated"),
    (2, "4:2:2"),
    (3, "4:4:4"),
];

fn init_data(w: &mut Walker) -> Option<()> {
    let n = w.u("codecIntializationDataSize", 16)?;
    if n > 0 {
        w.skip_as(
            "codecIntializationData",
            usize::try_from(n).ok()?.checked_mul(8)?,
        )?;
    }
    Some(())
}

fn vpcc_summary(profile: u64, level: u64, sub: u64, depth: u64) -> String {
    let chroma = match sub {
        0 | 1 => "4:2:0",
        2 => "4:2:2",
        _ => "4:4:4",
    };
    format!(
        "profile {profile}, level {}.{}, {chroma} {depth}-bit",
        level / 10,
        level % 10
    )
}

/// The draft (version 0) `VPCodecConfigurationRecord`, after its version
/// and flags: colour space and transfer function in 4-bit VP9 code points.
pub fn vpcc_v0(w: &mut Walker) -> Option<String> {
    let profile = w.u("profile", 8)?;
    let level = w.u("level", 8)?;
    w.summary(|| format!("{}.{}", level / 10, level % 10));
    let depth = w.u("bitDepth", 4)?;
    w.en("colorSpace", 4, VP9_COLOR_SPACES)?;
    let sub = w.en("chromaSubsampling", 4, CHROMA_SUBSAMPLING)?;
    w.u("transferFunction", 4)?;
    w.flag("videoFullRangeFlag")?;
    w.u("reserved", 7)?;
    init_data(w)?;
    Some(vpcc_summary(profile, level, sub, depth))
}

/// The `vp09` codec string (`vp09.00.10.08`).
pub fn vp09_codec_string(profile: u64, level: u64, bit_depth: u64) -> String {
    format!("vp09.{profile:02}.{level:02}.{bit_depth:02}")
}
