//! Code points shared by the video codecs: ITU-T H.273 colour description,
//! sample aspect ratios, NAL unit types and profiles.

use crate::value::EnumTable;

pub fn lookup_or(table: EnumTable, raw: u64) -> String {
    crate::value::lookup(table, raw).map_or_else(|| format!("{raw}"), str::to_owned)
}

// ---------------------------------------------------------------------------
// Colour description (ITU-T H.273 code points)

pub const COLOUR_PRIMARIES: EnumTable = &[
    (0, "reserved"),
    (1, "BT.709"),
    (2, "unspecified"),
    (4, "BT.470 M"),
    (5, "BT.470 BG"),
    (6, "SMPTE 170M"),
    (7, "SMPTE 240M"),
    (8, "generic film"),
    (9, "BT.2020"),
    (10, "SMPTE ST 428-1"),
    (11, "DCI-P3"),
    (12, "Display P3"),
    (22, "EBU Tech. 3213-E"),
];

pub const TRANSFER_CHARACTERISTICS: EnumTable = &[
    (0, "reserved"),
    (1, "BT.709"),
    (2, "unspecified"),
    (4, "gamma 2.2"),
    (5, "gamma 2.8"),
    (6, "SMPTE 170M"),
    (7, "SMPTE 240M"),
    (8, "linear"),
    (9, "log 100:1"),
    (10, "log 316:1"),
    (11, "IEC 61966-2-4"),
    (12, "BT.1361"),
    (13, "sRGB"),
    (14, "BT.2020 10-bit"),
    (15, "BT.2020 12-bit"),
    (16, "PQ (SMPTE ST 2084)"),
    (17, "SMPTE ST 428-1"),
    (18, "HLG (ARIB STD-B67)"),
];

pub const MATRIX_COEFFICIENTS: EnumTable = &[
    (0, "identity (RGB)"),
    (1, "BT.709"),
    (2, "unspecified"),
    (4, "FCC"),
    (5, "BT.470 BG"),
    (6, "SMPTE 170M"),
    (7, "SMPTE 240M"),
    (8, "YCgCo"),
    (9, "BT.2020 non-constant"),
    (10, "BT.2020 constant"),
    (11, "SMPTE ST 2085"),
    (12, "chromaticity non-constant"),
    (13, "chromaticity constant"),
    (14, "ICtCp"),
];

/// `video_format` of H.264/HEVC VUI.
pub const VIDEO_FORMATS: EnumTable = &[
    (0, "component"),
    (1, "PAL"),
    (2, "NTSC"),
    (3, "SECAM"),
    (4, "MAC"),
    (5, "unspecified"),
];

pub const CHROMA_FORMATS: EnumTable =
    &[(0, "monochrome"), (1, "4:2:0"), (2, "4:2:2"), (3, "4:4:4")];

/// `aspect_ratio_idc` (H.264 Table E-1, HEVC Table E.1).
pub const ASPECT_RATIO_IDC: EnumTable = &[
    (0, "unspecified"),
    (1, "1:1"),
    (2, "12:11"),
    (3, "10:11"),
    (4, "16:11"),
    (5, "40:33"),
    (6, "24:11"),
    (7, "20:11"),
    (8, "32:11"),
    (9, "80:33"),
    (10, "18:11"),
    (11, "15:11"),
    (12, "64:33"),
    (13, "160:99"),
    (14, "4:3"),
    (15, "3:2"),
    (16, "2:1"),
    (255, "extended SAR"),
];

/// The sample aspect ratio an `aspect_ratio_idc` stands for.
pub fn sar_of(idc: u64) -> Option<(u64, u64)> {
    Some(match idc {
        1 => (1, 1),
        2 => (12, 11),
        3 => (10, 11),
        4 => (16, 11),
        5 => (40, 33),
        6 => (24, 11),
        7 => (20, 11),
        8 => (32, 11),
        9 => (80, 33),
        10 => (18, 11),
        11 => (15, 11),
        12 => (64, 33),
        13 => (160, 99),
        14 => (4, 3),
        15 => (3, 2),
        16 => (2, 1),
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// NAL unit types

pub const H264_NAL_TYPES: EnumTable = &[
    (1, "Coded slice (non-IDR)"),
    (2, "Slice data partition A"),
    (3, "Slice data partition B"),
    (4, "Slice data partition C"),
    (5, "Coded slice (IDR)"),
    (6, "SEI"),
    (7, "Sequence parameter set"),
    (8, "Picture parameter set"),
    (9, "Access unit delimiter"),
    (10, "End of sequence"),
    (11, "End of stream"),
    (12, "Filler data"),
    (13, "SPS extension"),
    (14, "Prefix NAL unit"),
    (15, "Subset SPS"),
    (16, "Depth parameter set"),
    (19, "Auxiliary slice"),
    (20, "Coded slice extension"),
    (21, "Depth/3D-AVC slice extension"),
];

pub const HEVC_NAL_TYPES: EnumTable = &[
    (0, "TRAIL_N"),
    (1, "TRAIL_R"),
    (2, "TSA_N"),
    (3, "TSA_R"),
    (4, "STSA_N"),
    (5, "STSA_R"),
    (6, "RADL_N"),
    (7, "RADL_R"),
    (8, "RASL_N"),
    (9, "RASL_R"),
    (16, "BLA_W_LP"),
    (17, "BLA_W_RADL"),
    (18, "BLA_N_LP"),
    (19, "IDR_W_RADL"),
    (20, "IDR_N_LP"),
    (21, "CRA_NUT"),
    (32, "Video parameter set"),
    (33, "Sequence parameter set"),
    (34, "Picture parameter set"),
    (35, "Access unit delimiter"),
    (36, "End of sequence"),
    (37, "End of bitstream"),
    (38, "Filler data"),
    (39, "SEI (prefix)"),
    (40, "SEI (suffix)"),
];

pub const VVC_NAL_TYPES: EnumTable = &[
    (0, "TRAIL_NUT"),
    (1, "STSA_NUT"),
    (2, "RADL_NUT"),
    (3, "RASL_NUT"),
    (7, "IDR_W_RADL"),
    (8, "IDR_N_LP"),
    (9, "CRA_NUT"),
    (10, "GDR_NUT"),
    (12, "Operating point information"),
    (13, "Decoding capability information"),
    (14, "Video parameter set"),
    (15, "Sequence parameter set"),
    (16, "Picture parameter set"),
    (17, "Adaptation parameter set (prefix)"),
    (18, "Adaptation parameter set (suffix)"),
    (19, "Picture header"),
    (20, "Access unit delimiter"),
    (21, "End of sequence"),
    (22, "End of bitstream"),
    (23, "SEI (prefix)"),
    (24, "SEI (suffix)"),
    (25, "Filler data"),
];

// ---------------------------------------------------------------------------
// Profiles

pub const H264_PROFILES: EnumTable = &[
    (44, "CAVLC 4:4:4 Intra"),
    (66, "Baseline"),
    (77, "Main"),
    (83, "Scalable Baseline"),
    (86, "Scalable High"),
    (88, "Extended"),
    (100, "High"),
    (110, "High 10"),
    (118, "Multiview High"),
    (122, "High 4:2:2"),
    (128, "Stereo High"),
    (134, "MFC High"),
    (135, "MFC Depth High"),
    (138, "Multiview Depth High"),
    (139, "Enhanced Multiview Depth High"),
    (244, "High 4:4:4 Predictive"),
];

pub const HEVC_PROFILES: EnumTable = &[
    (1, "Main"),
    (2, "Main 10"),
    (3, "Main Still Picture"),
    (4, "Range extensions"),
    (5, "High throughput"),
    (6, "Multiview Main"),
    (7, "Scalable Main"),
    (8, "3D Main"),
    (9, "Screen content coding"),
    (10, "Scalable range extensions"),
    (11, "High throughput SCC"),
];

/// The H.264 profile name, refined by the constraint flags (Constrained
/// Baseline, Progressive/Constrained High, the Intra profiles).
pub fn h264_profile_name(profile: u8, constraints: u8) -> String {
    let set = |n: u8| constraints & (0x80 >> n) != 0;
    match profile {
        66 if set(1) => "Constrained Baseline".to_owned(),
        100 if set(4) && set(5) => "Constrained High".to_owned(),
        100 if set(4) => "Progressive High".to_owned(),
        110 if set(3) => "High 10 Intra".to_owned(),
        122 if set(3) => "High 4:2:2 Intra".to_owned(),
        244 if set(3) => "High 4:4:4 Intra".to_owned(),
        _ => crate::value::lookup(H264_PROFILES, profile.into())
            .map_or_else(|| format!("profile {profile}"), str::to_owned),
    }
}

/// An H.264 `level_idc` as a level number ("3.1", "1b").
pub fn h264_level_name(profile: u8, constraints: u8, level: u8) -> String {
    if level == 9 || (level == 11 && constraints & 0x10 != 0 && matches!(profile, 66 | 77 | 88)) {
        return "1b".to_owned();
    }
    format!("{}.{}", level / 10, level % 10)
}

/// An HEVC `general_level_idc` (30 × level) as a level number.
pub fn hevc_level_name(level: u8) -> String {
    let tenth = level / 3;
    if tenth.is_multiple_of(10) {
        format!("{}", tenth / 10)
    } else {
        format!("{}.{}", tenth / 10, tenth % 10)
    }
}

/// Bits needed to code values below `n` (`Ceil(Log2(n))`).
pub fn ceil_log2(n: u64) -> u32 {
    if n <= 1 {
        0
    } else {
        64u32.saturating_sub(n.saturating_sub(1).leading_zeros())
    }
}

/// `n` / `d` as a frame rate ("25", "23.976", "29.97").
pub fn rate(n: u64, d: u64) -> String {
    if d == 0 {
        return "?".to_owned();
    }
    if n.checked_rem(d) == Some(0) {
        return format!("{}", n.checked_div(d).unwrap_or(0));
    }
    let v = n as f64 / d as f64;
    let s = format!("{v:.3}");
    let s = s.trim_end_matches('0').trim_end_matches('.');
    s.to_owned()
}

/// Reduces a ratio by its greatest common divisor.
pub fn reduce(a: u64, b: u64) -> (u64, u64) {
    let (mut x, mut y) = (a, b);
    while let Some(r) = x.checked_rem(y) {
        x = y;
        y = r;
    }
    match (a.checked_div(x), b.checked_div(x)) {
        (Some(p), Some(q)) => (p, q),
        _ => (a, b),
    }
}
