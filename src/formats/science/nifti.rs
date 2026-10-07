//! NIfTI-1 and NIfTI-2 neuroimaging volumes.
//!
//! A NIfTI-1 file starts with a 348-byte header (`sizeof_hdr` = 348, in the
//! file's byte order) ending in the magic `n+1` (single `.nii` file) or `ni1`
//! (`.hdr` with the voxels in a separate `.img`). NIfTI-2 is the same model
//! with a 540-byte header of 64-bit fields and the magic `n+2`/`ni2` at
//! offset 4. After the header come four "extender" bytes; a nonzero first
//! byte means header extensions follow, each `esize` (a multiple of 16,
//! counting its own 8-byte head), `ecode` and data, up to `vox_offset`. The
//! voxels start at `vox_offset`, the first dimension varying fastest.
//!
//! Field layouts, the datatype, intent, transform, unit and slice-order
//! codes follow `nifti1.h` and `nifti2.h` as we remember them; the fixtures
//! written by nibabel agree with every field shown.

use super::numarray::{Array, Elem, num};
use crate::bytes::{to_u64, u32_be, u32_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::{Head, Input, embedded};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Value, lookup};
use std::sync::Arc;

pub fn probe(h: &Head<'_>) -> bool {
    let sizeof = |n: u32| u32_le(h.data, 0) == Some(n) || u32_be(h.data, 0) == Some(n);
    (sizeof(348) && (h.at(344, b"n+1\0") || h.at(344, b"ni1\0")))
        || (sizeof(540) && (h.at(4, b"n+2\0") || h.at(4, b"ni2\0")))
}

const DATATYPES: EnumTable = &[
    (0, "unknown"),
    (1, "binary"),
    (2, "uint8"),
    (4, "int16"),
    (8, "int32"),
    (16, "float32"),
    (32, "complex64"),
    (64, "float64"),
    (128, "rgb24"),
    (256, "int8"),
    (512, "uint16"),
    (768, "uint32"),
    (1024, "int64"),
    (1280, "uint64"),
    (1536, "float128"),
    (1792, "complex128"),
    (2048, "complex256"),
    (2304, "rgba32"),
];

fn elem(datatype: u64) -> Option<Elem> {
    Some(match datatype {
        2 => Elem::U8,
        4 => Elem::I16,
        8 => Elem::I32,
        16 => Elem::F32,
        32 => Elem::C64,
        64 => Elem::F64,
        128 => Elem::Rgb24,
        256 => Elem::I8,
        512 => Elem::U16,
        768 => Elem::U32,
        1024 => Elem::I64,
        1280 => Elem::U64,
        1792 => Elem::C128,
        2304 => Elem::Rgba32,
        _ => return None,
    })
}

const INTENTS: EnumTable = &[
    (0, "none"),
    (2, "correlation coefficient"),
    (3, "t statistic"),
    (4, "F statistic"),
    (5, "z score"),
    (6, "chi-squared"),
    (7, "beta distribution"),
    (8, "binomial distribution"),
    (9, "gamma distribution"),
    (10, "Poisson distribution"),
    (11, "normal distribution"),
    (12, "noncentral F"),
    (13, "noncentral chi-squared"),
    (14, "logistic distribution"),
    (15, "Laplace distribution"),
    (16, "uniform distribution"),
    (17, "noncentral t"),
    (18, "Weibull distribution"),
    (19, "chi distribution"),
    (20, "inverse Gaussian"),
    (21, "extreme value"),
    (22, "p-value"),
    (23, "ln(p-value)"),
    (24, "log10(p-value)"),
    (1001, "estimate"),
    (1002, "label"),
    (1003, "NeuroNames label"),
    (1004, "general matrix"),
    (1005, "symmetric matrix"),
    (1006, "displacement vector"),
    (1007, "vector"),
    (1008, "point set"),
    (1009, "triangle"),
    (1010, "quaternion"),
    (1011, "dimensionless"),
    (2001, "time series"),
    (2002, "node index"),
    (2003, "RGB vector"),
    (2004, "RGBA vector"),
    (2005, "shape"),
];

const XFORMS: EnumTable = &[
    (0, "unknown"),
    (1, "scanner anatomical"),
    (2, "aligned anatomical"),
    (3, "Talairach"),
    (4, "MNI 152"),
    (5, "other template"),
];

const SLICE_CODES: EnumTable = &[
    (0, "unknown"),
    (1, "sequential increasing"),
    (2, "sequential decreasing"),
    (3, "alternating increasing"),
    (4, "alternating decreasing"),
    (5, "alternating increasing from 2"),
    (6, "alternating decreasing from 2"),
];

const EXTENSIONS: EnumTable = &[
    (0, "ignore"),
    (2, "DICOM"),
    (4, "AFNI"),
    (6, "comment"),
    (8, "XCEDE"),
    (10, "JIM dimension info"),
    (12, "workflow forwards"),
    (14, "FreeSurfer"),
    (16, "Python pickle"),
    (18, "MIND identifier"),
    (20, "b-value"),
    (22, "spherical direction"),
    (24, "DT component"),
    (26, "SHC degree/order"),
    (28, "VoxBo"),
    (30, "Caret"),
    (32, "CIFTI"),
    (34, "variable frame timing"),
    (38, "eval"),
    (40, "MATLAB"),
    (42, "Quantiphyse"),
    (44, "MRS"),
];

fn spatial_unit(code: u64) -> &'static str {
    match code & 0x07 {
        1 => "m",
        2 => "mm",
        3 => "µm",
        _ => "",
    }
}

fn temporal_unit(code: u64) -> &'static str {
    match code & 0x38 {
        8 => "s",
        16 => "ms",
        24 => "µs",
        32 => "Hz",
        40 => "ppm",
        48 => "rad/s",
        _ => "",
    }
}

fn units_summary(code: u64) -> String {
    let s = spatial_unit(code);
    let t = temporal_unit(code);
    format!(
        "space {}, time {}",
        if s.is_empty() { "unknown" } else { s },
        if t.is_empty() { "unknown" } else { t }
    )
}

fn dim_info_summary(v: u8) -> String {
    let part = |bits: u8| match bits {
        0 => "unknown".to_owned(),
        n => format!("dim {n}"),
    };
    format!(
        "frequency {}, phase {}, slice {}",
        part(v & 3),
        part((v >> 2) & 3),
        part((v >> 4) & 3)
    )
}

/// The decoded header, common to both versions (offsets are of NIfTI-1 or
/// NIfTI-2 as appropriate).
#[derive(Clone, Debug, Default)]
struct Hdr {
    version: u8,
    endian: Option<Endian>,
    single: bool,
    size: u64,
    dim: [i64; 8],
    pixdim: [f64; 8],
    intent: [f64; 3],
    intent_code: u64,
    intent_name: String,
    datatype: u64,
    bitpix: i64,
    vox_offset: f64,
    slope: f64,
    inter: f64,
    cal: (f64, f64),
    slice_code: u64,
    slice_range: (i64, i64),
    slice_duration: f64,
    toffset: f64,
    xyzt_units: u64,
    dim_info: u8,
    descrip: String,
    aux_file: String,
    qform_code: u64,
    sform_code: u64,
    quatern: [f64; 6],
    srow: [f64; 12],
}

#[derive(Clone, Copy)]
struct Raw<'a> {
    data: &'a [u8],
    endian: Endian,
}

impl Raw<'_> {
    fn bytes<const N: usize>(&self, at: usize) -> [u8; N] {
        let mut a: [u8; N] = crate::bytes::array(self.data, at).unwrap_or([0; N]);
        if self.endian == Endian::Big {
            a.reverse();
        }
        a
    }
    fn i16(&self, at: usize) -> i64 {
        i16::from_le_bytes(self.bytes(at)).into()
    }
    fn i32(&self, at: usize) -> i64 {
        i32::from_le_bytes(self.bytes(at)).into()
    }
    fn i64(&self, at: usize) -> i64 {
        i64::from_le_bytes(self.bytes(at))
    }
    fn f32(&self, at: usize) -> f64 {
        f32::from_le_bytes(self.bytes(at)).into()
    }
    fn f64(&self, at: usize) -> f64 {
        f64::from_le_bytes(self.bytes(at))
    }
    fn u8(&self, at: usize) -> u8 {
        self.data.get(at).copied().unwrap_or(0)
    }
    fn text(&self, at: usize, len: usize) -> String {
        crate::text::until_nul(
            self.data
                .get(at..at.saturating_add(len))
                .unwrap_or_default(),
        )
        .trim_end()
        .to_owned()
    }
}

fn parse(data: &[u8]) -> Option<Hdr> {
    let le = u32_le(data, 0)?;
    let be = u32_be(data, 0)?;
    let (endian, size) = match (le, be) {
        (348 | 540, _) => (Endian::Little, le),
        (_, 348 | 540) => (Endian::Big, be),
        _ => return None,
    };
    let r = Raw { data, endian };
    let mut h = Hdr {
        endian: Some(endian),
        size: size.into(),
        ..Hdr::default()
    };
    let f32x =
        |at: usize, n: usize| (0..n).map(move |i| r.f32(at.saturating_add(i.saturating_mul(4))));
    if size == 348 {
        h.version = 1;
        h.single = data.get(344..347) == Some(b"n+1");
        h.dim_info = r.u8(39);
        for (i, d) in h.dim.iter_mut().enumerate() {
            *d = r.i16(40usize.saturating_add(i.saturating_mul(2)));
        }
        for (i, p) in f32x(56, 3).enumerate() {
            if let Some(slot) = h.intent.get_mut(i) {
                *slot = p;
            }
        }
        h.intent_code = r.i16(68) as u64;
        h.datatype = r.i16(70) as u64;
        h.bitpix = r.i16(72);
        h.slice_range.0 = r.i16(74);
        for (i, p) in f32x(76, 8).enumerate() {
            if let Some(slot) = h.pixdim.get_mut(i) {
                *slot = p;
            }
        }
        h.vox_offset = r.f32(108);
        h.slope = r.f32(112);
        h.inter = r.f32(116);
        h.slice_range.1 = r.i16(120);
        h.slice_code = r.u8(122).into();
        h.xyzt_units = r.u8(123).into();
        h.cal = (r.f32(128), r.f32(124));
        h.slice_duration = r.f32(132);
        h.toffset = r.f32(136);
        h.descrip = r.text(148, 80);
        h.aux_file = r.text(228, 24);
        h.qform_code = r.i16(252) as u64;
        h.sform_code = r.i16(254) as u64;
        for (i, p) in f32x(256, 6).enumerate() {
            if let Some(slot) = h.quatern.get_mut(i) {
                *slot = p;
            }
        }
        for (i, p) in f32x(280, 12).enumerate() {
            if let Some(slot) = h.srow.get_mut(i) {
                *slot = p;
            }
        }
        h.intent_name = r.text(328, 16);
    } else {
        h.version = 2;
        h.single = data.get(4..7) == Some(b"n+2");
        h.datatype = r.i16(12) as u64;
        h.bitpix = r.i16(14);
        let f64x = |at: usize, n: usize| {
            (0..n).map(move |i| r.f64(at.saturating_add(i.saturating_mul(8))))
        };
        for (i, d) in h.dim.iter_mut().enumerate() {
            *d = r.i64(16usize.saturating_add(i.saturating_mul(8)));
        }
        for (i, p) in f64x(80, 3).enumerate() {
            if let Some(slot) = h.intent.get_mut(i) {
                *slot = p;
            }
        }
        for (i, p) in f64x(104, 8).enumerate() {
            if let Some(slot) = h.pixdim.get_mut(i) {
                *slot = p;
            }
        }
        h.vox_offset = r.i64(168) as f64;
        h.slope = r.f64(176);
        h.inter = r.f64(184);
        h.cal = (r.f64(200), r.f64(192));
        h.slice_duration = r.f64(208);
        h.toffset = r.f64(216);
        h.slice_range = (r.i64(224), r.i64(232));
        h.descrip = r.text(240, 80);
        h.aux_file = r.text(320, 24);
        h.qform_code = r.i32(344) as u64;
        h.sform_code = r.i32(348) as u64;
        for (i, p) in f64x(352, 6).enumerate() {
            if let Some(slot) = h.quatern.get_mut(i) {
                *slot = p;
            }
        }
        for (i, p) in f64x(400, 12).enumerate() {
            if let Some(slot) = h.srow.get_mut(i) {
                *slot = p;
            }
        }
        h.slice_code = r.i32(496) as u64;
        h.xyzt_units = r.i32(500) as u64;
        h.intent_code = r.i32(504) as u64;
        h.intent_name = r.text(508, 16);
        h.dim_info = r.u8(524);
    }
    Some(h)
}

impl Hdr {
    /// The used dimensions (`dim[1..=dim[0]]`).
    fn dims(&self) -> Vec<u64> {
        let rank = usize::try_from(self.dim[0].clamp(0, 7)).unwrap_or(0);
        self.dim
            .get(1..=rank)
            .unwrap_or_default()
            .iter()
            .map(|&d| u64::try_from(d.max(0)).unwrap_or(0))
            .collect()
    }

    fn voxels(&self) -> u64 {
        self.dims().iter().fold(1u64, |a, &d| a.saturating_mul(d))
    }

    /// Bytes per voxel: from the datatype, or `bitpix` for types we do not
    /// decode.
    fn voxel_bytes(&self) -> u64 {
        elem(self.datatype).map_or_else(
            || u64::try_from(self.bitpix.max(0)).unwrap_or(0) / 8,
            Elem::size,
        )
    }

    fn shape(&self) -> String {
        let dims: Vec<String> = self.dims().iter().map(u64::to_string).collect();
        dims.join("×")
    }

    fn voxel_size(&self) -> String {
        let rank = usize::try_from(self.dim[0].clamp(0, 7)).unwrap_or(0);
        let spatial: Vec<String> = self
            .pixdim
            .get(1..=rank.min(3))
            .unwrap_or_default()
            .iter()
            .map(|&p| num(p))
            .collect();
        if self
            .pixdim
            .get(1..=rank.min(3))
            .unwrap_or_default()
            .iter()
            .all(|&p| p == 0.0)
        {
            return String::new();
        }
        let mut s = spatial.join("×");
        let unit = spatial_unit(self.xyzt_units);
        if !unit.is_empty() {
            s.push(' ');
            s.push_str(unit);
        }
        if rank >= 4 {
            let t = self.pixdim[4];
            let unit = temporal_unit(self.xyzt_units);
            s.push_str(&format!(
                ", {} {}{}",
                if unit == "s" || unit == "ms" || unit == "µs" {
                    "TR"
                } else {
                    "step"
                },
                num(t),
                if unit.is_empty() {
                    String::new()
                } else {
                    format!(" {unit}")
                }
            ));
        }
        s
    }

    fn type_name(&self) -> String {
        lookup(DATATYPES, self.datatype)
            .map_or_else(|| format!("datatype {}", self.datatype), str::to_owned)
    }

    /// The qform matrix (rows of the 3×4 affine) from the quaternion.
    fn qform_matrix(&self) -> [[f64; 4]; 3] {
        let [b, c, d, x, y, z] = self.quatern;
        let a = (1.0 - (b * b + c * c + d * d)).max(0.0).sqrt();
        let r = [
            [
                a * a + b * b - c * c - d * d,
                2.0 * (b * c - a * d),
                2.0 * (b * d + a * c),
            ],
            [
                2.0 * (b * c + a * d),
                a * a + c * c - b * b - d * d,
                2.0 * (c * d - a * b),
            ],
            [
                2.0 * (b * d - a * c),
                2.0 * (c * d + a * b),
                a * a + d * d - c * c - b * b,
            ],
        ];
        let qfac = if self.pixdim[0] < 0.0 { -1.0 } else { 1.0 };
        let scale = [self.pixdim[1], self.pixdim[2], self.pixdim[3] * qfac];
        let offset = [x, y, z];
        let mut m = [[0.0; 4]; 3];
        for (row, (rr, o)) in m.iter_mut().zip(r.iter().zip(offset)) {
            for (cell, (v, s)) in row.iter_mut().zip(rr.iter().zip(scale)) {
                *cell = v * s;
            }
            row[3] = o;
        }
        m
    }
}

fn matrix_row(row: &[f64]) -> String {
    let cells: Vec<String> = row.iter().map(|&v| num(v)).collect();
    format!("[{}]", cells.join(", "))
}

const DIM_NAMES: [&str; 8] = [
    "dim[0] (rank)",
    "dim[1]",
    "dim[2]",
    "dim[3]",
    "dim[4]",
    "dim[5]",
    "dim[6]",
    "dim[7]",
];
const PIXDIM_NAMES: [&str; 8] = [
    "pixdim[0] (qfac)",
    "pixdim[1]",
    "pixdim[2]",
    "pixdim[3]",
    "pixdim[4]",
    "pixdim[5]",
    "pixdim[6]",
    "pixdim[7]",
];
const SROW_NAMES: [&str; 12] = [
    "srow_x[0]",
    "srow_x[1]",
    "srow_x[2]",
    "srow_x[3]",
    "srow_y[0]",
    "srow_y[1]",
    "srow_y[2]",
    "srow_y[3]",
    "srow_z[0]",
    "srow_z[1]",
    "srow_z[2]",
    "srow_z[3]",
];

fn header1(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.i32("sizeof_hdr").emit()?;
    f.ascii("data_type (unused)", 10).emit()?;
    f.ascii("db_name (unused)", 18).emit()?;
    f.i32("extents (unused)").emit()?;
    f.int::<i16>("session_error (unused)").emit()?;
    f.u8("regular (unused)").emit()?;
    f.u8("dim_info")
        .hex()
        .with(|&v, n| n.summary(dim_info_summary(v)))
        .emit()?;
    for name in DIM_NAMES {
        f.int::<i16>(name).emit()?;
    }
    f.f32("intent_p1").emit()?;
    f.f32("intent_p2").emit()?;
    f.f32("intent_p3").emit()?;
    f.int::<i16>("intent_code").enumeration(INTENTS).emit()?;
    f.int::<i16>("datatype").enumeration(DATATYPES).emit()?;
    f.int::<i16>("bitpix").emit()?;
    f.int::<i16>("slice_start").emit()?;
    for name in PIXDIM_NAMES {
        f.f32(name).emit()?;
    }
    f.f32("vox_offset")
        .desc("Byte offset of the voxel data")
        .emit()?;
    f.f32("scl_slope").emit()?;
    f.f32("scl_inter").emit()?;
    f.int::<i16>("slice_end").emit()?;
    f.u8("slice_code").enumeration(SLICE_CODES).emit()?;
    f.u8("xyzt_units")
        .hex()
        .with(|&v, n| n.summary(units_summary(v.into())))
        .emit()?;
    f.f32("cal_max").emit()?;
    f.f32("cal_min").emit()?;
    f.f32("slice_duration").emit()?;
    f.f32("toffset").emit()?;
    f.i32("glmax (unused)").emit()?;
    f.i32("glmin (unused)").emit()?;
    f.ascii("descrip", 80).emit()?;
    f.ascii("aux_file", 24).emit()?;
    f.int::<i16>("qform_code").enumeration(XFORMS).emit()?;
    f.int::<i16>("sform_code").enumeration(XFORMS).emit()?;
    f.f32("quatern_b").emit()?;
    f.f32("quatern_c").emit()?;
    f.f32("quatern_d").emit()?;
    f.f32("qoffset_x").emit()?;
    f.f32("qoffset_y").emit()?;
    f.f32("qoffset_z").emit()?;
    for name in SROW_NAMES {
        f.f32(name).emit()?;
    }
    f.ascii("intent_name", 16).emit()?;
    f.ascii("magic", 4).emit()?;
    Ok(())
}

fn header2(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.i32("sizeof_hdr").emit()?;
    f.bytes("magic", 8).emit()?;
    f.int::<i16>("datatype").enumeration(DATATYPES).emit()?;
    f.int::<i16>("bitpix").emit()?;
    for name in DIM_NAMES {
        f.int::<i64>(name).emit()?;
    }
    f.f64("intent_p1").emit()?;
    f.f64("intent_p2").emit()?;
    f.f64("intent_p3").emit()?;
    for name in PIXDIM_NAMES {
        f.f64(name).emit()?;
    }
    f.int::<i64>("vox_offset")
        .desc("Byte offset of the voxel data")
        .emit()?;
    f.f64("scl_slope").emit()?;
    f.f64("scl_inter").emit()?;
    f.f64("cal_max").emit()?;
    f.f64("cal_min").emit()?;
    f.f64("slice_duration").emit()?;
    f.f64("toffset").emit()?;
    f.int::<i64>("slice_start").emit()?;
    f.int::<i64>("slice_end").emit()?;
    f.ascii("descrip", 80).emit()?;
    f.ascii("aux_file", 24).emit()?;
    f.i32("qform_code").enumeration(XFORMS).emit()?;
    f.i32("sform_code").enumeration(XFORMS).emit()?;
    f.f64("quatern_b").emit()?;
    f.f64("quatern_c").emit()?;
    f.f64("quatern_d").emit()?;
    f.f64("qoffset_x").emit()?;
    f.f64("qoffset_y").emit()?;
    f.f64("qoffset_z").emit()?;
    for name in SROW_NAMES {
        f.f64(name).emit()?;
    }
    f.i32("slice_code").enumeration(SLICE_CODES).emit()?;
    f.i32("xyzt_units")
        .hex()
        .with(|&v, n| n.summary(units_summary(u64::try_from(v).unwrap_or(0))))
        .emit()?;
    f.i32("intent_code").enumeration(INTENTS).emit()?;
    f.ascii("intent_name", 16).emit()?;
    f.u8("dim_info")
        .hex()
        .with(|&v, n| n.summary(dim_info_summary(v)))
        .emit()?;
    f.bytes("unused_str", 15).emit()?;
    Ok(())
}

/// Offsets of a few fields, for the spans of the summary nodes.
struct Layout {
    dim: (u64, u64),
    pixdim: (u64, u64),
    datatype: u64,
    intent_code: (u64, u64),
    scl: (u64, u64),
    cal: (u64, u64),
    slice_code: (u64, u64),
    qform: (u64, u64),
    sform: (u64, u64),
    quatern: (u64, u64),
    srow: (u64, u64),
    descrip: u64,
    aux_file: u64,
    toffset: (u64, u64),
}

const LAYOUT1: Layout = Layout {
    dim: (40, 16),
    pixdim: (76, 32),
    datatype: 70,
    intent_code: (68, 2),
    scl: (112, 8),
    cal: (124, 8),
    slice_code: (122, 1),
    qform: (252, 2),
    sform: (254, 2),
    quatern: (256, 24),
    srow: (280, 48),
    descrip: 148,
    aux_file: 228,
    toffset: (136, 4),
};

const LAYOUT2: Layout = Layout {
    dim: (16, 64),
    pixdim: (104, 64),
    datatype: 12,
    intent_code: (504, 4),
    scl: (176, 16),
    cal: (192, 16),
    slice_code: (496, 4),
    qform: (344, 4),
    sform: (348, 4),
    quatern: (352, 48),
    srow: (400, 96),
    descrip: 240,
    aux_file: 320,
    toffset: (216, 8),
};

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 540)).await?;
    let h = parse(&head).ok_or_else(|| Diagnostic::malformed("not a NIfTI header"))?;
    let endian = h.endian.unwrap_or(Endian::Little);
    let at = |(off, len): (u64, u64)| file.sub(off, len);
    let l = if h.version == 1 { &LAYOUT1 } else { &LAYOUT2 };
    let header_span = file.sub(0, h.size);
    let header = if h.version == 1 {
        struct_node("Header", header_span, endian, (), header1)
    } else {
        struct_node("Header", header_span, endian, (), header2)
    };
    cx.emit(header.summary(format!(
        "NIfTI-{}, {} bytes, {}",
        h.version,
        h.size,
        if endian == Endian::Big {
            "big-endian"
        } else {
            "little-endian"
        }
    )));
    if head.len() < usize::try_from(h.size).unwrap_or(usize::MAX) {
        return Err(Diagnostic::truncated(header_span, to_u64(head.len())));
    }

    let rank = h.dim[0];
    let mut dims_node = Node::new("Dimensions")
        .span(at(l.dim))
        .value(Value::Text(h.shape()))
        .summary(format!("rank {rank}, {} voxels", h.voxels()));
    if !(1..=7).contains(&rank) {
        dims_node = dims_node.diag(Diagnostic::malformed(format!("dim[0] = {rank}")));
    }
    cx.emit(dims_node);
    cx.emit(
        Node::new("Voxel size")
            .span(at(l.pixdim))
            .value(Value::Text(h.voxel_size()))
            .summary(units_summary(h.xyzt_units)),
    );
    let mut type_node = Node::new("Data type")
        .span(file.sub(l.datatype, 4))
        .value(Value::Enum {
            raw: h.datatype,
            bits: 16,
            name: lookup(DATATYPES, h.datatype),
        })
        .summary(format!("{} bits per voxel", h.bitpix));
    if elem(h.datatype)
        .is_some_and(|e| e.size().saturating_mul(8) != u64::try_from(h.bitpix).unwrap_or(0))
    {
        type_node = type_node.diag(Diagnostic::warning(format!(
            "bitpix {} does not match the datatype",
            h.bitpix
        )));
    }
    cx.emit(type_node);
    if h.intent_code != 0 || !h.intent_name.is_empty() {
        let params: Vec<String> = h.intent.iter().map(|&p| num(p)).collect();
        cx.emit(
            Node::new("Intent")
                .span(at(l.intent_code))
                .value(Value::Enum {
                    raw: h.intent_code,
                    bits: 16,
                    name: lookup(INTENTS, h.intent_code),
                })
                .summary(format!(
                    "parameters {}{}",
                    params.join(", "),
                    if h.intent_name.is_empty() {
                        String::new()
                    } else {
                        format!(", name {:?}", h.intent_name)
                    }
                )),
        );
    }
    let scaled = h.slope != 0.0 && (h.slope != 1.0 || h.inter != 0.0);
    if scaled {
        cx.emit(
            Node::new("Scaling")
                .span(at(l.scl))
                .value(Value::Text(format!(
                    "value × {} + {}",
                    num(h.slope),
                    num(h.inter)
                ))),
        );
    }
    if h.cal != (0.0, 0.0) {
        cx.emit(
            Node::new("Display range")
                .span(at(l.cal))
                .value(Value::Text(format!("{} … {}", num(h.cal.0), num(h.cal.1)))),
        );
    }
    if h.slice_code != 0 || h.slice_duration != 0.0 {
        let slice_dim = (h.dim_info >> 4) & 3;
        cx.emit(
            Node::new("Slice timing")
                .span(at(l.slice_code))
                .value(Value::Enum {
                    raw: h.slice_code,
                    bits: 8,
                    name: lookup(SLICE_CODES, h.slice_code),
                })
                .summary(format!(
                    "slices {}–{}, {} {} each{}",
                    h.slice_range.0,
                    h.slice_range.1,
                    num(h.slice_duration),
                    temporal_unit(h.xyzt_units),
                    if slice_dim == 0 {
                        String::new()
                    } else {
                        format!(", slice dimension {slice_dim}")
                    }
                )),
        );
    }
    if h.toffset != 0.0 {
        cx.emit(
            Node::new("Time offset")
                .span(at(l.toffset))
                .value(Value::Float(h.toffset)),
        );
    }
    for (name, code, code_span, matrix, matrix_span) in [
        ("qform", h.qform_code, l.qform, h.qform_matrix(), l.quatern),
        (
            "sform",
            h.sform_code,
            l.sform,
            [
                [h.srow[0], h.srow[1], h.srow[2], h.srow[3]],
                [h.srow[4], h.srow[5], h.srow[6], h.srow[7]],
                [h.srow[8], h.srow[9], h.srow[10], h.srow[11]],
            ],
            l.srow,
        ),
    ] {
        let mut node = Node::new(name).span(at(code_span)).value(Value::Enum {
            raw: code,
            bits: 16,
            name: lookup(XFORMS, code),
        });
        if code != 0 {
            let rows: Vec<String> = matrix.iter().map(|r| matrix_row(r)).collect();
            node = node.summary(rows.join(" ")).lazy(
                transform,
                (at(matrix_span), matrix, name == "qform", h.quatern),
            );
        }
        cx.emit(node);
    }
    if !h.descrip.is_empty() {
        cx.emit(
            Node::new("Description")
                .span(file.sub(l.descrip, 80))
                .value(Value::Text(h.descrip.clone())),
        );
    }
    if !h.aux_file.is_empty() {
        cx.emit(
            Node::new("Auxiliary file")
                .span(file.sub(l.aux_file, 24))
                .value(Value::Text(h.aux_file.clone())),
        );
    }

    // Extensions: an extender after the header, then esize/ecode records up
    // to the voxel data (or the end of a .hdr).
    let ext_at = h.size;
    let vox_offset = if h.vox_offset.is_finite() && h.vox_offset >= 0.0 {
        h.vox_offset as u64
    } else {
        0
    };
    let ext_end = if h.single {
        vox_offset.min(file.len)
    } else {
        file.len
    };
    let mut extensions = 0u32;
    if file.len >= ext_at.saturating_add(4) {
        let extender = cx.read(file.sub(ext_at, 4)).await?;
        let present = extender.first().copied().unwrap_or(0) != 0;
        let span = file.sub(
            ext_at.saturating_add(4),
            ext_end.saturating_sub(ext_at.saturating_add(4)),
        );
        if present {
            extensions = count_extensions(&cx, span, endian).await;
            cx.emit(
                Node::new("Extensions")
                    .span(file.sub(ext_at, ext_end.saturating_sub(ext_at)))
                    .summary(format!("{extensions} extension(s)"))
                    .lazy(extension_list, (input, span, endian)),
            );
        } else {
            cx.emit(
                Node::new("Extensions")
                    .span(file.sub(ext_at, 4))
                    .value(Value::Bytes(extender))
                    .summary("none"),
            );
        }
    }

    let mut voxel_summary = String::new();
    if h.single {
        let len = h.voxels().saturating_mul(h.voxel_bytes());
        let span = file.sub(vox_offset, len);
        if vox_offset < ext_at {
            cx.emit(
                Node::new("Voxel data")
                    .span(span)
                    .diag(Diagnostic::malformed(format!(
                        "vox_offset {vox_offset} inside the header"
                    ))),
            );
        } else if let Some(el) = elem(h.datatype) {
            let array = Array {
                span,
                elem: el,
                endian,
                dims: Arc::new(h.dims()),
                row_major: false,
                scale: scaled.then_some((h.slope, h.inter)),
            };
            cx.emit(array.node("Voxel data"));
        } else {
            cx.emit(
                Node::new("Voxel data")
                    .span(span)
                    .diag(Diagnostic::unsupported(format!(
                        "voxel type {}",
                        h.type_name()
                    ))),
            );
        }
        let rest = vox_offset.saturating_add(len);
        if rest < file.len {
            cx.emit(Node::new("Trailing data").span(file.tail(rest)));
        }
    } else {
        voxel_summary = ", voxels in the .img file".to_owned();
        cx.emit(
            Node::new("Voxel data")
                .summary(format!(
                    "{} bytes in the companion .img file, from offset {vox_offset}",
                    h.voxels().saturating_mul(h.voxel_bytes())
                ))
                .value(Value::Text(String::from("separate file"))),
        );
    }

    let mut summary = format!(
        "NIfTI-{}{}, {} {}",
        h.version,
        if h.single { "" } else { " header" },
        h.shape(),
        h.type_name(),
    );
    let size = h.voxel_size();
    if !size.is_empty() {
        summary.push_str(&format!(", {size}"));
    }
    if let Some(intent) = lookup(INTENTS, h.intent_code).filter(|_| h.intent_code != 0) {
        summary.push_str(&format!(", {intent}"));
    }
    if extensions > 0 {
        summary.push_str(&format!(", {extensions} extension(s)"));
    }
    if !h.descrip.is_empty() {
        summary.push_str(&format!(", {:?}", h.descrip));
    }
    summary.push_str(&voxel_summary);
    cx.annotate(summary);
    Ok(())
}

async fn transform(
    cx: Cx,
    (span, matrix, quaternion, quatern): (Span, [[f64; 4]; 3], bool, [f64; 6]),
) -> Result<()> {
    if quaternion {
        let [b, c, d, x, y, z] = quatern;
        cx.emit(
            Node::new("Quaternion (b, c, d)")
                .span(span.sub(0, span.len / 2))
                .value(Value::Text(format!("{}, {}, {}", num(b), num(c), num(d)))),
        );
        cx.emit(
            Node::new("Offset (x, y, z)")
                .span(span.sub(span.len / 2, span.len / 2))
                .value(Value::Text(format!("{}, {}, {}", num(x), num(y), num(z)))),
        );
    }
    let row_len = if quaternion { 0 } else { span.len / 3 };
    for (i, (name, row)) in ["x", "y", "z"].iter().zip(matrix.iter()).enumerate() {
        let mut node = Node::new(format!("Row {name}")).value(Value::Text(matrix_row(row)));
        if row_len > 0 {
            node = node.span(span.sub(to_u64(i).saturating_mul(row_len), row_len));
        }
        cx.emit(node);
    }
    Ok(())
}

const MAX_EXTENSIONS: u32 = 10_000;

async fn count_extensions(cx: &Cx, span: Span, endian: Endian) -> u32 {
    let mut pos = 0u64;
    let mut n = 0u32;
    while pos.saturating_add(8) <= span.len && n < MAX_EXTENSIONS {
        let Ok(head) = cx.read(span.sub(pos, 8)).await else {
            break;
        };
        let esize = word(&head, 0, endian);
        if esize < 8 {
            break;
        }
        n = n.saturating_add(1);
        pos = pos.saturating_add(esize.into());
    }
    n
}

fn word(data: &[u8], at: usize, endian: Endian) -> u32 {
    if endian == Endian::Big {
        u32_be(data, at)
    } else {
        u32_le(data, at)
    }
    .unwrap_or(0)
}

async fn extension_list(cx: Cx, (input, span, endian): (Input, Span, Endian)) -> Result<()> {
    let mut pos = 0u64;
    let mut index = 0u32;
    while pos.saturating_add(8) <= span.len && index < MAX_EXTENSIONS {
        let head = cx.read(span.sub(pos, 8)).await?;
        let esize = u64::from(word(&head, 0, endian));
        let ecode = u64::from(word(&head, 4, endian));
        if esize < 8 {
            cx.diag(Diagnostic::malformed(format!("extension size {esize}")).at(span.sub(pos, 4)));
            break;
        }
        let ext = span.sub(pos, esize);
        let data = ext.tail(8);
        let mut node = Node::new(format!("Extension {index}"))
            .span(ext)
            .value(Value::Enum {
                raw: ecode,
                bits: 32,
                name: lookup(EXTENSIONS, ecode),
            })
            .summary(format!("{esize} bytes"));
        if ext.len < esize {
            node = node.diag(Diagnostic::truncated(
                Span::new(span.source, ext.offset, esize),
                ext.len,
            ));
        } else if esize % 16 != 0 {
            node = node.diag(Diagnostic::warning(format!(
                "esize {esize} is not a multiple of 16"
            )));
        }
        node = node.lazy(extension, (input, data, ecode, esize));
        cx.push(node).await;
        index = index.saturating_add(1);
        pos = pos.saturating_add(esize);
    }
    Ok(())
}

async fn extension(cx: Cx, (input, data, ecode, esize): (Input, Span, u64, u64)) -> Result<()> {
    cx.emit(
        Node::new("esize")
            .span(Span::new(data.source, data.offset.saturating_sub(8), 4))
            .value(Value::UInt {
                value: esize,
                bits: 32,
                radix: crate::value::Radix::Dec,
            }),
    );
    cx.emit(
        Node::new("ecode")
            .span(Span::new(data.source, data.offset.saturating_sub(4), 4))
            .value(Value::Enum {
                raw: ecode,
                bits: 32,
                name: lookup(EXTENSIONS, ecode),
            }),
    );
    // Text payloads (comments, AFNI and CIFTI XML, XCEDE, MATLAB/eval
    // strings) are NUL-padded to the 16-byte boundary.
    let preview = cx.read_avail(data.sub(0, 4096)).await?;
    let used = preview
        .iter()
        .rposition(|&b| b != 0)
        .map_or(0, |p| p.saturating_add(1));
    let body = if data.len > 4096 {
        data
    } else {
        data.sub(0, to_u64(used))
    };
    let texty = matches!(ecode, 4 | 6 | 8 | 32 | 38 | 40)
        && crate::text::looks_like_text(preview.get(..used).unwrap_or_default());
    if texty && ecode == 6 {
        cx.emit(Node::new("Text").span(body).value(Value::Text(
            String::from_utf8_lossy(preview.get(..used).unwrap_or_default()).into_owned(),
        )));
    } else {
        cx.emit(embedded("Data", input.nested(body)));
    }
    if body.len < data.len {
        cx.emit(Node::new("Padding").span(data.tail(body.len)));
    }
    Ok(())
}
