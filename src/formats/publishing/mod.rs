//! Desktop publishing, graphic design, illustration, multimedia authoring,
//! font development and printer files.
//!
//! - [`adobe`]: Photoshop presets (brushes, patterns, gradients, styles,
//!   actions, curves, colour books, colour tables, custom shapes) and the
//!   action descriptor structure most of them share.
//! - [`dtp`]: page-layout documents (InDesign, QuarkXPress, Xara, Scribus)
//!   and XMP sidecars.
//! - [`authoring`]: Director/Shockwave movies, HyperCard stacks, After
//!   Effects projects, Corel CMX, Figma, Rive, Live2D.
//! - [`design`]: pixel-art and paint-program images, palettes, gradients,
//!   colour lookup tables, metafiles (CGM, PICT) and GEM bitmaps.
//! - [`fonts`]: font sources and font binaries not covered elsewhere (CFF,
//!   FontForge, Glyphs, FontLab, Windows FNT/PFM, TeX TFM/VF, Amiga, PFR,
//!   BGI, UFO).
//! - [`printing`]: printer languages and descriptions (PJL, PCL, PCL XL,
//!   HP-GL, ESC/P, ZPL, PPD, GPD, CUPS and Apple raster).

pub mod adobe;
pub mod authoring;
pub mod design;
pub mod dtp;
pub mod fonts;
pub mod printing;

use crate::fields::Endian;
use crate::value::{Radix, Value};

pub(crate) fn text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

pub(crate) fn uint(value: impl Into<u64>, bits: u8) -> Value {
    Value::UInt { value: value.into(), bits, radix: Radix::Dec }
}

pub(crate) fn hex(value: impl Into<u64>, bits: u8) -> Value {
    Value::UInt { value: value.into(), bits, radix: Radix::Hex }
}

pub(crate) fn int(value: impl Into<i64>, bits: u8) -> Value {
    Value::Int { value: value.into(), bits }
}

/// A four-character code as text (lossy).
pub(crate) fn fourcc(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// A synchronous reader over bytes already in memory, for structures that
/// must be measured before they can be shown lazily (descriptors, action
/// lists). Every read checks bounds and returns `None` past the end.
pub(crate) struct Rd<'a> {
    data: &'a [u8],
    pub pos: usize,
    endian: Endian,
}

impl<'a> Rd<'a> {
    pub fn new(data: &'a [u8], endian: Endian) -> Self {
        Rd { data, pos: 0, endian }
    }

    pub fn at(data: &'a [u8], pos: usize, endian: Endian) -> Self {
        Rd { data, pos, endian }
    }

    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }

    pub fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        let s = self.take(N)?;
        s.try_into().ok()
    }

    pub fn u8(&mut self) -> Option<u8> {
        self.take(1)?.first().copied()
    }

    pub fn u16(&mut self) -> Option<u16> {
        let b = self.array::<2>()?;
        Some(match self.endian {
            Endian::Big => u16::from_be_bytes(b),
            Endian::Little => u16::from_le_bytes(b),
        })
    }

    pub fn u32(&mut self) -> Option<u32> {
        let b = self.array::<4>()?;
        Some(match self.endian {
            Endian::Big => u32::from_be_bytes(b),
            Endian::Little => u32::from_le_bytes(b),
        })
    }

    pub fn i32(&mut self) -> Option<i32> {
        self.u32().map(|v| i32::from_ne_bytes(v.to_ne_bytes()))
    }

    pub fn u64(&mut self) -> Option<u64> {
        let b = self.array::<8>()?;
        Some(match self.endian {
            Endian::Big => u64::from_be_bytes(b),
            Endian::Little => u64::from_le_bytes(b),
        })
    }

    pub fn f64(&mut self) -> Option<f64> {
        self.u64().map(f64::from_bits)
    }

    pub fn fourcc(&mut self) -> Option<[u8; 4]> {
        self.array::<4>()
    }

    /// A length-prefixed (u32 count of code units) UTF-16 string, as in
    /// Photoshop files; a trailing NUL is dropped.
    pub fn unicode(&mut self) -> Option<String> {
        let units = usize::try_from(self.u32()?).ok()?;
        let b = self.take(units.checked_mul(2)?)?;
        Some(crate::text::utf16(b, self.endian).trim_end_matches('\0').to_owned())
    }
}
