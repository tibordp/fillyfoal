//! DWARF debugging information (versions 2 to 5), as found in the
//! `.debug_*` sections of ELF files: units and their DIE trees with the
//! abbreviations they use (`.debug_info`, `.debug_types`, `.debug_abbrev`),
//! line number programs (`.debug_line`), string tables (`.debug_str`,
//! `.debug_line_str`, `.debug_str_offsets`), `.debug_addr`, address range
//! tables (`.debug_aranges`) and range and location lists (`.debug_ranges`,
//! `.debug_loc`, `.debug_rnglists`, `.debug_loclists`). Checked against
//! `llvm-dwarfdump`.
//!
//! Everything is decoded on demand and paged: a section lists its units
//! (one header read each), a unit its top-level DIEs, a DIE its attributes
//! and its children, so a large CU costs only what is looked at. Skipping
//! over a child's subtree to reach the next sibling (when it has no
//! `DW_AT_sibling`) walks it DIE by DIE, with a checkpoint every few DIEs.
//!
//! The container supplies the sections (decompressed if need be) and, for
//! relocatable objects, the relocations that patch offsets into other
//! sections (a RELA object's `.debug_str_offsets` holds zeros until
//! relocated); reads apply them.

pub(crate) mod expr;
mod info;
mod line;
mod lists;
pub(crate) mod tables;

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::span::Span;

/// The DWARF sections this module decodes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Sec {
    #[default]
    Info,
    Types,
    Abbrev,
    Str,
    LineStr,
    StrOffsets,
    Addr,
    Line,
    Aranges,
    Ranges,
    Rnglists,
    Loc,
    Loclists,
}

impl Sec {
    /// The section a name (`.debug_info`, Mach-O `__debug_info`) is.
    pub(crate) fn from_name(name: &str) -> Option<Sec> {
        let base = name
            .strip_prefix(".debug_")
            .or_else(|| name.strip_prefix("__debug_"))?;
        Some(match base {
            "info" => Sec::Info,
            "types" => Sec::Types,
            "abbrev" => Sec::Abbrev,
            "str" => Sec::Str,
            "line_str" => Sec::LineStr,
            "str_offsets" | "str_offs" => Sec::StrOffsets,
            "addr" => Sec::Addr,
            "line" => Sec::Line,
            "aranges" => Sec::Aranges,
            "ranges" => Sec::Ranges,
            "rnglists" => Sec::Rnglists,
            "loc" => Sec::Loc,
            "loclists" => Sec::Loclists,
            _ => return None,
        })
    }

    /// The label of the section's decoded contents.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Sec::Info => "Debug Information",
            Sec::Types => "Type Units",
            Sec::Abbrev => "Abbreviations",
            Sec::Str | Sec::LineStr => "Strings",
            Sec::StrOffsets => "String Offsets",
            Sec::Addr => "Addresses",
            Sec::Line => "Line Tables",
            Sec::Aranges => "Address Ranges",
            Sec::Ranges | Sec::Rnglists => "Range Lists",
            Sec::Loc | Sec::Loclists => "Location Lists",
        }
    }
}

/// A relocation applied when a section is read: `width` bytes at `offset`
/// (in the section) are replaced with `value`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Reloc {
    pub offset: u64,
    pub width: u8,
    pub value: u64,
}

/// One DWARF section: its (possibly decompressed) bytes and relocations,
/// sorted by offset.
#[derive(Clone, Debug)]
pub(crate) struct Section {
    pub sec: Sec,
    pub span: Span,
    pub relocs: Arc<Vec<Reloc>>,
}

/// The DWARF sections of one file.
#[derive(Debug)]
pub(crate) struct Dwarf {
    pub endian: Endian,
    /// The target's address size, for sections without their own
    /// (`.debug_ranges`, `.debug_loc`).
    pub address_size: u8,
    /// Whether addresses are before relocation (a relocatable object
    /// whose relocations against code were not applied).
    pub unrelocated: bool,
    pub sections: Vec<Section>,
    /// The container's span, whose empty start stands in for a missing
    /// section.
    pub file: Span,
}

impl Dwarf {
    fn section(&self, sec: Sec) -> Option<&Section> {
        self.sections.iter().find(|s| s.sec == sec)
    }

    pub(crate) fn span(&self, sec: Sec) -> Option<Span> {
        self.section(sec).map(|s| s.span)
    }

    /// The section's span, or an empty span if there is no such section.
    pub(crate) fn span_or_empty(&self, sec: Sec) -> Span {
        self.span(sec).unwrap_or_else(|| self.file.sub(0, 0))
    }

    /// Up to `len` bytes of `sec` at `offset` (fewer at its end), with
    /// relocations applied.
    pub(crate) async fn read(&self, cx: &Cx, sec: Sec, offset: u64, len: u64) -> Result<Vec<u8>> {
        let s = self
            .section(sec)
            .ok_or_else(|| Diagnostic::malformed(format!("no {sec:?} section")))?;
        if offset > s.span.len {
            return Err(Diagnostic::malformed(format!(
                "offset {offset:#x} is outside the {sec:?} section"
            )));
        }
        let mut data = cx.read_avail(s.span.sub(offset, len)).await?;
        let end = offset.saturating_add(to_u64(data.len()));
        let first = s.relocs.partition_point(|r| r.offset < offset);
        for r in s.relocs.iter().skip(first) {
            if r.offset >= end {
                break;
            }
            let at = to_usize(r.offset.saturating_sub(offset));
            let width = usize::from(r.width);
            let bytes = r.value.to_le_bytes();
            let Some(target) = at.checked_add(width).and_then(|e| data.get_mut(at..e)) else {
                continue;
            };
            for (i, b) in target.iter_mut().enumerate() {
                let k = if self.endian == Endian::Big {
                    width.saturating_sub(1).saturating_sub(i)
                } else {
                    i
                };
                *b = bytes.get(k).copied().unwrap_or(0);
            }
        }
        Ok(data)
    }

    /// An unsigned integer of `size` bytes (1, 2, 3, 4 or 8) at `offset`.
    pub(crate) async fn uint(&self, cx: &Cx, sec: Sec, offset: u64, size: u8) -> Option<u64> {
        let data = self.read(cx, sec, offset, size.into()).await.ok()?;
        uint_of(&data, size, self.endian)
    }

    /// The NUL-terminated string at `offset` in a string section.
    pub(crate) async fn string(&self, cx: &Cx, sec: Sec, offset: u64) -> Option<String> {
        let span = self.span(sec)?;
        crate::formats::util::binutil::string_at(cx, span, offset)
            .await
            .ok()
            .map(|(s, _)| s)
    }
}

/// An unsigned integer of `size` bytes from the start of `data`.
pub(crate) fn uint_of(data: &[u8], size: u8, endian: Endian) -> Option<u64> {
    let n = usize::from(size);
    let bytes = data.get(..n)?;
    if n > 8 {
        return None;
    }
    let mut v = 0u64;
    for i in 0..n {
        let k = if endian == Endian::Big {
            i
        } else {
            n.saturating_sub(1).saturating_sub(i)
        };
        v = (v << 8) | u64::from(*bytes.get(k)?);
    }
    Some(v)
}

/// A unit's initial length: the length, the offset size (4 or 8) and the
/// size of the length field itself.
pub(crate) fn initial_length(data: &[u8], endian: Endian) -> Option<(u64, u8, u64)> {
    let len32 = uint_of(data, 4, endian)?;
    if len32 == 0xffff_ffff {
        Some((uint_of(data.get(4..)?, 8, endian)?, 8, 12))
    } else if len32 >= 0xffff_fff0 {
        None
    } else {
        Some((len32, 4, 4))
    }
}

/// Expander: the decoded contents of one DWARF section.
pub(crate) async fn section(cx: Cx, (dw, sec): (Arc<Dwarf>, Sec)) -> Result<()> {
    let has_addresses = !matches!(sec, Sec::Abbrev | Sec::Str | Sec::LineStr | Sec::StrOffsets);
    if dw.unrelocated && has_addresses {
        cx.annotate("addresses before relocation");
    }
    match sec {
        Sec::Info | Sec::Types => info::units(&cx, &dw, sec).await,
        Sec::Abbrev => info::abbreviations(&cx, &dw).await,
        Sec::Str | Sec::LineStr => match dw.span(sec) {
            Some(span) => crate::formats::util::binutil::cstrings(cx.clone(), span).await,
            None => Ok(()),
        },
        Sec::StrOffsets => lists::str_offsets(&cx, &dw).await,
        Sec::Addr => lists::addresses(&cx, &dw).await,
        Sec::Line => line::tables(&cx, &dw).await,
        Sec::Aranges => lists::aranges(&cx, &dw).await,
        Sec::Ranges => lists::ranges(&cx, &dw).await,
        Sec::Loc => lists::loc(&cx, &dw).await,
        Sec::Rnglists | Sec::Loclists => lists::lists(&cx, &dw, sec).await,
    }
}
