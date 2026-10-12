//! The DWARF sections of COFF objects and PE images (MinGW GCC and clang
//! for `*-windows-gnu` write them; their `.debug_*` names are longer than
//! eight bytes, so the section table refers to them as `/4` and so on in
//! the COFF string table), gathered for the `dwarf` module.
//!
//! A linked image needs nothing applied. An object's DWARF holds REL-style
//! relocations: offsets into other DWARF sections are `SECREL` relocations
//! and addresses `ADDR64`/`ADDR32` ones, each storing its addend in place,
//! so a read adds the symbol's value to the stored bytes (GNU as and LLVM
//! mostly relocate against section symbols, whose value is 0, and those are
//! skipped).

use std::collections::BTreeMap;
use std::sync::Arc;

use super::coff::{Section, relocs};
use super::dwarf::{Arch, Dwarf, Reloc, Sec, Section as DwarfSection, uint_of};
use crate::bytes::{to_u64, u16_le, u32_le};
use crate::cx::Cx;
use crate::error::Result;
use crate::fields::Endian;
use crate::span::Span;

/// Relocation records read per window.
const WINDOW: u64 = 0x1000;

/// What the DWARF of a COFF object or PE image needs from it.
#[derive(Debug)]
pub(super) struct CoffDebug {
    pub file: Span,
    pub machine: u16,
    pub wide: bool,
    pub sections: Vec<Section>,
    /// A linked image: no relocations, and a section's data ends at its
    /// VirtualSize (the raw size is padded to FileAlignment).
    pub image: bool,
    pub image_base: u64,
    /// An object's symbol table and its record size (18, or 20 in bigobj).
    pub symbols: Span,
    pub record: u64,
}

pub(super) type Dbg = Arc<CoffDebug>;

impl CoffDebug {
    /// A section's bytes in the file.
    fn data(&self, s: &Section) -> Option<Span> {
        let data = s.data(self.file, 0)?;
        if self.image && s.virtual_size > 0 && s.virtual_size < s.raw_size {
            return Some(data.sub(0, s.virtual_size.into()));
        }
        Some(data)
    }

    fn section_at(&self, va: u64) -> Option<&Section> {
        let rva = va.checked_sub(self.image_base)?;
        self.sections.iter().find(|s| {
            let start = u64::from(s.virtual_address);
            rva >= start && rva < start.saturating_add(s.mapped_size().into())
        })
    }
}

/// Whether a section name is one this module decodes.
pub(super) fn is_debug(name: &str) -> bool {
    Sec::from_name(name).is_some() || name == ".debug_frame"
}

/// The `CoffDebug` of `file`, built by `make` once per file.
pub(super) fn shared(cx: &Cx, file: Span, image: bool, make: impl FnOnce() -> CoffDebug) -> Dbg {
    let kind = if image { "pe-debug" } else { "coff-debug" };
    if let Some(found) = cx.cached::<CoffDebug>(file, kind) {
        return found;
    }
    let dbg = Arc::new(make());
    cx.cache(file, kind, dbg.clone());
    dbg
}

/// The node for a DWARF section's contents (`.debug_frame` included), or
/// `None` if the section is not one.
pub(super) fn node(dbg: &Dbg, index: usize) -> Option<crate::node::Node> {
    let s = dbg.sections.get(index)?;
    let span = dbg.data(s)?;
    let node = crate::node::Node::new(match Sec::from_name(&s.name) {
        Some(sec) => sec.label(),
        None if s.name == ".debug_frame" => "Call Frame Information",
        None => return None,
    })
    .span(span);
    Some(node.lazy(contents, (dbg.clone(), index)))
}

async fn contents(cx: Cx, (dbg, index): (Dbg, usize)) -> Result<()> {
    let Some(s) = dbg.sections.get(index) else {
        return Ok(());
    };
    match Sec::from_name(&s.name) {
        Some(sec) => {
            let dw = dwarf(&cx, &dbg).await;
            super::dwarf::section(cx, (dw, sec)).await
        }
        None => {
            let Some(span) = dbg.data(s) else {
                return Ok(());
            };
            if !dbg.image {
                cx.annotate("addresses before relocation");
            }
            super::eh_frame::walk_debug_frame(&cx, &*dbg, span).await
        }
    }
}

/// The file's DWARF sections (built once per file and cached).
async fn dwarf(cx: &Cx, dbg: &CoffDebug) -> Arc<Dwarf> {
    let (key, kind) = (dbg.file, if dbg.image { "pe-dwarf" } else { "coff-dwarf" });
    if let Some(found) = cx.cached::<Dwarf>(key, kind) {
        return found;
    }
    let mut sections: Vec<DwarfSection> = Vec::new();
    for s in &dbg.sections {
        cx.checkpoint().await;
        let Some(sec) = Sec::from_name(&s.name) else {
            continue;
        };
        if sections.iter().any(|d| d.sec == sec) {
            continue;
        }
        let Some(span) = dbg.data(s) else {
            continue;
        };
        let relocs = if dbg.image || s.nreloc == 0 {
            Vec::new()
        } else {
            relocations(cx, dbg, s, span).await
        };
        sections.push(DwarfSection {
            sec,
            span,
            relocs: Arc::new(relocs),
        });
    }
    let dw = Arc::new(Dwarf {
        endian: Endian::Little,
        address_size: if dbg.wide { 8 } else { 4 },
        unrelocated: !dbg.image,
        arch: Arch::from_coff(dbg.machine),
        sections,
        file: dbg.file,
    });
    cx.cache(key, kind, dw.clone());
    dw
}

/// How many bytes a relocation type writes, for the absolute and
/// section-relative relocations debug sections use (others are left
/// alone).
fn width(machine: u16, kind: u16) -> Option<u8> {
    Some(match (machine, kind) {
        // AMD64: ADDR64, ADDR32, ADDR32NB, SECREL.
        (0x8664, 1) => 8,
        (0x8664, 2 | 3 | 0xb) => 4,
        // I386: DIR32, DIR32NB, SECREL.
        (0x14c, 6 | 7 | 0xb) => 4,
        // ARM64: ADDR32, ADDR32NB, SECREL, ADDR64.
        (0xaa64 | 0xa641 | 0xa64e, 1 | 2 | 8) => 4,
        (0xaa64 | 0xa641 | 0xa64e, 0xe) => 8,
        // ARM: ADDR32, ADDR32NB, SECREL.
        (0x1c0 | 0x1c2 | 0x1c4, 1 | 2 | 0xf) => 4,
        _ => return None,
    })
}

/// The relocations against `target` (whose bytes are `span`), with values
/// computed as S + the stored addend. Relocations against symbols whose
/// value is 0 (section symbols) change nothing and are left out.
async fn relocations(cx: &Cx, dbg: &CoffDebug, target: &Section, span: Span) -> Vec<Reloc> {
    let mut out = Vec::new();
    let Ok(table) = relocs(cx, dbg.file, target).await else {
        return out;
    };
    let mut values: BTreeMap<u32, u64> = BTreeMap::new();
    let data = table.span;
    // The overflow count record is not a relocation.
    let mut pos = if table.overflow { 10u64 } else { 0 };
    while pos.saturating_add(10) <= data.len {
        let n = WINDOW
            .min(data.len.saturating_sub(pos))
            .checked_div(10)
            .unwrap_or(0)
            .saturating_mul(10);
        let Ok(chunk) = cx.read(data.sub(pos, n)).await else {
            break;
        };
        for raw in chunk.as_chunks::<10>().0 {
            let (Some(offset), Some(sym), Some(kind)) =
                (u32_le(raw, 0), u32_le(raw, 4), u16_le(raw, 8))
            else {
                continue;
            };
            let Some(w) = width(dbg.machine, kind) else {
                continue;
            };
            let s = match values.get(&sym) {
                Some(v) => *v,
                None => {
                    let v = symbol_value(cx, dbg, sym).await;
                    values.insert(sym, v);
                    v
                }
            };
            if s == 0 {
                continue;
            }
            let offset = u64::from(offset);
            let stored = cx
                .read_avail(span.sub(offset, w.into()))
                .await
                .unwrap_or_default();
            let addend = uint_of(&stored, w, Endian::Little).unwrap_or(0);
            out.push(Reloc {
                offset,
                width: w,
                value: s.wrapping_add(addend),
            });
        }
        pos = pos.saturating_add(n.max(10));
        cx.checkpoint().await;
    }
    if !out.is_sorted_by_key(|r| r.offset) {
        cx.charge(to_u64(out.len()) / 16).await;
        out.sort_by_key(|r| r.offset);
    }
    out
}

/// A symbol's `Value` (0 when unreadable).
async fn symbol_value(cx: &Cx, dbg: &CoffDebug, sym: u32) -> u64 {
    let at = u64::from(sym).saturating_mul(dbg.record).saturating_add(8);
    match cx.read_avail(dbg.symbols.sub(at, 4)).await {
        Ok(b) => u32_le(&b, 0).map_or(0, u64::from),
        Err(_) => 0,
    }
}

impl super::eh_frame::Image for CoffDebug {
    fn endian(&self) -> Endian {
        Endian::Little
    }

    fn wide(&self) -> bool {
        self.wide
    }

    fn describe(&self, addr: u64) -> String {
        if !self.image {
            return format!("{addr:#x}");
        }
        match self.section_at(addr) {
            Some(s) => {
                let start = self.image_base.saturating_add(s.virtual_address.into());
                format!("{} + {:#x}", s.label(), addr.saturating_sub(start))
            }
            None => format!("{addr:#x}"),
        }
    }

    fn target(&self, addr: u64) -> Option<Span> {
        if !self.image {
            return None;
        }
        let s = self.section_at(addr)?;
        let start = self.image_base.saturating_add(s.virtual_address.into());
        let off = addr.saturating_sub(start);
        let data = s.data(self.file, 0)?;
        (off < data.len).then(|| data.sub(off, 0))
    }
}
