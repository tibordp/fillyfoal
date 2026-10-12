//! The DWARF sections of a Mach-O file (the `__DWARF` segment of an object
//! or of a dSYM bundle's companion file), gathered for the `dwarf` module.
//!
//! Mach-O needs no relocations applied: the assembler resolves references
//! between DWARF sections to section offsets itself, and the relocations an
//! object keeps against `__debug_info` and `__debug_line` are local
//! (`r_extern` 0) ones whose stored value is already the target's address
//! in the object (`llvm-objdump -r` and `llvm-dwarfdump` agree).

use std::sync::Arc;

use super::tables::*;
use super::{MachInfo, Macho};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::executable::dwarf::{Dwarf, Sec, Section as DwarfSection};

/// The file's DWARF sections (built once per file and cached).
async fn dwarf(cx: &Cx, m: &MachInfo) -> Arc<Dwarf> {
    let key = m.file();
    if let Some(found) = cx.cached::<Dwarf>(key, "macho-dwarf") {
        return found;
    }
    let mut sections: Vec<DwarfSection> = Vec::new();
    for s in &m.sections {
        let Some(sec) = dwarf_sec(&s.segname, &s.sectname) else {
            continue;
        };
        if s.is_zerofill() || s.offset == 0 || sections.iter().any(|d| d.sec == sec) {
            continue;
        }
        sections.push(DwarfSection {
            sec,
            span: m.file().sub(s.offset.into(), s.size),
            relocs: Arc::new(Vec::new()),
        });
    }
    let dw = Arc::new(Dwarf {
        endian: m.endian,
        address_size: if m.wide { 8 } else { 4 },
        unrelocated: m.header.filetype == MH_OBJECT,
        arch: m.arch(),
        sections,
        file: m.file(),
    });
    cx.cache(key, "macho-dwarf", dw.clone());
    dw
}

/// The DWARF section a section is, if it is one.
pub(super) fn dwarf_sec(segname: &str, sectname: &str) -> Option<Sec> {
    if segname != "__DWARF" {
        return None;
    }
    Sec::from_name(sectname)
}

/// Expander: a `__DWARF` section's decoded contents.
pub(super) async fn section(cx: Cx, (m, index): (Macho, usize)) -> Result<()> {
    let s = m
        .sections
        .get(index)
        .ok_or_else(|| Diagnostic::internal("section index out of range"))?;
    let Some(sec) = dwarf_sec(&s.segname, &s.sectname) else {
        return Ok(());
    };
    let dw = dwarf(&cx, &m).await;
    crate::formats::executable::dwarf::section(cx, (dw, sec)).await
}

/// Expander: `__DWARF,__debug_frame`, call frame information in the DWARF
/// form.
pub(super) async fn debug_frame(cx: Cx, (m, index): (Macho, usize)) -> Result<()> {
    let s = m
        .sections
        .get(index)
        .ok_or_else(|| Diagnostic::internal("section index out of range"))?;
    let span = m.file().sub(s.offset.into(), s.size);
    if m.header.filetype == MH_OBJECT {
        cx.annotate("addresses before relocation");
    }
    crate::formats::executable::eh_frame::walk_debug_frame(&cx, &*m, span).await
}
