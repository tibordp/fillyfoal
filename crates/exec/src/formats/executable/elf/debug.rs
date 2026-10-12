//! The DWARF sections of an ELF file, gathered for the `dwarf` module:
//! compressed sections (`SHF_COMPRESSED`) are decoded lazily, and in
//! relocatable objects the relocations against each debug section are
//! collected so reads see relocated offsets (a RELA object stores zeros in
//! `.debug_str_offsets` and puts the offsets in the addends).

use std::collections::BTreeMap;
use std::sync::Arc;

use super::tables::*;
use super::{Elf, Section};
use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::formats::Codec;
use crate::formats::executable::dwarf::{
    Arch, Dwarf, Reloc, Sec, Section as DwarfSection, uint_of,
};
use crate::span::Span;

/// Relocations read per window.
const WINDOW: u64 = 0x1000;

/// The file's DWARF sections (built once per file and cached).
pub(super) async fn dwarf(cx: &Cx, elf: &Elf) -> Arc<Dwarf> {
    let key = elf.file();
    if let Some(found) = cx.cached::<Dwarf>(key, "elf-dwarf") {
        return found;
    }
    let mut sections = Vec::new();
    for s in &elf.sections {
        let Some(sec) = Sec::from_name(&s.name) else {
            continue;
        };
        if !s.has_data() || sections.iter().any(|d: &DwarfSection| d.sec == sec) {
            continue;
        }
        let Some(span) = section_span(cx, elf, s).await else {
            continue;
        };
        let relocs = if elf.header.kind == ET_REL {
            relocations(cx, elf, s, span).await
        } else {
            Vec::new()
        };
        sections.push(DwarfSection {
            sec,
            span,
            relocs: Arc::new(relocs),
        });
    }
    let dw = Arc::new(Dwarf {
        endian: elf.endian(),
        address_size: if elf.class.wide { 8 } else { 4 },
        unrelocated: elf.header.kind == ET_REL,
        arch: Arch::from_elf(elf.header.machine),
        sections,
        file: elf.file(),
    });
    cx.cache(key, "elf-dwarf", dw.clone());
    dw
}

/// A section's bytes: the file's, or the lazily decoded contents of a
/// compressed section.
pub(super) async fn section_span(cx: &Cx, elf: &Elf, s: &Section) -> Option<Span> {
    let data = elf.data(s);
    if s.flags & SHF_COMPRESSED == 0 {
        return Some(data);
    }
    let wide = elf.class.wide;
    let header = if wide { 24u64 } else { 12 };
    let head = cx.read(data.sub(0, header)).await.ok()?;
    let e = elf.endian();
    let kind = uint_of(&head, 4, e)?;
    let size = if wide {
        uint_of(head.get(8..)?, 8, e)?
    } else {
        uint_of(head.get(4..)?, 4, e)?
    };
    let codec = match kind {
        1 => Codec::Zlib,
        2 => Codec::Zstd,
        _ => return None,
    };
    cx.decode_lazy(data.tail(header), &codec, size).ok()
}

/// How many bytes a relocation type writes, for the absolute data
/// relocations debug sections use (others are left alone).
fn width(machine: u16, kind: u32) -> Option<u8> {
    Some(match (machine, kind) {
        (EM_X86_64, 1) => 8,
        (EM_X86_64, 10 | 11) => 4,
        (EM_AARCH64, 257) => 8,
        (EM_AARCH64, 258) => 4,
        (EM_386, 1) => 4,
        (EM_ARM, 2) => 4,
        (EM_RISCV, 1) => 4,
        (EM_RISCV, 2) => 8,
        (EM_LOONGARCH, 1) => 4,
        (EM_LOONGARCH, 2) => 8,
        // PowerPC 64 and 32: ADDR32, ADDR64.
        (21 | 20, 1) => 4,
        (21, 38) => 8,
        // s390: R_390_32, R_390_64.
        (22, 4) => 4,
        (22, 22) => 8,
        // SPARC: R_SPARC_32, R_SPARC_UA32, R_SPARC_64, R_SPARC_UA64.
        (2 | 18 | 43, 3 | 23) => 4,
        (43, 32 | 54) => 8,
        _ => return None,
    })
}

/// The relocations against `target` (whose bytes are `span`), with values
/// computed as S + A (RELA) or S + the stored value (REL).
async fn relocations(cx: &Cx, elf: &Elf, target: &Section, span: Span) -> Vec<Reloc> {
    let mut out = Vec::new();
    let machine = elf.header.machine;
    if machine == EM_MIPS {
        // MIPS composes up to three types per entry; not applied.
        return out;
    }
    let wide = elf.class.wide;
    let e = elf.endian();
    let mut symbols: BTreeMap<u64, u64> = BTreeMap::new();
    for rel in &elf.sections {
        if !matches!(rel.kind, SHT_REL | SHT_RELA) || rel.info != target.index {
            continue;
        }
        let rela = rel.kind == SHT_RELA;
        let entry = elf.class.rel_size(rela);
        let Some(symtab) = elf.section(rel.link) else {
            continue;
        };
        let data = elf.data(rel);
        let mut pos = 0u64;
        while pos.saturating_add(entry) <= data.len {
            let n = WINDOW
                .min(data.len.saturating_sub(pos))
                .checked_div(entry)
                .unwrap_or(0)
                .saturating_mul(entry);
            let Ok(chunk) = cx.read(data.sub(pos, n)).await else {
                break;
            };
            for raw in chunk.chunks_exact(to_usize(entry)) {
                let word = if wide { 8 } else { 4 };
                let (Some(offset), Some(info)) = (
                    uint_of(raw, word, e),
                    uint_of(raw.get(usize::from(word)..).unwrap_or_default(), word, e),
                ) else {
                    continue;
                };
                let (sym, kind) = if wide {
                    (info >> 32, u32::try_from(info & 0xffff_ffff).unwrap_or(0))
                } else {
                    (info >> 8, u32::try_from(info & 0xff).unwrap_or(0))
                };
                let Some(w) = width(machine, kind) else {
                    continue;
                };
                let addend = if rela {
                    let a = uint_of(
                        raw.get(usize::from(word).saturating_mul(2)..)
                            .unwrap_or_default(),
                        word,
                        e,
                    )
                    .unwrap_or(0);
                    if wide {
                        a
                    } else {
                        // Sign-extend a 32-bit addend.
                        u64::from_ne_bytes(
                            i64::from(i32::from_ne_bytes(
                                u32::try_from(a).unwrap_or(0).to_ne_bytes(),
                            ))
                            .to_ne_bytes(),
                        )
                    }
                } else {
                    let stored = cx
                        .read_avail(span.sub(offset, w.into()))
                        .await
                        .unwrap_or_default();
                    uint_of(&stored, w, e).unwrap_or(0)
                };
                let s = match symbols.get(&sym) {
                    Some(v) => *v,
                    None => {
                        let v = symbol_value(cx, elf, symtab, sym).await;
                        symbols.insert(sym, v);
                        v
                    }
                };
                out.push(Reloc {
                    offset,
                    width: w,
                    value: s.wrapping_add(addend),
                });
            }
            pos = pos.saturating_add(n.max(entry));
            cx.checkpoint().await;
        }
    }
    // Assemblers write relocations in offset order; sort only if not.
    if !out.is_sorted_by_key(|r| r.offset) {
        cx.charge(to_u64(out.len()) / 16).await;
        out.sort_by_key(|r| r.offset);
    }
    out
}

/// A symbol's `st_value` (0 for the null symbol or when unreadable).
async fn symbol_value(cx: &Cx, elf: &Elf, symtab: &Section, sym: u64) -> u64 {
    if sym == 0 {
        return 0;
    }
    let size = elf.class.sym_size();
    let at = sym.saturating_mul(size);
    let value_at = if elf.class.wide { 8 } else { 4 };
    let word = if elf.class.wide { 8 } else { 4 };
    let data = elf.data(symtab);
    match cx
        .read_avail(data.sub(at.saturating_add(value_at), to_u64(usize::from(word))))
        .await
    {
        Ok(b) => uint_of(&b, word, elf.endian()).unwrap_or(0),
        Err(_) => 0,
    }
}
