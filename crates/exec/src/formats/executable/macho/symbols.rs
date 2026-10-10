//! Symbols: the `nlist` table (with stabs), the dynamic symbol table's
//! ranges and side tables (indirect symbols, table of contents, modules,
//! external references, two-level hints) and relocation entries.

use super::tables::*;
use super::{MachInfo, Macho, SectionInfo, Symtab, group};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::util::binutil::{get_at, string_at};
use crate::formats::util::val::{hex, name_or, text, uint};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, Value};

pub(super) fn symtab_node(m: &Macho, st: Symtab) -> Node {
    let span = m.file().sub(
        st.symoff.into(),
        u64::from(st.nsyms).saturating_mul(m.nlist_size()),
    );
    let mut node = Node::new("Symbol Table")
        .span(span)
        .summary(grouped_count(st.nsyms, "symbol", "symbols"))
        .lazy(symbols, (m.clone(), 0u32, st.nsyms));
    if span.len < u64::from(st.nsyms).saturating_mul(m.nlist_size()) {
        node = node.diag(Diagnostic::truncated(
            Span::new(
                span.source,
                span.offset,
                u64::from(st.nsyms).saturating_mul(m.nlist_size()),
            ),
            span.len,
        ));
    }
    node
}

/// A range of the symbol table named by `LC_DYSYMTAB`.
pub(super) fn symbol_range_node(m: &Macho, name: &'static str, first: u32, n: u32) -> Node {
    let mut node = Node::new(name).summary(format!(
        "{}, from index {first}",
        grouped_count(n, "symbol", "symbols")
    ));
    if let Some(st) = m.symtab {
        let size = m.nlist_size();
        node = node.span(m.file().sub(
            u64::from(st.symoff).saturating_add(u64::from(first).saturating_mul(size)),
            u64::from(n).saturating_mul(size),
        ));
    }
    node.lazy(symbols, (m.clone(), first, n))
}

#[derive(Clone, Copy, Debug)]
struct Nlist {
    strx: u32,
    kind: u8,
    sect: u8,
    desc: u16,
    value: u64,
}

impl Nlist {
    fn is_stab(&self) -> bool {
        self.kind & 0xe0 != 0
    }
    fn base_type(&self) -> u8 {
        self.kind & 0x0e
    }
    fn is_common(&self) -> bool {
        !self.is_stab() && self.base_type() == 0 && self.kind & 1 != 0 && self.value != 0
    }
}

fn stab_meaning(kind: u8) -> Option<(&'static str, &'static str)> {
    STAB_MEANING
        .iter()
        .find(|(k, _, _)| *k == kind)
        .map(|&(_, name, value)| (name, value))
}

fn nlist(f: &mut Fields<'_>, m: &Macho) -> Result<Nlist> {
    let strx = f
        .u32("n_strx")
        .hex()
        .desc("Offset of the name in the string table")
        .emit()?;
    let kind = f
        .u8("n_type")
        .hex()
        .with(|&v, n| n.summary(type_summary(v)))
        .emit()?;
    let stab = kind & 0xe0 != 0;
    let sect = f
        .u8("n_sect")
        .with(|&v, n| match m.section(v) {
            Some(s) if v != 0 => n.summary(s.label()),
            _ => n.summary("NO_SECT"),
        })
        .desc("Section number (1-based, in load command order)")
        .emit()?;
    let value_at = f.pos().saturating_add(2);
    let value = {
        let here = f.pos();
        f.seek(value_at);
        let v = f.uword("", m.wide).get().unwrap_or(0);
        f.seek(here);
        v
    };
    let desc = if stab {
        f.u16("n_desc")
            .with(|&v, n| match kind {
                N_SLINE => n.summary(format!("line {v}")),
                _ => n,
            })
            .desc("Stab-specific (line number, nesting level, ...)")
            .emit()?
    } else {
        let common = kind & 0x0e == 0 && kind & 1 != 0 && value != 0;
        let undefined = kind & 0x0e == 0;
        let two_level = m.two_level();
        if undefined && two_level || common {
            // The high byte is a library ordinal (or a common symbol's
            // alignment), the low byte flags.
            f.u16("n_desc")
                .hex()
                .with(|&v, n| {
                    let (set, _) = crate::value::decode_flags(N_DESC, (v & 0xff).into());
                    let mut s = if common {
                        format!("alignment 2^{}", (v >> 8) & 0xf)
                    } else {
                        format!("library ordinal {}: {}", v >> 8, m.dylib((v >> 8).into()))
                    };
                    if !set.is_empty() {
                        s.push_str(&format!(", {}", set.join(" | ")));
                    }
                    n.summary(s)
                })
                .emit()?
        } else {
            f.u16("n_desc").flags(N_DESC).emit()?
        }
    };
    let value = if stab && kind == N_OSO {
        f.uword("n_value", m.wide)
            .with(|&v, n| {
                n.value(Value::Timestamp {
                    unix_seconds: i64::try_from(v).unwrap_or(0),
                })
            })
            .desc("Modification time of the object file")
            .emit()?
    } else if kind & 0xe0 == 0 && kind & 0x0e == 0 && kind & 1 != 0 && value != 0 {
        f.uword("n_value", m.wide)
            .hex()
            .desc("Size of the common symbol")
            .emit()?
    } else {
        f.uword("n_value", m.wide).hex().emit()?
    };
    Ok(Nlist {
        strx,
        kind,
        sect,
        desc,
        value,
    })
}

const N_SLINE: u8 = 0x44;
const N_OSO: u8 = 0x66;
const N_FUN: u8 = 0x24;

fn type_summary(t: u8) -> String {
    if t & 0xe0 != 0 {
        return name_or(N_STAB, t.into(), "stab");
    }
    let mut s = name_or(N_TYPE, (t & 0x0e).into(), "type");
    if t & 0x10 != 0 {
        s.push_str(" PEXT");
    }
    if t & 0x01 != 0 {
        s.push_str(" EXT");
    }
    s
}

/// What `nm -m` says about a symbol: `(__TEXT,__text) external`,
/// `(undefined) weak external (from libSystem)`, a stab's meaning.
fn symbol_summary(m: &MachInfo, sym: &Nlist) -> String {
    if sym.is_stab() {
        let name = name_or(N_STAB, sym.kind.into(), "stab");
        return match stab_meaning(sym.kind) {
            Some((meaning, _)) => format!("{name}: {meaning}"),
            None => name,
        };
    }
    let place = match sym.base_type() {
        0 if sym.is_common() => format!("(common) size {:#x}", sym.value),
        0 => "(undefined)".to_owned(),
        0x2 => "(absolute)".to_owned(),
        0xa => "(indirect)".to_owned(),
        0xc => "(prebound undefined)".to_owned(),
        0xe => match m.section(sym.sect) {
            Some(s) => format!("({})", s.label()),
            None => format!("(section {})", sym.sect),
        },
        t => format!("(type {t:#x})"),
    };
    let mut words = vec![place];
    if sym.desc & 0x80 != 0 {
        words.push(if sym.base_type() == 0 {
            "weak-ref-to-weak".to_owned()
        } else {
            "weak".to_owned()
        });
    }
    if sym.desc & 0x40 != 0 {
        words.push("weak-import".to_owned());
    }
    words.push(
        if sym.kind & 0x10 != 0 {
            "private external"
        } else if sym.kind & 0x01 != 0 {
            "external"
        } else {
            "non-external"
        }
        .to_owned(),
    );
    if sym.base_type() != 0 {
        if sym.desc & 0x10 != 0 {
            words.insert(1, "[referenced dynamically]".to_owned());
        }
        if sym.desc & 0x100 != 0 {
            words.push("resolver".to_owned());
        }
        if sym.desc & 0x200 != 0 {
            words.push("alt-entry".to_owned());
        }
        if sym.desc & 0x400 != 0 {
            words.push("cold".to_owned());
        }
    }
    if sym.base_type() == 0 && !sym.is_common() && m.two_level() && !m.dylibs.is_empty() {
        words.push(format!("(from {})", m.dylib((sym.desc >> 8).into())));
    }
    words.join(" ")
}

pub(super) async fn symbol_name(cx: &Cx, m: &MachInfo, index: u32) -> Result<String> {
    let st = m
        .symtab
        .ok_or_else(|| Diagnostic::malformed("no symbol table"))?;
    if index >= st.nsyms {
        return Err(Diagnostic::malformed(format!(
            "symbol index {index} out of range"
        )));
    }
    let at = nlist_span(m, st, index).sub(0, 4);
    let data = cx.read(at).await?;
    let strx = get_at::<u32>(&data, 0, m.endian).unwrap_or(0);
    Ok(
        string_at(cx, m.linkedit(st.stroff, st.strsize), strx.into())
            .await?
            .0,
    )
}

fn nlist_span(m: &MachInfo, st: Symtab, index: u32) -> Span {
    let size = m.nlist_size();
    m.file().sub(
        u64::from(st.symoff).saturating_add(u64::from(index).saturating_mul(size)),
        size,
    )
}

/// Symbols `first..first + n` of the symbol table.
async fn symbols(cx: Cx, (m, first, n): (Macho, u32, u32)) -> Result<()> {
    let st = m
        .symtab
        .ok_or_else(|| Diagnostic::malformed("no symbol table"))?;
    let size = m.nlist_size();
    let available = m
        .file()
        .sub(st.symoff.into(), u64::from(st.nsyms).saturating_mul(size))
        .len
        .checked_div(size)
        .unwrap_or(0);
    let end = u64::from(first)
        .saturating_add(n.into())
        .min(st.nsyms.into())
        .min(available);
    let first = u64::from(first);
    if end < first.saturating_add(n.into()) {
        cx.diag(Diagnostic::truncated(
            m.file()
                .sub(st.symoff.into(), u64::from(st.nsyms).saturating_mul(size)),
            available.saturating_mul(size),
        ));
    }
    cx.set_count(Count::Exact(end.saturating_sub(first)));
    let strings = m.linkedit(st.stroff, st.strsize);
    let start = cx.resume::<u64>().unwrap_or(first);
    for i in start..end {
        cx.mark(move || i);
        let index = u32::try_from(i).unwrap_or(u32::MAX);
        let span = nlist_span(&m, st, index);
        if cx.skipping() {
            cx.push(Node::new("")).await;
            continue;
        }
        let sym = parse(&cx, span, m.endian, &m, nlist).await?;
        let (name, diag) = if sym.strx == 0 {
            (format!("#{i}"), None)
        } else {
            match string_at(&cx, strings, sym.strx.into()).await {
                Ok((s, _)) if s.is_empty() => (format!("#{i}"), None),
                Ok((s, _)) => (s, None),
                Err(e) => (format!("#{i}"), Some(e)),
            }
        };
        let value = if sym.is_stab() && sym.kind == N_OSO {
            Value::Timestamp {
                unix_seconds: i64::try_from(sym.value).unwrap_or(0),
            }
        } else {
            hex(sym.value, m.bits())
        };
        let mut node = struct_node(name, span, m.endian, m.clone(), nlist)
            .value(value)
            .summary(symbol_summary(&m, &sym));
        let defined = !sym.is_stab() && sym.base_type() == 0x0e;
        let code_stab = sym.is_stab() && sym.kind == N_FUN && sym.strx != 0;
        if (defined || code_stab)
            && let Some(t) = m.vm_span(sym.value, 0)
        {
            node = node.target(t);
        }
        if let Some(d) = diag {
            node = node.diag(d);
        }
        cx.push(node).await;
    }
    Ok(())
}

/// Entries of the indirect symbol table, `first..first + count`: the
/// symbols behind a pointer or stub section's entries.
pub(super) async fn indirect_symbols(cx: Cx, (m, first, count): (Macho, u32, u32)) -> Result<()> {
    let d = m
        .dysymtab
        .ok_or_else(|| Diagnostic::malformed("no LC_DYSYMTAB"))?;
    let table = m.linkedit(d.indirectsymoff, d.nindirectsyms.saturating_mul(4));
    let available = u32::try_from(table.len / 4).unwrap_or(u32::MAX);
    let count = count.min(available.saturating_sub(first));
    cx.set_count(Count::Exact(count.into()));
    for i in 0..count {
        let index = first.saturating_add(i);
        let at = table.sub(u64::from(index).saturating_mul(4), 4);
        let node = Node::new(format!("[{index}]")).span(at);
        let node = match indirect_entry(&cx, &m, index).await {
            Ok(e) => e.decorate(node),
            Err(e) => node.diag(e),
        };
        cx.push(node).await;
    }
    Ok(())
}

/// One indirect symbol table entry, resolved.
pub(super) struct Indirect {
    pub raw: u32,
    pub name: Option<String>,
    pub target: Option<Span>,
}

impl Indirect {
    pub fn label(&self) -> String {
        match (&self.name, self.raw) {
            (Some(name), _) => name.clone(),
            (None, 0x8000_0000) => "INDIRECT_SYMBOL_LOCAL".to_owned(),
            (None, 0x4000_0000) => "INDIRECT_SYMBOL_ABS".to_owned(),
            (None, 0xc000_0000) => "INDIRECT_SYMBOL_LOCAL | ABS".to_owned(),
            (None, raw) => format!("symbol #{raw}"),
        }
    }

    fn decorate(&self, node: Node) -> Node {
        let node = node.value(text(self.label()));
        let node = if self.name.is_some() {
            node.summary(format!("symbol {}", self.raw))
        } else {
            node
        };
        match self.target {
            Some(t) => node.target(t),
            None => node,
        }
    }
}

pub(super) async fn indirect_entry(cx: &Cx, m: &MachInfo, index: u32) -> Result<Indirect> {
    let d = m
        .dysymtab
        .ok_or_else(|| Diagnostic::malformed("no LC_DYSYMTAB"))?;
    if index >= d.nindirectsyms {
        return Err(Diagnostic::malformed(format!(
            "indirect symbol {index} is out of range"
        )));
    }
    let table = m.linkedit(d.indirectsymoff, d.nindirectsyms.saturating_mul(4));
    let data = cx
        .read(table.sub(u64::from(index).saturating_mul(4), 4))
        .await?;
    let raw = get_at::<u32>(&data, 0, m.endian).unwrap_or(0);
    if raw & 0xc000_0000 != 0 {
        return Ok(Indirect {
            raw,
            name: None,
            target: None,
        });
    }
    let name = symbol_name(cx, m, raw).await?;
    Ok(Indirect {
        raw,
        name: Some(name),
        target: m.symtab.map(|st| nlist_span(m, st, raw)),
    })
}

/// `dylib_table_of_contents` entries.
pub(super) async fn toc(cx: Cx, (m, span): (Macho, Span)) -> Result<()> {
    let n = span.len / 8;
    cx.set_count(Count::Exact(n));
    for i in 0..n {
        let at = span.sub(i.saturating_mul(8), 8);
        let data = cx.read(at).await?;
        let symbol = get_at::<u32>(&data, 0, m.endian).unwrap_or(0);
        let module = get_at::<u32>(&data, 4, m.endian).unwrap_or(0);
        let name = symbol_name(&cx, &m, symbol)
            .await
            .unwrap_or_else(|_| format!("symbol #{symbol}"));
        cx.push(
            group(
                name,
                at,
                vec![
                    Node::new("symbol_index")
                        .span(at.sub(0, 4))
                        .value(uint(symbol, 32)),
                    Node::new("module_index")
                        .span(at.sub(4, 4))
                        .value(uint(module, 32)),
                ],
            )
            .summary(format!("module {module}")),
        )
        .await;
    }
    Ok(())
}

fn module_layout(f: &mut Fields<'_>, wide: &bool) -> Result<()> {
    f.u32("module_name")
        .hex()
        .desc("Offset of the name in the string table")
        .emit()?;
    for name in [
        "iextdefsym",
        "nextdefsym",
        "irefsym",
        "nrefsym",
        "ilocalsym",
        "nlocalsym",
        "iextrel",
        "nextrel",
    ] {
        f.u32(name).emit()?;
    }
    f.u32("iinit_iterm")
        .hex()
        .desc("Indices of the first initializer (low 16 bits) and terminator (high 16 bits)")
        .emit()?;
    f.u32("ninit_nterm")
        .hex()
        .desc("Numbers of initializers (low 16 bits) and terminators (high 16 bits)")
        .emit()?;
    if *wide {
        f.u32("objc_module_info_size").hex().emit()?;
        f.u64("objc_module_info_addr").hex().emit()?;
    } else {
        f.u32("objc_module_info_addr").hex().emit()?;
        f.u32("objc_module_info_size").hex().emit()?;
    }
    Ok(())
}

/// `dylib_module` entries.
pub(super) async fn modules(cx: Cx, (m, span): (Macho, Span)) -> Result<()> {
    let size: u64 = if m.wide { 56 } else { 52 };
    let n = span.len.checked_div(size).unwrap_or(0);
    cx.set_count(Count::Exact(n));
    let strings = m.symtab.map(|st| m.linkedit(st.stroff, st.strsize));
    for i in 0..n {
        let at = span.sub(i.saturating_mul(size), size);
        let data = cx.read(at.sub(0, 4)).await?;
        let strx = get_at::<u32>(&data, 0, m.endian).unwrap_or(0);
        let name = match strings {
            Some(t) => string_at(&cx, t, strx.into())
                .await
                .map_or_else(|_| format!("Module {i}"), |s| s.0),
            None => format!("Module {i}"),
        };
        cx.push(struct_node(name, at, m.endian, m.wide, module_layout))
            .await;
    }
    Ok(())
}

const REFERENCE_TYPE: EnumTable = &[
    (0, "REFERENCE_FLAG_UNDEFINED_NON_LAZY"),
    (1, "REFERENCE_FLAG_UNDEFINED_LAZY"),
    (2, "REFERENCE_FLAG_DEFINED"),
    (3, "REFERENCE_FLAG_PRIVATE_DEFINED"),
    (4, "REFERENCE_FLAG_PRIVATE_UNDEFINED_NON_LAZY"),
    (5, "REFERENCE_FLAG_PRIVATE_UNDEFINED_LAZY"),
];

/// `dylib_reference` entries: a 24-bit symbol index and 8 bits of flags.
pub(super) async fn external_refs(cx: Cx, (m, span): (Macho, Span)) -> Result<()> {
    let n = span.len / 4;
    cx.set_count(Count::Exact(n));
    for i in 0..n {
        let at = span.sub(i.saturating_mul(4), 4);
        let data = cx.read(at).await?;
        let raw = get_at::<u32>(&data, 0, m.endian).unwrap_or(0);
        let (symbol, flags) = if m.endian == Endian::Little {
            (raw & 0x00ff_ffff, raw >> 24)
        } else {
            (raw >> 8, raw & 0xff)
        };
        let name = symbol_name(&cx, &m, symbol)
            .await
            .unwrap_or_else(|_| format!("symbol #{symbol}"));
        cx.push(
            Node::new(name)
                .span(at)
                .value(Value::Enum {
                    raw: flags.into(),
                    bits: 8,
                    name: crate::value::lookup(REFERENCE_TYPE, flags.into()),
                })
                .summary(format!("symbol {symbol}")),
        )
        .await;
    }
    Ok(())
}

/// `twolevel_hint` entries: the sub-image and table-of-contents index where
/// each undefined symbol is expected.
pub(super) async fn hints(cx: Cx, (m, span): (Macho, Span)) -> Result<()> {
    let n = span.len / 4;
    cx.set_count(Count::Exact(n));
    for i in 0..n {
        let at = span.sub(i.saturating_mul(4), 4);
        let data = cx.read(at).await?;
        let raw = get_at::<u32>(&data, 0, m.endian).unwrap_or(0);
        let (image, toc) = if m.endian == Endian::Little {
            (raw & 0xff, raw >> 8)
        } else {
            (raw >> 24, raw & 0x00ff_ffff)
        };
        cx.push(
            Node::new(format!("[{i}]"))
                .span(at)
                .value(hex(raw, 32))
                .summary(format!("sub-image {image}, table of contents entry {toc}")),
        )
        .await;
    }
    Ok(())
}

/// Relocation entries, paged. `section` is the index of the section they
/// apply to (`usize::MAX` for the dynamic symbol table's relocations, whose
/// addresses are relative to the first segment).
pub(super) async fn relocations(cx: Cx, (m, span, section): (Macho, Span, usize)) -> Result<()> {
    let count = span.len / 8;
    cx.set_count(Count::Exact(count));
    let types = relocation_types(m.header.cputype);
    let applies_to = m.sections.get(section);
    let addend_type = matches!(m.header.cputype, CPU_TYPE_ARM64 | CPU_TYPE_ARM64_32);
    for i in 0..count {
        let at = span.sub(i.saturating_mul(8), 8);
        let data = cx.read(at).await?;
        let first = get_at::<u32>(&data, 0, m.endian).unwrap_or(0);
        let second = get_at::<u32>(&data, 4, m.endian).unwrap_or(0);
        let word0 = at.sub(0, 4);
        let word1 = at.sub(4, 4);
        let field = |name: &'static str, span: Span, v: Value| Node::new(name).span(span).value(v);
        let node = if first & 0x8000_0000 != 0 {
            // Scattered: r_scattered:1 r_pcrel:1 r_length:2 r_type:4
            // r_address:24 in the first word, r_value in the second (the
            // same bit positions in either byte order).
            let address = first & 0x00ff_ffff;
            let kind = (first >> 24) & 0xf;
            let length = (first >> 28) & 3;
            let pcrel = (first >> 30) & 1;
            let mut flags = format!("{} bytes", 1u32 << length);
            if pcrel != 0 {
                flags.push_str(", pc-relative");
            }
            let target = m
                .vm_span(second.into(), 0)
                .map(|_| m.describe(second.into()))
                .unwrap_or_else(|| format!("{second:#x}"));
            let node = group(
                name_or(types, kind.into(), "type"),
                at,
                vec![
                    field("r_scattered", word0, Value::Bool(true)),
                    field("r_pcrel", word0, Value::Bool(pcrel != 0)),
                    field("r_length", word0, uint(length, 2))
                        .summary(format!("{} bytes", 1u32 << length)),
                    field(
                        "r_type",
                        word0,
                        Value::Enum {
                            raw: kind.into(),
                            bits: 4,
                            name: crate::value::lookup(types, kind.into()),
                        },
                    ),
                    field("r_address", word0, hex(address, 24)),
                    field("r_value", word1, hex(second, 32)).desc("Address of the relocated item"),
                ],
            )
            .value(hex(address, 32))
            .summary(format!("scattered, {target} ({flags})"));
            match applies_to {
                Some(s) if s.offset != 0 && kind != 1 => node.target(m.file().sub(
                    u64::from(s.offset).saturating_add(address.into()),
                    1u64 << length,
                )),
                _ => node,
            }
        } else {
            let (symbol, pcrel, length, external, kind) = if m.endian == Endian::Little {
                (
                    second & 0x00ff_ffff,
                    (second >> 24) & 1,
                    (second >> 25) & 3,
                    (second >> 27) & 1,
                    second >> 28,
                )
            } else {
                (
                    second >> 8,
                    (second >> 7) & 1,
                    (second >> 5) & 3,
                    (second >> 4) & 1,
                    second & 0xf,
                )
            };
            let target = if addend_type && kind == 10 {
                // ARM64_RELOC_ADDEND: the symbol field is a signed 24-bit
                // addend for the next relocation.
                let addend = if symbol & 0x80_0000 != 0 {
                    i64::from(symbol).saturating_sub(0x100_0000)
                } else {
                    i64::from(symbol)
                };
                format!("addend {addend:#x}")
            } else if external != 0 {
                symbol_name(&cx, &m, symbol)
                    .await
                    .unwrap_or_else(|_| format!("symbol #{symbol}"))
            } else if symbol == 0 {
                "absolute".to_owned()
            } else {
                m.section(u8::try_from(symbol).unwrap_or(0))
                    .map_or_else(|| format!("section {symbol}"), SectionInfo::label)
            };
            let mut flags = format!("{} bytes", 1u32 << length);
            if pcrel != 0 {
                flags.push_str(", pc-relative");
            }
            let mut node = group(
                name_or(types, kind.into(), "type"),
                at,
                vec![
                    field("r_address", word0, hex(first, 32))
                        .desc("Offset of the relocated item from the start of the section"),
                    field("r_symbolnum", word1, uint(symbol, 24)).desc(if external != 0 {
                        "Symbol table index"
                    } else {
                        "Section number (1-based), or 0 for absolute"
                    }),
                    field("r_pcrel", word1, Value::Bool(pcrel != 0)),
                    field("r_length", word1, uint(length, 2))
                        .summary(format!("{} bytes", 1u32 << length)),
                    field("r_extern", word1, Value::Bool(external != 0)),
                    field(
                        "r_type",
                        word1,
                        Value::Enum {
                            raw: kind.into(),
                            bits: 4,
                            name: crate::value::lookup(types, kind.into()),
                        },
                    ),
                ],
            )
            .value(hex(first, 32))
            .summary(format!("{target} ({flags})"));
            if let Some(s) = applies_to
                && s.offset != 0
            {
                node = node.target(m.file().sub(
                    u64::from(s.offset).saturating_add(first.into()),
                    1u64 << length,
                ));
            }
            node
        };
        cx.push(node).await;
    }
    Ok(())
}
