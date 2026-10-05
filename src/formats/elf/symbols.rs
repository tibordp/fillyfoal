//! Tables that refer to other sections: symbols, relocations, the dynamic
//! section, symbol versioning, and plain string tables.

use super::tables::*;
use super::{Class, Elf, MAX_NAME, Section};
use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::dsl::{Cursor, Record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Fields, parse, struct_node};
use crate::formats::binutil::{ellipsize, get_at, hex, name_or, text};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{Value, decode_flags, lookup};

/// Most bytes of a dynamic section we read at once.
const MAX_DYNAMIC: u64 = 1 << 20;
/// Version chains longer than this are cut off.
const MAX_VERSIONS: u32 = 4096;

// ---------------------------------------------------------------------------
// Symbols

#[derive(Clone, Copy, Debug)]
pub(super) struct Symbol {
    pub name: u32,
    pub value: u64,
    pub size: u64,
    pub info: u8,
    pub other: u8,
    pub shndx: u16,
}

impl Symbol {
    fn bind(&self) -> u8 {
        self.info >> 4
    }
    fn kind(&self) -> u8 {
        self.info & 0xf
    }
}

fn section_ref(elf: &Elf, shndx: u16) -> String {
    match shndx {
        0 => "UND".to_owned(),
        0xfff1 => "ABS".to_owned(),
        0xfff2 => "COMMON".to_owned(),
        SHN_XINDEX => "XINDEX".to_owned(),
        n if n >= SHN_LORESERVE => format!("{n:#x}"),
        n => elf.section_name(n.into()),
    }
}

fn symbol(f: &mut Fields<'_>, elf: &Elf) -> Result<Symbol> {
    let name = f
        .u32("st_name")
        .hex()
        .desc("Offset of the name in the linked string table")
        .emit()?;
    let info_field = |f: &mut Fields<'_>| {
        f.u8("st_info")
            .hex()
            .with(|&v, n| {
                n.summary(format!(
                    "{} {}",
                    name_or(SYMBOL_BIND, (v >> 4).into(), "bind"),
                    name_or(SYMBOL_TYPE, (v & 0xf).into(), "type")
                ))
            })
            .desc("Binding (high nibble) and type (low nibble)")
            .emit()
    };
    let other_field = |f: &mut Fields<'_>| {
        f.u8("st_other")
            .with(|&v, n| n.summary(name_or(SYMBOL_VISIBILITY, (v & 3).into(), "visibility")))
            .desc("Visibility (low two bits)")
            .emit()
    };
    let shndx_field = |f: &mut Fields<'_>| {
        f.u16("st_shndx")
            .with(|&v, n| n.summary(section_ref(elf, v)))
            .desc("Section the symbol is defined in")
            .emit()
    };
    if elf.class.wide {
        let info = info_field(f)?;
        let other = other_field(f)?;
        let shndx = shndx_field(f)?;
        let value = f.u64("st_value").hex().emit()?;
        let size = f.u64("st_size").emit()?;
        Ok(Symbol {
            name,
            value,
            size,
            info,
            other,
            shndx,
        })
    } else {
        let value = f.u32("st_value").hex().emit()?.into();
        let size = f.u32("st_size").emit()?.into();
        let info = info_field(f)?;
        let other = other_field(f)?;
        let shndx = shndx_field(f)?;
        Ok(Symbol {
            name,
            value,
            size,
            info,
            other,
            shndx,
        })
    }
}

/// A symbol table's geometry: where its entries are and how big they are.
struct Table {
    span: Span,
    entsize: u64,
    count: u64,
}

fn table(elf: &Elf, section: &Section, min: u64) -> Table {
    let entsize = section.entsize.max(min);
    let span = elf.data(section);
    Table {
        span,
        entsize,
        count: span.len.checked_div(entsize).unwrap_or(0),
    }
}

pub(super) fn table_node(elf: &Elf, section: &Section) -> Node {
    let t = table(elf, section, elf.class.sym_size());
    let label = if section.kind == SHT_DYNSYM {
        "Dynamic Symbols"
    } else {
        "Symbols"
    };
    Node::new(format!("{label} ({})", section.label()))
        .span(t.span)
        .summary(format!("{} symbols", t.count))
        .lazy(symbols, (elf.clone(), section.index))
}

/// The string table a section links to.
fn linked_strings(elf: &Elf, section: &Section) -> Option<Span> {
    let strtab = elf.section(section.link)?;
    (strtab.kind == SHT_STRTAB && section.link != 0).then(|| elf.data(strtab))
}

async fn string_at(cx: &Cx, strtab: Option<Span>, offset: u64) -> Result<String> {
    let strtab = strtab.ok_or_else(|| Diagnostic::malformed("no string table"))?;
    if offset >= strtab.len {
        return Err(Diagnostic::malformed(format!(
            "string offset {offset:#x} is outside the string table"
        )));
    }
    Ok(cx.cstr(strtab.tail(offset).sub(0, MAX_NAME)).await?.0)
}

async fn symbol_name(
    cx: &Cx,
    elf: &Elf,
    sym: &Symbol,
    strtab: Option<Span>,
) -> std::result::Result<String, Diagnostic> {
    if sym.name == 0 {
        if sym.kind() == STT_SECTION {
            return Ok(section_ref(elf, sym.shndx));
        }
        return Ok(String::new());
    }
    string_at(cx, strtab, sym.name.into()).await
}

async fn symbols(cx: Cx, (elf, index): (Elf, u32)) -> Result<()> {
    let section = elf
        .section(index)
        .ok_or_else(|| Diagnostic::internal("section index out of range"))?;
    let t = table(&elf, section, elf.class.sym_size());
    let strtab = linked_strings(&elf, section);
    cx.set_count(Count::Exact(t.count));
    for i in 0..t.count {
        let span = t.span.sub(i.saturating_mul(t.entsize), elf.class.sym_size());
        let sym = parse(&cx, span, elf.endian(), &elf, symbol).await?;
        let (label, diag) = match symbol_name(&cx, &elf, &sym, strtab).await {
            Ok(name) if name.is_empty() => (format!("#{i}"), None),
            Ok(name) => (name, None),
            Err(e) => (format!("#{i}"), Some(e)),
        };
        let mut node = struct_node(label, span, elf.endian(), elf.clone(), symbol)
            .value(hex(sym.value, elf.class.bits()))
            .summary(symbol_summary(&elf, &sym));
        if let Some(target) = sym_target(&elf, &sym) {
            node = node.target(target);
        }
        if let Some(d) = diag {
            node = node.diag(d);
        }
        cx.push(node).await;
    }
    Ok(())
}

fn symbol_summary(elf: &Elf, sym: &Symbol) -> String {
    let mut out = format!(
        "{} {} {} {}",
        name_or(SYMBOL_TYPE, sym.kind().into(), "type"),
        name_or(SYMBOL_BIND, sym.bind().into(), "bind"),
        name_or(SYMBOL_VISIBILITY, (sym.other & 3).into(), "visibility"),
        section_ref(elf, sym.shndx)
    );
    if sym.size != 0 {
        out.push_str(&format!(", {} bytes", sym.size));
    }
    out
}

/// Where a defined symbol's bytes are in the file.
fn sym_target(elf: &Elf, sym: &Symbol) -> Option<Span> {
    if sym.shndx == 0 || sym.shndx >= SHN_LORESERVE || sym.kind() == STT_SECTION {
        return None;
    }
    if elf.header.kind == ET_REL {
        let section = elf.section(sym.shndx.into())?;
        section
            .has_data()
            .then(|| elf.data(section).sub(sym.value, sym.size))
    } else {
        elf.vaddr_span(sym.value, sym.size)
    }
}

// ---------------------------------------------------------------------------
// Relocations

#[derive(Clone)]
struct RelCtx {
    elf: Elf,
    rela: bool,
}

#[derive(Clone, Copy, Debug)]
struct Relocation {
    offset: u64,
    sym: u64,
    kind: u64,
    addend: Option<i64>,
}

fn split_info(elf: &Elf, info: u64) -> (u64, u64) {
    if !elf.class.wide {
        (info >> 8, info & 0xff)
    } else if elf.header.machine == EM_MIPS && elf.class.endian == crate::fields::Endian::Little {
        // MIPS64 little-endian stores r_sym first, then four type bytes.
        (info & 0xffff_ffff, info >> 56)
    } else {
        (info >> 32, info & 0xffff_ffff)
    }
}

fn relocation(f: &mut Fields<'_>, c: &RelCtx) -> Result<Relocation> {
    let elf = &c.elf;
    let wide = elf.class.wide;
    let offset = f
        .uword("r_offset", wide)
        .hex()
        .desc("Where to apply the relocation (section offset or virtual address)")
        .emit()?;
    let info = f
        .uword("r_info", wide)
        .hex()
        .with(|&v, n| {
            let (sym, kind) = split_info(elf, v);
            n.summary(format!(
                "symbol {sym}, type {}",
                name_or(elf.relocation_types(), kind, "")
            ))
        })
        .desc("Symbol index and relocation type")
        .emit()?;
    let addend = if c.rela {
        Some(if wide {
            f.int::<i64>("r_addend").emit()?
        } else {
            f.int::<i32>("r_addend").emit()?.into()
        })
    } else {
        None
    };
    let (sym, kind) = split_info(elf, info);
    Ok(Relocation {
        offset,
        sym,
        kind,
        addend,
    })
}

pub(super) fn relocations_node(elf: &Elf, section: &Section) -> Node {
    let rela = section.kind == SHT_RELA;
    let t = table(elf, section, elf.class.rel_size(rela));
    Node::new("Relocations")
        .span(t.span)
        .summary(format!("{} entries", t.count))
        .lazy(relocations, (elf.clone(), section.index))
}

async fn relocations(cx: Cx, (elf, index): (Elf, u32)) -> Result<()> {
    let section = elf
        .section(index)
        .ok_or_else(|| Diagnostic::internal("section index out of range"))?;
    let rela = section.kind == SHT_RELA;
    let size = elf.class.rel_size(rela);
    let t = table(&elf, section, size);
    let symtab = elf.section(section.link).filter(|_| section.link != 0);
    let strtab = symtab.and_then(|s| linked_strings(&elf, s));
    let ctx = RelCtx {
        elf: elf.clone(),
        rela,
    };
    cx.set_count(Count::Exact(t.count));
    for i in 0..t.count {
        let span = t.span.sub(i.saturating_mul(t.entsize), size);
        let r = parse(&cx, span, elf.endian(), &ctx, relocation).await?;
        let mut target = String::new();
        let mut node_diag = None;
        if r.sym != 0
            && let Some(symtab) = symtab
        {
            let st = table(&elf, symtab, elf.class.sym_size());
            let at = st.span.sub(r.sym.saturating_mul(st.entsize), elf.class.sym_size());
            match parse(&cx, at, elf.endian(), &elf, symbol).await {
                Ok(sym) => match symbol_name(&cx, &elf, &sym, strtab).await {
                    Ok(name) => target = name,
                    Err(e) => node_diag = Some(e),
                },
                Err(e) => node_diag = Some(e),
            }
        }
        let addend = match r.addend {
            Some(a) if a < 0 => format!(" - {:#x}", a.unsigned_abs()),
            Some(a) => format!(" + {a:#x}"),
            None => String::new(),
        };
        let label = name_or(elf.relocation_types(), r.kind, "type");
        let mut node = struct_node(label, span, elf.endian(), ctx.clone(), relocation)
            .value(hex(r.offset, elf.class.bits()))
            .summary(if target.is_empty() && r.addend.is_none() {
                String::new()
            } else {
                format!("{target}{addend}")
            });
        if let Some(d) = node_diag {
            node = node.diag(d);
        }
        cx.push(node).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Dynamic section

#[derive(Clone, Copy, Debug)]
struct DynCtx {
    class: Class,
}

fn dyn_entry(f: &mut Fields<'_>, c: &DynCtx) -> Result<(u64, u64)> {
    let wide = c.class.wide;
    let tag = f.uword("d_tag", wide).enumeration(DYNAMIC_TAG).emit()?;
    let value = f.uword("d_val", wide);
    let value = match tag {
        DT_FLAGS => value.flags(DYNAMIC_FLAGS),
        DT_FLAGS_1 => value.flags(DYNAMIC_FLAGS_1),
        DT_POSFLAG_1 => value.flags(POSFLAGS_1),
        t if DT_ADDRESSES.contains(&t) || DT_STRINGS.contains(&t) => value.hex(),
        _ => value,
    };
    let value = value.emit()?;
    Ok((tag, value))
}

pub(super) async fn dynamic(cx: Cx, (elf, span, link): (Elf, Span, Option<u32>)) -> Result<()> {
    let data = cx.read_avail(span.sub(0, MAX_DYNAMIC)).await?;
    let size = elf.class.dyn_size();
    let entries: Vec<(u64, u64)> = (0..to_u64(data.len()).checked_div(size).unwrap_or(0))
        .map_while(|i| {
            let at = i.saturating_mul(size);
            let tag = super::word(&data, at, elf.class)?;
            let val = super::word(&data, at.saturating_add(elf.class.word()), elf.class)?;
            Some((tag, val))
        })
        .collect();
    let count = entries
        .iter()
        .position(|&(tag, _)| tag == DT_NULL)
        .map_or(entries.len(), |p| p.saturating_add(1));

    // The string table: DT_STRTAB/DT_STRSZ, else the section's sh_link.
    let find = |wanted: u64| entries.iter().find(|&&(t, _)| t == wanted).map(|&(_, v)| v);
    let strtab = match (find(DT_STRTAB), find(DT_STRSZ)) {
        (Some(addr), Some(len)) => elf.vaddr_span(addr, len),
        _ => None,
    }
    .or_else(|| {
        let s = elf.section(link?)?;
        (s.kind == SHT_STRTAB).then(|| elf.data(s))
    });

    let mut needed = Vec::new();
    for &(tag, val) in entries.iter().take(count) {
        if tag == DT_NEEDED
            && needed.len() < 8
            && let Ok(name) = string_at(&cx, strtab, val).await
        {
            needed.push(name);
        }
    }
    if !needed.is_empty() {
        cx.annotate(format!("needs {}", needed.join(", ")));
    }

    cx.set_count(Count::Exact(to_u64(count)));
    let ctx = DynCtx { class: elf.class };
    for (i, &(tag, val)) in entries.iter().take(count).enumerate() {
        let entry = span.sub(to_u64(i).saturating_mul(size), size);
        let name = lookup(DYNAMIC_TAG, tag).map_or_else(|| format!("{tag:#x}"), str::to_owned);
        let mut node = struct_node(name, entry, elf.endian(), ctx, dyn_entry);
        if DT_STRINGS.contains(&tag) {
            node = match string_at(&cx, strtab, val).await {
                Ok(s) => node.value(text(s)),
                Err(e) => node.value(hex(val, elf.class.bits())).diag(e),
            };
        } else if let Some(table) = match tag {
            DT_FLAGS => Some(DYNAMIC_FLAGS),
            DT_FLAGS_1 => Some(DYNAMIC_FLAGS_1),
            DT_POSFLAG_1 => Some(POSFLAGS_1),
            _ => None,
        } {
            let (set, unknown) = decode_flags(table, val);
            node = node.value(Value::Flags {
                raw: val,
                bits: elf.class.bits(),
                set,
                unknown,
            });
        } else if DT_ADDRESSES.contains(&tag) {
            node = node.value(hex(val, elf.class.bits()));
            if let Some(at) = elf.vaddr_span(val, 0) {
                node = node.target(at);
            }
        } else {
            node = node.value(crate::formats::binutil::dec(val, elf.class.bits()));
        }
        cx.push(node).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Simple sections

/// NUL-terminated strings, listed by offset.
pub(super) async fn strings(cx: Cx, span: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, crate::fields::Endian::Little);
    while !cur.at_end() {
        let start = cur.pos();
        let (s, at) = cur.cstr(MAX_NAME).await?;
        if s.is_empty() {
            continue;
        }
        cx.push(
            Node::new(format!("{start:#x}"))
                .span(at)
                .value(text(s)),
        )
        .await;
    }
    Ok(())
}

/// Arrays of code pointers (`.init_array` and friends).
pub(super) async fn pointers(cx: Cx, (elf, span): (Elf, Span)) -> Result<()> {
    let word = elf.class.word();
    let count = span.len.checked_div(word).unwrap_or(0);
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let at = span.sub(i.saturating_mul(word), word);
        let data = cx.read(at).await?;
        let value = super::word(&data, 0, elf.class).unwrap_or(0);
        let mut node = Node::new(format!("[{i}]"))
            .span(at)
            .value(hex(value, elf.class.bits()));
        if let Some(t) = elf.vaddr_span(value, 0) {
            node = node.target(t);
        }
        cx.push(node).await;
    }
    Ok(())
}

/// `SHT_GROUP`: a flag word, then the member section indices.
pub(super) async fn group(cx: Cx, (elf, span): (Elf, Span)) -> Result<()> {
    let endian = elf.endian();
    let flags = cx.block(span.sub(0, 4)).await?;
    Fields::emitting(&cx, &flags, endian)
        .u32("Flags")
        .flags(GROUP_FLAGS)
        .emit()?;
    let count = span.len.saturating_sub(4) / 4;
    for i in 0..count {
        let at = span.sub(i.saturating_add(1).saturating_mul(4), 4);
        let data = cx.read(at).await?;
        let index = get_at::<u32>(&data, 0, endian).unwrap_or(0);
        cx.push(
            Node::new(format!("Member {i}"))
                .span(at)
                .value(crate::formats::binutil::dec(index.into(), 32))
                .summary(elf.section_name(index)),
        )
        .await;
    }
    Ok(())
}

/// `.gnu_debuglink` (file name and CRC) and `.gnu_debugaltlink` (file name
/// and build ID).
pub(super) async fn debuglink(cx: Cx, (class, span): (Class, Span)) -> Result<()> {
    let (name, at) = cx.cstr(span.sub(0, MAX_NAME)).await?;
    cx.annotate(name.clone());
    cx.emit(Node::new("File name").span(at).value(text(name)));
    let rest = at.len.next_multiple_of(4);
    if span.len == rest.saturating_add(4) {
        let crc = span.sub(rest, 4);
        let block = cx.block(crc).await?;
        Fields::emitting(&cx, &block, class.endian)
            .u32("CRC-32")
            .hex()
            .emit()?;
    } else if span.len > at.len {
        let id = span.tail(at.len);
        let bytes = cx.read(id).await?;
        cx.emit(
            Node::new("Build ID")
                .span(id)
                .value(text(crate::formats::binutil::hex_string(&bytes))),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Symbol versioning

record! {
    struct Verneed {
        version: u16 "vn_version",
        count: u16 "vn_cnt" .desc("Number of Vernaux entries"),
        file: u32 "vn_file" .hex() .desc("Offset of the library name"),
        aux: u32 "vn_aux" .hex() .desc("Offset of the first Vernaux, from this entry"),
        next: u32 "vn_next" .hex() .desc("Offset of the next Verneed, from this entry"),
    }
}

record! {
    struct Vernaux {
        hash: u32 "vna_hash" .hex(),
        flags: u16 "vna_flags" .flags(VERSION_FLAGS),
        other: u16 "vna_other" .desc("Version index used in .gnu.version"),
        name: u32 "vna_name" .hex(),
        next: u32 "vna_next" .hex(),
    }
}

record! {
    struct Verdef {
        version: u16 "vd_version",
        flags: u16 "vd_flags" .flags(VERSION_FLAGS),
        index: u16 "vd_ndx" .desc("Version index used in .gnu.version"),
        count: u16 "vd_cnt",
        hash: u32 "vd_hash" .hex(),
        aux: u32 "vd_aux" .hex(),
        next: u32 "vd_next" .hex(),
    }
}

record! {
    struct Verdaux {
        name: u32 "vda_name" .hex(),
        next: u32 "vda_next" .hex(),
    }
}

/// Walks a chain of records linked by relative `next` offsets.
fn chain_step(offset: u64, next: u32, region: Span) -> Option<u64> {
    if next == 0 {
        return None;
    }
    let pos = offset.checked_add(next.into())?;
    (pos < region.len).then_some(pos)
}

pub(super) async fn verneed(cx: Cx, (elf, index): (Elf, u32)) -> Result<()> {
    let section = elf
        .section(index)
        .ok_or_else(|| Diagnostic::internal("section index out of range"))?;
    let span = elf.data(section);
    let strtab = linked_strings(&elf, section);
    let endian = elf.endian();
    let mut offset = Some(0u64);
    let mut seen = 0u32;
    while let Some(at) = offset {
        if seen >= MAX_VERSIONS.min(section.info.max(1)) {
            break;
        }
        seen = seen.saturating_add(1);
        let head = span.sub(at, Verneed::SIZE);
        let need = parse(&cx, head, endian, &(), Verneed::layout).await?;
        let file = string_at(&cx, strtab, need.file.into()).await;
        let mut versions = Vec::new();
        let mut aux = chain_step(at, need.aux, span);
        for _ in 0..need.count.min(256) {
            let Some(a) = aux else { break };
            let entry = span.sub(a, Vernaux::SIZE);
            let v = parse(&cx, entry, endian, &(), Vernaux::layout).await?;
            let name = string_at(&cx, strtab, v.name.into())
                .await
                .unwrap_or_else(|_| format!("#{}", v.other));
            versions.push((name, entry));
            aux = chain_step(a, v.next, span);
        }
        let names: Vec<&str> = versions.iter().map(|(n, _)| n.as_str()).collect();
        let summary = ellipsize(&names.join(", "), 120);
        let label = file.unwrap_or_else(|_| "<unreadable name>".to_owned());
        cx.push(
            Node::new(label)
                .span(head)
                .summary(summary)
                .lazy(version_entry, (head, versions, true, endian)),
        )
        .await;
        offset = chain_step(at, need.next, span);
    }
    Ok(())
}

pub(super) async fn verdef(cx: Cx, (elf, index): (Elf, u32)) -> Result<()> {
    let section = elf
        .section(index)
        .ok_or_else(|| Diagnostic::internal("section index out of range"))?;
    let span = elf.data(section);
    let strtab = linked_strings(&elf, section);
    let endian = elf.endian();
    let mut offset = Some(0u64);
    let mut seen = 0u32;
    while let Some(at) = offset {
        if seen >= MAX_VERSIONS.min(section.info.max(1)) {
            break;
        }
        seen = seen.saturating_add(1);
        let head = span.sub(at, Verdef::SIZE);
        let def = parse(&cx, head, endian, &(), Verdef::layout).await?;
        let mut names = Vec::new();
        let mut aux = chain_step(at, def.aux, span);
        for _ in 0..def.count.min(256) {
            let Some(a) = aux else { break };
            let entry = span.sub(a, Verdaux::SIZE);
            let v = parse(&cx, entry, endian, &(), Verdaux::layout).await?;
            let name = string_at(&cx, strtab, v.name.into())
                .await
                .unwrap_or_else(|_| "<unreadable>".to_owned());
            names.push((name, entry));
            aux = chain_step(a, v.next, span);
        }
        let label = names
            .first()
            .map_or_else(|| format!("#{}", def.index), |(n, _)| n.clone());
        let mut summary = format!("index {}", def.index);
        if def.flags & 1 != 0 {
            summary.push_str(", base");
        }
        if names.len() > 1 {
            let parents: Vec<&str> = names.iter().skip(1).map(|(n, _)| n.as_str()).collect();
            summary.push_str(&format!(", parent {}", parents.join(", ")));
        }
        cx.push(
            Node::new(label)
                .span(head)
                .summary(summary)
                .lazy(version_entry, (head, names, false, endian)),
        )
        .await;
        offset = chain_step(at, def.next, span);
    }
    Ok(())
}

async fn version_entry(
    cx: Cx,
    (head, versions, need, endian): (Span, Vec<(String, Span)>, bool, crate::fields::Endian),
) -> Result<()> {
    if need {
        cx.emit(Verneed::node("Verneed", head, endian));
    } else {
        cx.emit(Verdef::node("Verdef", head, endian));
    }
    for (name, span) in versions {
        cx.emit(if need {
            Vernaux::node(name, span, endian)
        } else {
            Verdaux::node(name, span, endian)
        });
    }
    Ok(())
}
