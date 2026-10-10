//! COFF object files (`.obj` from MSVC, clang-cl, MinGW), in the regular
//! and `/bigobj` layouts, and the short import records that make up import
//! libraries (`.lib` members starting `00 00 FF FF`).
//!
//! The file header gives the section table and the symbol table; the string
//! table follows the symbols. Expanding the file reads the headers and the
//! string table (for long names); sections, relocations and symbols are
//! decoded on expansion.

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u16_le, u32_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::executable::pe::tables::{
    FILE_CHARACTERISTICS, MACHINE, SECTION_CHARACTERISTICS,
};
use crate::formats::util::binutil::{cstrings, data_node};
use crate::formats::util::fmt::clip;
use crate::formats::util::val::{hex, name_or, text};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, lookup};

const LE: Endian = Endian::Little;
/// Largest string table we load.
const MAX_STRINGS: u64 = 4 << 20;
const BIGOBJ_CLASS_ID: [u8; 16] = [
    0xc7, 0xa1, 0xba, 0xd1, 0xee, 0xba, 0xa9, 0x4b, 0xaf, 0x20, 0xfa, 0xf6, 0x6a, 0xa4, 0xdc, 0xb8,
];

pub static FORMAT: Format = Format {
    name: "coff",
    title: "COFF object file",
    extensions: &["obj", "o"],
    mime: "application/x-coff",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

pub static IMPORT: Format = Format {
    name: "coff-import",
    title: "COFF short import record (import library member)",
    extensions: &[],
    mime: "application/octet-stream",
    probe: Probe::Custom(|h| {
        h.starts_with(b"\0\0\xff\xff")
            && u16_le(h.data, 4) == Some(0)
            && u16_le(h.data, 6).is_some_and(known_machine)
    }),
    dissect: crate::expander!(import: Input),
};

/// Machines that produce COFF objects.
fn known_machine(m: u16) -> bool {
    matches!(
        m,
        0x14c
            | 0x8664
            | 0x1c0
            | 0x1c2
            | 0x1c4
            | 0xaa64
            | 0xa641
            | 0xa64e
            | 0x200
            | 0x5032
            | 0x5064
            | 0x1f0
            | 0x1f1
            | 0x166
            | 0x169
            | 0x1a2
            | 0x1a6
            | 0xebc
    )
}

fn probe(h: &Head<'_>) -> bool {
    if h.starts_with(b"\0\0\xff\xff") {
        return u16_le(h.data, 4).is_some_and(|v| v >= 2)
            && h.at(12, &BIGOBJ_CLASS_ID)
            && u16_le(h.data, 6).is_some_and(known_machine);
    }
    let (Some(machine), Some(sections), Some(symptr), Some(nsyms), Some(optional)) = (
        u16_le(h.data, 0),
        u16_le(h.data, 2),
        u32_le(h.data, 8),
        u32_le(h.data, 12),
        u16_le(h.data, 16),
    ) else {
        return false;
    };
    let table_end = 20u64.saturating_add(u64::from(sections).saturating_mul(40));
    let symbols_end = u64::from(symptr).saturating_add(u64::from(nsyms).saturating_mul(18));
    let first_name = h.data.get(20..28).unwrap_or_default();
    known_machine(machine)
        && (1..=0x1000).contains(&sections)
        && optional == 0
        && table_end <= h.len
        && (symptr == 0 || (u64::from(symptr) >= table_end && symbols_end <= h.len))
        && first_name.iter().all(|&b| b == 0 || b.is_ascii_graphic())
        && first_name.first().is_some_and(|&b| b != 0)
}

const STORAGE_CLASS: EnumTable = &[
    (0, "NULL"),
    (1, "AUTOMATIC"),
    (2, "EXTERNAL"),
    (3, "STATIC"),
    (4, "REGISTER"),
    (5, "EXTERNAL_DEF"),
    (6, "LABEL"),
    (7, "UNDEFINED_LABEL"),
    (8, "MEMBER_OF_STRUCT"),
    (9, "ARGUMENT"),
    (10, "STRUCT_TAG"),
    (11, "MEMBER_OF_UNION"),
    (12, "UNION_TAG"),
    (13, "TYPE_DEFINITION"),
    (14, "UNDEFINED_STATIC"),
    (15, "ENUM_TAG"),
    (16, "MEMBER_OF_ENUM"),
    (17, "REGISTER_PARAM"),
    (18, "BIT_FIELD"),
    (100, "BLOCK"),
    (101, "FUNCTION"),
    (102, "END_OF_STRUCT"),
    (103, "FILE"),
    (104, "SECTION"),
    (105, "WEAK_EXTERNAL"),
    (107, "CLR_TOKEN"),
    (0xff, "END_OF_FUNCTION"),
];

const COMDAT_SELECTION: EnumTable = &[
    (0, "none"),
    (1, "NODUPLICATES"),
    (2, "ANY"),
    (3, "SAME_SIZE"),
    (4, "EXACT_MATCH"),
    (5, "ASSOCIATIVE"),
    (6, "LARGEST"),
];

const WEAK_SEARCH: EnumTable = &[
    (1, "NOLIBRARY"),
    (2, "LIBRARY"),
    (3, "ALIAS"),
    (4, "ANTI_DEPENDENCY"),
];

const IMPORT_TYPE: EnumTable = &[(0, "CODE"), (1, "DATA"), (2, "CONST")];

const IMPORT_NAME_TYPE: EnumTable = &[
    (0, "ORDINAL"),
    (1, "NAME"),
    (2, "NAME_NOPREFIX"),
    (3, "NAME_UNDECORATE"),
    (4, "NAME_EXPORTAS"),
];

const REL_AMD64: EnumTable = &[
    (0x0, "ABSOLUTE"),
    (0x1, "ADDR64"),
    (0x2, "ADDR32"),
    (0x3, "ADDR32NB"),
    (0x4, "REL32"),
    (0x5, "REL32_1"),
    (0x6, "REL32_2"),
    (0x7, "REL32_3"),
    (0x8, "REL32_4"),
    (0x9, "REL32_5"),
    (0xa, "SECTION"),
    (0xb, "SECREL"),
    (0xc, "SECREL7"),
    (0xd, "TOKEN"),
    (0xe, "SREL32"),
    (0xf, "PAIR"),
    (0x10, "SSPAN32"),
];

const REL_I386: EnumTable = &[
    (0x0, "ABSOLUTE"),
    (0x1, "DIR16"),
    (0x2, "REL16"),
    (0x6, "DIR32"),
    (0x7, "DIR32NB"),
    (0x9, "SEG12"),
    (0xa, "SECTION"),
    (0xb, "SECREL"),
    (0xc, "TOKEN"),
    (0xd, "SECREL7"),
    (0x14, "REL32"),
];

const REL_ARM64: EnumTable = &[
    (0x0, "ABSOLUTE"),
    (0x1, "ADDR32"),
    (0x2, "ADDR32NB"),
    (0x3, "BRANCH26"),
    (0x4, "PAGEBASE_REL21"),
    (0x5, "REL21"),
    (0x6, "PAGEOFFSET_12A"),
    (0x7, "PAGEOFFSET_12L"),
    (0x8, "SECREL"),
    (0x9, "SECREL_LOW12A"),
    (0xa, "SECREL_HIGH12A"),
    (0xb, "SECREL_LOW12L"),
    (0xc, "TOKEN"),
    (0xd, "SECTION"),
    (0xe, "ADDR64"),
    (0xf, "BRANCH19"),
    (0x10, "BRANCH14"),
    (0x11, "REL32"),
];

const REL_ARM: EnumTable = &[
    (0x0, "ABSOLUTE"),
    (0x1, "ADDR32"),
    (0x2, "ADDR32NB"),
    (0x3, "BRANCH24"),
    (0x4, "BRANCH11"),
    (0xa, "REL32"),
    (0xe, "SECTION"),
    (0xf, "SECREL"),
    (0x10, "MOV32"),
    (0x11, "THUMB_MOV32"),
    (0x12, "THUMB_BRANCH20"),
    (0x14, "THUMB_BRANCH24"),
    (0x15, "THUMB_BLX23"),
    (0x16, "PAIR"),
];

fn relocation_types(machine: u16) -> EnumTable {
    match machine {
        0x8664 => REL_AMD64,
        0x14c => REL_I386,
        0xaa64 | 0xa641 | 0xa64e => REL_ARM64,
        0x1c0 | 0x1c2 | 0x1c4 => REL_ARM,
        _ => &[],
    }
}

// ---------------------------------------------------------------------------
// Model

#[derive(Clone, Debug)]
struct Section {
    header: Span,
    name: String,
    raw_size: u32,
    raw_ptr: u32,
    reloc_ptr: u32,
    nreloc: u16,
    chars: u32,
}

type Coff = Arc<CoffInfo>;

struct CoffInfo {
    file: Span,
    big: bool,
    machine: u16,
    sections: Vec<Section>,
    symbols: Span,
    nsyms: u32,
    strings: Vec<u8>,
}

impl CoffInfo {
    fn record(&self) -> u64 {
        if self.big { 20 } else { 18 }
    }

    fn string(&self, offset: u32) -> Option<String> {
        self.strings
            .get(to_usize(offset.into())..)
            .map(crate::text::until_nul)
    }

    /// A short name field: inline, or `/offset` into the string table.
    fn section_name(&self, raw: &[u8]) -> String {
        let inline = crate::text::until_nul(raw);
        match inline.strip_prefix('/').and_then(|n| n.parse::<u32>().ok()) {
            Some(offset) => self.string(offset).unwrap_or(inline),
            None => inline,
        }
    }

    /// A symbol name field: inline, or zeros and a string table offset.
    fn symbol_name(&self, raw: &[u8]) -> String {
        if raw.get(..4) == Some(&[0, 0, 0, 0]) {
            let offset = u32_le(raw, 4).unwrap_or(0);
            self.string(offset)
                .unwrap_or_else(|| format!("<string {offset:#x}>"))
        } else {
            crate::text::until_nul(raw)
        }
    }

    fn section_label(&self, number: i32) -> String {
        match number {
            0 => "UNDEF".to_owned(),
            -1 => "ABS".to_owned(),
            -2 => "DEBUG".to_owned(),
            n => usize::try_from(n)
                .ok()
                .and_then(|n| n.checked_sub(1))
                .and_then(|i| self.sections.get(i))
                .map_or_else(|| format!("section {n}"), |s| s.name.clone()),
        }
    }

    fn symbol_span(&self, index: u32) -> Span {
        self.symbols.sub(
            u64::from(index).saturating_mul(self.record()),
            self.record(),
        )
    }
}

// ---------------------------------------------------------------------------
// Headers

#[derive(Clone, Copy, Debug)]
struct Header {
    machine: u16,
    sections: u32,
    symptr: u32,
    nsyms: u32,
    size: u64,
}

fn file_header(f: &mut Fields<'_>, _: &()) -> Result<Header> {
    let machine = f.u16("Machine").enumeration(MACHINE).emit()?;
    let sections = f.u16("NumberOfSections").emit()?;
    f.u32("TimeDateStamp").timestamp().emit()?;
    let symptr = f.u32("PointerToSymbolTable").hex().emit()?;
    let nsyms = f
        .u32("NumberOfSymbols")
        .desc("Including auxiliary records")
        .emit()?;
    f.u16("SizeOfOptionalHeader").emit()?;
    f.u16("Characteristics")
        .flags(FILE_CHARACTERISTICS)
        .emit()?;
    Ok(Header {
        machine,
        sections: sections.into(),
        symptr,
        nsyms,
        size: 20,
    })
}

fn bigobj_header(f: &mut Fields<'_>, _: &()) -> Result<Header> {
    f.u16("Sig1").hex().emit()?;
    f.u16("Sig2").hex().emit()?;
    f.u16("Version").emit()?;
    let machine = f.u16("Machine").enumeration(MACHINE).emit()?;
    f.u32("TimeDateStamp").timestamp().emit()?;
    f.guid("ClassID")
        .desc("{d1baa1c7-baee-4ba9-af20-faf66aa4dcb8} for /bigobj")
        .emit()?;
    f.u32("SizeOfData").emit()?;
    f.u32("Flags").hex().emit()?;
    f.u32("MetaDataSize").emit()?;
    f.u32("MetaDataOffset").hex().emit()?;
    let sections = f.u32("NumberOfSections").emit()?;
    let symptr = f.u32("PointerToSymbolTable").hex().emit()?;
    let nsyms = f.u32("NumberOfSymbols").emit()?;
    Ok(Header {
        machine,
        sections,
        symptr,
        nsyms,
        size: 56,
    })
}

fn section_header(f: &mut Fields<'_>, c: &Coff) -> Result<()> {
    let raw = f.block().data.get(..8).unwrap_or_default().to_vec();
    f.bytes("Name", 8)
        .with(|_, n| n.value(text(c.section_name(&raw))))
        .emit()?;
    f.u32("VirtualSize").hex().emit()?;
    f.u32("VirtualAddress").hex().emit()?;
    let size = f.u32("SizeOfRawData").hex().emit()?;
    let file = c.file;
    f.u32("PointerToRawData")
        .hex()
        .with(|&p, n| {
            if p == 0 {
                n
            } else {
                n.target(file.sub(p.into(), size.into()))
            }
        })
        .emit()?;
    f.u32("PointerToRelocations").hex().emit()?;
    f.u32("PointerToLinenumbers").hex().emit()?;
    f.u16("NumberOfRelocations").emit()?;
    f.u16("NumberOfLinenumbers").emit()?;
    f.u32("Characteristics")
        .flags(SECTION_CHARACTERISTICS)
        .emit()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Entry point

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 4)).await?;
    let big = head.starts_with(b"\0\0\xff\xff");
    let layout: crate::fields::Layout<(), Header> = if big { bigobj_header } else { file_header };
    let header_span = file.sub(0, if big { 56 } else { 20 });
    cx.emit(struct_node(
        if big { "Bigobj Header" } else { "File Header" },
        header_span,
        LE,
        (),
        layout,
    ));
    let h = parse(&cx, header_span, LE, &(), layout).await?;
    let record: u64 = if big { 20 } else { 18 };

    let table = file.sub_exact(h.size, u64::from(h.sections).saturating_mul(40))?;
    let symbols = file.sub(h.symptr.into(), u64::from(h.nsyms).saturating_mul(record));
    let strings_at = u64::from(h.symptr).saturating_add(u64::from(h.nsyms).saturating_mul(record));
    let mut strings = Vec::new();
    if h.symptr != 0 {
        let size = cx.read_avail(file.sub(strings_at, 4)).await?;
        let size = u64::from(u32_le(&size, 0).unwrap_or(0)).min(MAX_STRINGS);
        strings = cx.read_avail(file.sub(strings_at, size)).await?;
    }
    let mut info = CoffInfo {
        file,
        big,
        machine: h.machine,
        sections: Vec::new(),
        symbols,
        nsyms: u32::try_from(symbols.len.checked_div(record).unwrap_or(0)).unwrap_or(0),
        strings,
    };
    let block = cx.block(table).await?;
    for i in 0..u64::from(h.sections) {
        cx.checkpoint().await;
        let at = to_usize(i.saturating_mul(40));
        let d = block
            .data
            .get(at..at.saturating_add(40))
            .unwrap_or_default();
        info.sections.push(Section {
            header: table.sub(i.saturating_mul(40), 40),
            name: info.section_name(d.get(..8).unwrap_or_default()),
            raw_size: u32_le(d, 16).unwrap_or(0),
            raw_ptr: u32_le(d, 20).unwrap_or(0),
            reloc_ptr: u32_le(d, 24).unwrap_or(0),
            nreloc: u16_le(d, 32).unwrap_or(0),
            chars: u32_le(d, 36).unwrap_or(0),
        });
    }
    let c: Coff = Arc::new(info);

    let mut summary = format!(
        "COFF object{}, {}, {} sections, {} symbols",
        if big { " (bigobj)" } else { "" },
        lookup(MACHINE, h.machine.into()).unwrap_or("unknown machine"),
        h.sections,
        h.nsyms
    );
    let directives = c.sections.iter().find(|s| s.name == ".drectve");
    let mut directive_text = None;
    if let Some(s) = directives {
        let span = file.sub(s.raw_ptr.into(), s.raw_size.into());
        let bytes = cx.read_avail(span.sub(0, 0x10000)).await?;
        let t = String::from_utf8_lossy(&bytes).trim().to_owned();
        summary.push_str(&format!(", directives: {}", clip(&t, 80)));
        directive_text = Some((t, span));
    }
    cx.annotate(summary);

    cx.emit(
        Node::new("Section Table")
            .span(table)
            .summary(format!("{} sections", c.sections.len()))
            .lazy(section_list, c.clone()),
    );
    if let Some((t, span)) = directive_text {
        cx.emit(
            Node::new("Linker Directives")
                .span(span)
                .value(text(t))
                .desc("Contents of .drectve: options passed to the linker"),
        );
    }
    if h.symptr != 0 {
        cx.emit(
            Node::new("Symbol Table")
                .span(symbols)
                .summary(format!("{} records", c.nsyms))
                .lazy(symbol_list, c.clone()),
        );
        let strtab = file.sub(strings_at, to_u64(c.strings.len()));
        cx.emit(
            Node::new("String Table")
                .span(strtab)
                .lazy(cstrings, strtab.tail(4)),
        );
    }
    Ok(())
}

async fn section_list(cx: Cx, c: Coff) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(c.sections.len())));
    for (i, s) in c.sections.iter().enumerate() {
        let flag = |bit: u32, ch: char| if s.chars & bit != 0 { ch } else { '-' };
        let summary = format!(
            "{}{}{}  {:#x} bytes at {:#x}, {} relocations",
            flag(0x4000_0000, 'r'),
            flag(0x8000_0000, 'w'),
            flag(0x2000_0000, 'x'),
            s.raw_size,
            s.raw_ptr,
            s.nreloc
        );
        cx.push(
            Node::new(s.name.clone())
                .span(s.header)
                .summary(summary)
                .lazy(section_node, (c.clone(), i)),
        )
        .await;
    }
    Ok(())
}

async fn section_node(cx: Cx, (c, index): (Coff, usize)) -> Result<()> {
    let s = c
        .sections
        .get(index)
        .ok_or_else(|| Diagnostic::internal("section index out of range"))?;
    let block = cx.block(s.header).await?;
    section_header(&mut Fields::emitting(&cx, &block, LE), &c)?;
    if s.raw_size > 0 && s.raw_ptr != 0 {
        let data = c.file.sub(s.raw_ptr.into(), s.raw_size.into());
        cx.emit(data_node("Raw Data", data, s.raw_size.into()));
    }
    if s.nreloc > 0 {
        let span = c
            .file
            .sub(s.reloc_ptr.into(), u64::from(s.nreloc).saturating_mul(10));
        cx.emit(
            Node::new("Relocations")
                .span(span)
                .summary(format!("{} entries", s.nreloc))
                .lazy(relocations, (c.clone(), span)),
        );
    }
    Ok(())
}

async fn symbol_name_at(cx: &Cx, c: &CoffInfo, index: u32) -> Result<String> {
    if index >= c.nsyms {
        return Err(Diagnostic::malformed(format!(
            "symbol index {index} out of range"
        )));
    }
    let data = cx.read(c.symbol_span(index).sub(0, 8)).await?;
    Ok(c.symbol_name(&data))
}

async fn relocations(cx: Cx, (c, span): (Coff, Span)) -> Result<()> {
    let count = span.len / 10;
    let types = relocation_types(c.machine);
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let at = span.sub(i.saturating_mul(10), 10);
        let data = cx.read(at).await?;
        let address = u32_le(&data, 0).unwrap_or(0);
        let symbol = u32_le(&data, 4).unwrap_or(0);
        let kind = u16_le(&data, 8).unwrap_or(0);
        let target = symbol_name_at(&cx, &c, symbol)
            .await
            .unwrap_or_else(|_| format!("symbol #{symbol}"));
        cx.push(
            Node::new(name_or(types, kind.into(), "type"))
                .span(at)
                .value(hex(address, 32))
                .summary(target),
        )
        .await;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct Symbol {
    value: u32,
    section: i32,
    kind: u16,
    class: u8,
    aux: u8,
}

fn symbol(f: &mut Fields<'_>, c: &Coff) -> Result<Symbol> {
    let raw = f.block().data.get(..8).unwrap_or_default().to_vec();
    f.bytes("Name", 8)
        .with(|_, n| n.value(text(c.symbol_name(&raw))))
        .emit()?;
    let value = f.u32("Value").hex().emit()?;
    let section = if c.big {
        f.i32("SectionNumber")
            .with(|&v, n| n.summary(c.section_label(v)))
            .emit()?
    } else {
        f.int::<i16>("SectionNumber")
            .with(|&v, n| n.summary(c.section_label(v.into())))
            .emit()?
            .into()
    };
    let kind = f
        .u16("Type")
        .hex()
        .with(|&v, n| {
            if v & 0x30 == 0x20 {
                n.summary("function")
            } else {
                n
            }
        })
        .emit()?;
    let class = f.u8("StorageClass").enumeration(STORAGE_CLASS).emit()?;
    let aux = f.u8("NumberOfAuxSymbols").emit()?;
    Ok(Symbol {
        value,
        section,
        kind,
        class,
        aux,
    })
}

async fn symbol_list(cx: Cx, c: Coff) -> Result<()> {
    let record = c.record();
    let mut index = 0u32;
    while index < c.nsyms {
        let span = c.symbol_span(index);
        let sym = parse(&cx, span, LE, &c, symbol).await?;
        let raw = cx.read(span.sub(0, 8)).await?;
        let mut name = c.symbol_name(&raw);
        if name.is_empty() {
            name = format!("#{index}");
        }
        let aux = u32::from(sym.aux).min(c.nsyms.saturating_sub(index).saturating_sub(1));
        let whole = c.symbols.sub(
            u64::from(index).saturating_mul(record),
            u64::from(aux).saturating_add(1).saturating_mul(record),
        );
        let mut summary = format!(
            "{} {}",
            name_or(STORAGE_CLASS, sym.class.into(), "class"),
            c.section_label(sym.section)
        );
        if sym.kind & 0x30 == 0x20 {
            summary.push_str(" function");
        }
        if aux > 0 {
            summary.push_str(&format!(", {aux} aux"));
        }
        cx.progress(index.into(), c.nsyms.into());
        cx.push(
            Node::new(name)
                .span(whole)
                .value(hex(sym.value, 32))
                .summary(summary)
                .lazy(symbol_node, (c.clone(), index, sym, aux)),
        )
        .await;
        index = index.saturating_add(aux).saturating_add(1);
    }
    Ok(())
}

async fn symbol_node(cx: Cx, (c, index, sym, aux): (Coff, u32, Symbol, u32)) -> Result<()> {
    let span = c.symbol_span(index);
    let block = cx.block(span).await?;
    symbol(&mut Fields::emitting(&cx, &block, LE), &c)?;
    if aux == 0 {
        return Ok(());
    }
    let record = c.record();
    let aux_span = c.symbols.sub(
        u64::from(index).saturating_add(1).saturating_mul(record),
        u64::from(aux).saturating_mul(record),
    );
    if sym.class == 103 {
        // FILE: the aux records hold the file name.
        let bytes = cx.read(aux_span).await?;
        cx.emit(
            Node::new("File name")
                .span(aux_span)
                .value(text(crate::text::until_nul(&bytes))),
        );
        return Ok(());
    }
    let first = aux_span.sub(0, record);
    let section_definition = sym.class == 3 && sym.value == 0 && sym.section > 0;
    let layout: crate::fields::Layout<bool, ()> = if section_definition {
        aux_section
    } else if sym.class == 105 {
        aux_weak
    } else if sym.class == 2 && sym.kind & 0x30 == 0x20 && sym.section > 0 {
        aux_function
    } else {
        aux_raw
    };
    cx.emit(struct_node("Auxiliary record", first, LE, c.big, layout));
    for i in 1..u64::from(aux) {
        cx.emit(Node::new("Auxiliary record").span(aux_span.sub(i.saturating_mul(record), record)));
    }
    Ok(())
}

fn aux_section(f: &mut Fields<'_>, big: &bool) -> Result<()> {
    f.u32("Length").hex().emit()?;
    f.u16("NumberOfRelocations").emit()?;
    f.u16("NumberOfLinenumbers").emit()?;
    f.u32("CheckSum").hex().emit()?;
    f.u16("Number")
        .desc("Associated section (for ASSOCIATIVE COMDATs)")
        .emit()?;
    f.u8("Selection").enumeration(COMDAT_SELECTION).emit()?;
    f.u8("Reserved").emit()?;
    if *big {
        f.u16("HighNumber").emit()?;
    }
    Ok(())
}

fn aux_weak(f: &mut Fields<'_>, _: &bool) -> Result<()> {
    f.u32("TagIndex")
        .desc("Symbol to use if the weak external is not defined")
        .emit()?;
    f.u32("Characteristics").enumeration(WEAK_SEARCH).emit()?;
    Ok(())
}

fn aux_function(f: &mut Fields<'_>, _: &bool) -> Result<()> {
    f.u32("TagIndex").emit()?;
    f.u32("TotalSize").hex().emit()?;
    f.u32("PointerToLinenumber").hex().emit()?;
    f.u32("PointerToNextFunction").emit()?;
    Ok(())
}

fn aux_raw(f: &mut Fields<'_>, _: &bool) -> Result<()> {
    let rest = f.remaining();
    f.bytes("Data", rest).emit()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Short import records

fn import_header(f: &mut Fields<'_>, _: &()) -> Result<(u16, u16)> {
    f.u16("Sig1").hex().emit()?;
    f.u16("Sig2").hex().emit()?;
    f.u16("Version").emit()?;
    f.u16("Machine").enumeration(MACHINE).emit()?;
    f.u32("TimeDateStamp").timestamp().emit()?;
    f.u32("SizeOfData")
        .desc("Bytes of names after this header")
        .emit()?;
    let hint = f.u16("OrdinalOrHint").emit()?;
    let kind = f
        .u16("Type")
        .hex()
        .with(|&v, n| {
            n.summary(format!(
                "{}, {}",
                name_or(IMPORT_TYPE, (v & 3).into(), "type"),
                name_or(IMPORT_NAME_TYPE, ((v >> 2) & 7).into(), "name type")
            ))
        })
        .emit()?;
    Ok((hint, kind))
}

pub async fn import(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = file.sub(0, 20);
    cx.emit(struct_node("Import Header", head, LE, (), import_header));
    let (hint, kind) = parse(&cx, head, LE, &(), import_header).await?;
    let (symbol, at) = cx.cstr(file.tail(20).sub(0, 4096)).await?;
    cx.emit(Node::new("Symbol").span(at).value(text(symbol.clone())));
    let rest = file.tail(20u64.saturating_add(at.len));
    let (dll, at) = cx.cstr(rest.sub(0, 4096)).await?;
    cx.emit(Node::new("DLL").span(at).value(text(dll.clone())));
    let name_type = (kind >> 2) & 7;
    if name_type == 4 {
        let (export, at) = cx.cstr(rest.tail(at.len).sub(0, 4096)).await?;
        cx.emit(Node::new("Export name").span(at).value(text(export)));
    }
    let how = if name_type == 0 {
        format!("by ordinal {hint}")
    } else {
        format!("by name, hint {hint}")
    };
    cx.annotate(format!(
        "Import record: {dll}!{symbol} ({}, {how})",
        name_or(IMPORT_TYPE, (kind & 3).into(), "type").to_lowercase()
    ));
    Ok(())
}
