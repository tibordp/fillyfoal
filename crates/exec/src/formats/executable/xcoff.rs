//! XCOFF (AIX) objects and executables, 32-bit (`0x01DF`) and 64-bit
//! (`0x01F7`): a COFF variant with an auxiliary header, sections,
//! relocations, a symbol table with csect auxiliary entries and a string
//! table. Always big-endian.

use std::sync::Arc;

use crate::bytes::{to_u64, u16_be, u32_be, u64_be};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::util::binutil::{cstrings, data_node};
use crate::formats::util::val::{hex, name_or};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, flag};

const BE: Endian = Endian::Big;

pub static FORMAT: Format = Format {
    name: "xcoff",
    title: "XCOFF object or executable (AIX)",
    extensions: &["o", "a", "so"],
    mime: "application/x-xcoff",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    let sections = u16_be(h.data, 2).unwrap_or(0);
    matches!(u16_be(h.data, 0), Some(0x01df | 0x01f7)) && (1..=0x400).contains(&sections)
}

const FILE_FLAGS: FlagTable = &[
    flag(0x1, "F_RELFLG"),
    flag(0x2, "F_EXEC"),
    flag(0x4, "F_LNNO"),
    flag(0x10, "F_FDPR_PROF"),
    flag(0x20, "F_FDPR_OPTI"),
    flag(0x40, "F_DSA"),
    flag(0x100, "F_VARPG"),
    flag(0x1000, "F_DYNLOAD"),
    flag(0x2000, "F_SHROBJ"),
    flag(0x4000, "F_LOADONLY"),
];

const SECTION_FLAGS: FlagTable = &[
    flag(0x8, "STYP_PAD"),
    flag(0x10, "STYP_DWARF"),
    flag(0x20, "STYP_TEXT"),
    flag(0x40, "STYP_DATA"),
    flag(0x80, "STYP_BSS"),
    flag(0x100, "STYP_EXCEPT"),
    flag(0x200, "STYP_INFO"),
    flag(0x400, "STYP_TDATA"),
    flag(0x800, "STYP_TBSS"),
    flag(0x1000, "STYP_LOADER"),
    flag(0x2000, "STYP_DEBUG"),
    flag(0x4000, "STYP_TYPCHK"),
    flag(0x8000, "STYP_OVRFLO"),
];

const STORAGE_CLASS: EnumTable = &[
    (0, "C_NULL"),
    (2, "C_EXT"),
    (3, "C_STAT"),
    (6, "C_LABEL"),
    (103, "C_FILE"),
    (107, "C_HIDEXT"),
    (108, "C_BINCL"),
    (109, "C_EINCL"),
    (110, "C_INFO"),
    (111, "C_WEAKEXT"),
    (112, "C_DWARF"),
    (128, "C_GSYM"),
    (129, "C_LSYM"),
    (130, "C_PSYM"),
    (131, "C_RSYM"),
    (133, "C_STSYM"),
    (137, "C_FUN"),
    (143, "C_DECL"),
];

const RELOCATION: EnumTable = &[
    (0x00, "R_POS"),
    (0x01, "R_NEG"),
    (0x02, "R_REL"),
    (0x03, "R_TOC"),
    (0x04, "R_TRL"),
    (0x05, "R_GL"),
    (0x06, "R_TCL"),
    (0x0c, "R_RL"),
    (0x0d, "R_RLA"),
    (0x0f, "R_REF"),
    (0x12, "R_BA"),
    (0x13, "R_RBA"),
    (0x18, "R_BR"),
    (0x19, "R_RBR"),
    (0x20, "R_TLS"),
    (0x21, "R_TLS_IE"),
    (0x22, "R_TLS_LD"),
    (0x23, "R_TLS_LE"),
    (0x24, "R_TLSM"),
    (0x25, "R_TLSML"),
    (0x30, "R_TOCU"),
    (0x31, "R_TOCL"),
];

#[derive(Clone, Copy, Debug)]
struct Header {
    sections: u16,
    symptr: u64,
    nsyms: u32,
    opthdr: u16,
    flags: u16,
}

fn header(f: &mut Fields<'_>, wide: &bool) -> Result<Header> {
    f.u16("f_magic")
        .hex()
        .with(|&v, n| n.summary(if v == 0x01f7 { "64-bit" } else { "32-bit" }))
        .emit()?;
    let sections = f.u16("f_nscns").emit()?;
    f.u32("f_timdat").timestamp().emit()?;
    if *wide {
        let symptr = f.u64("f_symptr").hex().emit()?;
        let opthdr = f.u16("f_opthdr").emit()?;
        let flags = f.u16("f_flags").flags(FILE_FLAGS).emit()?;
        let nsyms = f.u32("f_nsyms").emit()?;
        Ok(Header {
            sections,
            symptr,
            nsyms,
            opthdr,
            flags,
        })
    } else {
        let symptr = f.u32("f_symptr").hex().emit()?.into();
        let nsyms = f.u32("f_nsyms").emit()?;
        let opthdr = f.u16("f_opthdr").emit()?;
        let flags = f.u16("f_flags").flags(FILE_FLAGS).emit()?;
        Ok(Header {
            sections,
            symptr,
            nsyms,
            opthdr,
            flags,
        })
    }
}

#[derive(Clone, Debug)]
struct Section {
    name: String,
    header: Span,
    size: u64,
    scnptr: u64,
    relptr: u64,
    nreloc: u32,
    flags: u32,
}

fn section(f: &mut Fields<'_>, wide: &bool) -> Result<Section> {
    let header = f.peek_span(if *wide { 72 } else { 40 });
    let name = f.ascii("s_name", 8).emit()?;
    f.uword("s_paddr", *wide).hex().emit()?;
    f.uword("s_vaddr", *wide).hex().emit()?;
    let size = f.uword("s_size", *wide).hex().emit()?;
    let scnptr = f.uword("s_scnptr", *wide).hex().emit()?;
    let relptr = f.uword("s_relptr", *wide).hex().emit()?;
    f.uword("s_lnnoptr", *wide).hex().emit()?;
    let nreloc = if *wide {
        let n = f.u32("s_nreloc").emit()?;
        f.u32("s_nlnno").emit()?;
        n
    } else {
        let n = f.u16("s_nreloc").emit()?;
        f.u16("s_nlnno").emit()?;
        n.into()
    };
    let flags = f.u32("s_flags").flags(SECTION_FLAGS).emit()?;
    if *wide {
        f.u32("s_pad").emit()?;
    }
    Ok(Section {
        name,
        header,
        size,
        scnptr,
        relptr,
        nreloc,
        flags,
    })
}

type Xcoff = Arc<Info>;

struct Info {
    file: Span,
    wide: bool,
    sections: Vec<Section>,
    symbols: Span,
    nsyms: u32,
    strings: Span,
}

impl Info {
    async fn symbol_name(&self, cx: &Cx, index: u32) -> Option<String> {
        let data = cx
            .read(self.symbols.sub(u64::from(index).saturating_mul(18), 18))
            .await
            .ok()?;
        if self.wide {
            let offset = u32_be(&data, 8)?;
            return crate::formats::util::binutil::string_at(cx, self.strings, offset.into())
                .await
                .ok()
                .map(|(s, _)| s);
        }
        if data.get(..4) == Some(&[0, 0, 0, 0]) {
            let offset = u32_be(&data, 4)?;
            crate::formats::util::binutil::string_at(cx, self.strings, offset.into())
                .await
                .ok()
                .map(|(s, _)| s)
        } else {
            Some(crate::text::until_nul(data.get(..8)?))
        }
    }

    fn section_name(&self, number: i16) -> String {
        match number {
            0 => "N_UNDEF".to_owned(),
            -1 => "N_ABS".to_owned(),
            -2 => "N_DEBUG".to_owned(),
            n => usize::try_from(n)
                .ok()
                .and_then(|n| n.checked_sub(1))
                .and_then(|i| self.sections.get(i))
                .map_or_else(|| format!("section {n}"), |s| s.name.clone()),
        }
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let magic = cx.read_avail(file.sub(0, 2)).await?;
    let wide = magic.as_slice() == [0x01, 0xf7];
    let hsize: u64 = if wide { 24 } else { 20 };
    let hspan = file.sub(0, hsize);
    cx.emit(struct_node("File Header", hspan, BE, wide, header));
    let h = parse(&cx, hspan, BE, &wide, header).await?;
    if h.opthdr > 0 {
        cx.emit(data_node(
            "Auxiliary Header",
            file.sub(hsize, h.opthdr.into()),
            h.opthdr.into(),
        ));
    }
    let ssize: u64 = if wide { 72 } else { 40 };
    let table = file.sub(
        hsize.saturating_add(h.opthdr.into()),
        u64::from(h.sections).saturating_mul(ssize),
    );
    let mut sections = Vec::new();
    for i in 0..table.len.checked_div(ssize).unwrap_or(0) {
        sections.push(
            parse(
                &cx,
                table.sub(i.saturating_mul(ssize), ssize),
                BE,
                &wide,
                section,
            )
            .await?,
        );
    }
    let symbols = file.sub(h.symptr, u64::from(h.nsyms).saturating_mul(18));
    let strings_at = h.symptr.saturating_add(symbols.len);
    let size = cx.read_avail(file.sub(strings_at, 4)).await?;
    let strings = file.sub(strings_at, u32_be(&size, 0).unwrap_or(0).into());
    let x: Xcoff = Arc::new(Info {
        file,
        wide,
        sections,
        symbols,
        nsyms: u32::try_from(symbols.len / 18).unwrap_or(0),
        strings,
    });
    let kind = if h.flags & 0x2000 != 0 {
        "shared object"
    } else if h.flags & 0x2 != 0 {
        "executable"
    } else {
        "object"
    };
    let names: Vec<&str> = x.sections.iter().map(|s| s.name.as_str()).collect();
    cx.annotate(format!(
        "XCOFF {} {kind} (AIX), sections {}, {} symbols",
        if wide { "64-bit" } else { "32-bit" },
        names.join(" "),
        h.nsyms
    ));
    cx.emit(
        Node::new("Section Table")
            .span(table)
            .summary(format!("{} sections", x.sections.len()))
            .lazy(section_list, x.clone()),
    );
    if h.symptr != 0 {
        cx.emit(
            Node::new("Symbol Table")
                .span(symbols)
                .summary(format!("{} entries", h.nsyms))
                .lazy(symbol_list, x.clone()),
        );
        cx.emit(
            Node::new("String Table")
                .span(strings)
                .lazy(cstrings, strings.tail(4)),
        );
    }
    Ok(())
}

async fn section_list(cx: Cx, x: Xcoff) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(x.sections.len())));
    for (i, s) in x.sections.iter().enumerate() {
        let (set, _) = crate::value::decode_flags(SECTION_FLAGS, s.flags.into());
        cx.push(
            Node::new(s.name.clone())
                .span(s.header)
                .summary(format!(
                    "{}, {:#x} bytes, {} relocations",
                    set.join(" "),
                    s.size,
                    s.nreloc
                ))
                .lazy(section_node, (x.clone(), i)),
        )
        .await;
    }
    Ok(())
}

async fn section_node(cx: Cx, (x, index): (Xcoff, usize)) -> Result<()> {
    let s = x
        .sections
        .get(index)
        .ok_or_else(|| Diagnostic::internal("section index"))?;
    let block = cx.block(s.header).await?;
    section(&mut Fields::emitting(&cx, &block, BE), &x.wide)?;
    if s.scnptr != 0 && s.flags & 0x80 == 0 {
        cx.emit(data_node("Raw Data", x.file.sub(s.scnptr, s.size), s.size));
    }
    if s.nreloc > 0 {
        let width: u64 = if x.wide { 14 } else { 10 };
        let span = x
            .file
            .sub(s.relptr, u64::from(s.nreloc).saturating_mul(width));
        cx.emit(
            Node::new("Relocations")
                .span(span)
                .summary(format!("{} entries", s.nreloc))
                .lazy(relocations, (x.clone(), span)),
        );
    }
    Ok(())
}

async fn relocations(cx: Cx, (x, span): (Xcoff, Span)) -> Result<()> {
    let width: u64 = if x.wide { 14 } else { 10 };
    let count = span.len.checked_div(width).unwrap_or(0);
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let at = span.sub(i.saturating_mul(width), width);
        let data = cx.read(at).await?;
        let (addr, rest) = if x.wide {
            (u64_be(&data, 0).unwrap_or(0), 8usize)
        } else {
            (u32_be(&data, 0).unwrap_or(0).into(), 4)
        };
        let symbol = u32_be(&data, rest).unwrap_or(0);
        let size = data.get(rest.saturating_add(4)).copied().unwrap_or(0);
        let kind = data.get(rest.saturating_add(5)).copied().unwrap_or(0);
        let target = x
            .symbol_name(&cx, symbol)
            .await
            .unwrap_or_else(|| format!("#{symbol}"));
        cx.push(
            Node::new(name_or(RELOCATION, kind.into(), "type"))
                .span(at)
                .value(hex(addr, 64))
                .summary(format!(
                    "{target}, {} bits{}",
                    (size & 0x3f).saturating_add(1),
                    if size & 0x80 != 0 { ", signed" } else { "" }
                )),
        )
        .await;
    }
    Ok(())
}

async fn symbol_list(cx: Cx, x: Xcoff) -> Result<()> {
    let mut index = 0u32;
    while index < x.nsyms {
        let at = x.symbols.sub(u64::from(index).saturating_mul(18), 18);
        let data = cx.read(at).await?;
        let (value, scnum_at) = if x.wide {
            (u64_be(&data, 0).unwrap_or(0), 12usize)
        } else {
            (u32_be(&data, 8).unwrap_or(0).into(), 12)
        };
        let scnum = u16_be(&data, scnum_at).map_or(0, |v| i16::from_be_bytes(v.to_be_bytes()));
        let class = data.get(16).copied().unwrap_or(0);
        let aux = u32::from(data.get(17).copied().unwrap_or(0));
        let name = x.symbol_name(&cx, index).await.unwrap_or_default();
        let span = x.symbols.sub(
            u64::from(index).saturating_mul(18),
            u64::from(aux).saturating_add(1).saturating_mul(18),
        );
        cx.progress(index.into(), x.nsyms.into());
        cx.push(
            Node::new(if name.is_empty() {
                format!("#{index}")
            } else {
                name
            })
            .span(span)
            .value(hex(value, if x.wide { 64 } else { 32 }))
            .summary(format!(
                "{} {}{}",
                name_or(STORAGE_CLASS, class.into(), "class"),
                x.section_name(scnum),
                if aux > 0 {
                    format!(", {aux} aux")
                } else {
                    String::new()
                }
            )),
        )
        .await;
        index = index.saturating_add(aux).saturating_add(1);
    }
    Ok(())
}
