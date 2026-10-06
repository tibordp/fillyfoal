//! ELF: executables, shared objects, relocatable objects and core dumps, in
//! all four flavours (32/64-bit, little/big-endian).
//!
//! Expanding the file reads the ELF header, the program header table, the
//! section header table and the section name table: everything else
//! (symbols, relocations, the dynamic section, notes, contents) is located
//! from these and decoded only when expanded. A few small notes are read
//! eagerly for the summary (interpreter, build ID, ABI tag).

mod notes;
mod symbols;
mod tables;

use std::sync::Arc;

use tables::*;

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::util::binutil::{data_node, get_at, name_or, perms, text};
use crate::formats::{Codec, Format, Head, Input, Probe, content, embedded};
use crate::node::{Count, Node};
use crate::span::Span;

/// Longest symbol or library name we look for a terminator in.
const MAX_NAME: u64 = 4096;
/// Largest section name table we load.
const MAX_SHSTRTAB: u64 = 1 << 20;

pub static FORMAT: Format = Format {
    name: "elf",
    title: "Executable and Linkable Format",
    extensions: &[
        "elf", "so", "o", "ko", "axf", "prx", "mod", "core", "debug", "out", "bin",
    ],
    mime: "application/x-executable",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    h.starts_with(b"\x7fELF")
        && matches!(h.data.get(4), Some(1 | 2))
        && matches!(h.data.get(5), Some(1 | 2))
}

// ---------------------------------------------------------------------------
// Model

/// Word size and byte order, from `e_ident`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Class {
    pub wide: bool,
    pub endian: Endian,
}

impl Class {
    fn word(self) -> u64 {
        if self.wide { 8 } else { 4 }
    }
    fn ehdr_size(self) -> u64 {
        if self.wide { 64 } else { 52 }
    }
    fn phdr_size(self) -> u64 {
        if self.wide { 56 } else { 32 }
    }
    fn shdr_size(self) -> u64 {
        if self.wide { 64 } else { 40 }
    }
    fn sym_size(self) -> u64 {
        if self.wide { 24 } else { 16 }
    }
    fn rel_size(self, rela: bool) -> u64 {
        match (self.wide, rela) {
            (true, true) => 24,
            (true, false) => 16,
            (false, true) => 12,
            (false, false) => 8,
        }
    }
    fn dyn_size(self) -> u64 {
        self.word().saturating_mul(2)
    }
    fn bits(self) -> u8 {
        if self.wide { 64 } else { 32 }
    }
}

#[derive(Clone, Copy, Debug)]
struct Header {
    osabi: u8,
    kind: u16,
    machine: u16,
    phoff: u64,
    shoff: u64,
    phentsize: u16,
    phnum: u16,
    shentsize: u16,
    shnum: u16,
    shstrndx: u16,
}

#[derive(Clone, Debug)]
struct Section {
    index: u32,
    header: Span,
    name_offset: u32,
    name: String,
    kind: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    align: u64,
    entsize: u64,
}

impl Section {
    fn label(&self) -> String {
        if self.name.is_empty() {
            format!("[{}]", self.index)
        } else {
            self.name.clone()
        }
    }

    fn has_data(&self) -> bool {
        self.kind != SHT_NOBITS && self.kind != 0
    }

    fn summary(&self) -> String {
        let kind = name_or(SECTION_TYPE, self.kind.into(), "type");
        let flag = |bit: u64| self.flags & bit != 0;
        let mut out = format!(
            "{kind}, {}, {:#x} bytes",
            perms(flag(0x2), flag(0x1), flag(0x4)),
            self.size
        );
        if self.addr != 0 {
            out.push_str(&format!(" at {:#x}", self.addr));
        }
        out
    }
}

#[derive(Clone, Debug)]
struct Segment {
    header: Span,
    kind: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
    align: u64,
}

impl Segment {
    fn label(&self) -> String {
        name_or(SEGMENT_TYPE, self.kind.into(), "type")
    }

    fn summary(&self) -> String {
        format!(
            "{}  file {:#x}+{:#x}, mem {:#x}+{:#x}",
            perms(
                self.flags & 4 != 0,
                self.flags & 2 != 0,
                self.flags & 1 != 0
            ),
            self.offset,
            self.filesz,
            self.vaddr,
            self.memsz
        )
    }
}

pub(crate) type Elf = Arc<ElfInfo>;

pub(crate) struct ElfInfo {
    input: Input,
    class: Class,
    header: Header,
    sections: Vec<Section>,
    segments: Vec<Segment>,
    shstrtab: Vec<u8>,
}

impl ElfInfo {
    fn file(&self) -> Span {
        self.input.span
    }

    fn endian(&self) -> Endian {
        self.class.endian
    }

    fn section(&self, index: u32) -> Option<&Section> {
        self.sections.get(to_usize(index.into()))
    }

    fn section_name(&self, index: u32) -> String {
        self.section(index)
            .map_or_else(|| format!("[{index}]"), Section::label)
    }

    fn name_at(&self, offset: u32) -> Option<String> {
        self.shstrtab
            .get(to_usize(offset.into())..)
            .map(crate::text::until_nul)
    }

    /// The file bytes of a section (empty for `SHT_NOBITS`).
    fn data(&self, section: &Section) -> Span {
        if section.has_data() {
            self.file().sub(section.offset, section.size)
        } else {
            self.file().sub(section.offset, 0)
        }
    }

    /// Translates a virtual address to a file offset through the loadable
    /// segments (or, in relocatable files, the allocated sections).
    fn vaddr_offset(&self, vaddr: u64) -> Option<u64> {
        let loads = self.segments.iter().filter(|s| s.kind == PT_LOAD);
        for s in loads {
            if let Some(delta) = vaddr.checked_sub(s.vaddr)
                && delta < s.filesz
            {
                return s.offset.checked_add(delta);
            }
        }
        if self.segments.is_empty() {
            for s in self
                .sections
                .iter()
                .filter(|s| s.has_data() && s.flags & 2 != 0)
            {
                if let Some(delta) = vaddr.checked_sub(s.addr)
                    && delta < s.size
                {
                    return s.offset.checked_add(delta);
                }
            }
        }
        None
    }

    fn vaddr_span(&self, vaddr: u64, len: u64) -> Option<Span> {
        self.vaddr_offset(vaddr).map(|o| self.file().sub(o, len))
    }

    fn relocation_types(&self) -> crate::value::EnumTable {
        relocation_types(self.header.machine)
    }
}

// ---------------------------------------------------------------------------
// Entry point

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let ident = cx.read_avail(file.sub(0, 16)).await?;
    let wide = match ident.get(4) {
        Some(1) => false,
        Some(2) => true,
        other => {
            return Err(Diagnostic::unsupported(format!(
                "ELF class {}",
                other.copied().unwrap_or(0)
            ))
            .at(file.sub(4, 1)));
        }
    };
    let endian = match ident.get(5) {
        Some(1) => Endian::Little,
        Some(2) => Endian::Big,
        other => {
            return Err(Diagnostic::unsupported(format!(
                "ELF data encoding {}",
                other.copied().unwrap_or(0)
            ))
            .at(file.sub(5, 1)));
        }
    };
    let class = Class { wide, endian };
    let hctx = HeaderCtx { class, file };
    let ehdr = file.sub(0, class.ehdr_size());
    let header = parse(&cx, ehdr, endian, &hctx, elf_header).await;
    let mut node = struct_node("ELF Header", ehdr, endian, hctx, elf_header);
    if let Ok(h) = &header {
        node = node.summary(format!(
            "{}, {}",
            name_or(TYPE, h.kind.into(), "type"),
            machine_name(h.machine)
        ));
    }
    cx.emit(node);
    let header = header?;

    let segments = load_segments(&cx, file, class, &header).await;
    let (segments, segment_table) = match segments {
        Ok(s) => s,
        Err(e) => {
            cx.diag(e);
            (Vec::new(), None)
        }
    };
    let sections = load_sections(&cx, file, class, &header).await;
    let (sections, section_table, shstrtab) = match sections {
        Ok(s) => s,
        Err(e) => {
            cx.diag(e);
            (Vec::new(), None, Vec::new())
        }
    };

    let elf: Elf = Arc::new(ElfInfo {
        input,
        class,
        header,
        sections,
        segments,
        shstrtab,
    });

    let facts = gather_facts(&cx, &elf).await;
    cx.annotate(summary(&elf, &facts));

    if let Some(table) = segment_table {
        cx.emit(
            Node::new("Program Headers")
                .span(table)
                .summary(format!("{} segments", elf.segments.len()))
                .lazy(segment_list, elf.clone()),
        );
    }
    if let Some(table) = section_table {
        cx.emit(
            Node::new("Section Headers")
                .span(table)
                .summary(format!("{} sections", elf.sections.len()))
                .lazy(section_list, elf.clone()),
        );
    }

    if let Some((interp, span)) = &facts.interpreter {
        cx.emit(
            Node::new("Interpreter")
                .span(*span)
                .value(text(interp.clone()))
                .desc("Program interpreter (dynamic linker)"),
        );
    }

    // Notes: from PT_NOTE segments, or from SHT_NOTE sections in files
    // without program headers.
    let regions = note_regions(&elf);
    if !regions.is_empty() {
        let total: u64 = regions.iter().map(|r| r.span.len).sum();
        cx.emit(
            Node::new("Notes")
                .summary(format!("{} regions, {total:#x} bytes", regions.len()))
                .lazy(all_notes, (elf.clone(), regions)),
        );
    }

    if let Some(node) = dynamic_node(&elf) {
        cx.emit(node);
    }

    for section in &elf.sections {
        if matches!(section.kind, SHT_SYMTAB | SHT_DYNSYM) {
            cx.emit(symbols::table_node(&elf, section));
        }
    }

    let end = image_end(&elf);
    if end < file.len {
        cx.emit(
            embedded("Overlay", input.nested(file.tail(end)))
                .summary(format!(
                    "{:#x} bytes after the last section",
                    file.len.saturating_sub(end)
                ))
                .desc("Data appended to the image"),
        );
    }
    Ok(())
}

/// Facts the summary line needs, gathered with a few small reads.
#[derive(Default)]
struct Facts {
    interpreter: Option<(String, Span)>,
    build_id: Option<Vec<u8>>,
    abi_tag: Option<String>,
    go_build_id: Option<String>,
    flags_1: u64,
    core_command: Option<String>,
}

async fn gather_facts(cx: &Cx, elf: &Elf) -> Facts {
    let mut facts = Facts::default();
    if let Some(s) = elf.segments.iter().find(|s| s.kind == PT_INTERP) {
        let span = elf.file().sub(s.offset, s.filesz.min(MAX_NAME));
        if let Ok(data) = cx.read_avail(span).await {
            let name = crate::text::until_nul(&data);
            facts.interpreter = Some((name, span));
        }
    }
    for region in note_regions(elf) {
        let Ok(found) = notes::scan(cx, &region, 32).await else {
            continue;
        };
        for note in found {
            let desc = || async { cx.read_avail(note.desc.sub(0, 256)).await.ok() };
            match (note.name.as_str(), note.kind) {
                ("GNU", 3) => facts.build_id = desc().await,
                ("GNU", 1) => {
                    if let Some(d) = desc().await {
                        facts.abi_tag = notes::abi_tag(&d, elf.endian());
                    }
                }
                ("Go", 4) => {
                    facts.go_build_id = desc().await.map(|d| crate::text::until_nul(&d));
                }
                ("CORE", NT_PRPSINFO) => {
                    if let Some(d) = desc().await {
                        let at = if elf.class.wide { 40 } else { 28 };
                        let name = crate::text::until_nul(d.get(at..).unwrap_or_default());
                        let name = name.get(..16.min(name.len())).unwrap_or_default();
                        facts.core_command = Some(name.to_owned());
                    }
                }
                _ => {}
            }
        }
    }
    if let Some(dynamic) = elf.segments.iter().find(|s| s.kind == PT_DYNAMIC) {
        let span = elf.file().sub(dynamic.offset, dynamic.filesz.min(0x10000));
        if let Ok(data) = cx.read_avail(span).await {
            let size = elf.class.dyn_size();
            let mut at = 0u64;
            while let (Some(tag), Some(val)) = (
                word(&data, at, elf.class),
                word(&data, at.saturating_add(elf.class.word()), elf.class),
            ) {
                if tag == DT_NULL {
                    break;
                }
                if tag == DT_FLAGS_1 {
                    facts.flags_1 = val;
                }
                at = at.saturating_add(size);
            }
        }
    }
    facts
}

fn word(data: &[u8], at: u64, class: Class) -> Option<u64> {
    if class.wide {
        get_at::<u64>(data, at, class.endian)
    } else {
        get_at::<u32>(data, at, class.endian).map(u64::from)
    }
}

fn summary(elf: &ElfInfo, facts: &Facts) -> String {
    let h = &elf.header;
    let bits = if elf.class.wide { 64 } else { 32 };
    let order = match elf.class.endian {
        Endian::Little => "LSB",
        Endian::Big => "MSB",
    };
    let dynamic = elf.segments.iter().any(|s| s.kind == PT_DYNAMIC);
    let kind = match h.kind {
        ET_REL => "relocatable".to_owned(),
        ET_EXEC => "executable".to_owned(),
        ET_DYN if facts.flags_1 & DF_1_PIE != 0 || facts.interpreter.is_some() => {
            "pie executable".to_owned()
        }
        ET_DYN => "shared object".to_owned(),
        ET_CORE => "core file".to_owned(),
        other => format!("type {other:#x}"),
    };
    let mut parts = vec![
        format!("ELF {bits}-bit {order} {kind}"),
        machine_name(h.machine),
    ];
    if h.osabi != 0 {
        parts.push(name_or(OSABI, h.osabi.into(), "OS/ABI"));
    }
    if matches!(h.kind, ET_EXEC | ET_DYN) {
        parts.push(
            if dynamic {
                "dynamically linked"
            } else {
                "statically linked"
            }
            .to_owned(),
        );
    }
    if let Some((interp, _)) = &facts.interpreter {
        parts.push(format!("interpreter {interp}"));
    }
    if let Some(id) = &facts.build_id {
        let hash = match id.len() {
            20 => "sha1",
            16 => "md5/uuid",
            8 => "xxHash",
            _ => "hex",
        };
        parts.push(format!(
            "BuildID[{hash}]={}",
            crate::formats::util::binutil::hex_string(id)
        ));
    }
    if let Some(id) = &facts.go_build_id {
        parts.push(format!("Go BuildID={id}"));
    }
    if let Some(tag) = &facts.abi_tag {
        parts.push(format!("for {tag}"));
    }
    if let Some(command) = &facts.core_command {
        parts.push(format!("from '{command}'"));
    }
    if h.kind != ET_CORE && !elf.sections.is_empty() {
        let symtab = elf.sections.iter().any(|s| s.kind == SHT_SYMTAB);
        let debug = elf.sections.iter().any(|s| s.name == ".debug_info");
        if debug {
            parts.push("with debug_info".to_owned());
        }
        parts.push(if symtab { "not stripped" } else { "stripped" }.to_owned());
    }
    parts.join(", ")
}

/// One past the last byte any header or section claims.
fn image_end(elf: &ElfInfo) -> u64 {
    let h = &elf.header;
    let tables = [
        elf.class.ehdr_size(),
        h.phoff
            .saturating_add(u64::from(h.phnum).saturating_mul(h.phentsize.into())),
        h.shoff
            .saturating_add(to_u64(elf.sections.len()).saturating_mul(h.shentsize.into())),
    ];
    let sections = elf
        .sections
        .iter()
        .filter(|s| s.has_data())
        .map(|s| s.offset.saturating_add(s.size));
    let segments = elf
        .segments
        .iter()
        .map(|s| s.offset.saturating_add(s.filesz));
    tables
        .into_iter()
        .chain(sections)
        .chain(segments)
        .max()
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// ELF header

#[derive(Clone, Copy, Debug)]
struct HeaderCtx {
    class: Class,
    file: Span,
}

fn ident(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.bytes("EI_MAG", 4).desc("\"\\x7fELF\"").emit()?;
    f.u8("EI_CLASS").enumeration(CLASS).emit()?;
    f.u8("EI_DATA").enumeration(DATA).emit()?;
    f.u8("EI_VERSION").emit()?;
    f.u8("EI_OSABI").enumeration(OSABI).emit()?;
    f.u8("EI_ABIVERSION").emit()?;
    f.bytes("EI_PAD", 7).emit()?;
    Ok(())
}

fn elf_header(f: &mut Fields<'_>, c: &HeaderCtx) -> Result<Header> {
    let wide = c.class.wide;
    let id = f.peek_span(16);
    let osabi = f.block().data.get(7).copied().unwrap_or(0);
    f.node(
        struct_node("e_ident", id, c.class.endian, (), ident).summary(format!(
            "{}-bit, {}, {}",
            c.class.bits(),
            match c.class.endian {
                Endian::Little => "little-endian",
                Endian::Big => "big-endian",
            },
            name_or(OSABI, osabi.into(), "OS/ABI")
        )),
    );
    f.skip(16);
    let kind = f
        .u16("e_type")
        .enumeration(TYPE)
        .with(|&t, n| match t {
            0xfe00..=0xfeff => n.summary("OS-specific"),
            0xff00..=0xffff => n.summary("processor-specific"),
            _ => n,
        })
        .emit()?;
    let machine = f.u16("e_machine").enumeration(MACHINE).emit()?;
    f.u32("e_version").desc("1 = current").emit()?;
    f.uword("e_entry", wide)
        .hex()
        .desc("Virtual address of the entry point, or 0")
        .emit()?;
    let file = c.file;
    let phoff = f
        .uword("e_phoff", wide)
        .hex()
        .desc("File offset of the program header table")
        .with(|&v, n| if v == 0 { n } else { n.target(file.sub(v, 0)) })
        .emit()?;
    let shoff = f
        .uword("e_shoff", wide)
        .hex()
        .desc("File offset of the section header table")
        .with(|&v, n| if v == 0 { n } else { n.target(file.sub(v, 0)) })
        .emit()?;
    f.u32("e_flags")
        .flags(machine_flags(machine))
        .desc("Processor-specific flags")
        .emit()?;
    f.u16("e_ehsize").desc("Size of this header").emit()?;
    let phentsize = f.u16("e_phentsize").emit()?;
    let phnum = f
        .u16("e_phnum")
        .desc("0xffff: the real count is in section 0's sh_info")
        .emit()?;
    let shentsize = f.u16("e_shentsize").emit()?;
    let shnum = f
        .u16("e_shnum")
        .desc("0: the real count is in section 0's sh_size")
        .emit()?;
    let shstrndx = f
        .u16("e_shstrndx")
        .desc("Index of the section name table (0xffff: in section 0's sh_link)")
        .emit()?;
    Ok(Header {
        osabi,
        kind,
        machine,
        phoff,
        shoff,
        phentsize,
        phnum,
        shentsize,
        shnum,
        shstrndx,
    })
}

// ---------------------------------------------------------------------------
// Program headers

fn segment_header(f: &mut Fields<'_>, c: &HeaderCtx) -> Result<Segment> {
    let wide = c.class.wide;
    let header = f.peek_span(c.class.phdr_size());
    let file = c.file;
    let kind = f.u32("p_type").enumeration(SEGMENT_TYPE).emit()?;
    // 64-bit headers put p_flags second, for alignment.
    let mut flags = 0;
    if wide {
        flags = f.u32("p_flags").flags(SEGMENT_FLAGS).emit()?;
    }
    let filesz = peek_word(f, if wide { 24 } else { 12 }, wide);
    let offset = f
        .uword("p_offset", wide)
        .hex()
        .with(|&v, n| n.target(file.sub(v, filesz)))
        .emit()?;
    let vaddr = f.uword("p_vaddr", wide).hex().emit()?;
    f.uword("p_paddr", wide).hex().emit()?;
    let filesz = f.uword("p_filesz", wide).hex().emit()?;
    let memsz = f.uword("p_memsz", wide).hex().emit()?;
    if !wide {
        flags = f.u32("p_flags").flags(SEGMENT_FLAGS).emit()?;
    }
    let align = f.uword("p_align", wide).hex().emit()?;
    Ok(Segment {
        header,
        kind,
        flags,
        offset,
        vaddr,
        filesz,
        memsz,
        align,
    })
}

/// Reads a word `ahead` bytes past the current position without consuming
/// anything (0 if it is not there).
fn peek_word(f: &mut Fields<'_>, ahead: u64, wide: bool) -> u64 {
    let here = f.pos();
    f.skip(ahead);
    let value = f.uword("", wide).get().unwrap_or(0);
    f.seek(here);
    value
}

async fn load_segments(
    cx: &Cx,
    file: Span,
    class: Class,
    header: &Header,
) -> Result<(Vec<Segment>, Option<Span>)> {
    if header.phoff == 0 || header.phnum == 0 {
        return Ok((Vec::new(), None));
    }
    let mut count = u64::from(header.phnum);
    if header.phnum == 0xffff && header.shoff != 0 {
        // PN_XNUM: the real count is in sh_info of section 0.
        let s0 = file.sub(header.shoff, class.shdr_size());
        let data = cx.read_avail(s0).await?;
        let at = if class.wide { 44 } else { 28 };
        count = get_at::<u32>(&data, at, class.endian).map_or(count, u64::from);
    }
    let entsize = u64::from(header.phentsize);
    if entsize < class.phdr_size() {
        return Err(Diagnostic::malformed(format!(
            "program header size {entsize} is smaller than {}",
            class.phdr_size()
        )));
    }
    let table = file.sub_exact(header.phoff, count.saturating_mul(entsize))?;
    let block = cx.block(table).await?;
    let ctx = HeaderCtx { class, file };
    let mut segments = Vec::new();
    for i in 0..count {
        cx.checkpoint().await;
        let mut f = Fields::new(&block, class.endian);
        f.seek(i.saturating_mul(entsize));
        segments.push(segment_header(&mut f, &ctx)?);
    }
    Ok((segments, Some(table)))
}

async fn segment_list(cx: Cx, elf: Elf) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(elf.segments.len())));
    for (index, segment) in elf.segments.iter().enumerate() {
        cx.push(
            Node::new(segment.label())
                .span(segment.header)
                .summary(segment.summary())
                .lazy(segment_node, (elf.clone(), index)),
        )
        .await;
    }
    Ok(())
}

async fn segment_node(cx: Cx, (elf, index): (Elf, usize)) -> Result<()> {
    let segment = elf
        .segments
        .get(index)
        .ok_or_else(|| Diagnostic::internal("segment index out of range"))?;
    let block = cx.block(segment.header).await?;
    let ctx = HeaderCtx {
        class: elf.class,
        file: elf.file(),
    };
    segment_header(&mut Fields::emitting(&cx, &block, elf.endian()), &ctx)?;
    let data = elf.file().sub(segment.offset, segment.filesz);
    match segment.kind {
        PT_INTERP => {
            let bytes = cx.read_avail(data.sub(0, MAX_NAME)).await?;
            cx.emit(
                Node::new("Interpreter")
                    .span(data)
                    .value(text(crate::text::until_nul(&bytes))),
            );
        }
        PT_NOTE => {
            let region = notes::Region::new(&elf, data, segment.align);
            cx.emit(
                Node::new("Notes")
                    .span(data)
                    .lazy(notes::list, (elf.clone(), region)),
            );
        }
        PT_DYNAMIC => cx.emit(
            Node::new("Dynamic Entries")
                .span(data)
                .lazy(symbols::dynamic, (elf.clone(), data, None::<u32>)),
        ),
        _ if segment.filesz > 0 => {
            cx.emit(data_node("Contents", data, segment.filesz));
        }
        _ => {}
    }
    // Which sections the segment maps.
    let inside: Vec<String> = elf
        .sections
        .iter()
        .filter(|s| {
            s.has_data()
                && s.size > 0
                && s.offset >= segment.offset
                && s.offset.saturating_add(s.size) <= segment.offset.saturating_add(segment.filesz)
        })
        .map(Section::label)
        .collect();
    if !inside.is_empty() {
        cx.emit(
            Node::new("Sections")
                .value(text(inside.join(" ")))
                .desc("Sections whose file contents lie within this segment"),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Section headers

#[derive(Clone)]
struct SectionCtx {
    class: Class,
    file: Span,
    elf: Option<Elf>,
}

fn section_header(f: &mut Fields<'_>, c: &SectionCtx) -> Result<Section> {
    let wide = c.class.wide;
    let header = f.peek_span(c.class.shdr_size());
    let elf = c.elf.as_ref();
    let name_offset = f
        .u32("sh_name")
        .hex()
        .with(|&v, n| match elf.and_then(|e| e.name_at(v)) {
            Some(name) => n.summary(format!("{name:?}")),
            None => n,
        })
        .desc("Offset of the name in the section name table")
        .emit()?;
    let kind = f.u32("sh_type").enumeration(SECTION_TYPE).emit()?;
    let flags = f.uword("sh_flags", wide).flags(SECTION_FLAGS).emit()?;
    let addr = f.uword("sh_addr", wide).hex().emit()?;
    let size = peek_word(f, c.class.word(), wide);
    let file = c.file;
    let offset = f
        .uword("sh_offset", wide)
        .hex()
        .with(|&v, n| {
            if kind == SHT_NOBITS {
                n
            } else {
                n.target(file.sub(v, size))
            }
        })
        .emit()?;
    let size = f.uword("sh_size", wide).hex().emit()?;
    let link = f
        .u32("sh_link")
        .with(|&v, n| match elf {
            Some(e) if v != 0 => n.summary(e.section_name(v)),
            _ => n,
        })
        .emit()?;
    let info = f
        .u32("sh_info")
        .with(|&v, n| match elf {
            Some(e) if matches!(kind, SHT_REL | SHT_RELA) && v != 0 => {
                n.summary(format!("applies to {}", e.section_name(v)))
            }
            Some(_) if matches!(kind, SHT_SYMTAB | SHT_DYNSYM) => {
                n.summary("index of the first non-local symbol")
            }
            _ => n,
        })
        .emit()?;
    let align = f.uword("sh_addralign", wide).hex().emit()?;
    let entsize = f
        .uword("sh_entsize", wide)
        .hex()
        .desc("Size of each entry, for tables")
        .emit()?;
    Ok(Section {
        index: 0,
        header,
        name_offset,
        name: elf.and_then(|e| e.name_at(name_offset)).unwrap_or_default(),
        kind,
        flags,
        addr,
        offset,
        size,
        link,
        info,
        align,
        entsize,
    })
}

type LoadedSections = (Vec<Section>, Option<Span>, Vec<u8>);

async fn load_sections(
    cx: &Cx,
    file: Span,
    class: Class,
    header: &Header,
) -> Result<LoadedSections> {
    if header.shoff == 0 {
        return Ok((Vec::new(), None, Vec::new()));
    }
    let entsize = u64::from(header.shentsize);
    if entsize < class.shdr_size() {
        return Err(Diagnostic::malformed(format!(
            "section header size {entsize} is smaller than {}",
            class.shdr_size()
        )));
    }
    let ctx = SectionCtx {
        class,
        file,
        elf: None,
    };
    // Extended numbering: section 0 holds the real count and name index.
    let first = parse(
        cx,
        file.sub(header.shoff, entsize),
        class.endian,
        &ctx,
        section_header,
    )
    .await?;
    let count = if header.shnum == 0 {
        first.size
    } else {
        header.shnum.into()
    };
    let shstrndx = if header.shstrndx == SHN_XINDEX {
        first.link
    } else {
        header.shstrndx.into()
    };
    let table = file.sub_exact(header.shoff, count.saturating_mul(entsize))?;
    let block = cx.block(table).await?;
    let mut sections = Vec::new();
    for i in 0..count {
        cx.checkpoint().await;
        let mut f = Fields::new(&block, class.endian);
        f.seek(i.saturating_mul(entsize));
        let mut section = section_header(&mut f, &ctx)?;
        section.index = u32::try_from(i).unwrap_or(u32::MAX);
        sections.push(section);
    }

    let mut shstrtab = Vec::new();
    if let Some(names) = sections.get(to_usize(shstrndx.into()))
        && names.has_data()
        && shstrndx != 0
    {
        let span = file.sub(names.offset, names.size.min(MAX_SHSTRTAB));
        shstrtab = cx.read_avail(span).await?;
    }
    // Section names are resolved once the name table is known.
    for section in &mut sections {
        if let Some(name) = shstrtab.get(to_usize(section.name_offset.into())..) {
            section.name = crate::text::until_nul(name);
        }
    }
    Ok((sections, Some(table), shstrtab))
}

async fn section_list(cx: Cx, elf: Elf) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(elf.sections.len())));
    for (index, section) in elf.sections.iter().enumerate() {
        cx.push(
            Node::new(section.label())
                .span(section.header)
                .summary(section.summary())
                .lazy(section_node, (elf.clone(), index)),
        )
        .await;
    }
    Ok(())
}

async fn section_node(cx: Cx, (elf, index): (Elf, usize)) -> Result<()> {
    let section = elf
        .sections
        .get(index)
        .ok_or_else(|| Diagnostic::internal("section index out of range"))?;
    let block = cx.block(section.header).await?;
    let ctx = SectionCtx {
        class: elf.class,
        file: elf.file(),
        elf: Some(elf.clone()),
    };
    section_header(&mut Fields::emitting(&cx, &block, elf.endian()), &ctx)?;
    if let Some(node) = section_contents(&cx, &elf, section).await? {
        cx.emit(node);
    }
    Ok(())
}

/// The node showing a section's contents, decoded according to its type.
async fn section_contents(cx: &Cx, elf: &Elf, section: &Section) -> Result<Option<Node>> {
    if !section.has_data() || section.size == 0 {
        return Ok(None);
    }
    let data = elf.data(section);
    let raw = data_node("Contents", data, section.size);
    if section.flags & SHF_COMPRESSED != 0 {
        return Ok(Some(compressed(cx, elf, section, data).await?));
    }
    let lazy = |name: &'static str| Node::new(name).span(data);
    let index = section.index;
    let node = match section.kind {
        SHT_SYMTAB | SHT_DYNSYM => symbols::table_node(elf, section),
        SHT_STRTAB => lazy("Strings").lazy(symbols::strings, data),
        SHT_NOTE => lazy("Notes").lazy(
            notes::list,
            (elf.clone(), notes::Region::new(elf, data, section.align)),
        ),
        SHT_DYNAMIC => {
            lazy("Dynamic Entries").lazy(symbols::dynamic, (elf.clone(), data, Some(section.link)))
        }
        SHT_REL | SHT_RELA => symbols::relocations_node(elf, section),
        SHT_INIT_ARRAY | SHT_FINI_ARRAY | SHT_PREINIT_ARRAY => lazy("Pointers")
            .summary(format!(
                "{} entries",
                section.size.checked_div(elf.class.word()).unwrap_or(0)
            ))
            .lazy(symbols::pointers, (elf.clone(), data)),
        SHT_GROUP => lazy("Group").lazy(symbols::group, (elf.clone(), data)),
        SHT_GNU_VERNEED => {
            lazy("Version Requirements").lazy(symbols::verneed, (elf.clone(), index))
        }
        SHT_GNU_VERDEF => lazy("Version Definitions").lazy(symbols::verdef, (elf.clone(), index)),
        SHT_GNU_VERSYM => raw.summary(format!("{} symbol versions", section.size / 2)),
        SHT_HASH => raw.summary("SysV symbol hash table"),
        SHT_RELR => raw.summary(format!(
            "{} packed relative relocation words",
            section.size.checked_div(elf.class.word()).unwrap_or(0)
        )),
        _ => match section.name.as_str() {
            ".comment" | ".note.GNU-stack" => lazy("Strings").lazy(symbols::strings, data),
            ".interp" => {
                let bytes = cx.read_avail(data.sub(0, MAX_NAME)).await?;
                lazy("Interpreter").value(text(crate::text::until_nul(&bytes)))
            }
            ".gnu_debuglink" => lazy("Debug Link").lazy(symbols::debuglink, (elf.class, data)),
            ".gnu_debugaltlink" => {
                lazy("Debug Alt Link").lazy(symbols::debuglink, (elf.class, data))
            }
            ".nv_fatbin" | "__nv_relfatbin" => embedded("Fat Binary", elf.input.nested(data)),
            _ => raw,
        },
    };
    Ok(Some(node))
}

async fn compressed(cx: &Cx, elf: &Elf, section: &Section, data: Span) -> Result<Node> {
    let wide = elf.class.wide;
    let header_size = if wide { 24 } else { 12 };
    let header = data.sub(0, header_size);
    let block = cx.block(header).await?;
    let mut f = Fields::new(&block, elf.endian());
    let kind = f.u32("ch_type").get()?;
    if wide {
        f.u32("ch_reserved").get()?;
    }
    let size = f.uword("ch_size", wide).get()?;
    let payload = data.tail(header_size);
    let node = match kind {
        1 => content("Decompressed", elf.input, payload, Codec::Zlib, Some(size)),
        _ => data_node("Compressed data", payload, payload.len).diag(Diagnostic::unsupported(
            format!("{} compression", name_or(COMPRESSION, kind.into(), "type")),
        )),
    };
    let _ = section;
    Ok(Node::new("Compressed Section")
        .span(data)
        .summary(format!(
            "{}, {size:#x} bytes uncompressed",
            name_or(COMPRESSION, kind.into(), "type")
        ))
        .lazy(compressed_parts, (elf.class, header, node)))
}

async fn compressed_parts(cx: Cx, (class, header, payload): (Class, Span, Node)) -> Result<()> {
    cx.emit(struct_node(
        "Compression Header",
        header,
        class.endian,
        class,
        compression_header,
    ));
    cx.emit(payload);
    Ok(())
}

fn compression_header(f: &mut Fields<'_>, class: &Class) -> Result<()> {
    f.u32("ch_type").enumeration(COMPRESSION).emit()?;
    if class.wide {
        f.u32("ch_reserved").emit()?;
    }
    f.uword("ch_size", class.wide)
        .hex()
        .desc("Uncompressed size")
        .emit()?;
    f.uword("ch_addralign", class.wide).hex().emit()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Notes and the dynamic section at the top level

fn note_regions(elf: &Elf) -> Vec<notes::Region> {
    let from_segments: Vec<notes::Region> = elf
        .segments
        .iter()
        .filter(|s| s.kind == PT_NOTE)
        .map(|s| notes::Region::new(elf, elf.file().sub(s.offset, s.filesz), s.align))
        .collect();
    if !from_segments.is_empty() {
        return from_segments;
    }
    elf.sections
        .iter()
        .filter(|s| s.kind == SHT_NOTE)
        .map(|s| notes::Region::new(elf, elf.data(s), s.align))
        .collect()
}

async fn all_notes(cx: Cx, (elf, regions): (Elf, Vec<notes::Region>)) -> Result<()> {
    for region in regions {
        notes::emit_all(&cx, &elf, &region).await?;
    }
    Ok(())
}

fn dynamic_node(elf: &Elf) -> Option<Node> {
    let section = elf.sections.iter().find(|s| s.kind == SHT_DYNAMIC);
    let (span, link) = match elf.segments.iter().find(|s| s.kind == PT_DYNAMIC) {
        Some(s) => (elf.file().sub(s.offset, s.filesz), section.map(|s| s.link)),
        None => {
            let s = section?;
            (elf.data(s), Some(s.link))
        }
    };
    Some(
        Node::new("Dynamic Section")
            .span(span)
            .summary(format!(
                "{} entries",
                span.len.checked_div(elf.class.dyn_size()).unwrap_or(0)
            ))
            .lazy(symbols::dynamic, (elf.clone(), span, link)),
    )
}
