//! PE/COFF images: EXE, DLL, SYS, EFI.
//!
//! Expanding the file costs a handful of small reads: the DOS header, the NT
//! headers and the section table, which everything else depends on (RVA
//! translation). Directories, sections and their contents are dissected only
//! when expanded.

mod extra;
pub(crate) mod resource;
pub(crate) mod tables;
pub(crate) mod version;

pub use extra::DOS_EXE;

use std::sync::Arc;

use tables::*;

use crate::bytes::{to_u64, to_usize, u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Field, Fields, parse, struct_node};
use crate::formats::{Format, Input, Probe, embedded};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{Radix, Value, lookup};

const LE: Endian = Endian::Little;
/// Longest name (DLL, function, forwarder) we look for a terminator in.
const MAX_NAME: u64 = 4096;
/// Windows uses three levels (type, name, language).
const MAX_RESOURCE_DEPTH: usize = 8;
const HIGH_BIT: u32 = 0x8000_0000;
const ORDINAL_FLAG_32: u64 = 0x8000_0000;
const ORDINAL_FLAG_64: u64 = 0x8000_0000_0000_0000;
const IMAGE_FILE_EXECUTABLE: u16 = 0x0002;
const IMAGE_FILE_DLL: u16 = 0x2000;

// ---------------------------------------------------------------------------
// Entry point

pub static FORMAT: Format = Format {
    name: "pe",
    title: "Portable Executable (EXE, DLL, SYS, EFI)",
    extensions: &[
        "exe", "dll", "sys", "efi", "scr", "ocx", "cpl", "drv", "mui",
    ],
    mime: "application/vnd.microsoft.portable-executable",
    probe: Probe::Magic(&[(0, b"MZ")]),
    dissect: crate::expander!(dissect: Input),
};

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;

    let dos = file.sub(0, 64);
    cx.emit(struct_node("DOS Header", dos, LE, file, dos_header));
    let lfanew = u64::from(parse(&cx, dos, LE, &file, dos_header).await?);
    if lfanew > 64 {
        cx.emit(
            Node::new("DOS Stub")
                .span(file.sub(64, lfanew.saturating_sub(64)))
                .desc("Real-mode program run when the image is started under DOS"),
        );
        if let Ok(Some(rich)) = extra::rich_header(&cx, file, lfanew).await {
            cx.emit(rich);
        }
    }

    let nt = file.tail(lfanew);
    // Older executables behind an MZ stub have their own dissectors.
    let signature = cx.read_avail(nt.sub(0, 4)).await?;
    let other = match signature.get(..2) {
        Some(b"NE") => Some((
            "NE Executable",
            "16-bit NE executable",
            &crate::formats::executable::ne::FORMAT,
        )),
        Some(b"LE" | b"LX") => Some((
            "Linear Executable",
            "LE/LX executable",
            &crate::formats::executable::lx::FORMAT,
        )),
        _ if signature.as_slice() != b"PE\0\0" => {
            Some(("DOS Executable", "MS-DOS executable", &DOS_EXE))
        }
        _ => None,
    };
    if let Some((name, summary, format)) = other {
        cx.annotate(summary);
        cx.emit(crate::formats::embedded_as(
            name,
            input.nested(file),
            format,
        ));
        return Ok(());
    }
    let header = parse(&cx, nt.sub(4, 20), LE, &(), file_header).await;
    let nt_len = 24u64.saturating_add(header.as_ref().map_or(0, |h| h.optional_size.into()));
    cx.emit(
        Node::new("NT Headers")
            .span(nt.sub(0, nt_len))
            .lazy(nt_headers, (file, lfanew)),
    );
    let signature = cx.read_avail(nt.sub(0, 4)).await?;
    if signature != b"PE\0\0" {
        return Err(not_pe(&signature).at(nt.sub(0, 4)));
    }
    let header = header?;
    let optional = parse(
        &cx,
        nt.sub(24, header.optional_size.into()),
        LE,
        &(),
        optional_header,
    )
    .await?;
    cx.annotate(summary(&header, &optional));

    // The section table is a prerequisite for translating RVAs.
    let table = nt.sub(
        24u64.saturating_add(header.optional_size.into()),
        u64::from(header.sections).saturating_mul(40),
    );
    let block = cx.block(table).await?;
    let mut sections = Vec::new();
    let mut fields = Fields::new(&block, LE);
    for _ in 0..header.sections {
        cx.checkpoint().await;
        match section_header(&mut fields, &file) {
            Ok(section) => sections.push(section),
            Err(e) => {
                cx.diag(e);
                break;
            }
        }
    }

    let pe: Pe = Arc::new(PeInfo {
        input,
        wide: optional.wide,
        size_of_headers: optional.size_of_headers,
        sections,
    });
    cx.emit(
        Node::new("Section Table")
            .span(table)
            .summary(format!("{} sections", pe.sections.len()))
            .lazy(section_table, pe.clone()),
    );

    let directories = cx.read_avail(optional.directories).await?;
    for (index, name) in DATA_DIRECTORIES.iter().enumerate() {
        let at = index.saturating_mul(8);
        let (Some(rva), Some(size)) = (
            u32_le(&directories, at),
            u32_le(&directories, at.saturating_add(4)),
        ) else {
            break;
        };
        if rva != 0 || size != 0 {
            cx.emit(directory(&pe, index, name, rva, size));
        }
    }

    if let (Some(rva), Some(size)) = (
        u32_le(&directories, DIR_RESOURCE.saturating_mul(8)),
        u32_le(
            &directories,
            DIR_RESOURCE.saturating_mul(8).saturating_add(4),
        ),
    ) && rva != 0
        && size != 0
        && let Ok(Some(span)) = find_version(&cx, &pe, rva).await
    {
        let node = Node::new("Version Information")
            .span(span)
            .lazy(version::block, span);
        cx.emit(match version::summary(&cx, span).await {
            Ok(summary) => node.summary(summary),
            Err(e) => node.diag(e),
        });
    }

    // Inno Setup's loader keeps the offsets of the installer data in
    // RCDATA #11111 (5.1.5 and later) or at file offset 0x30.
    let inno = if let (Some(rva), Some(size)) = (
        u32_le(&directories, DIR_RESOURCE.saturating_mul(8)),
        u32_le(
            &directories,
            DIR_RESOURCE.saturating_mul(8).saturating_add(4),
        ),
    ) && rva != 0
        && size != 0
        && let Ok(Some(span)) = find_resource(&cx, &pe, rva, resource::RT_RCDATA, Some(11111)).await
    {
        Some(span)
    } else {
        None
    };
    if let Some(table) =
        crate::formats::archive::installer::inno::loader_table(&cx, file, inno).await
    {
        cx.emit(
            crate::formats::embedded_as(
                "Inno Setup installer",
                input.nested(table),
                &crate::formats::archive::installer::inno::FORMAT,
            )
            .desc("The installer data, located by the setup loader's offset table"),
        );
    }

    let end = pe
        .sections
        .iter()
        .map(|s| u64::from(s.raw_pointer).saturating_add(s.raw_size.into()))
        .chain([u64::from(pe.size_of_headers)])
        .max()
        .unwrap_or(0);
    if end < file.len {
        cx.emit(
            embedded("Overlay", input.nested(file.tail(end)))
                .summary(format!(
                    "{:#x} bytes after the last section",
                    file.len.saturating_sub(end)
                ))
                .desc(
                    "Data appended to the image; installers and self-extractors keep payloads here",
                ),
        );
    }
    Ok(())
}

fn not_pe(signature: &[u8]) -> Diagnostic {
    match signature.get(..2) {
        Some(b"NE") => Diagnostic::unsupported("16-bit NE executable"),
        Some(b"LE" | b"LX") => Diagnostic::unsupported("LE/LX executable (VxD or OS/2)"),
        _ => Diagnostic::unsupported("DOS executable without a PE header"),
    }
}

fn summary(header: &FileHeader, optional: &OptionalHeader) -> String {
    let format = if optional.wide { "PE32+" } else { "PE32" };
    let kind = if header.characteristics & IMAGE_FILE_DLL != 0 {
        "DLL"
    } else if header.characteristics & IMAGE_FILE_EXECUTABLE != 0 {
        "executable"
    } else {
        "image"
    };
    let machine = lookup(MACHINE, header.machine.into())
        .map_or_else(|| format!("machine {:#x}", header.machine), str::to_owned);
    let subsystem = lookup(SUBSYSTEM, optional.subsystem.into()).unwrap_or("unknown subsystem");
    format!("{format} {kind}, {machine}, {subsystem}")
}

// ---------------------------------------------------------------------------
// Image model shared by the lazy expansions

type Pe = Arc<PeInfo>;

struct PeInfo {
    input: Input,
    wide: bool,
    size_of_headers: u32,
    sections: Vec<Section>,
}

#[derive(Clone, Debug)]
struct Section {
    header: Span,
    name: String,
    virtual_size: u32,
    virtual_address: u32,
    raw_size: u32,
    raw_pointer: u32,
    characteristics: u32,
}

impl Section {
    fn summary(&self) -> String {
        let flag = |bit: u32, c: char| {
            if self.characteristics & bit != 0 {
                c
            } else {
                '-'
            }
        };
        format!(
            "{}{}{}  VA {:#x}+{:#x}, file {:#x}+{:#x}",
            flag(SCN_MEM_READ, 'r'),
            flag(SCN_MEM_WRITE, 'w'),
            flag(SCN_MEM_EXECUTE, 'x'),
            self.virtual_address,
            self.virtual_size,
            self.raw_pointer,
            self.raw_size,
        )
    }
}

impl PeInfo {
    fn file(&self) -> Span {
        self.input.span
    }

    /// Translates an RVA to an offset in the file.
    fn rva_offset(&self, rva: u32) -> Result<u64> {
        for s in &self.sections {
            let size = if s.virtual_size == 0 {
                s.raw_size
            } else {
                s.virtual_size
            };
            if let Some(delta) = rva.checked_sub(s.virtual_address)
                && delta < size
            {
                if delta < s.raw_size {
                    return Ok(u64::from(s.raw_pointer).saturating_add(delta.into()));
                }
                return Err(Diagnostic::malformed(format!(
                    "RVA {rva:#x} lies in the zero-filled part of section {:?}",
                    s.name
                )));
            }
        }
        if rva < self.size_of_headers {
            return Ok(rva.into());
        }
        Err(Diagnostic::malformed(format!(
            "RVA {rva:#x} is not backed by file data"
        )))
    }

    /// The file bytes at `rva`, clamped to the end of the image.
    fn rva_span(&self, rva: u32, len: u64) -> Result<Span> {
        Ok(self.file().sub(self.rva_offset(rva)?, len))
    }

    /// Like [`PeInfo::rva_span`], but all `len` bytes must exist.
    fn rva_exact(&self, rva: u32, len: u64) -> Result<Span> {
        self.file().sub_exact(self.rva_offset(rva)?, len)
    }

    /// An array of `count` elements of `width` bytes at `rva`.
    fn table(&self, rva: u32, count: u32, width: u64) -> Result<Span> {
        if count == 0 {
            return Ok(self.file().sub(0, 0));
        }
        self.rva_exact(rva, u64::from(count).saturating_mul(width))
    }
}

/// Decorates an RVA field with where it points (or why it points nowhere).
fn rva_field<'a>(field: Field<'a, u32>, pe: &PeInfo) -> Field<'a, u32> {
    field.hex().with(|&rva, node| {
        if rva == 0 {
            return node;
        }
        match pe.rva_span(rva, 0) {
            Ok(span) => node.target(span),
            Err(e) => node.diag(e),
        }
    })
}

fn overflow() -> Diagnostic {
    Diagnostic::malformed("address arithmetic overflows")
}

async fn read_name(cx: &Cx, pe: &PeInfo, rva: u32) -> Result<(String, Span)> {
    cx.cstr(pe.rva_span(rva, MAX_NAME)?).await
}

// ---------------------------------------------------------------------------
// Headers

fn dos_header(f: &mut Fields<'_>, file: &Span) -> Result<u32> {
    f.ascii("e_magic", 2).desc("\"MZ\"").emit()?;
    f.u16("e_cblp")
        .desc("Bytes on the last page of the file")
        .emit()?;
    f.u16("e_cp").desc("Pages in the file").emit()?;
    f.u16("e_crlc").desc("Relocations").emit()?;
    f.u16("e_cparhdr")
        .desc("Size of the header in paragraphs")
        .emit()?;
    f.u16("e_minalloc")
        .desc("Minimum extra paragraphs needed")
        .emit()?;
    f.u16("e_maxalloc")
        .desc("Maximum extra paragraphs needed")
        .emit()?;
    f.u16("e_ss").hex().desc("Initial (relative) SS").emit()?;
    f.u16("e_sp").hex().desc("Initial SP").emit()?;
    f.u16("e_csum").hex().desc("Checksum").emit()?;
    f.u16("e_ip").hex().desc("Initial IP").emit()?;
    f.u16("e_cs").hex().desc("Initial (relative) CS").emit()?;
    f.u16("e_lfarlc")
        .hex()
        .desc("File offset of the relocation table")
        .emit()?;
    f.u16("e_ovno").desc("Overlay number").emit()?;
    f.bytes("e_res", 8).emit()?;
    f.u16("e_oemid").hex().emit()?;
    f.u16("e_oeminfo").hex().emit()?;
    f.bytes("e_res2", 20).emit()?;
    f.u32("e_lfanew")
        .hex()
        .desc("File offset of the PE header")
        .with(|&v, n| n.target(file.sub(v.into(), 4)))
        .emit()
}

async fn nt_headers(cx: Cx, (file, lfanew): (Span, u64)) -> Result<()> {
    let nt = file.tail(lfanew);
    let signature = cx.block(nt.sub(0, 4)).await?;
    Fields::emitting(&cx, &signature, LE)
        .bytes("Signature", 4)
        .desc("\"PE\\0\\0\"")
        .emit()?;
    let header_span = nt.sub(4, 20);
    cx.emit(struct_node("File Header", header_span, LE, (), file_header));
    let header = parse(&cx, header_span, LE, &(), file_header).await?;
    cx.emit(struct_node(
        "Optional Header",
        nt.sub(24, header.optional_size.into()),
        LE,
        (),
        optional_header,
    ));
    Ok(())
}

struct FileHeader {
    machine: u16,
    sections: u16,
    optional_size: u16,
    characteristics: u16,
}

fn file_header(f: &mut Fields<'_>, _: &()) -> Result<FileHeader> {
    let machine = f
        .u16("Machine")
        .enumeration(MACHINE)
        .desc("Target architecture")
        .emit()?;
    let sections = f.u16("NumberOfSections").emit()?;
    f.u32("TimeDateStamp")
        .timestamp()
        .desc("Link time, or a content hash for reproducible builds")
        .emit()?;
    f.u32("PointerToSymbolTable")
        .hex()
        .desc("File offset of the COFF symbol table (deprecated for images)")
        .emit()?;
    f.u32("NumberOfSymbols").emit()?;
    let optional_size = f.u16("SizeOfOptionalHeader").hex().emit()?;
    let characteristics = f
        .u16("Characteristics")
        .flags(FILE_CHARACTERISTICS)
        .emit()?;
    Ok(FileHeader {
        machine,
        sections,
        optional_size,
        characteristics,
    })
}

struct OptionalHeader {
    wide: bool,
    subsystem: u16,
    size_of_headers: u32,
    directories: Span,
}

fn optional_header(f: &mut Fields<'_>, _: &()) -> Result<OptionalHeader> {
    let magic = f
        .u16("Magic")
        .enumeration(OPTIONAL_MAGIC)
        .desc("PE32 (32-bit) or PE32+ (64-bit)")
        .emit()?;
    let wide = match magic {
        0x10b => false,
        0x20b => true,
        _ => {
            return Err(Diagnostic::unsupported(format!(
                "optional header magic {magic:#x}"
            )));
        }
    };
    f.u8("MajorLinkerVersion").emit()?;
    f.u8("MinorLinkerVersion").emit()?;
    f.u32("SizeOfCode").hex().emit()?;
    f.u32("SizeOfInitializedData").hex().emit()?;
    f.u32("SizeOfUninitializedData").hex().emit()?;
    f.u32("AddressOfEntryPoint")
        .hex()
        .desc("RVA of the entry point, or 0")
        .emit()?;
    f.u32("BaseOfCode").hex().emit()?;
    if !wide {
        f.u32("BaseOfData").hex().emit()?;
    }
    f.uword("ImageBase", wide)
        .hex()
        .desc("Preferred load address")
        .emit()?;
    f.u32("SectionAlignment").hex().emit()?;
    f.u32("FileAlignment").hex().emit()?;
    f.u16("MajorOperatingSystemVersion").emit()?;
    f.u16("MinorOperatingSystemVersion").emit()?;
    f.u16("MajorImageVersion").emit()?;
    f.u16("MinorImageVersion").emit()?;
    f.u16("MajorSubsystemVersion").emit()?;
    f.u16("MinorSubsystemVersion").emit()?;
    f.u32("Win32VersionValue").emit()?;
    f.u32("SizeOfImage").hex().emit()?;
    let size_of_headers = f.u32("SizeOfHeaders").hex().emit()?;
    f.u32("CheckSum").hex().emit()?;
    let subsystem = f.u16("Subsystem").enumeration(SUBSYSTEM).emit()?;
    f.u16("DllCharacteristics")
        .flags(DLL_CHARACTERISTICS)
        .emit()?;
    f.uword("SizeOfStackReserve", wide).hex().emit()?;
    f.uword("SizeOfStackCommit", wide).hex().emit()?;
    f.uword("SizeOfHeapReserve", wide).hex().emit()?;
    f.uword("SizeOfHeapCommit", wide).hex().emit()?;
    f.u32("LoaderFlags").hex().emit()?;
    let declared = f.u32("NumberOfRvaAndSizes").emit()?;
    let count = u64::from(declared)
        .min(16)
        .min(f.remaining().checked_div(8).unwrap_or(0));
    let directories = f.peek_span(count.saturating_mul(8));
    f.node(
        Node::new("Data Directories")
            .span(directories)
            .summary(format!("{count} entries"))
            .lazy(data_directories, directories),
    );
    Ok(OptionalHeader {
        wide,
        subsystem,
        size_of_headers,
        directories,
    })
}

async fn data_directories(cx: Cx, table: Span) -> Result<()> {
    let data = cx.read(table).await?;
    let count = table.len.checked_div(8).unwrap_or(0);
    cx.set_count(Count::Exact(count));
    for (index, name) in DATA_DIRECTORIES.iter().enumerate() {
        let at = index.saturating_mul(8);
        let (Some(rva), Some(size)) = (u32_le(&data, at), u32_le(&data, at.saturating_add(4)))
        else {
            break;
        };
        let entry = table.sub(to_u64(at), 8);
        cx.push(
            struct_node(*name, entry, LE, (), data_directory)
                .summary(format!("RVA {rva:#x}, {size:#x} bytes")),
        )
        .await;
    }
    Ok(())
}

fn data_directory(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("VirtualAddress").hex().emit()?;
    f.u32("Size").hex().emit()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Sections

fn section_header(f: &mut Fields<'_>, file: &Span) -> Result<Section> {
    let header = f.peek_span(40);
    let name = f.ascii("Name", 8).emit()?;
    let virtual_size = f.u32("VirtualSize").hex().emit()?;
    let virtual_address = f.u32("VirtualAddress").hex().emit()?;
    let raw_size = f.u32("SizeOfRawData").hex().emit()?;
    let raw_pointer = f
        .u32("PointerToRawData")
        .hex()
        .with(|&p, n| n.target(file.sub(p.into(), raw_size.into())))
        .emit()?;
    f.u32("PointerToRelocations").hex().emit()?;
    f.u32("PointerToLinenumbers").hex().emit()?;
    f.u16("NumberOfRelocations").emit()?;
    f.u16("NumberOfLinenumbers").emit()?;
    let characteristics = f
        .u32("Characteristics")
        .flags(SECTION_CHARACTERISTICS)
        .emit()?;
    Ok(Section {
        header,
        name,
        virtual_size,
        virtual_address,
        raw_size,
        raw_pointer,
        characteristics,
    })
}

async fn section_table(cx: Cx, pe: Pe) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(pe.sections.len())));
    for (index, section) in pe.sections.iter().enumerate() {
        let name = if section.name.is_empty() {
            "(unnamed)".to_owned()
        } else {
            section.name.clone()
        };
        cx.push(
            Node::new(name)
                .span(section.header)
                .summary(section.summary())
                .lazy(section_node, (pe.clone(), index)),
        )
        .await;
    }
    Ok(())
}

async fn section_node(cx: Cx, (pe, index): (Pe, usize)) -> Result<()> {
    let section = pe
        .sections
        .get(index)
        .ok_or_else(|| Diagnostic::internal("section index out of range"))?;
    let block = cx.block(section.header).await?;
    section_header(&mut Fields::emitting(&cx, &block, LE), &pe.file())?;
    if section.raw_size > 0 {
        let wanted = u64::from(section.raw_size);
        let data = pe.file().sub(section.raw_pointer.into(), wanted);
        let mut node = Node::new("Raw Data").span(data);
        if data.len < wanted {
            node = node.diag(Diagnostic::truncated(
                Span::new(data.source, data.offset, wanted),
                data.len,
            ));
        }
        cx.emit(node);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Data directories

#[derive(Clone, Copy, Debug)]
struct Directory {
    rva: u32,
    size: u32,
    span: Span,
}

fn directory(pe: &Pe, index: usize, name: &'static str, rva: u32, size: u32) -> Node {
    let node = Node::new(name);
    // The certificate table is addressed by file offset, not RVA.
    let (node, span) = if index == DIR_SECURITY {
        (
            node.summary(format!("file offset {rva:#x}, {size:#x} bytes")),
            Ok(pe.file().sub(rva.into(), size.into())),
        )
    } else {
        (
            node.summary(format!("RVA {rva:#x}, {size:#x} bytes")),
            pe.rva_span(rva, size.into()),
        )
    };
    let span = match span {
        Ok(span) => span,
        Err(e) => return node.diag(e),
    };
    let node = node.span(span);
    let dir = Directory { rva, size, span };
    let pe = pe.clone();
    match index {
        DIR_EXPORT => node.lazy(exports, (pe, dir)),
        DIR_IMPORT => node.lazy(imports, (pe, dir)),
        DIR_RESOURCE => node.lazy(
            resource_directory,
            ResourceDir {
                pe,
                base: rva,
                offset: 0,
                path: vec![0],
                kind: None,
                name: None,
            },
        ),
        DIR_SECURITY => node.lazy(certificates, (pe.input, dir)),
        DIR_DEBUG => node.lazy(debug_directory, (pe, dir)),
        3 => node.lazy(extra::exceptions, (pe, dir)),
        5 => node.lazy(extra::base_relocations, (pe, dir)),
        9 => node.lazy(extra::tls, (pe, dir)),
        10 => node.lazy(extra::load_config, (pe, dir)),
        13 => node.lazy(extra::delay_imports, (pe, dir)),
        14 => node.lazy(extra::clr, (pe, dir)),
        _ => node,
    }
}

// --- Exports

#[derive(Clone, Copy, Debug)]
struct ExportDirectory {
    name: u32,
    base: u32,
    functions: u32,
    names: u32,
    address_of_functions: u32,
    address_of_names: u32,
    address_of_name_ordinals: u32,
}

fn export_directory(f: &mut Fields<'_>, pe: &Pe) -> Result<ExportDirectory> {
    f.u32("Characteristics").hex().emit()?;
    f.u32("TimeDateStamp").timestamp().emit()?;
    f.u16("MajorVersion").emit()?;
    f.u16("MinorVersion").emit()?;
    let name = rva_field(f.u32("Name"), pe)
        .desc("RVA of the DLL name")
        .emit()?;
    let base = f
        .u32("Base")
        .desc("Ordinal of the first exported function")
        .emit()?;
    let functions = f.u32("NumberOfFunctions").emit()?;
    let names = f.u32("NumberOfNames").emit()?;
    let address_of_functions = rva_field(f.u32("AddressOfFunctions"), pe).emit()?;
    let address_of_names = rva_field(f.u32("AddressOfNames"), pe).emit()?;
    let address_of_name_ordinals = rva_field(f.u32("AddressOfNameOrdinals"), pe).emit()?;
    Ok(ExportDirectory {
        name,
        base,
        functions,
        names,
        address_of_functions,
        address_of_names,
        address_of_name_ordinals,
    })
}

async fn exports(cx: Cx, (pe, dir): (Pe, Directory)) -> Result<()> {
    let span = pe.rva_span(dir.rva, 40)?;
    cx.emit(struct_node(
        "Export Directory",
        span,
        LE,
        pe.clone(),
        export_directory,
    ));
    let ed = parse(&cx, span, LE, &pe, export_directory).await?;
    match read_name(&cx, &pe, ed.name).await {
        Ok((name, at)) => {
            cx.annotate(format!("{name}, {} functions", ed.functions));
            cx.emit(Node::new("Name").value(Value::Text(name)).span(at));
        }
        Err(e) => cx.diag(e),
    }
    cx.emit(
        Node::new("Functions")
            .summary(format!("{} functions, {} by name", ed.functions, ed.names))
            .lazy(export_functions, (pe, dir, ed)),
    );
    Ok(())
}

async fn export_functions(cx: Cx, (pe, dir, ed): (Pe, Directory, ExportDirectory)) -> Result<()> {
    let address_table = pe.table(ed.address_of_functions, ed.functions, 4)?;
    let addresses = cx.read(address_table).await?;
    let names = cx.read(pe.table(ed.address_of_names, ed.names, 4)?).await?;
    let ordinals = cx
        .read(pe.table(ed.address_of_name_ordinals, ed.names, 2)?)
        .await?;

    // Allocation is bounded by bytes actually read, not by declared counts.
    let mut named = vec![false; addresses.len().checked_div(4).unwrap_or(0)];
    for i in 0..ordinals.len().checked_div(2).unwrap_or(0) {
        if let Some(o) = u16_le(&ordinals, i.saturating_mul(2))
            && let Some(slot) = named.get_mut(usize::from(o))
        {
            *slot = true;
        }
    }
    let unnamed: Vec<usize> = named
        .iter()
        .enumerate()
        .filter(|&(i, &n)| !n && u32_le(&addresses, i.saturating_mul(4)).is_some_and(|a| a != 0))
        .map(|(i, _)| i)
        .collect();
    cx.set_count(Count::Exact(
        u64::from(ed.names).saturating_add(to_u64(unnamed.len())),
    ));

    let exports = Exports {
        pe: &pe,
        dir,
        base: ed.base,
        table: address_table,
        addresses: &addresses,
    };
    for i in 0..to_usize(ed.names.into()) {
        let name_rva = u32_le(&names, i.saturating_mul(4)).unwrap_or(0);
        let index = u16_le(&ordinals, i.saturating_mul(2)).unwrap_or(0);
        let node = match read_name(&cx, &pe, name_rva).await {
            Ok((name, _)) => exports.entry(&cx, index.into(), name).await,
            Err(e) => exports
                .entry(&cx, index.into(), "<unreadable name>".to_owned())
                .await
                .diag(e),
        };
        cx.push(node).await;
    }
    for index in unnamed {
        let ordinal = ed
            .base
            .saturating_add(u32::try_from(index).unwrap_or(u32::MAX));
        let node = exports.entry(&cx, index, format!("#{ordinal}")).await;
        cx.push(node).await;
    }
    Ok(())
}

struct Exports<'a> {
    pe: &'a PeInfo,
    dir: Directory,
    base: u32,
    table: Span,
    addresses: &'a [u8],
}

impl Exports<'_> {
    async fn entry(&self, cx: &Cx, index: usize, name: String) -> Node {
        let ordinal = self
            .base
            .saturating_add(u32::try_from(index).unwrap_or(u32::MAX));
        let at = index.saturating_mul(4);
        let node = Node::new(name).span(self.table.sub(to_u64(at), 4));
        let Some(address) = u32_le(self.addresses, at) else {
            return node.diag(Diagnostic::malformed(format!(
                "ordinal index {index} is outside the export address table"
            )));
        };
        let node = node.value(Value::UInt {
            value: address.into(),
            bits: 32,
            radix: Radix::Hex,
        });
        // An address inside the export directory is a forwarder string.
        let forwarded = address
            .checked_sub(self.dir.rva)
            .is_some_and(|d| d < self.dir.size);
        if forwarded {
            match read_name(cx, self.pe, address).await {
                Ok((target, at)) => node
                    .summary(format!("ordinal {ordinal}, forwarded to {target}"))
                    .target(at),
                Err(e) => node.diag(e),
            }
        } else {
            let node = node.summary(format!("ordinal {ordinal}"));
            match self.pe.rva_span(address, 0) {
                Ok(at) => node.target(at),
                Err(_) => node,
            }
        }
    }
}

// --- Imports

#[derive(Clone, Copy, Debug)]
struct ImportDescriptor {
    lookup: u32,
    name: u32,
    address: u32,
    null: bool,
}

fn import_descriptor(f: &mut Fields<'_>, pe: &Pe) -> Result<ImportDescriptor> {
    let lookup = rva_field(f.u32("OriginalFirstThunk"), pe)
        .desc("RVA of the import lookup table")
        .emit()?;
    let timestamp = f
        .u32("TimeDateStamp")
        .hex()
        .desc("0, or 0xffffffff if the imports are bound")
        .emit()?;
    let forwarder = f.u32("ForwarderChain").hex().emit()?;
    let name = rva_field(f.u32("Name"), pe)
        .desc("RVA of the DLL name")
        .emit()?;
    let address = rva_field(f.u32("FirstThunk"), pe)
        .desc("RVA of the import address table")
        .emit()?;
    Ok(ImportDescriptor {
        lookup,
        name,
        address,
        null: lookup | timestamp | forwarder | name | address == 0,
    })
}

async fn imports(cx: Cx, (pe, dir): (Pe, Directory)) -> Result<()> {
    let mut rva = dir.rva;
    loop {
        let span = pe.rva_span(rva, 20)?;
        let descriptor = parse(&cx, span, LE, &pe, import_descriptor).await?;
        if descriptor.null {
            break;
        }
        let node = match read_name(&cx, &pe, descriptor.name).await {
            Ok((name, _)) => Node::new(name),
            Err(e) => Node::new("<unreadable name>").diag(e),
        };
        cx.push(node.span(span).lazy(import_module, (pe.clone(), span)))
            .await;
        rva = rva.checked_add(20).ok_or_else(overflow)?;
    }
    Ok(())
}

async fn import_module(cx: Cx, (pe, descriptor): (Pe, Span)) -> Result<()> {
    cx.emit(struct_node(
        "Import Descriptor",
        descriptor,
        LE,
        pe.clone(),
        import_descriptor,
    ));
    let d = parse(&cx, descriptor, LE, &pe, import_descriptor).await?;
    let table = if d.lookup != 0 { d.lookup } else { d.address };
    let (width, ordinal_flag) = if pe.wide {
        (8u32, ORDINAL_FLAG_64)
    } else {
        (4u32, ORDINAL_FLAG_32)
    };
    let mut index = 0u32;
    loop {
        let rva = index
            .checked_mul(width)
            .and_then(|o| table.checked_add(o))
            .ok_or_else(overflow)?;
        let span = pe.rva_exact(rva, width.into())?;
        let data = cx.read(span).await?;
        let thunk = if pe.wide {
            u64_le(&data, 0)
        } else {
            u32_le(&data, 0).map(u64::from)
        }
        .unwrap_or(0);
        if thunk == 0 {
            break;
        }
        let node = if thunk & ordinal_flag != 0 {
            Node::new(format!("Ordinal {}", thunk & 0xffff))
        } else {
            let hint_name = u32::try_from(thunk & 0x7fff_ffff).unwrap_or(0);
            match hint_and_name(&cx, &pe, hint_name).await {
                Ok((hint, name, at)) => Node::new(name).summary(format!("hint {hint}")).target(at),
                Err(e) => Node::new("<unreadable>").diag(e),
            }
        };
        cx.push(node.span(span)).await;
        index = index.checked_add(1).ok_or_else(overflow)?;
    }
    Ok(())
}

async fn hint_and_name(cx: &Cx, pe: &PeInfo, rva: u32) -> Result<(u16, String, Span)> {
    let span = pe.rva_span(rva, MAX_NAME.saturating_add(2))?;
    let hint = cx.read(span.sub(0, 2)).await?;
    let (name, at) = cx.cstr(span.tail(2)).await?;
    Ok((
        u16_le(&hint, 0).unwrap_or(0),
        name,
        span.sub(0, at.len.saturating_add(2)),
    ))
}

// --- Resources

#[derive(Clone)]
struct ResourceDir {
    pe: Pe,
    /// RVA of the resource section; all offsets are relative to it.
    base: u32,
    offset: u32,
    /// Offsets of this directory and its ancestors, for cycle detection.
    path: Vec<u32>,
    /// Resource type (`RT_*`), once known from the first level.
    kind: Option<u32>,
    /// Ordinal resource name, once known from the second level.
    name: Option<u32>,
}

async fn resource_directory(cx: Cx, dir: ResourceDir) -> Result<()> {
    let pe = &dir.pe;
    let level = dir.path.len();
    let header_rva = dir.base.checked_add(dir.offset).ok_or_else(overflow)?;
    let header = cx.read(pe.rva_exact(header_rva, 16)?).await?;
    let named = u16_le(&header, 12).unwrap_or(0);
    let ids = u16_le(&header, 14).unwrap_or(0);
    let total = u32::from(named).saturating_add(ids.into());
    cx.set_count(Count::Exact(total.into()));

    for i in 0..total {
        let entry_rva = i
            .checked_mul(8)
            .and_then(|o| header_rva.checked_add(16)?.checked_add(o))
            .ok_or_else(overflow)?;
        let entry = pe.rva_exact(entry_rva, 8)?;
        let data = cx.read(entry).await?;
        let name = u32_le(&data, 0).unwrap_or(0);
        let offset = u32_le(&data, 4).unwrap_or(0);

        let mut diagnostics = Vec::new();
        let label = if name & HIGH_BIT != 0 {
            match resource_name(&cx, pe, dir.base, name & !HIGH_BIT).await {
                Ok(text) => format!("{text:?}"),
                Err(e) => {
                    diagnostics.push(e);
                    "<unreadable name>".to_owned()
                }
            }
        } else {
            id_label(level, name)
        };
        let mut node = Node::new(label).span(entry);
        for d in diagnostics {
            node = node.diag(d);
        }

        let child = offset & !HIGH_BIT;
        let child_rva = dir.base.checked_add(child).ok_or_else(overflow)?;
        if offset & HIGH_BIT != 0 {
            if dir.path.contains(&child) {
                node = node.diag(Diagnostic::malformed(format!(
                    "directory at offset {child:#x} contains itself"
                )));
            } else if level >= MAX_RESOURCE_DEPTH {
                node = node.diag(Diagnostic::limit(format!(
                    "resource directories nested deeper than {MAX_RESOURCE_DEPTH}"
                )));
            } else {
                if let Ok(at) = pe.rva_span(child_rva, 16) {
                    node = node.target(at);
                }
                let mut path = dir.path.clone();
                path.push(child);
                node = node.lazy(
                    crate::expander!(resource_directory: ResourceDir),
                    ResourceDir {
                        pe: pe.clone(),
                        base: dir.base,
                        offset: child,
                        path,
                        kind: if level == 1 && name & HIGH_BIT == 0 {
                            Some(name)
                        } else {
                            dir.kind
                        },
                        name: if level == 2 && name & HIGH_BIT == 0 {
                            Some(name)
                        } else {
                            dir.name
                        },
                    },
                );
            }
        } else {
            let span = pe.rva_span(child_rva, 16)?;
            match parse(&cx, span, LE, pe, resource_data_entry).await {
                Ok(e) => node = node.summary(format!("{:#x} bytes", e.size)).target(span),
                Err(e) => node = node.diag(e),
            }
            node = node.lazy(resource_data, (pe.clone(), span, dir.kind, dir.name));
        }
        cx.push(node).await;
    }
    Ok(())
}

/// Follows type `RT_VERSION`, then the first name and the first language, to
/// the version resource's data.
async fn find_version(cx: &Cx, pe: &PeInfo, base: u32) -> Result<Option<Span>> {
    find_resource(cx, pe, base, RT_VERSION, None).await
}

/// Follows type `kind`, then name `id` (or the first name), then the first
/// language, to a resource's data.
async fn find_resource(
    cx: &Cx,
    pe: &PeInfo,
    base: u32,
    kind: u32,
    id: Option<u32>,
) -> Result<Option<Span>> {
    let mut offset = 0u32;
    for level in 0..3 {
        let header_rva = base.checked_add(offset).ok_or_else(overflow)?;
        let header = cx.read(pe.rva_exact(header_rva, 16)?).await?;
        let total = usize::from(u16_le(&header, 12).unwrap_or(0))
            .saturating_add(u16_le(&header, 14).unwrap_or(0).into());
        let entries_rva = header_rva.checked_add(16).ok_or_else(overflow)?;
        let entries = cx
            .read(pe.rva_exact(entries_rva, to_u64(total.min(64)).saturating_mul(8))?)
            .await?;
        let found = (0..total.min(64)).find_map(|i| {
            let name = u32_le(&entries, i.saturating_mul(8))?;
            let target = u32_le(&entries, i.saturating_mul(8).saturating_add(4))?;
            match (level, id) {
                (0, _) => name == kind,
                (1, Some(id)) => name == id,
                _ => true,
            }
            .then_some(target)
        });
        let Some(target) = found else {
            return Ok(None);
        };
        offset = target & !HIGH_BIT;
        if target & HIGH_BIT == 0 {
            let entry_rva = base.checked_add(offset).ok_or_else(overflow)?;
            let entry = parse(cx, pe.rva_exact(entry_rva, 16)?, LE, &(), data_entry).await?;
            return Ok(Some(pe.rva_span(entry.rva, entry.size.into())?));
        }
    }
    Ok(None)
}

fn data_entry(f: &mut Fields<'_>, _: &()) -> Result<DataEntry> {
    let rva = f.u32("OffsetToData").get()?;
    let size = f.u32("Size").get()?;
    Ok(DataEntry { rva, size })
}

fn id_label(level: usize, id: u32) -> String {
    match level {
        1 => lookup(RESOURCE_TYPE, id.into()).map_or_else(|| format!("#{id}"), str::to_owned),
        3 => format!("Language {}", crate::formats::util::lcid::describe(id)),
        _ => format!("#{id}"),
    }
}

async fn resource_name(cx: &Cx, pe: &PeInfo, base: u32, offset: u32) -> Result<String> {
    let rva = base.checked_add(offset).ok_or_else(overflow)?;
    let len = cx.read(pe.rva_exact(rva, 2)?).await?;
    let len = u16_le(&len, 0).unwrap_or(0);
    let text = cx
        .read(pe.rva_exact(
            rva.checked_add(2).ok_or_else(overflow)?,
            u64::from(len).saturating_mul(2),
        )?)
        .await?;
    let units: Vec<u16> = (0..usize::from(len))
        .filter_map(|i| u16_le(&text, i.saturating_mul(2)))
        .collect();
    Ok(String::from_utf16_lossy(&units))
}

#[derive(Clone, Copy, Debug)]
struct DataEntry {
    rva: u32,
    size: u32,
}

fn resource_data_entry(f: &mut Fields<'_>, pe: &Pe) -> Result<DataEntry> {
    let rva = rva_field(f.u32("OffsetToData"), pe)
        .desc("RVA of the resource data")
        .emit()?;
    let size = f.u32("Size").hex().emit()?;
    f.u32("CodePage").emit()?;
    f.u32("Reserved").emit()?;
    Ok(DataEntry { rva, size })
}

async fn resource_data(
    cx: Cx,
    (pe, span, kind, name): (Pe, Span, Option<u32>, Option<u32>),
) -> Result<()> {
    cx.emit(struct_node(
        "Data Entry",
        span,
        LE,
        pe.clone(),
        resource_data_entry,
    ));
    let entry = parse(&cx, span, LE, &pe, resource_data_entry).await?;
    let wanted = u64::from(entry.size);
    let content = pe.rva_span(entry.rva, wanted)?;
    let mut node = resource::content(&cx, pe.input, content, kind, name).await;
    if content.len < wanted {
        node = node.diag(Diagnostic::truncated(
            Span::new(content.source, content.offset, wanted),
            content.len,
        ));
    }
    cx.emit(node);
    Ok(())
}

// --- Debug directory

#[derive(Clone, Copy, Debug)]
struct DebugEntry {
    kind: u32,
    size: u32,
    pointer: u32,
}

fn debug_entry(f: &mut Fields<'_>, pe: &Pe) -> Result<DebugEntry> {
    f.u32("Characteristics").hex().emit()?;
    f.u32("TimeDateStamp").timestamp().emit()?;
    f.u16("MajorVersion").emit()?;
    f.u16("MinorVersion").emit()?;
    let kind = f.u32("Type").enumeration(DEBUG_TYPE).emit()?;
    let size = f.u32("SizeOfData").hex().emit()?;
    rva_field(f.u32("AddressOfRawData"), pe).emit()?;
    let file = pe.file();
    let pointer = f
        .u32("PointerToRawData")
        .hex()
        .with(|&p, n| n.target(file.sub(p.into(), size.into())))
        .emit()?;
    Ok(DebugEntry {
        kind,
        size,
        pointer,
    })
}

async fn debug_directory(cx: Cx, (pe, dir): (Pe, Directory)) -> Result<()> {
    if dir.size % 28 != 0 {
        cx.diag(Diagnostic::warning(format!(
            "size {:#x} is not a multiple of the 28-byte entry size",
            dir.size
        )));
    }
    let count = dir.size.checked_div(28).unwrap_or(0);
    cx.set_count(Count::Exact(count.into()));
    for i in 0..count {
        let span = dir.span.sub(u64::from(i).saturating_mul(28), 28);
        let entry = parse(&cx, span, LE, &pe, debug_entry).await?;
        let label = lookup(DEBUG_TYPE, entry.kind.into())
            .map_or_else(|| format!("Type {}", entry.kind), str::to_owned);
        cx.push(
            Node::new(label)
                .span(span)
                .summary(format!("{:#x} bytes", entry.size))
                .lazy(debug_entry_node, (pe.clone(), span)),
        )
        .await;
    }
    Ok(())
}

async fn debug_entry_node(cx: Cx, (pe, span): (Pe, Span)) -> Result<()> {
    let block = cx.block(span).await?;
    let entry = debug_entry(&mut Fields::emitting(&cx, &block, LE), &pe)?;
    if entry.size > 0 {
        let data = pe.file().sub(entry.pointer.into(), entry.size.into());
        if entry.kind == DEBUG_TYPE_CODEVIEW {
            cx.emit(Node::new("CodeView").span(data).lazy(codeview, data));
        } else {
            cx.emit(Node::new("Data").span(data));
        }
    }
    Ok(())
}

async fn codeview(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    let signature = f.ascii("Signature", 4).emit()?;
    match signature.as_str() {
        "RSDS" => {
            f.guid("Guid").desc("Must match the PDB").emit()?;
            f.u32("Age").emit()?;
        }
        "NB10" => {
            f.u32("Offset").emit()?;
            f.u32("Signature").timestamp().emit()?;
            f.u32("Age").emit()?;
        }
        _ => {
            return Err(Diagnostic::unsupported(format!(
                "CodeView signature {signature:?}"
            )));
        }
    }
    let path = f.cstr("PdbFileName").emit()?;
    cx.annotate(path);
    Ok(())
}

// --- Certificates

#[derive(Clone, Copy, Debug)]
struct WinCertificate {
    length: u32,
    kind: u16,
}

fn win_certificate(f: &mut Fields<'_>, _: &()) -> Result<WinCertificate> {
    let length = f
        .u32("dwLength")
        .hex()
        .desc("Length including this header")
        .emit()?;
    f.u16("wRevision")
        .enumeration(CERTIFICATE_REVISION)
        .emit()?;
    let kind = f
        .u16("wCertificateType")
        .enumeration(CERTIFICATE_TYPE)
        .emit()?;
    Ok(WinCertificate { length, kind })
}

async fn certificates(cx: Cx, (input, dir): (Input, Directory)) -> Result<()> {
    let table = dir.span;
    let mut offset = 0u64;
    while offset < table.len {
        let header = table.sub(offset, 8);
        let cert = parse(&cx, header, LE, &(), win_certificate).await?;
        if cert.length < 8 {
            return Err(Diagnostic::malformed(format!(
                "certificate length {:#x} is shorter than its header",
                cert.length
            ))
            .at(header));
        }
        let span = table.sub(offset, cert.length.into());
        let label = lookup(CERTIFICATE_TYPE, cert.kind.into()).unwrap_or("Certificate");
        cx.push(
            Node::new(label)
                .span(span)
                .summary(format!("{:#x} bytes", cert.length))
                .lazy(certificate, (input, span)),
        )
        .await;
        let step = u64::from(cert.length)
            .checked_next_multiple_of(8)
            .ok_or_else(overflow)?;
        offset = offset.saturating_add(step);
    }
    Ok(())
}

async fn certificate(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    let block = cx.block(span.sub(0, 8)).await?;
    win_certificate(&mut Fields::emitting(&cx, &block, LE), &())?;
    cx.emit(crate::formats::embedded_as(
        "bCertificate",
        input.nested(span.tail(8)),
        &crate::formats::asn1::PKCS7,
    ));
    Ok(())
}
