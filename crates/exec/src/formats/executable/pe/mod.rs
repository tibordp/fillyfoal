//! PE/COFF images: EXE, DLL, SYS, EFI (Microsoft PE/COFF specification,
//! revision 12; `winnt.h` for the structures it leaves out).
//!
//! Expanding the file costs a handful of small reads: the DOS header, the NT
//! headers and the section table, which everything else depends on (RVA
//! translation), plus the import descriptors and their lookup tables, counted
//! for the summary. Directories, sections and their contents are dissected
//! only when expanded:
//!
//! - `exports`, `imports` (also delay-load, bound imports and the IAT),
//!   `resdir` (the resource tree; typed resource data in `resource` and
//!   `version`), `debug`, `loadcfg` (TLS and load configuration with the
//!   guard tables), `unwind` (exception data), `extra` (Rich header, base
//!   relocations, certificates, plain DOS executables);
//! - `.NET`: `clr` (CLR header and metadata root), `metadata` (tables and
//!   heaps), `signature` (blobs), `managed` (manifest resources).

mod clr;
mod debug;
mod exports;
mod extra;
mod imports;
mod loadcfg;
mod managed;
mod metadata;
mod resdir;
pub mod resource;
mod signature;
pub mod tables;
mod unwind;
pub mod version;

pub use extra::DOS_EXE;

use std::sync::Arc;

use tables::*;

use crate::bytes::{to_u64, u16_le, u32_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Field, Fields, parse, struct_node};
use crate::formats::util::binutil::RangeIndex;
use crate::formats::util::fmt::count;
use crate::formats::{Format, Input, Probe, embedded};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{Value, lookup};

const LE: Endian = Endian::Little;
/// Longest name (DLL, function, forwarder) we look for a terminator in.
const MAX_NAME: u64 = 4096;
const IMAGE_FILE_EXECUTABLE: u16 = 0x0002;
const IMAGE_FILE_DLL: u16 = 0x2000;
const DLLCHAR_WDM_DRIVER: u16 = 0x2000;
/// Offset of `CheckSum` in the optional header (both PE32 and PE32+).
const CHECKSUM_AT: u64 = 64;
/// Images up to this size get their checksum verified.
const MAX_CHECKSUM_FILE: u64 = 64 << 20;

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
        let rich = extra::rich_header(&cx, file, lfanew).await.ok().flatten();
        let stub_end = rich.as_ref().map_or(lfanew, |r| r.start);
        cx.emit(stub_node(&cx, file, stub_end).await);
        if let Some(rich) = rich {
            let end = rich.end;
            cx.emit(rich.node);
            if end < lfanew {
                cx.emit(padding_node(
                    "Padding",
                    file.sub(end, lfanew.saturating_sub(end)),
                    "Zero bytes between the Rich header and the PE header",
                ));
            }
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
            .lazy(nt_headers, (input, lfanew)),
    );
    let pe = load(&cx, input, lfanew).await?;
    cx.annotate(summary(&pe, &Overview::default()));

    let table = pe.section_table;
    cx.emit(
        Node::new("Section Table")
            .span(table)
            .summary(format!("{} sections", pe.sections.len()))
            .lazy(section_table, pe.clone()),
    );
    let headers_end = u64::from(pe.size_of_headers).min(file.len);
    let table_end = table.end().saturating_sub(file.offset);
    if table_end < headers_end {
        cx.emit(
            Node::new("Header Padding")
                .span(file.sub(table_end, headers_end.saturating_sub(table_end)))
                .desc("Rest of the headers, up to SizeOfHeaders (FileAlignment); bound imports may live here"),
        );
    }

    for (index, name) in DATA_DIRECTORIES.iter().enumerate() {
        let (rva, size) = pe.directory(index);
        if rva != 0 || size != 0 {
            cx.emit(directory(&pe, index, name, rva, size));
        }
    }

    let (res_rva, res_size) = pe.directory(DIR_RESOURCE);
    if res_rva != 0
        && res_size != 0
        && let Ok(Some(span)) = resdir::find(&cx, &pe, res_rva, RT_VERSION, None).await
    {
        let node = Node::new("Version Information")
            .span(span)
            .lazy(version::block, (span, resource::Layout::Win32));
        cx.emit(
            match version::summary(&cx, span, resource::Layout::Win32).await {
                Ok(summary) => node.summary(summary),
                Err(e) => node.diag(e),
            },
        );
    }

    // Inno Setup's loader keeps the offsets of the installer data in
    // RCDATA #11111 (5.1.5 and later) or at file offset 0x30.
    let inno = if res_rva != 0 && res_size != 0 {
        resdir::find(&cx, &pe, res_rva, resource::RT_RCDATA, Some(11111))
            .await
            .ok()
            .flatten()
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

    let end = pe.image_end();
    if end < file.len {
        // The certificate table is appended after the image; anything
        // beyond it (or instead of it) is overlay data.
        let (cert_at, cert_len) = pe.directory(DIR_SECURITY);
        let cert_end = u64::from(cert_at).saturating_add(cert_len.into());
        let overlay_at = if cert_at != 0 && u64::from(cert_at) >= end && cert_end <= file.len {
            if u64::from(cert_at) > end {
                cx.emit(
                    Node::new("Overlay")
                        .span(file.sub(end, u64::from(cert_at).saturating_sub(end)))
                        .desc("Data between the last section and the certificate table"),
                );
            }
            cert_end
        } else {
            end
        };
        if overlay_at < file.len {
            cx.emit(
                embedded("Overlay", input.nested(file.tail(overlay_at)))
                    .summary(format!(
                        "{} bytes after the {}",
                        file.len.saturating_sub(overlay_at),
                        if overlay_at == end {
                            "last section"
                        } else {
                            "certificate table"
                        }
                    ))
                    .desc(
                        "Data appended to the image; installers and self-extractors keep payloads here",
                    ),
            );
        }
    }

    let overview = overview(&cx, &pe).await;
    cx.annotate(summary(&pe, &overview));
    Ok(())
}

fn not_pe(signature: &[u8]) -> Diagnostic {
    match signature.get(..2) {
        Some(b"NE") => Diagnostic::unsupported("16-bit NE executable"),
        Some(b"LE" | b"LX") => Diagnostic::unsupported("LE/LX executable (VxD or OS/2)"),
        _ => Diagnostic::unsupported("DOS executable without a PE header"),
    }
}

/// Reads the NT headers and the section table.
async fn load(cx: &Cx, input: Input, lfanew: u64) -> Result<Pe> {
    let file = input.span;
    let nt = file.tail(lfanew);
    let signature = cx.read_avail(nt.sub(0, 4)).await?;
    if signature != b"PE\0\0" {
        return Err(not_pe(&signature).at(nt.sub(0, 4)));
    }
    let header = parse(cx, nt.sub(4, 20), LE, &(), file_header).await?;
    let optional = parse(
        cx,
        nt.sub(24, header.optional_size.into()),
        LE,
        &OptCtx::default(),
        optional_header,
    )
    .await?;
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
    let rva_index = RangeIndex::new(
        sections
            .iter()
            .map(|s| (s.virtual_address.into(), s.mapped_size().into())),
    );
    let raw = cx.read_avail(optional.directories).await?;
    let mut directories = [(0u32, 0u32); 16];
    for (index, slot) in directories.iter_mut().enumerate() {
        let at = index.saturating_mul(8);
        if let (Some(rva), Some(size)) = (u32_le(&raw, at), u32_le(&raw, at.saturating_add(4))) {
            *slot = (rva, size);
        }
    }
    Ok(Arc::new(PeInfo {
        input,
        wide: optional.wide,
        machine: header.machine,
        characteristics: header.characteristics,
        subsystem: optional.subsystem,
        dll_characteristics: optional.dll_characteristics,
        image_base: optional.image_base,
        size_of_headers: optional.size_of_headers,
        section_table: table,
        sections,
        rva_index,
        directories,
    }))
}

// ---------------------------------------------------------------------------
// Summary

#[derive(Default)]
struct Overview {
    imports: u64,
    import_dlls: u64,
    delay_dlls: u64,
    exports: u64,
    dotnet: Option<String>,
}

/// Counts what the summary reports: a bounded number of small reads.
async fn overview(cx: &Cx, pe: &Pe) -> Overview {
    let mut out = Overview::default();
    if let Ok((dlls, functions)) = imports::count(cx, pe).await {
        out.import_dlls = dlls;
        out.imports = functions;
    }
    out.delay_dlls = imports::count_delay(cx, pe).await.unwrap_or(0);
    out.exports = exports::count(cx, pe).await.unwrap_or(0);
    out.dotnet = clr::runtime_version(cx, pe).await.ok();
    out
}

fn summary(pe: &PeInfo, o: &Overview) -> String {
    let format = if pe.wide { "PE32+" } else { "PE32" };
    let machine = lookup(MACHINE_SHORT, pe.machine.into())
        .map_or_else(|| format!("machine {:#x}", pe.machine), str::to_owned);
    let dll = pe.characteristics & IMAGE_FILE_DLL != 0;
    let kind = match (pe.subsystem, dll) {
        (10, _) => "EFI application",
        (11, _) => "EFI boot service driver",
        (12, _) => "EFI runtime driver",
        (13, _) => "EFI ROM image",
        (_, true) => "DLL",
        (1, false) if pe.dll_characteristics & DLLCHAR_WDM_DRIVER != 0 => "driver",
        (1, false) => "native executable",
        _ if pe.characteristics & IMAGE_FILE_EXECUTABLE != 0 => "EXE",
        _ => "image",
    };
    let mut out = format!("{format} {machine} {kind}");
    if let 2 | 3 | 9 | 16 = pe.subsystem
        && let Some(ui) = lookup(SUBSYSTEM_SHORT, pe.subsystem.into())
    {
        out.push_str(&format!(" ({ui})"));
    }
    if o.import_dlls > 0 {
        out.push_str(&format!(
            ", {} from {}",
            count(o.imports, "import", "imports"),
            count(o.import_dlls, "DLL", "DLLs")
        ));
    }
    if o.delay_dlls > 0 {
        out.push_str(&format!(
            ", {} delay-loaded",
            count(o.delay_dlls, "DLL", "DLLs")
        ));
    }
    if o.exports > 0 {
        out.push_str(&format!(", {}", count(o.exports, "export", "exports")));
    }
    if pe.directory(DIR_SECURITY).1 > 0 {
        out.push_str(", signed");
    }
    if let Some(version) = &o.dotnet {
        out.push_str(&format!(", .NET {version}"));
    } else if pe.directory(DIR_CLR).0 != 0 {
        out.push_str(", .NET");
    }
    out
}

// ---------------------------------------------------------------------------
// Image model shared by the lazy expansions

type Pe = Arc<PeInfo>;

struct PeInfo {
    input: Input,
    wide: bool,
    machine: u16,
    characteristics: u16,
    subsystem: u16,
    dll_characteristics: u16,
    image_base: u64,
    size_of_headers: u32,
    section_table: Span,
    sections: Vec<Section>,
    /// The sections' RVA ranges, for [`PeInfo::rva_offset`].
    rva_index: RangeIndex,
    directories: [(u32, u32); 16],
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
    /// The size of the section in memory (the raw size if the virtual size
    /// is zero).
    fn mapped_size(&self) -> u32 {
        if self.virtual_size == 0 {
            self.raw_size
        } else {
            self.virtual_size
        }
    }

    fn label(&self) -> String {
        if self.name.is_empty() {
            "(unnamed)".to_owned()
        } else {
            self.name.clone()
        }
    }

    fn summary(&self) -> String {
        let flag = |bit: u32, c: char| {
            if self.characteristics & bit != 0 {
                c
            } else {
                '-'
            }
        };
        let contents = if self.characteristics & 0x20 != 0 {
            ", code"
        } else if self.characteristics & 0x80 != 0 {
            ", uninitialized data"
        } else if self.characteristics & 0x40 != 0 {
            ", data"
        } else {
            ""
        };
        format!(
            "{}{}{}  VA {:#x}+{:#x}, file {:#x}+{:#x}{contents}",
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

    /// A pointer-sized value (32 or 64 bits), in hex.
    fn word_value(&self, value: u64) -> Value {
        crate::formats::util::val::hex(value, if self.wide { 64 } else { 32 })
    }

    /// `(VirtualAddress, Size)` of data directory `index`.
    fn directory(&self, index: usize) -> (u32, u32) {
        self.directories.get(index).copied().unwrap_or((0, 0))
    }

    /// The end of the image in the file: the furthest section or header byte.
    fn image_end(&self) -> u64 {
        self.sections
            .iter()
            .filter(|s| s.raw_size > 0)
            .map(|s| u64::from(s.raw_pointer).saturating_add(s.raw_size.into()))
            .chain([u64::from(self.size_of_headers)])
            .max()
            .unwrap_or(0)
    }

    fn section_of(&self, rva: u32) -> Option<&Section> {
        self.rva_index
            .find(rva.into())
            .and_then(|i| self.sections.get(i))
    }

    /// "RVA 0x1234 (.text)".
    fn describe_rva(&self, rva: u32) -> String {
        match self.section_of(rva) {
            Some(s) => format!("RVA {rva:#x} ({})", s.label()),
            None => format!("RVA {rva:#x}"),
        }
    }

    /// Translates an RVA to an offset in the file.
    fn rva_offset(&self, rva: u32) -> Result<u64> {
        // The first section containing the RVA wins.
        if let Some(s) = self.section_of(rva) {
            let delta = rva.saturating_sub(s.virtual_address);
            if delta < s.raw_size {
                return Ok(u64::from(s.raw_pointer).saturating_add(delta.into()));
            }
            return Err(Diagnostic::malformed(format!(
                "RVA {rva:#x} lies in the zero-filled part of section {:?}",
                s.name
            )));
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

    /// The RVA of a virtual address, if it lies above the image base.
    fn va_rva(&self, va: u64) -> Option<u32> {
        u32::try_from(va.checked_sub(self.image_base)?).ok()
    }

    /// The file bytes at virtual address `va`.
    fn va_span(&self, va: u64, len: u64) -> Result<Span> {
        let rva = self
            .va_rva(va)
            .ok_or_else(|| Diagnostic::malformed(format!("VA {va:#x} is outside the image")))?;
        self.rva_span(rva, len)
    }

    /// Size of a pointer in the image.
    fn word(&self) -> u64 {
        if self.wide { 8 } else { 4 }
    }
}

/// Decorates an RVA field with where it points (or why it points nowhere).
fn rva_field<'a>(field: Field<'a, u32>, pe: &PeInfo) -> Field<'a, u32> {
    field.hex().with(|&rva, node| {
        if rva == 0 {
            return node;
        }
        let node = match pe.section_of(rva) {
            Some(s) => node.summary(s.label()),
            None => node,
        };
        match pe.rva_span(rva, 0) {
            Ok(span) => node.target(span),
            // An end address (exclusive) may lie just past its section.
            Err(e) => match pe.rva_span(rva.saturating_sub(1), 1) {
                Ok(last) => node.target(Span::new(last.source, last.end(), 0)),
                Err(_) => node.diag(e),
            },
        }
    })
}

/// Decorates a virtual address field with where it points.
fn va_field<'a>(field: Field<'a, u64>, pe: &PeInfo) -> Field<'a, u64> {
    field.hex().with(|&va, node| {
        if va == 0 {
            return node;
        }
        match pe.va_rva(va) {
            Some(rva) => {
                let node = node.summary(pe.describe_rva(rva));
                match pe.rva_span(rva, 0) {
                    Ok(span) => node.target(span),
                    Err(_) => node,
                }
            }
            None => node.diag(Diagnostic::warning(format!(
                "VA {va:#x} is below the image base"
            ))),
        }
    })
}

fn overflow() -> Diagnostic {
    Diagnostic::malformed("address arithmetic overflows")
}

async fn read_name(cx: &Cx, pe: &PeInfo, rva: u32) -> Result<(String, Span)> {
    cx.cstr(pe.rva_span(rva, MAX_NAME)?).await
}

/// A NUL-terminated name as a text node.
fn name_node(label: &'static str, name: &str, span: Span) -> Node {
    Node::new(label)
        .span(span)
        .value(Value::Text(name.to_owned()))
}

fn padding_node(name: &'static str, span: Span, desc: &'static str) -> Node {
    Node::new(name)
        .span(span)
        .summary(format!("{} bytes", span.len))
        .desc(desc)
}

// ---------------------------------------------------------------------------
// DOS header and stub

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

/// The real-mode program between the DOS header and the PE header (or the
/// Rich header), as linkers write it: code that prints a `$`-terminated
/// message with `int 21h` function 9 and exits.
struct Stub {
    /// Offset of the code from the start of the stub.
    code: usize,
    message: usize,
    message_len: usize,
    exit_code: u8,
}

/// `push cs; pop ds; mov dx, imm16; mov ah, 9; int 21h; mov ax, 4Cxxh; int 21h`.
fn standard_stub(data: &[u8], code: usize) -> Option<Stub> {
    let at = |i: usize| data.get(code.checked_add(i)?).copied();
    let pattern_ok = at(0)? == 0x0e
        && at(1)? == 0x1f
        && at(2)? == 0xba
        && at(5)? == 0xb4
        && at(6)? == 0x09
        && at(7)? == 0xcd
        && at(8)? == 0x21
        && at(9)? == 0xb8
        && at(11)? == 0x4c
        && at(12)? == 0xcd
        && at(13)? == 0x21;
    if !pattern_ok {
        return None;
    }
    let dx = usize::from(u16::from_le_bytes([at(3)?, at(4)?]));
    let message = code.checked_add(dx)?;
    let rest = data.get(message..)?;
    let len = rest.iter().take(512).position(|&b| b == b'$')?;
    Some(Stub {
        code,
        message,
        message_len: len.saturating_add(1),
        exit_code: at(10)?,
    })
}

async fn stub_node(cx: &Cx, file: Span, end: u64) -> Node {
    let span = file.sub(64, end.saturating_sub(64));
    let node = Node::new("DOS Stub")
        .span(span)
        .desc("Real-mode program run when the image is started under DOS");
    let Ok(header) = cx.read_avail(file.sub(8, 2)).await else {
        return node;
    };
    let paragraphs = u64::from(u16_le(&header, 0).unwrap_or(4));
    let Ok(data) = cx.read_avail(span.sub(0, 0x200)).await else {
        return node;
    };
    let code = paragraphs.saturating_mul(16).saturating_sub(64);
    match standard_stub(&data, crate::bytes::to_usize(code)) {
        Some(stub) => {
            let message = data
                .get(
                    stub.message
                        ..stub
                            .message
                            .saturating_add(stub.message_len.saturating_sub(1)),
                )
                .map(crate::text::latin1)
                .unwrap_or_default();
            node.summary(format!("{:?}", message.trim_end()))
                .lazy(stub_children, (span, paragraphs))
        }
        None => node.lazy(stub_children, (span, paragraphs)),
    }
}

async fn stub_children(cx: Cx, (span, paragraphs): (Span, u64)) -> Result<()> {
    let data = cx.read_avail(span.sub(0, 0x200)).await?;
    let code = paragraphs.saturating_mul(16).saturating_sub(64);
    let Some(stub) = standard_stub(&data, crate::bytes::to_usize(code)) else {
        cx.emit(
            Node::new("Program")
                .span(span)
                .desc("Real-mode code and data (not the standard linker stub)"),
        );
        return Ok(());
    };
    let at = |o: usize| to_u64(o);
    if stub.code > 0 {
        cx.emit(padding_node(
            "Header Extension",
            span.sub(0, at(stub.code)),
            "Bytes between the 64-byte header and the paragraph-aligned load module",
        ));
    }
    cx.emit(
        Node::new("Code")
            .span(span.sub(at(stub.code), 14))
            .value(Value::Text(format!(
                "push cs; pop ds; mov dx, {:#06x}; mov ah, 9; int 21h; mov ax, 0x4c{:02x}; int 21h",
                stub.message.saturating_sub(stub.code),
                stub.exit_code
            )))
            .summary(format!(
                "prints the message, exits with code {}",
                stub.exit_code
            )),
    );
    let code_end = stub.code.saturating_add(14);
    if stub.message > code_end {
        cx.emit(padding_node(
            "Padding",
            span.sub(at(code_end), at(stub.message.saturating_sub(code_end))),
            "Between the code and the message",
        ));
    }
    let message_span = span.sub(at(stub.message), at(stub.message_len));
    let text = data
        .get(stub.message..stub.message.saturating_add(stub.message_len))
        .map(crate::text::latin1)
        .unwrap_or_default();
    cx.emit(
        Node::new("Message")
            .span(message_span)
            .value(Value::Text(text))
            .desc("Printed by DOS function 9, which stops at '$'"),
    );
    let end = stub.message.saturating_add(stub.message_len);
    if at(end) < span.len {
        cx.emit(padding_node(
            "Padding",
            span.tail(at(end)),
            "Zero bytes up to the next structure",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// NT headers

async fn nt_headers(cx: Cx, (input, lfanew): (Input, u64)) -> Result<()> {
    let file = input.span;
    let nt = file.tail(lfanew);
    let signature = cx.block(nt.sub(0, 4)).await?;
    Fields::emitting(&cx, &signature, LE)
        .bytes("Signature", 4)
        .desc("\"PE\\0\\0\"")
        .emit()?;
    let header_span = nt.sub(4, 20);
    cx.emit(struct_node("File Header", header_span, LE, (), file_header));
    let header = parse(&cx, header_span, LE, &(), file_header).await?;
    let pe = load(&cx, input, lfanew).await.ok();
    let checksum = if file.len <= MAX_CHECKSUM_FILE {
        pe_checksum(
            &cx,
            file,
            lfanew.saturating_add(24).saturating_add(CHECKSUM_AT),
        )
        .await
        .ok()
    } else {
        None
    };
    cx.emit(struct_node(
        "Optional Header",
        nt.sub(24, header.optional_size.into()),
        LE,
        OptCtx { pe, checksum },
        optional_header,
    ));
    Ok(())
}

/// The image checksum (`CheckSumMappedFile`): 32-bit one's-complement-style
/// sum of the file's dwords, skipping the `CheckSum` field, folded to 16
/// bits, plus the file length.
async fn pe_checksum(cx: &Cx, file: Span, checksum_at: u64) -> Result<u32> {
    const CHUNK: u64 = 1 << 20;
    let mut sum = 0u64;
    let mut pos = 0u64;
    while pos < file.len {
        let data = cx.read(file.sub(pos, CHUNK)).await?;
        if data.is_empty() {
            break;
        }
        for (i, word) in data.chunks(4).enumerate() {
            if i.is_multiple_of(0x4000) {
                cx.checkpoint().await;
            }
            let at = pos.saturating_add(to_u64(i).saturating_mul(4));
            if at == checksum_at & !3 {
                continue;
            }
            let mut bytes = [0u8; 4];
            for (dst, src) in bytes.iter_mut().zip(word) {
                *dst = *src;
            }
            let dword = u64::from(u32::from_le_bytes(bytes));
            sum = (sum & 0xffff_ffff)
                .saturating_add(dword)
                .saturating_add(sum >> 32);
            if sum > 0xffff_ffff {
                sum = (sum & 0xffff_ffff).saturating_add(sum >> 32);
            }
        }
        pos = pos.saturating_add(to_u64(data.len()));
    }
    sum = (sum & 0xffff).saturating_add(sum >> 16);
    sum = sum.saturating_add(sum >> 16);
    sum &= 0xffff;
    Ok(u32::try_from(sum.saturating_add(file.len) & 0xffff_ffff).unwrap_or(0))
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

/// Context for rendering the optional header: the image (for addresses)
/// and the computed checksum, when known.
#[derive(Clone, Default)]
struct OptCtx {
    pe: Option<Pe>,
    checksum: Option<u32>,
}

struct OptionalHeader {
    wide: bool,
    subsystem: u16,
    dll_characteristics: u16,
    image_base: u64,
    size_of_headers: u32,
    directories: Span,
}

fn optional_header(f: &mut Fields<'_>, ctx: &OptCtx) -> Result<OptionalHeader> {
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
    let entry = f
        .u32("AddressOfEntryPoint")
        .desc("RVA of the entry point, or 0");
    match &ctx.pe {
        Some(pe) => rva_field(entry, pe).emit()?,
        None => entry.hex().emit()?,
    };
    f.u32("BaseOfCode").hex().emit()?;
    if !wide {
        f.u32("BaseOfData").hex().emit()?;
    }
    let image_base = f
        .uword("ImageBase", wide)
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
    let computed = ctx.checksum;
    f.u32("CheckSum")
        .hex()
        .desc("Image checksum (CheckSumMappedFile); required for drivers, 0 if not set")
        .with(|&v, n| match computed {
            Some(c) if v == 0 => n.summary(format!("not set (computed {c:#x})")),
            Some(c) if c == v => n.summary("valid"),
            Some(c) => n.diag(Diagnostic::warning(format!(
                "checksum mismatch: computed {c:#x}"
            ))),
            None => n,
        })
        .emit()?;
    let subsystem = f.u16("Subsystem").enumeration(SUBSYSTEM).emit()?;
    let dll_characteristics = f
        .u16("DllCharacteristics")
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
            .lazy(data_directories, (directories, ctx.pe.clone())),
    );
    Ok(OptionalHeader {
        wide,
        subsystem,
        dll_characteristics,
        image_base,
        size_of_headers,
        directories,
    })
}

async fn data_directories(cx: Cx, (table, pe): (Span, Option<Pe>)) -> Result<()> {
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
        let summary = match (&pe, index) {
            _ if rva == 0 && size == 0 => "empty".to_owned(),
            (_, DIR_SECURITY) => format!("file offset {rva:#x}, {size:#x} bytes"),
            (Some(pe), _) => format!("{}, {size:#x} bytes", pe.describe_rva(rva)),
            (None, _) => format!("RVA {rva:#x}, {size:#x} bytes"),
        };
        cx.push(
            struct_node(*name, entry, LE, (pe.clone(), index), data_directory).summary(summary),
        )
        .await;
    }
    Ok(())
}

fn data_directory(f: &mut Fields<'_>, (pe, index): &(Option<Pe>, usize)) -> Result<()> {
    if *index == DIR_SECURITY {
        let file = pe.as_ref().map(|p| p.file());
        let at = f
            .u32("VirtualAddress")
            .hex()
            .desc("A file offset, not an RVA, for the certificate table");
        let size_at = f
            .block()
            .data
            .get(4..8)
            .and_then(|b| u32_le(b, 0))
            .unwrap_or(0);
        match file {
            Some(file) => at
                .with(|&v, n| {
                    if v == 0 {
                        n
                    } else {
                        n.target(file.sub(v.into(), size_at.into()))
                    }
                })
                .emit()?,
            None => at.emit()?,
        };
    } else {
        match pe {
            Some(pe) => rva_field(f.u32("VirtualAddress"), pe).emit()?,
            None => f.u32("VirtualAddress").hex().emit()?,
        };
    }
    f.u32("Size").hex().emit()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Sections

fn section_header(f: &mut Fields<'_>, file: &Span) -> Result<Section> {
    let header = f.peek_span(40);
    let name = f
        .ascii("Name", 8)
        .desc("A \"/123\" name refers to the COFF string table (object files only)")
        .emit()?;
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
        cx.push(
            Node::new(section.label())
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
    // The data directories that live in this section.
    let start = section.virtual_address;
    let end = start.saturating_add(section.mapped_size());
    let inside: Vec<&str> = DATA_DIRECTORIES
        .iter()
        .enumerate()
        .filter(|&(i, _)| {
            let (rva, size) = pe.directory(i);
            i != DIR_SECURITY && size > 0 && rva >= start && rva < end
        })
        .map(|(_, &name)| name)
        .collect();
    if section.raw_size > 0 {
        let wanted = u64::from(section.raw_size);
        // Bytes beyond VirtualSize are FileAlignment padding.
        let used = if section.virtual_size > 0 && section.virtual_size < section.raw_size {
            u64::from(section.virtual_size)
        } else {
            wanted
        };
        let data = pe.file().sub(section.raw_pointer.into(), used);
        let mut node = Node::new("Raw Data").span(data);
        if !inside.is_empty() {
            node = node.summary(format!("holds {}", inside.join(", ")));
        }
        if data.len < used {
            node = node.diag(Diagnostic::truncated(
                Span::new(data.source, data.offset, used),
                data.len,
            ));
        }
        cx.emit(node);
        if used < wanted {
            cx.emit(padding_node(
                "Alignment Padding",
                pe.file().sub(
                    u64::from(section.raw_pointer).saturating_add(used),
                    wanted.saturating_sub(used),
                ),
                "File bytes beyond VirtualSize, up to FileAlignment",
            ));
        }
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
            node.summary(format!("{}, {size:#x} bytes", pe.describe_rva(rva))),
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
        DIR_EXPORT => node.lazy(exports::exports, (pe, dir)),
        DIR_IMPORT => node.lazy(imports::imports, (pe, dir)),
        DIR_RESOURCE => node.lazy(resdir::root, (pe, rva)),
        DIR_EXCEPTION => node.lazy(unwind::exceptions, (pe, dir)),
        DIR_SECURITY => node.lazy(extra::certificates, (pe.input, dir)),
        DIR_BASERELOC => node.lazy(extra::base_relocations, (pe, dir)),
        DIR_DEBUG => node.lazy(debug::directory, (pe, dir)),
        DIR_TLS => node.lazy(loadcfg::tls, (pe, dir)),
        DIR_LOAD_CONFIG => node.lazy(loadcfg::load_config, (pe, dir)),
        DIR_BOUND_IMPORT => node.lazy(imports::bound, (pe, dir)),
        DIR_IAT => node.lazy(imports::iat, (pe, dir)),
        DIR_DELAY_IMPORT => node.lazy(imports::delay_imports, (pe, dir)),
        DIR_CLR => node.lazy(clr::clr, (pe, dir)),
        _ => node,
    }
}
