//! Mach-O (macOS, iOS, ...): executables, dylibs, bundles, objects, in
//! 32/64-bit and either byte order; universal ("fat") binaries; code
//! signatures; and the dyld shared cache header.
//!
//! Expanding the file reads the header and the load commands (one read,
//! usually a few KiB): segments, sections, linked libraries and symbol table
//! locations all come from there. Symbol tables, signatures and the
//! `__LINKEDIT` structures are decoded only when expanded.

pub mod codesign;
pub mod dyld_cache;
pub mod fat;
mod linkedit;
pub(crate) mod tables;

use std::sync::Arc;

use tables::*;

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::util::binutil::{
    NodeExt, RangeIndex, cstrings, data_node, ellipsize, get_at, hex, name_or, perms, string_at,
    text,
};
use crate::formats::{Format, Input, Probe, embedded};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::lookup;

pub static FORMAT: Format = Format {
    name: "macho",
    title: "Mach-O executable, library or object",
    extensions: &["dylib", "bundle", "o", "kext", "macho", "dSYM"],
    mime: "application/x-mach-binary",
    probe: Probe::Magic(&[
        (0, b"\xce\xfa\xed\xfe"),
        (0, b"\xcf\xfa\xed\xfe"),
        (0, b"\xfe\xed\xfa\xce"),
        (0, b"\xfe\xed\xfa\xcf"),
    ]),
    dissect: crate::expander!(dissect: Input),
};

/// Load command regions larger than this are not read.
const MAX_COMMANDS: u64 = 4 << 20;

// ---------------------------------------------------------------------------
// Model

#[derive(Clone, Copy, Debug)]
struct Header {
    cputype: u32,
    cpusubtype: u32,
    filetype: u32,
    ncmds: u32,
    sizeofcmds: u32,
    flags: u32,
}

#[derive(Clone, Copy, Debug)]
struct Command {
    span: Span,
    cmd: u32,
}

#[derive(Clone, Debug)]
struct SegmentInfo {
    name: String,
    vmaddr: u64,
    fileoff: u64,
    filesize: u64,
    nsects: u32,
}

#[derive(Clone, Debug)]
struct SectionInfo {
    sectname: String,
    segname: String,
    addr: u64,
    size: u64,
    offset: u32,
    reloff: u32,
    nreloc: u32,
    flags: u32,
    reserved1: u32,
    reserved2: u32,
}

impl SectionInfo {
    fn kind(&self) -> u32 {
        self.flags & 0xff
    }
    fn label(&self) -> String {
        format!("{},{}", self.segname, self.sectname)
    }
    fn is_zerofill(&self) -> bool {
        matches!(
            self.kind(),
            S_ZEROFILL | S_GB_ZEROFILL | S_THREAD_LOCAL_ZEROFILL
        )
    }
}

#[derive(Clone, Copy, Debug)]
struct Symtab {
    symoff: u32,
    nsyms: u32,
    stroff: u32,
    strsize: u32,
}

#[derive(Clone, Copy, Debug)]
struct Dysymtab {
    indirectsymoff: u32,
    nindirectsyms: u32,
}

type Macho = Arc<MachInfo>;

struct MachInfo {
    input: Input,
    endian: Endian,
    wide: bool,
    header: Header,
    commands: Vec<Command>,
    segments: Vec<SegmentInfo>,
    sections: Vec<SectionInfo>,
    dylibs: Vec<String>,
    symtab: Option<Symtab>,
    dysymtab: Option<Dysymtab>,
    code_signature: Option<(u32, u32)>,
    /// The segments' address ranges, for [`MachInfo::vm_span`].
    vm_index: RangeIndex,
}

impl MachInfo {
    fn file(&self) -> Span {
        self.input.span
    }

    fn word(&self) -> u64 {
        if self.wide { 8 } else { 4 }
    }

    fn bits(&self) -> u8 {
        if self.wide { 64 } else { 32 }
    }

    fn nlist_size(&self) -> u64 {
        if self.wide { 16 } else { 12 }
    }

    /// The section numbered `n` (1-based, as in `n_sect`).
    fn section(&self, n: u8) -> Option<&SectionInfo> {
        self.sections.get(usize::from(n).checked_sub(1)?)
    }

    fn dylib(&self, ordinal: u8) -> String {
        match usize::from(ordinal)
            .checked_sub(1)
            .and_then(|i| self.dylibs.get(i))
        {
            Some(name) => name.clone(),
            None => lookup(BIND_SPECIAL_DYLIB, ordinal.into())
                .map_or_else(|| format!("library #{ordinal}"), str::to_owned),
        }
    }

    /// Translates a virtual address to a file span through the segments.
    /// The first segment containing the address wins.
    fn vm_span(&self, addr: u64, len: u64) -> Option<Span> {
        let s = self.segments.get(self.vm_index.find(addr)?)?;
        let delta = addr.saturating_sub(s.vmaddr);
        Some(self.file().sub(
            s.fileoff.saturating_add(delta),
            len.min(s.filesize.saturating_sub(delta)),
        ))
    }

    fn text_vmaddr(&self) -> u64 {
        self.segments
            .iter()
            .find(|s| s.name == "__TEXT")
            .map_or(0, |s| s.vmaddr)
    }

    fn linkedit(&self, offset: u32, size: u32) -> Span {
        self.file().sub(offset.into(), size.into())
    }
}

/// Context shared by the layouts of load commands.
#[derive(Clone, Copy, Debug)]
struct Ctx {
    wide: bool,
    file: Span,
}

// ---------------------------------------------------------------------------
// Entry point

fn magic(data: &[u8]) -> Option<(Endian, bool)> {
    match data.get(..4)? {
        b"\xce\xfa\xed\xfe" => Some((Endian::Little, false)),
        b"\xcf\xfa\xed\xfe" => Some((Endian::Little, true)),
        b"\xfe\xed\xfa\xce" => Some((Endian::Big, false)),
        b"\xfe\xed\xfa\xcf" => Some((Endian::Big, true)),
        _ => None,
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 4)).await?;
    let (endian, wide) = magic(&head)
        .ok_or_else(|| Diagnostic::malformed("not a Mach-O header").at(file.sub(0, 4)))?;
    let header_size = if wide { 32 } else { 28 };
    let header_span = file.sub(0, header_size);
    let header = parse(&cx, header_span, endian, &wide, mach_header).await;
    let mut node = struct_node("Mach Header", header_span, endian, wide, mach_header);
    if let Ok(h) = &header {
        node = node.summary(format!(
            "{}, {}",
            name_or(FILE_TYPE, h.filetype.into(), "filetype"),
            arch_name(h.cputype, h.cpusubtype)
        ));
    }
    cx.emit(node);
    let header = header?;

    let ctx = Ctx { wide, file };
    let region = file.sub(header_size, header.sizeofcmds.into());
    if region.len > MAX_COMMANDS {
        return Err(Diagnostic::limit("load commands are implausibly large").at(region));
    }
    let bytes = cx.read_avail(region).await?;
    if to_u64(bytes.len()) < u64::from(header.sizeofcmds) {
        cx.diag(Diagnostic::truncated(
            Span::new(region.source, region.offset, header.sizeofcmds.into()),
            to_u64(bytes.len()),
        ));
    }
    let mut info = MachInfo {
        input,
        endian,
        wide,
        header,
        commands: Vec::new(),
        segments: Vec::new(),
        sections: Vec::new(),
        dylibs: Vec::new(),
        symtab: None,
        dysymtab: None,
        code_signature: None,
        vm_index: RangeIndex::default(),
    };
    let block = crate::cx::Block {
        span: region,
        data: bytes,
    };
    let mut offset = 0u64;
    for _ in 0..header.ncmds {
        cx.checkpoint().await;
        let (Some(cmd), Some(size)) = (
            get_at::<u32>(&block.data, offset, endian),
            get_at::<u32>(&block.data, offset.saturating_add(4), endian),
        ) else {
            cx.diag(Diagnostic::truncated(region.sub(offset, 8), 0));
            break;
        };
        if size < 8 {
            cx.diag(
                Diagnostic::malformed(format!("load command size {size} is too small"))
                    .at(region.sub(offset, 8)),
            );
            break;
        }
        let span = region.sub(offset, size.into());
        info.commands.push(Command { span, cmd });
        let mut f = Fields::new(&block, endian);
        f.seek(offset);
        if let Err(e) = learn(&mut info, &mut f, &ctx, cmd, size) {
            cx.diag(e);
        }
        offset = offset.saturating_add(size.into());
    }
    info.vm_index = RangeIndex::new(info.segments.iter().map(|s| (s.vmaddr, s.filesize)));
    let m: Macho = Arc::new(info);

    let signature = m.code_signature.map(|(o, s)| m.linkedit(o, s));
    let signed = match signature {
        Some(span) => codesign::summary(&cx, span).await.ok(),
        None => None,
    };
    cx.annotate(summary(&m, &block.data, signed.as_deref()));

    cx.emit(
        Node::new("Load Commands")
            .span(region)
            .summary(format!("{} commands", m.commands.len()))
            .lazy(command_list, m.clone()),
    );
    if !m.dylibs.is_empty() {
        cx.emit(
            Node::new("Linked Libraries")
                .summary(ellipsize(&m.dylibs.join(", "), 120))
                .lazy(libraries, m.clone()),
        );
    }
    if let Some(symtab) = m.symtab {
        cx.emit(symtab_node(&m, symtab));
    }
    if let Some(span) = signature {
        let mut node = Node::new("Code Signature")
            .span(span)
            .lazy(codesign::superblob, span);
        if let Some(s) = signed {
            node = node.summary(s);
        }
        cx.emit(node);
    }

    let end = m
        .segments
        .iter()
        .map(|s| s.fileoff.saturating_add(s.filesize))
        .chain(
            m.sections
                .iter()
                .filter(|s| !s.is_zerofill())
                .map(|s| u64::from(s.offset).saturating_add(s.size)),
        )
        .chain([header_size.saturating_add(header.sizeofcmds.into())])
        .max()
        .unwrap_or(0);
    if end < file.len && header.filetype != 1 {
        cx.emit(
            embedded("Overlay", input.nested(file.tail(end))).summary(format!(
                "{:#x} bytes after the last segment",
                file.len.saturating_sub(end)
            )),
        );
    }
    Ok(())
}

/// Records what later expansions need from a load command.
fn learn(info: &mut MachInfo, f: &mut Fields<'_>, ctx: &Ctx, cmd: u32, size: u32) -> Result<()> {
    let start = f.pos();
    match cmd {
        LC_SEGMENT | LC_SEGMENT_64 => {
            let segment = segment_command(f, ctx)?;
            // Only the section headers inside the command: a bogus `nsects`
            // in a run of tiny commands would otherwise re-read the rest of
            // the load commands once per command.
            let room = u64::from(size)
                .saturating_sub(f.pos().saturating_sub(start))
                .checked_div(if ctx.wide { 80 } else { 68 })
                .unwrap_or(0);
            for _ in 0..u64::from(segment.nsects).min(room) {
                info.sections.push(section_header(f, ctx)?);
            }
            info.segments.push(segment);
        }
        LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB | LC_LAZY_LOAD_DYLIB
        | LC_LOAD_UPWARD_DYLIB => {
            f.skip(8);
            let name = f.u32("name").get()?;
            f.seek(start.saturating_add(name.into()));
            let path = f.cstr("path").get().unwrap_or_default();
            info.dylibs.push(short_dylib(&path).to_owned());
        }
        LC_SYMTAB => {
            f.skip(8);
            info.symtab = Some(Symtab {
                symoff: f.u32("symoff").get()?,
                nsyms: f.u32("nsyms").get()?,
                stroff: f.u32("stroff").get()?,
                strsize: f.u32("strsize").get()?,
            });
        }
        LC_CODE_SIGNATURE => {
            f.skip(8);
            info.code_signature = Some((f.u32("dataoff").get()?, f.u32("datasize").get()?));
        }
        LC_DYSYMTAB => {
            f.skip(8 + 12 * 4);
            info.dysymtab = Some(Dysymtab {
                indirectsymoff: f.u32("indirectsymoff").get()?,
                nindirectsyms: f.u32("nindirectsyms").get()?,
            });
        }
        _ => {}
    }
    Ok(())
}

fn short_dylib(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn summary(m: &MachInfo, commands: &[u8], signed: Option<&str>) -> String {
    let h = &m.header;
    let bits = if m.wide { "64-bit" } else { "32-bit" };
    let order = if m.endian == Endian::Big {
        " big-endian"
    } else {
        ""
    };
    let mut parts = vec![format!(
        "Mach-O {bits}{order} {} {}",
        name_or(FILE_TYPE_WORDS, h.filetype.into(), "file type"),
        arch_name(h.cputype, h.cpusubtype)
    )];
    if h.flags & MH_PIE != 0 && h.filetype == MH_EXECUTE {
        parts.push("PIE".to_owned());
    }
    let base = to_u64(if m.wide { 32 } else { 28 });
    for c in &m.commands {
        let rel = c
            .span
            .offset
            .saturating_sub(m.file().offset)
            .saturating_sub(base);
        let bytes = commands
            .get(to_usize(rel)..to_usize(rel.saturating_add(c.span.len)))
            .unwrap_or_default();
        let w = |at: usize| get_at::<u32>(bytes, to_u64(at), m.endian).unwrap_or(0);
        match c.cmd {
            LC_BUILD_VERSION => parts.push(format!(
                "{} {}",
                name_or(PLATFORM, w(8).into(), "platform"),
                version(w(12))
            )),
            LC_VERSION_MIN_MACOSX => parts.push(format!("macOS {}", version(w(8)))),
            LC_VERSION_MIN_IPHONEOS => parts.push(format!("iOS {}", version(w(8)))),
            LC_VERSION_MIN_TVOS => parts.push(format!("tvOS {}", version(w(8)))),
            LC_VERSION_MIN_WATCHOS => parts.push(format!("watchOS {}", version(w(8)))),
            LC_ID_DYLIB => {
                let name =
                    crate::text::until_nul(bytes.get(to_usize(w(8).into())..).unwrap_or_default());
                parts.push(name);
            }
            _ => {}
        }
    }
    if let Some(s) = signed {
        parts.push(format!("signed ({s})"));
    }
    parts.join(", ")
}

// ---------------------------------------------------------------------------
// Header

fn mach_header(f: &mut Fields<'_>, wide: &bool) -> Result<Header> {
    f.u32("magic")
        .hex()
        .desc("MH_MAGIC (0xfeedface) or MH_MAGIC_64 (0xfeedfacf)")
        .emit()?;
    let cputype = f.u32("cputype").enumeration(CPU_TYPE).emit()?;
    let cpusubtype = f
        .u32("cpusubtype")
        .hex()
        .with(|&v, n| {
            let mut s = arch_name(cputype, v);
            if v & 0x8000_0000 != 0 {
                s.push_str(", pointer authentication ABI");
            }
            n.summary(s)
        })
        .emit()?;
    let filetype = f.u32("filetype").enumeration(FILE_TYPE).emit()?;
    let ncmds = f.u32("ncmds").desc("Number of load commands").emit()?;
    let sizeofcmds = f
        .u32("sizeofcmds")
        .hex()
        .desc("Total size of the load commands")
        .emit()?;
    let flags = f.u32("flags").flags(HEADER_FLAGS).emit()?;
    if *wide {
        f.u32("reserved").emit()?;
    }
    Ok(Header {
        cputype,
        cpusubtype,
        filetype,
        ncmds,
        sizeofcmds,
        flags,
    })
}

// ---------------------------------------------------------------------------
// Load commands

async fn command_list(cx: Cx, m: Macho) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(m.commands.len())));
    for (index, c) in m.commands.iter().enumerate() {
        let bytes = cx.read_avail(c.span.sub(0, 0x1000)).await?;
        let label = lookup(LOAD_COMMAND, c.cmd.into())
            .map_or_else(|| format!("LC {:#x}", c.cmd), str::to_owned);
        cx.push(
            Node::new(label)
                .span(c.span)
                .maybe_summary(command_summary(&m, c.cmd, &bytes))
                .lazy(command_node, (m.clone(), index)),
        )
        .await;
    }
    Ok(())
}

fn command_summary(m: &MachInfo, cmd: u32, b: &[u8]) -> String {
    let e = m.endian;
    let w = |at: u64| get_at::<u32>(b, at, e).unwrap_or(0);
    let q = |at: u64| get_at::<u64>(b, at, e).unwrap_or(0);
    let lc_str =
        |at: u64| crate::text::until_nul(b.get(to_usize(w(at).into())..).unwrap_or_default());
    match cmd {
        LC_SEGMENT | LC_SEGMENT_64 => {
            let name = crate::text::until_nul(b.get(8..24).unwrap_or_default());
            let (vmaddr, vmsize, fileoff, filesize, prot, nsects) = if cmd == LC_SEGMENT_64 {
                (q(24), q(32), q(40), q(48), w(60), w(64))
            } else {
                (
                    w(24).into(),
                    w(28).into(),
                    w(32).into(),
                    w(36).into(),
                    w(44),
                    w(48),
                )
            };
            format!(
                "{name} {}  vm {vmaddr:#x}+{vmsize:#x}, file {fileoff:#x}+{filesize:#x}, {nsects} sections",
                perms(prot & 1 != 0, prot & 2 != 0, prot & 4 != 0)
            )
        }
        LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB | LC_LAZY_LOAD_DYLIB
        | LC_LOAD_UPWARD_DYLIB | LC_ID_DYLIB => format!(
            "{} ({}, compatibility {})",
            lc_str(8),
            version(w(16)),
            version(w(20))
        ),
        LC_LOAD_DYLINKER | LC_ID_DYLINKER | LC_DYLD_ENVIRONMENT | LC_RPATH | LC_SUB_FRAMEWORK
        | LC_SUB_UMBRELLA | LC_SUB_CLIENT | LC_SUB_LIBRARY | LC_TARGET_TRIPLE => lc_str(8),
        LC_UUID => uuid(b.get(8..24).unwrap_or_default()),
        LC_BUILD_VERSION => {
            let mut s = format!(
                "{} {}, SDK {}",
                name_or(PLATFORM, w(8).into(), "platform"),
                version(w(12)),
                version(w(16))
            );
            for i in 0..u64::from(w(20)).min(8) {
                let at = 24u64.saturating_add(i.saturating_mul(8));
                s.push_str(&format!(
                    ", {} {}",
                    name_or(TOOL, w(at).into(), "tool"),
                    version(w(at.saturating_add(4)))
                ));
            }
            s
        }
        LC_VERSION_MIN_MACOSX
        | LC_VERSION_MIN_IPHONEOS
        | LC_VERSION_MIN_TVOS
        | LC_VERSION_MIN_WATCHOS => format!("{}, SDK {}", version(w(8)), version(w(12))),
        LC_MAIN => format!("entry offset {:#x}, stack size {:#x}", q(8), q(16)),
        LC_SYMTAB => format!("{} symbols, {:#x} bytes of strings", w(12), w(20)),
        LC_DYSYMTAB => format!(
            "{} local, {} defined external, {} undefined, {} indirect",
            w(12),
            w(20),
            w(28),
            w(60)
        ),
        LC_CODE_SIGNATURE
        | LC_SEGMENT_SPLIT_INFO
        | LC_FUNCTION_STARTS
        | LC_DATA_IN_CODE
        | LC_DYLIB_CODE_SIGN_DRS
        | LC_LINKER_OPTIMIZATION_HINT
        | LC_DYLD_EXPORTS_TRIE
        | LC_DYLD_CHAINED_FIXUPS
        | LC_ATOM_INFO
        | LC_FUNCTION_VARIANTS
        | LC_FUNCTION_VARIANT_FIXUPS => format!("{:#x} bytes at {:#x}", w(12), w(8)),
        LC_DYLD_INFO | LC_DYLD_INFO_ONLY => format!(
            "rebase {:#x}, bind {:#x}, weak {:#x}, lazy {:#x}, export {:#x} bytes",
            w(12),
            w(20),
            w(28),
            w(36),
            w(44)
        ),
        LC_SOURCE_VERSION => source_version(q(8)),
        LC_ENCRYPTION_INFO | LC_ENCRYPTION_INFO_64 => {
            format!("cryptid {} ({:#x} bytes at {:#x})", w(16), w(12), w(8))
        }
        LC_LINKER_OPTION => {
            let strings: Vec<String> = b
                .get(12..)
                .unwrap_or_default()
                .split(|&c| c == 0)
                .take(to_usize(w(8).into()).min(32))
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect();
            strings.join(" ")
        }
        LC_NOTE => format!(
            "{}, {:#x} bytes at {:#x}",
            crate::text::until_nul(b.get(8..24).unwrap_or_default()),
            q(32),
            q(24)
        ),
        LC_FILESET_ENTRY => lc_str(24),
        LC_THREAD | LC_UNIXTHREAD => format!("flavor {}", w(8)),
        _ => String::new(),
    }
}

async fn command_node(cx: Cx, (m, index): (Macho, usize)) -> Result<()> {
    let c = *m
        .commands
        .get(index)
        .ok_or_else(|| Diagnostic::internal("command index out of range"))?;
    let block = cx.block(c.span).await?;
    let ctx = Ctx {
        wide: m.wide,
        file: m.file(),
    };
    let mut f = Fields::emitting(&cx, &block, m.endian);
    let mut extras = Vec::new();
    match c.cmd {
        LC_SEGMENT | LC_SEGMENT_64 => {
            let segment = segment_command(&mut f, &ctx)?;
            // Section headers follow the segment command.
            let size = if m.wide { 80 } else { 68 };
            for i in 0..u64::from(segment.nsects) {
                let header = c
                    .span
                    .sub(f.pos().saturating_add(i.saturating_mul(size)), size);
                let s = parse(&cx, header, m.endian, &ctx, section_header).await?;
                extras.push(
                    Node::new(s.label())
                        .span(header)
                        .summary(section_summary(&s))
                        .lazy(section_node, (m.clone(), header)),
                );
            }
        }
        LC_SYMTAB => {
            let st = symtab_command(&mut f, &ctx)?;
            extras.push(symtab_node(&m, st));
            extras.push(
                Node::new("String Table")
                    .span(m.linkedit(st.stroff, st.strsize))
                    .lazy(cstrings, m.linkedit(st.stroff, st.strsize)),
            );
        }
        LC_DYSYMTAB => {
            let d = dysymtab_command(&mut f, &ctx)?;
            if d.nindirectsyms > 0 {
                let span = m.linkedit(d.indirectsymoff, d.nindirectsyms.saturating_mul(4));
                extras.push(
                    Node::new("Indirect Symbols")
                        .span(span)
                        .summary(format!("{} entries", d.nindirectsyms))
                        .lazy(indirect_symbols, (m.clone(), 0u32, d.nindirectsyms)),
                );
            }
        }
        LC_CODE_SIGNATURE
        | LC_SEGMENT_SPLIT_INFO
        | LC_FUNCTION_STARTS
        | LC_DATA_IN_CODE
        | LC_DYLIB_CODE_SIGN_DRS
        | LC_LINKER_OPTIMIZATION_HINT
        | LC_DYLD_EXPORTS_TRIE
        | LC_DYLD_CHAINED_FIXUPS
        | LC_ATOM_INFO
        | LC_FUNCTION_VARIANTS
        | LC_FUNCTION_VARIANT_FIXUPS => {
            let (offset, size) = linkedit_data(&mut f, &ctx)?;
            let span = m.linkedit(offset, size);
            let node = match c.cmd {
                LC_CODE_SIGNATURE => Node::new("Code Signature")
                    .span(span)
                    .lazy(codesign::superblob, span),
                LC_FUNCTION_STARTS => Node::new("Function Starts")
                    .span(span)
                    .lazy(linkedit::function_starts, (span, m.text_vmaddr(), m.file())),
                LC_DATA_IN_CODE => Node::new("Data in Code")
                    .span(span)
                    .summary(format!("{} entries", span.len / 8))
                    .lazy(linkedit::data_in_code, (span, m.endian)),
                LC_DYLD_CHAINED_FIXUPS => Node::new("Chained Fixups")
                    .span(span)
                    .lazy(linkedit::chained_fixups, (span, m.endian, m.dylibs.clone())),
                LC_DYLD_EXPORTS_TRIE => Node::new("Exports Trie")
                    .span(span)
                    .lazy(linkedit::exports_trie, (span, m.text_vmaddr())),
                _ => data_node("Data", span, size.into()),
            };
            extras.push(node);
        }
        LC_DYLD_INFO | LC_DYLD_INFO_ONLY => {
            for (name, offset, size) in dyld_info(&mut f, &ctx)? {
                if size == 0 {
                    continue;
                }
                let span = m.linkedit(offset, size);
                extras.push(match name {
                    "Export Info" => Node::new(name)
                        .span(span)
                        .lazy(linkedit::exports_trie, (span, m.text_vmaddr())),
                    "Rebase Info" => data_node(name, span, size.into()),
                    _ => Node::new(name)
                        .span(span)
                        .lazy(linkedit::bind_opcodes, (span, m.wide, m.dylibs.clone())),
                });
            }
        }
        LC_NOTE => {
            let (offset, size) = note_command(&mut f, &ctx)?;
            extras.push(embedded(
                "Note Data",
                m.input.nested(m.file().sub(offset, size)),
            ));
        }
        LC_THREAD | LC_UNIXTHREAD => {
            thread_command(&cx, &mut f, c.span.len).await?;
        }
        _ => {
            simple_command(&mut f, &ctx, c.cmd)?;
        }
    }
    for node in extras {
        cx.emit(node);
    }
    Ok(())
}

/// Emits `cmd` and `cmdsize`.
fn command_head(f: &mut Fields<'_>) -> Result<u32> {
    let cmd = f.u32("cmd").enumeration(LOAD_COMMAND).emit()?;
    f.u32("cmdsize").emit()?;
    Ok(cmd)
}

/// An `lc_str`: an offset (from the command start) of a NUL-terminated
/// string inside the command.
fn lc_str(f: &mut Fields<'_>, label: &'static str, name: &'static str) -> Result<String> {
    let offset = f.u32(label).hex().desc("Offset of the string").emit()?;
    let here = f.pos();
    f.seek(offset.into());
    let s = f.cstr(name).emit();
    f.seek(here);
    s
}

fn segment_command(f: &mut Fields<'_>, c: &Ctx) -> Result<SegmentInfo> {
    command_head(f)?;
    let name = f.ascii("segname", 16).emit()?;
    let vmaddr = f.uword("vmaddr", c.wide).hex().emit()?;
    f.uword("vmsize", c.wide).hex().emit()?;
    let filesize = peek_word(f, if c.wide { 8 } else { 4 }, c.wide);
    let file = c.file;
    let fileoff = f
        .uword("fileoff", c.wide)
        .hex()
        .with(|&v, n| n.target(file.sub(v, filesize)))
        .emit()?;
    let filesize = f.uword("filesize", c.wide).hex().emit()?;
    f.u32("maxprot").flags(VM_PROT).emit()?;
    f.u32("initprot").flags(VM_PROT).emit()?;
    let nsects = f.u32("nsects").emit()?;
    f.u32("flags").flags(SEGMENT_FLAGS).emit()?;
    Ok(SegmentInfo {
        name,
        vmaddr,
        fileoff,
        filesize,
        nsects,
    })
}

fn peek_word(f: &mut Fields<'_>, ahead: u64, wide: bool) -> u64 {
    let here = f.pos();
    f.skip(ahead);
    let v = f.uword("", wide).get().unwrap_or(0);
    f.seek(here);
    v
}

fn section_header(f: &mut Fields<'_>, c: &Ctx) -> Result<SectionInfo> {
    let sectname = f.ascii("sectname", 16).emit()?;
    let segname = f.ascii("segname", 16).emit()?;
    let addr = f.uword("addr", c.wide).hex().emit()?;
    let size = f.uword("size", c.wide).hex().emit()?;
    let file = c.file;
    let offset = f
        .u32("offset")
        .hex()
        .with(|&v, n| {
            if v == 0 {
                n
            } else {
                n.target(file.sub(v.into(), size))
            }
        })
        .emit()?;
    f.u32("align")
        .with(|&v, n| n.summary(format!("2^{v}")))
        .emit()?;
    let reloff = f.u32("reloff").hex().emit()?;
    let nreloc = f.u32("nreloc").emit()?;
    let flags = f.u32("flags").flags(SECTION_FLAGS).emit()?;
    let reserved1 = f
        .u32("reserved1")
        .desc("Indirect symbol index (pointer and stub sections)")
        .emit()?;
    let reserved2 = f
        .u32("reserved2")
        .desc("Stub size (stub sections)")
        .emit()?;
    if c.wide {
        f.u32("reserved3").emit()?;
    }
    Ok(SectionInfo {
        sectname,
        segname,
        addr,
        size,
        offset,
        reloff,
        nreloc,
        flags,
        reserved1,
        reserved2,
    })
}

fn section_summary(s: &SectionInfo) -> String {
    let kind = name_or(SECTION_TYPE, s.kind().into(), "type");
    format!("{kind}, {:#x} bytes at {:#x}", s.size, s.addr)
}

fn symtab_command(f: &mut Fields<'_>, c: &Ctx) -> Result<Symtab> {
    command_head(f)?;
    let file = c.file;
    let symoff = f.u32("symoff").hex().emit()?;
    let nsyms = f.u32("nsyms").emit()?;
    let stroff = f
        .u32("stroff")
        .hex()
        .with(|&v, n| n.target(file.sub(v.into(), 0)))
        .emit()?;
    let strsize = f.u32("strsize").hex().emit()?;
    Ok(Symtab {
        symoff,
        nsyms,
        stroff,
        strsize,
    })
}

fn dysymtab_command(f: &mut Fields<'_>, _: &Ctx) -> Result<Dysymtab> {
    command_head(f)?;
    for name in [
        "ilocalsym",
        "nlocalsym",
        "iextdefsym",
        "nextdefsym",
        "iundefsym",
        "nundefsym",
    ] {
        f.u32(name).emit()?;
    }
    for name in [
        "tocoff",
        "ntoc",
        "modtaboff",
        "nmodtab",
        "extrefsymoff",
        "nextrefsyms",
    ] {
        f.u32(name).emit()?;
    }
    let indirectsymoff = f.u32("indirectsymoff").hex().emit()?;
    let nindirectsyms = f.u32("nindirectsyms").emit()?;
    for name in ["extreloff", "nextrel", "locreloff", "nlocrel"] {
        f.u32(name).emit()?;
    }
    Ok(Dysymtab {
        indirectsymoff,
        nindirectsyms,
    })
}

fn linkedit_data(f: &mut Fields<'_>, c: &Ctx) -> Result<(u32, u32)> {
    command_head(f)?;
    let file = c.file;
    let size = peek_word(f, 4, false);
    let offset = f
        .u32("dataoff")
        .hex()
        .with(|&v, n| n.target(file.sub(v.into(), size)))
        .emit()?;
    let size = f.u32("datasize").hex().emit()?;
    Ok((offset, size))
}

fn dyld_info(f: &mut Fields<'_>, _: &Ctx) -> Result<Vec<(&'static str, u32, u32)>> {
    command_head(f)?;
    let mut out = Vec::new();
    for (name, off, size) in [
        ("Rebase Info", "rebase_off", "rebase_size"),
        ("Bind Info", "bind_off", "bind_size"),
        ("Weak Bind Info", "weak_bind_off", "weak_bind_size"),
        ("Lazy Bind Info", "lazy_bind_off", "lazy_bind_size"),
        ("Export Info", "export_off", "export_size"),
    ] {
        let o = f.u32(off).hex().emit()?;
        let s = f.u32(size).hex().emit()?;
        out.push((name, o, s));
    }
    Ok(out)
}

fn note_command(f: &mut Fields<'_>, _: &Ctx) -> Result<(u64, u64)> {
    command_head(f)?;
    f.ascii("data_owner", 16).emit()?;
    let offset = f.u64("offset").hex().emit()?;
    let size = f.u64("size").hex().emit()?;
    Ok((offset, size))
}

/// Thread states (a flavor, a count and the words), a checkpoint per few
/// hundred: a large command holds many.
async fn thread_command(cx: &Cx, f: &mut Fields<'_>, len: u64) -> Result<()> {
    command_head(f)?;
    let mut states = 0u32;
    while f.pos().saturating_add(8) <= len {
        states = states.wrapping_add(1);
        if states.is_multiple_of(256) {
            cx.checkpoint().await;
        }
        f.u32("flavor").emit()?;
        let count = f
            .u32("count")
            .desc("Number of 32-bit words of state")
            .emit()?;
        let size = u64::from(count).saturating_mul(4);
        f.bytes("state", size.min(len.saturating_sub(f.pos())))
            .emit()?;
        if count == 0 {
            break;
        }
    }
    Ok(())
}

/// Fixed-layout commands that need no extra nodes.
fn simple_command(f: &mut Fields<'_>, c: &Ctx, cmd: u32) -> Result<()> {
    command_head(f)?;
    match cmd {
        LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB | LC_LAZY_LOAD_DYLIB
        | LC_LOAD_UPWARD_DYLIB | LC_ID_DYLIB => {
            lc_str(f, "name.offset", "name")?;
            f.u32("timestamp").timestamp().emit()?;
            f.u32("current_version")
                .hex()
                .with(|&v, n| n.summary(version(v)))
                .emit()?;
            f.u32("compatibility_version")
                .hex()
                .with(|&v, n| n.summary(version(v)))
                .emit()?;
        }
        LC_LOAD_DYLINKER | LC_ID_DYLINKER | LC_DYLD_ENVIRONMENT => {
            lc_str(f, "name.offset", "name")?;
        }
        LC_RPATH => {
            lc_str(f, "path.offset", "path")?;
        }
        LC_SUB_FRAMEWORK => {
            lc_str(f, "umbrella.offset", "umbrella")?;
        }
        LC_SUB_UMBRELLA => {
            lc_str(f, "sub_umbrella.offset", "sub_umbrella")?;
        }
        LC_SUB_CLIENT => {
            lc_str(f, "client.offset", "client")?;
        }
        LC_SUB_LIBRARY => {
            lc_str(f, "sub_library.offset", "sub_library")?;
        }
        LC_TARGET_TRIPLE => {
            lc_str(f, "triple.offset", "triple")?;
        }
        LC_UUID => {
            f.bytes("uuid", 16).with(|v, n| n.summary(uuid(v))).emit()?;
        }
        LC_VERSION_MIN_MACOSX
        | LC_VERSION_MIN_IPHONEOS
        | LC_VERSION_MIN_TVOS
        | LC_VERSION_MIN_WATCHOS => {
            f.u32("version")
                .hex()
                .with(|&v, n| n.summary(version(v)))
                .emit()?;
            f.u32("sdk")
                .hex()
                .with(|&v, n| n.summary(version(v)))
                .emit()?;
        }
        LC_BUILD_VERSION => {
            f.u32("platform").enumeration(PLATFORM).emit()?;
            f.u32("minos")
                .hex()
                .with(|&v, n| n.summary(version(v)))
                .emit()?;
            f.u32("sdk")
                .hex()
                .with(|&v, n| n.summary(version(v)))
                .emit()?;
            let ntools = f.u32("ntools").emit()?;
            for _ in 0..ntools.min(64) {
                f.u32("tool").enumeration(TOOL).emit()?;
                f.u32("version")
                    .hex()
                    .with(|&v, n| n.summary(version(v)))
                    .emit()?;
            }
        }
        LC_MAIN => {
            let file = c.file;
            f.u64("entryoff")
                .hex()
                .desc("File offset of main()")
                .with(|&v, n| n.target(file.sub(v, 0)))
                .emit()?;
            f.u64("stacksize").hex().emit()?;
        }
        LC_SOURCE_VERSION => {
            f.u64("version")
                .hex()
                .with(|&v, n| n.summary(source_version(v)))
                .emit()?;
        }
        LC_ENCRYPTION_INFO | LC_ENCRYPTION_INFO_64 => {
            let file = c.file;
            let size = peek_word(f, 4, false);
            f.u32("cryptoff")
                .hex()
                .with(|&v, n| n.target(file.sub(v.into(), size)))
                .emit()?;
            f.u32("cryptsize").hex().emit()?;
            f.u32("cryptid").desc("0: not encrypted").emit()?;
            if cmd == LC_ENCRYPTION_INFO_64 {
                f.u32("pad").emit()?;
            }
        }
        LC_LINKER_OPTION => {
            let count = f.u32("count").emit()?;
            for _ in 0..count.min(256) {
                f.cstr("option").emit()?;
            }
        }
        LC_FILESET_ENTRY => {
            f.u64("vmaddr").hex().emit()?;
            f.u64("fileoff").hex().emit()?;
            lc_str(f, "entry_id.offset", "entry_id")?;
            f.u32("reserved").emit()?;
        }
        _ => {
            let rest = f.remaining();
            if rest > 0 {
                f.bytes("data", rest).emit()?;
            }
        }
    }
    Ok(())
}

async fn libraries(cx: Cx, m: Macho) -> Result<()> {
    for (i, name) in m.dylibs.iter().enumerate() {
        cx.push(
            Node::new(format!("{}", i.saturating_add(1)))
                .value(text(name.clone()))
                .desc("Library ordinal, as used by symbols and binds"),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Sections

async fn section_node(cx: Cx, (m, header): (Macho, Span)) -> Result<()> {
    let ctx = Ctx {
        wide: m.wide,
        file: m.file(),
    };
    let block = cx.block(header).await?;
    let s = section_header(&mut Fields::emitting(&cx, &block, m.endian), &ctx)?;
    let data = m.file().sub(s.offset.into(), s.size);
    if !s.is_zerofill() && s.size > 0 {
        let node = match s.kind() {
            S_CSTRING_LITERALS => Node::new("Strings").span(data).lazy(cstrings, data),
            S_NON_LAZY_SYMBOL_POINTERS | S_LAZY_SYMBOL_POINTERS | S_SYMBOL_STUBS => {
                let stride = if s.kind() == S_SYMBOL_STUBS {
                    u64::from(s.reserved2)
                } else {
                    m.word()
                };
                let count = s.size.checked_div(stride).unwrap_or(0);
                let count = u32::try_from(count).unwrap_or(u32::MAX);
                Node::new("Indirect Symbols")
                    .span(data)
                    .summary(format!("{count} entries"))
                    .lazy(indirect_symbols, (m.clone(), s.reserved1, count))
            }
            S_MOD_INIT_FUNC_POINTERS => Node::new("Initializers")
                .span(data)
                .lazy(pointers, (m.clone(), data)),
            _ if s.sectname == "__info_plist" => {
                let bytes = cx.read_avail(data.sub(0, 0x10000)).await?;
                Node::new("Info.plist")
                    .span(data)
                    .value(text(String::from_utf8_lossy(&bytes).into_owned()))
            }
            _ => data_node("Contents", data, s.size),
        };
        cx.emit(node);
    }
    if s.nreloc > 0 {
        let span = m
            .file()
            .sub(s.reloff.into(), u64::from(s.nreloc).saturating_mul(8));
        cx.emit(
            Node::new("Relocations")
                .span(span)
                .summary(format!("{} entries", s.nreloc))
                .lazy(relocations, (m.clone(), span)),
        );
    }
    Ok(())
}

async fn pointers(cx: Cx, (m, span): (Macho, Span)) -> Result<()> {
    let w = m.word();
    let count = span.len.checked_div(w).unwrap_or(0);
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let at = span.sub(i.saturating_mul(w), w);
        let data = cx.read(at).await?;
        let value = if m.wide {
            get_at::<u64>(&data, 0, m.endian).unwrap_or(0)
        } else {
            get_at::<u32>(&data, 0, m.endian).map_or(0, u64::from)
        };
        let mut node = Node::new(format!("[{i}]"))
            .span(at)
            .value(hex(value, m.bits()));
        if let Some(t) = m.vm_span(value, 0) {
            node = node.target(t);
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn relocations(cx: Cx, (m, span): (Macho, Span)) -> Result<()> {
    let count = span.len / 8;
    cx.set_count(Count::Exact(count));
    let types = relocation_types(m.header.cputype);
    for i in 0..count {
        let at = span.sub(i.saturating_mul(8), 8);
        let data = cx.read(at).await?;
        let first = get_at::<u32>(&data, 0, m.endian).unwrap_or(0);
        let second = get_at::<u32>(&data, 4, m.endian).unwrap_or(0);
        let node = if first & 0x8000_0000 != 0 {
            // Scattered relocation.
            let kind = (first >> 24) & 0xf;
            Node::new(name_or(types, kind.into(), "type"))
                .span(at)
                .value(hex((first & 0x00ff_ffff).into(), 32))
                .summary(format!("scattered, value {second:#x}"))
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
            let target = if external != 0 {
                symbol_name(&cx, &m, symbol)
                    .await
                    .unwrap_or_else(|_| format!("symbol #{symbol}"))
            } else {
                m.section(u8::try_from(symbol).unwrap_or(0))
                    .map_or_else(|| format!("section {symbol}"), SectionInfo::label)
            };
            let mut flags = format!("{} bytes", 1u32 << length);
            if pcrel != 0 {
                flags.push_str(", pc-relative");
            }
            Node::new(name_or(types, kind.into(), "type"))
                .span(at)
                .value(hex(first.into(), 32))
                .summary(format!("{target} ({flags})"))
        };
        cx.push(node).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Symbols

fn symtab_node(m: &Macho, st: Symtab) -> Node {
    let span = m.file().sub(
        st.symoff.into(),
        u64::from(st.nsyms).saturating_mul(m.nlist_size()),
    );
    Node::new("Symbol Table")
        .span(span)
        .summary(format!("{} symbols", st.nsyms))
        .lazy(symbols, (m.clone(), st))
}

#[derive(Clone, Copy, Debug)]
struct Nlist {
    strx: u32,
    kind: u8,
    sect: u8,
    desc: u16,
    value: u64,
}

fn nlist(f: &mut Fields<'_>, m: &Macho) -> Result<Nlist> {
    let strx = f
        .u32("n_strx")
        .hex()
        .desc("Offset in the string table")
        .emit()?;
    let kind = f
        .u8("n_type")
        .hex()
        .with(|&v, n| n.summary(type_summary(v)))
        .emit()?;
    let sect = f
        .u8("n_sect")
        .with(|&v, n| match m.section(v) {
            Some(s) if v != 0 => n.summary(s.label()),
            _ => n.summary("NO_SECT"),
        })
        .emit()?;
    let desc = f
        .u16("n_desc")
        .flags(N_DESC)
        .with(|&v, n| {
            if kind & 0x0e == 0 && kind & 0xe0 == 0 {
                n.summary(m.dylib(u8::try_from(v >> 8).unwrap_or(0)))
            } else {
                n
            }
        })
        .emit()?;
    let value = f.uword("n_value", m.wide).hex().emit()?;
    Ok(Nlist {
        strx,
        kind,
        sect,
        desc,
        value,
    })
}

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

async fn symbol_name(cx: &Cx, m: &MachInfo, index: u32) -> Result<String> {
    let st = m
        .symtab
        .ok_or_else(|| Diagnostic::malformed("no symbol table"))?;
    if index >= st.nsyms {
        return Err(Diagnostic::malformed(format!(
            "symbol index {index} out of range"
        )));
    }
    let at = m.file().sub(
        u64::from(st.symoff).saturating_add(u64::from(index).saturating_mul(m.nlist_size())),
        4,
    );
    let data = cx.read(at).await?;
    let strx = get_at::<u32>(&data, 0, m.endian).unwrap_or(0);
    Ok(
        string_at(cx, m.linkedit(st.stroff, st.strsize), strx.into())
            .await?
            .0,
    )
}

async fn symbols(cx: Cx, (m, st): (Macho, Symtab)) -> Result<()> {
    let size = m.nlist_size();
    let table = m
        .file()
        .sub(st.symoff.into(), u64::from(st.nsyms).saturating_mul(size));
    let strings = m.linkedit(st.stroff, st.strsize);
    let count = table.len.checked_div(size).unwrap_or(0);
    if count < st.nsyms.into() {
        cx.diag(Diagnostic::truncated(
            Span::new(
                table.source,
                table.offset,
                u64::from(st.nsyms).saturating_mul(size),
            ),
            table.len,
        ));
    }
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let span = table.sub(i.saturating_mul(size), size);
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
        let mut summary = type_summary(sym.kind);
        if sym.kind & 0xe0 == 0 {
            match sym.kind & 0x0e {
                0 if !m.dylibs.is_empty() => summary.push_str(&format!(
                    " from {}",
                    m.dylib(u8::try_from(sym.desc >> 8).unwrap_or(0))
                )),
                0x0e => {
                    if let Some(s) = m.section(sym.sect) {
                        summary.push_str(&format!(" {}", s.label()));
                    }
                }
                _ => {}
            }
        }
        let mut node = struct_node(name, span, m.endian, m.clone(), nlist)
            .value(hex(sym.value, m.bits()))
            .summary(summary);
        if sym.kind & 0xee == 0x0e
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

/// Entries of the indirect symbol table, `first..first + count`.
async fn indirect_symbols(cx: Cx, (m, first, count): (Macho, u32, u32)) -> Result<()> {
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
        let data = cx.read(at).await?;
        let sym = get_at::<u32>(&data, 0, m.endian).unwrap_or(0);
        let node = Node::new(format!("[{i}]")).span(at);
        let node = match sym {
            0x8000_0000 => node.value(text("INDIRECT_SYMBOL_LOCAL")),
            0x4000_0000 => node.value(text("INDIRECT_SYMBOL_ABS")),
            0xc000_0000 => node.value(text("INDIRECT_SYMBOL_LOCAL | ABS")),
            _ => match symbol_name(&cx, &m, sym).await {
                Ok(name) => node.value(text(name)).summary(format!("symbol {sym}")),
                Err(e) => node
                    .value(crate::formats::util::binutil::dec(sym.into(), 32))
                    .diag(e),
            },
        };
        cx.push(node).await;
    }
    Ok(())
}
