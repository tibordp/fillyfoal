//! Mach-O (macOS, iOS, ...): executables, dylibs, bundles, objects, in
//! 32/64-bit and either byte order; universal ("fat") binaries; code
//! signatures; and the dyld shared cache header.
//!
//! Expanding the file reads the header and the load commands (one read,
//! usually a few KiB): segments, sections, linked libraries and the
//! locations of every `__LINKEDIT` table come from there. The file is then
//! laid out by offset: each segment lists what it holds (the header and load
//! commands, sections, the `__LINKEDIT` tables) with the padding between
//! them, and whatever lies outside every segment (an object file's
//! relocations and symbols) follows at the top level. Section contents,
//! symbols, fixups and signatures are decoded only when expanded.

pub mod codesign;
pub mod dyld_cache;
pub mod fat;
mod linkedit;
mod sections;
mod symbols;
pub(crate) mod tables;
mod unwind;

use std::sync::Arc;

use tables::*;

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::util::binutil::{NodeExt, RangeIndex, cstrings, data_node, get_at, perms};
use crate::formats::util::fmt::{clip, size};
use crate::formats::util::val::{name_or, text};
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
/// How much of a gap between structures is read to tell padding from data.
const GAP_PROBE: u64 = 0x1_0000;

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
    /// The regions this command points at: `regions[first..end]`.
    regions: (usize, usize),
    /// The sections a segment command declares: `sections[first..end]`.
    sections: (usize, usize),
}

#[derive(Clone, Debug)]
struct SegmentInfo {
    name: String,
    vmaddr: u64,
    fileoff: u64,
    filesize: u64,
    initprot: u32,
    nsects: u32,
}

impl SegmentInfo {
    fn label(&self) -> String {
        if self.name.is_empty() {
            "Segment".to_owned()
        } else {
            self.name.clone()
        }
    }
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

#[derive(Clone, Copy, Debug, Default)]
struct Dysymtab {
    ilocalsym: u32,
    nlocalsym: u32,
    iextdefsym: u32,
    nextdefsym: u32,
    iundefsym: u32,
    nundefsym: u32,
    indirectsymoff: u32,
    nindirectsyms: u32,
}

#[derive(Clone, Debug)]
struct Dylib {
    cmd: u32,
    path: String,
    current: u32,
}

impl Dylib {
    fn short(&self) -> &str {
        short_dylib(&self.path)
    }
}

/// What a region of the file holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Item {
    Header,
    Commands,
    /// A section's contents (index into `sections`).
    Section(usize),
    /// A section's relocation entries.
    Relocations(usize),
    Symtab,
    Strtab,
    Toc,
    Modtab,
    ExtRefs,
    Indirect,
    ExtRel,
    LocRel,
    Rebase,
    Bind,
    WeakBind,
    LazyBind,
    Export,
    /// A `linkedit_data_command` region, by command.
    Data(u32),
    TwoLevelHints,
    Note,
    SymSeg,
}

#[derive(Clone, Copy, Debug)]
struct Region {
    offset: u64,
    len: u64,
    item: Item,
}

type Macho = Arc<MachInfo>;

struct MachInfo {
    input: Input,
    endian: Endian,
    wide: bool,
    header: Header,
    header_size: u64,
    commands: Vec<Command>,
    segments: Vec<SegmentInfo>,
    sections: Vec<SectionInfo>,
    dylibs: Vec<Dylib>,
    symtab: Option<Symtab>,
    dysymtab: Option<Dysymtab>,
    code_signature: Option<(u32, u32)>,
    chained_fixups: Option<(u32, u32)>,
    /// Everything the header and load commands point at, in command order.
    regions: Vec<Region>,
    /// `regions` indices sorted by offset (longest first at equal offsets).
    layout: Vec<usize>,
    /// The segments' address ranges, for [`MachInfo::vm_span`].
    vm_index: RangeIndex,
    /// The segments' file ranges.
    file_index: RangeIndex,
    /// The sections' address ranges, for [`MachInfo::describe`].
    section_index: RangeIndex,
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

    fn two_level(&self) -> bool {
        self.header.flags & MH_TWOLEVEL != 0
    }

    /// The section numbered `n` (1-based, as in `n_sect`).
    fn section(&self, n: u8) -> Option<&SectionInfo> {
        self.sections.get(usize::from(n).checked_sub(1)?)
    }

    /// The library a two-level ordinal refers to.
    fn dylib(&self, ordinal: u64) -> String {
        match to_usize(ordinal)
            .checked_sub(1)
            .and_then(|i| self.dylibs.get(i))
        {
            Some(d) => d.short().to_owned(),
            None => lookup(BIND_SPECIAL_DYLIB, ordinal)
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

    /// `__DATA,__got+0x8` for an address inside a section, else the address.
    fn describe(&self, addr: u64) -> String {
        match self
            .section_index
            .find(addr)
            .and_then(|i| self.sections.get(i))
        {
            Some(s) if addr == s.addr => s.label(),
            Some(s) => format!("{}+{:#x}", s.label(), addr.saturating_sub(s.addr)),
            None => match self.vm_index.find(addr).and_then(|i| self.segments.get(i)) {
                Some(s) => format!("{}+{:#x}", s.label(), addr.saturating_sub(s.vmaddr)),
                None => format!("{addr:#x}"),
            },
        }
    }

    /// The image's base address: the `__TEXT` segment's (the mach header's).
    fn text_vmaddr(&self) -> u64 {
        self.segments
            .iter()
            .find(|s| s.name == "__TEXT")
            .or_else(|| {
                self.segments
                    .iter()
                    .find(|s| s.fileoff == 0 && s.filesize > 0)
            })
            .map_or(0, |s| s.vmaddr)
    }

    fn linkedit(&self, offset: u32, size: u32) -> Span {
        self.file().sub(offset.into(), size.into())
    }

    fn region_span(&self, r: &Region) -> Span {
        self.file().sub(r.offset, r.len)
    }

    /// The region of an item, if the load commands point at one.
    fn region(&self, item: Item) -> Option<&Region> {
        self.regions.iter().find(|r| r.item == item)
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
    let header_size: u64 = if wide { 32 } else { 28 };
    let header_span = file.sub(0, header_size);
    let header = parse(&cx, header_span, endian, &wide, mach_header).await;
    cx.emit(header_node(header_span, endian, wide, header.as_ref().ok()));
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
        header_size,
        commands: Vec::new(),
        segments: Vec::new(),
        sections: Vec::new(),
        dylibs: Vec::new(),
        symtab: None,
        dysymtab: None,
        code_signature: None,
        chained_fixups: None,
        regions: vec![
            Region {
                offset: 0,
                len: header_size,
                item: Item::Header,
            },
            Region {
                offset: header_size,
                len: header.sizeofcmds.into(),
                item: Item::Commands,
            },
        ],
        layout: Vec::new(),
        vm_index: RangeIndex::default(),
        file_index: RangeIndex::default(),
        section_index: RangeIndex::default(),
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
        let first = info.regions.len();
        let first_section = info.sections.len();
        let mut f = Fields::new(&block, endian);
        f.seek(offset);
        if let Err(e) = learn(&mut info, &mut f, &ctx, cmd, size) {
            cx.diag(e);
        }
        info.commands.push(Command {
            span,
            cmd,
            regions: (first, info.regions.len()),
            sections: (first_section, info.sections.len()),
        });
        offset = offset.saturating_add(size.into());
    }
    // Sorting is covered by the per-command checkpoints above.
    let mut layout: Vec<usize> = (0..info.regions.len()).collect();
    layout.sort_by_key(|&i| {
        info.regions.get(i).map_or((u64::MAX, 0), |r| {
            (r.offset, u64::MAX.saturating_sub(r.len))
        })
    });
    info.layout = layout;
    info.vm_index = RangeIndex::new(info.segments.iter().map(|s| (s.vmaddr, s.filesize)));
    info.file_index = RangeIndex::new(info.segments.iter().map(|s| (s.fileoff, s.filesize)));
    info.section_index = RangeIndex::new(info.sections.iter().map(|s| (s.addr, s.size)));
    let m: Macho = Arc::new(info);

    let signature = m.code_signature.map(|(o, s)| m.linkedit(o, s));
    let signed = match signature {
        Some(span) => codesign::brief(&cx, span).await.ok(),
        None => None,
    };
    cx.annotate(summary(&m, &block.data, signed.as_deref()));

    cx.emit(commands_node(&m, region));
    if !m.dylibs.is_empty() {
        let names: Vec<&str> = m.dylibs.iter().map(Dylib::short).collect();
        cx.emit(
            Node::new("Linked Libraries")
                .summary(clip(&names.join(", "), 120))
                .lazy(libraries, m.clone()),
        );
    }
    top_level(&cx, &m).await?;
    Ok(())
}

/// Records what later expansions need from a load command.
fn learn(info: &mut MachInfo, f: &mut Fields<'_>, ctx: &Ctx, cmd: u32, size: u32) -> Result<()> {
    let start = f.pos();
    let mut region = |offset: u64, len: u64, item: Item| {
        if len > 0 {
            info.regions.push(Region { offset, len, item });
        }
    };
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
                let s = section_header(f, ctx)?;
                let index = info.sections.len();
                if !s.is_zerofill() && s.offset != 0 {
                    region(s.offset.into(), s.size, Item::Section(index));
                }
                region(
                    s.reloff.into(),
                    u64::from(s.nreloc).saturating_mul(8),
                    Item::Relocations(index),
                );
                info.sections.push(s);
            }
            info.segments.push(segment);
        }
        LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB | LC_LAZY_LOAD_DYLIB
        | LC_LOAD_UPWARD_DYLIB => {
            f.skip(8);
            let name = f.u32("name").get()?;
            f.skip(4);
            let current = f.u32("current_version").get().unwrap_or(0);
            f.seek(start.saturating_add(name.into()));
            let path = f.cstr("path").get().unwrap_or_default();
            info.dylibs.push(Dylib { cmd, path, current });
        }
        LC_SYMTAB => {
            f.skip(8);
            let st = Symtab {
                symoff: f.u32("symoff").get()?,
                nsyms: f.u32("nsyms").get()?,
                stroff: f.u32("stroff").get()?,
                strsize: f.u32("strsize").get()?,
            };
            let nlist: u64 = if ctx.wide { 16 } else { 12 };
            region(
                st.symoff.into(),
                u64::from(st.nsyms).saturating_mul(nlist),
                Item::Symtab,
            );
            region(st.stroff.into(), st.strsize.into(), Item::Strtab);
            info.symtab = Some(st);
        }
        LC_DYSYMTAB => {
            f.skip(8);
            let mut v = [0u32; 18];
            for slot in &mut v {
                *slot = f.u32("").get()?;
            }
            let [
                ilocalsym,
                nlocalsym,
                iextdefsym,
                nextdefsym,
                iundefsym,
                nundefsym,
                tocoff,
                ntoc,
                modtaboff,
                nmodtab,
                extrefsymoff,
                nextrefsyms,
                indirectsymoff,
                nindirectsyms,
                extreloff,
                nextrel,
                locreloff,
                nlocrel,
            ] = v;
            let d = Dysymtab {
                ilocalsym,
                nlocalsym,
                iextdefsym,
                nextdefsym,
                iundefsym,
                nundefsym,
                indirectsymoff,
                nindirectsyms,
            };
            let module: u64 = if ctx.wide { 56 } else { 52 };
            let table = |n: u32, size: u64| u64::from(n).saturating_mul(size);
            region(tocoff.into(), table(ntoc, 8), Item::Toc);
            region(modtaboff.into(), table(nmodtab, module), Item::Modtab);
            region(extrefsymoff.into(), table(nextrefsyms, 4), Item::ExtRefs);
            region(
                indirectsymoff.into(),
                table(nindirectsyms, 4),
                Item::Indirect,
            );
            region(extreloff.into(), table(nextrel, 8), Item::ExtRel);
            region(locreloff.into(), table(nlocrel, 8), Item::LocRel);
            info.dysymtab = Some(d);
        }
        LC_DYLD_INFO | LC_DYLD_INFO_ONLY => {
            f.skip(8);
            for item in [
                Item::Rebase,
                Item::Bind,
                Item::WeakBind,
                Item::LazyBind,
                Item::Export,
            ] {
                let offset = f.u32("off").get()?;
                let size = f.u32("size").get()?;
                region(offset.into(), size.into(), item);
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
            f.skip(8);
            let offset = f.u32("dataoff").get()?;
            let size = f.u32("datasize").get()?;
            region(offset.into(), size.into(), Item::Data(cmd));
            match cmd {
                LC_CODE_SIGNATURE => info.code_signature = Some((offset, size)),
                LC_DYLD_CHAINED_FIXUPS => info.chained_fixups = Some((offset, size)),
                _ => {}
            }
        }
        LC_TWOLEVEL_HINTS => {
            f.skip(8);
            let offset = f.u32("offset").get()?;
            let count = f.u32("nhints").get()?;
            region(
                offset.into(),
                u64::from(count).saturating_mul(4),
                Item::TwoLevelHints,
            );
        }
        LC_SYMSEG => {
            f.skip(8);
            let offset = f.u32("offset").get()?;
            let size = f.u32("size").get()?;
            region(offset.into(), size.into(), Item::SymSeg);
        }
        LC_NOTE => {
            f.skip(24);
            let offset = f.u64("offset").get()?;
            let size = f.u64("size").get()?;
            region(offset, size, Item::Note);
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
    let mut parts = vec![format!(
        "Mach-O {} {}",
        arch_name(h.cputype, h.cpusubtype),
        name_or(FILE_TYPE_WORDS, h.filetype.into(), "file type")
    )];
    let base = m.header_size;
    let mut platform = None;
    let mut encrypted = false;
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
            LC_BUILD_VERSION => {
                platform.get_or_insert_with(|| {
                    format!(
                        "{} {}",
                        name_or(PLATFORM, w(8).into(), "platform"),
                        version(w(12))
                    )
                });
            }
            LC_VERSION_MIN_MACOSX
            | LC_VERSION_MIN_IPHONEOS
            | LC_VERSION_MIN_TVOS
            | LC_VERSION_MIN_WATCHOS => {
                let os = match c.cmd {
                    LC_VERSION_MIN_MACOSX => "macOS",
                    LC_VERSION_MIN_IPHONEOS => "iOS",
                    LC_VERSION_MIN_TVOS => "tvOS",
                    _ => "watchOS",
                };
                platform.get_or_insert_with(|| format!("{os} {}", version(w(8))));
            }
            LC_ID_DYLIB => {
                let name =
                    crate::text::until_nul(bytes.get(to_usize(w(8).into())..).unwrap_or_default());
                parts.push(format!("{} {}", short_dylib(&name), version(w(16))));
            }
            LC_ENCRYPTION_INFO | LC_ENCRYPTION_INFO_64 if w(16) != 0 => encrypted = true,
            _ => {}
        }
    }
    parts.extend(platform);
    if !m.dylibs.is_empty() {
        parts.push(grouped_count(to_u64(m.dylibs.len()), "dylib", "dylibs"));
    }
    if let Some(s) = signed {
        parts.push(format!("signed ({s})"));
    }
    if encrypted {
        parts.push("encrypted".to_owned());
    }
    if h.flags & MH_PIE != 0 && h.filetype == MH_EXECUTE {
        parts.push("PIE".to_owned());
    }
    if let Some(st) = m.symtab {
        parts.push(grouped_count(st.nsyms, "symbol", "symbols"));
    }
    parts.join(", ")
}

// ---------------------------------------------------------------------------
// Layout

/// What lies at the top level besides the header and load commands.
#[derive(Clone, Copy, Debug)]
enum Top {
    Segment(usize),
    Region(usize),
}

/// The segments, the regions outside every segment, the gaps between them,
/// shortcuts to the symbol table and signature, and any overlay.
async fn top_level(cx: &Cx, m: &Macho) -> Result<()> {
    let file = m.file();
    let mut tops: Vec<(u64, u64, Top)> = Vec::new();
    for (i, s) in m.segments.iter().enumerate() {
        if s.filesize > 0 {
            tops.push((s.fileoff, s.filesize, Top::Segment(i)));
        }
    }
    let inside = |r: &Region| m.file_index.find(r.offset).is_some();
    for &i in &m.layout {
        let Some(r) = m.regions.get(i) else { continue };
        if matches!(r.item, Item::Header | Item::Commands) || inside(r) {
            continue;
        }
        tops.push((r.offset, r.len, Top::Region(i)));
    }
    tops.sort_by_key(|&(offset, len, _)| (offset, u64::MAX.saturating_sub(len)));
    let end = m
        .regions
        .iter()
        .map(|r| r.offset.saturating_add(r.len))
        .chain(tops.iter().map(|t| t.0.saturating_add(t.1)))
        .max()
        .unwrap_or(0)
        .min(file.len);
    let mut cursor = m
        .header_size
        .saturating_add(m.header.sizeofcmds.into())
        .min(file.len);
    for (offset, len, top) in tops {
        if offset >= file.len {
            continue;
        }
        if offset > cursor {
            cx.push(gap_node(cx, file.sub(cursor, offset.saturating_sub(cursor))).await?)
                .await;
        }
        let node = match top {
            Top::Segment(i) => segment_node(m, i),
            Top::Region(i) => match m.regions.get(i) {
                Some(r) => item_node(m, r),
                None => continue,
            },
        };
        cx.push(node).await;
        cursor = cursor.max(offset.saturating_add(len));
    }
    let overlay = m.header.filetype != MH_OBJECT && end < file.len;
    let tail = if overlay { end } else { file.len };
    if cursor < tail {
        cx.push(gap_node(cx, file.sub(cursor, tail.saturating_sub(cursor))).await?)
            .await;
    }
    // Shortcuts to what users look for first, when it sits in a segment.
    for item in [Item::Symtab, Item::Data(LC_CODE_SIGNATURE)] {
        if let Some(r) = m.region(item).filter(|r| inside(r)) {
            cx.push(item_node(m, r)).await;
        }
    }
    if overlay {
        cx.push(
            embedded("Overlay", m.input.nested(file.tail(end))).summary(format!(
                "{} after the last segment",
                size(file.len.saturating_sub(end))
            )),
        )
        .await;
    }
    Ok(())
}

/// A gap between structures: zero padding, or bytes nothing points at.
async fn gap_node(cx: &Cx, span: Span) -> Result<Node> {
    let data = cx.read_avail(span.sub(0, GAP_PROBE)).await?;
    let zeros = data.iter().all(|&b| b == 0);
    Ok(if zeros {
        Node::new("Padding")
            .span(span)
            .summary(size(span.len))
            .desc("Alignment padding (zeros)")
    } else {
        Node::new("Unreferenced Data")
            .span(span)
            .summary(size(span.len))
            .desc("Bytes no load command points at")
    })
}

fn segment_node(m: &Macho, index: usize) -> Node {
    let Some(s) = m.segments.get(index) else {
        return Node::new("?");
    };
    let span = m.file().sub(s.fileoff, s.filesize);
    let mut node = Node::new(s.label())
        .span(span)
        .summary(format!(
            "{}, {}, {} at {:#x}",
            perms(
                s.initprot & 1 != 0,
                s.initprot & 2 != 0,
                s.initprot & 4 != 0
            ),
            grouped_count(s.nsects, "section", "sections"),
            size(s.filesize),
            s.vmaddr
        ))
        .lazy(segment_contents, (m.clone(), index));
    if span.len < s.filesize {
        node = node.diag(Diagnostic::truncated(
            Span::new(span.source, span.offset, s.filesize),
            span.len,
        ));
    }
    node
}

/// A segment's file range: the regions inside it in offset order, with the
/// gaps between them.
async fn segment_contents(cx: Cx, (m, index): (Macho, usize)) -> Result<()> {
    let s = m
        .segments
        .get(index)
        .ok_or_else(|| Diagnostic::internal("segment index out of range"))?;
    let span = m.file().sub(s.fileoff, s.filesize);
    let start = span.offset.saturating_sub(m.file().offset);
    let end = start.saturating_add(span.len);
    let first = m
        .layout
        .partition_point(|&i| m.regions.get(i).is_some_and(|r| r.offset < start));
    let mut cursor = start;
    for &i in m.layout.get(first..).unwrap_or_default() {
        let Some(r) = m.regions.get(i) else { continue };
        if r.offset >= end {
            break;
        }
        if r.offset > cursor {
            cx.push(gap_node(&cx, m.file().sub(cursor, r.offset.saturating_sub(cursor))).await?)
                .await;
        }
        cx.push(item_node(&m, r)).await;
        cursor = cursor.max(r.offset.saturating_add(r.len));
    }
    if cursor < end {
        cx.push(gap_node(&cx, m.file().sub(cursor, end.saturating_sub(cursor))).await?)
            .await;
    }
    Ok(())
}

/// The node for what a region holds.
fn item_node(m: &Macho, r: &Region) -> Node {
    let span = m.region_span(r);
    let node = match r.item {
        Item::Header => header_node(span, m.endian, m.wide, Some(&m.header)),
        Item::Commands => commands_node(m, span),
        Item::Section(i) => sections::section_node(m, i),
        Item::Relocations(i) => {
            let label = m
                .sections
                .get(i)
                .map_or_else(String::new, SectionInfo::label);
            Node::new(format!("Relocations ({label})"))
                .span(span)
                .summary(grouped_count(span.len / 8, "entry", "entries"))
                .lazy(symbols::relocations, (m.clone(), span, i))
        }
        Item::Symtab => match m.symtab {
            Some(st) => symbols::symtab_node(m, st),
            None => data_node("Symbol Table", span, r.len),
        },
        Item::Strtab => Node::new("String Table")
            .span(span)
            .summary(size(span.len))
            .lazy(cstrings, span),
        Item::Toc => Node::new("Table of Contents")
            .span(span)
            .summary(grouped_count(span.len / 8, "entry", "entries"))
            .desc("Defined external symbols and the modules defining them")
            .lazy(symbols::toc, (m.clone(), span)),
        Item::Modtab => Node::new("Module Table")
            .span(span)
            .lazy(symbols::modules, (m.clone(), span)),
        Item::ExtRefs => Node::new("External References")
            .span(span)
            .summary(grouped_count(span.len / 4, "entry", "entries"))
            .lazy(symbols::external_refs, (m.clone(), span)),
        Item::Indirect => Node::new("Indirect Symbol Table")
            .span(span)
            .summary(grouped_count(span.len / 4, "entry", "entries"))
            .desc("Symbol indices for the entries of pointer and stub sections")
            .lazy(
                symbols::indirect_symbols,
                (
                    m.clone(),
                    0u32,
                    u32::try_from(span.len / 4).unwrap_or(u32::MAX),
                ),
            ),
        Item::ExtRel | Item::LocRel => Node::new(if r.item == Item::ExtRel {
            "External Relocations"
        } else {
            "Local Relocations"
        })
        .span(span)
        .summary(grouped_count(span.len / 8, "entry", "entries"))
        .lazy(symbols::relocations, (m.clone(), span, usize::MAX)),
        Item::Rebase => Node::new("Rebase Info")
            .span(span)
            .desc("Rebase opcodes: pointers to slide when the image moves")
            .lazy(linkedit::rebase_opcodes, (m.clone(), span)),
        Item::Bind | Item::WeakBind | Item::LazyBind => {
            let (name, desc) = match r.item {
                Item::Bind => ("Bind Info", "Bind opcodes: pointers to imported symbols"),
                Item::WeakBind => (
                    "Weak Bind Info",
                    "Bind opcodes: weak definitions coalesced across images",
                ),
                _ => (
                    "Lazy Bind Info",
                    "Bind opcodes run by the stub helper on first call, one entry per stub",
                ),
            };
            Node::new(name)
                .span(span)
                .desc(desc)
                .lazy(linkedit::bind_opcodes, (m.clone(), span))
        }
        Item::Export => Node::new("Export Info")
            .span(span)
            .desc("Exported symbols, as a prefix trie")
            .lazy(linkedit::exports_trie, (m.clone(), span)),
        Item::Data(cmd) => linkedit_data_node(m, cmd, span),
        Item::TwoLevelHints => Node::new("Two-Level Namespace Hints")
            .span(span)
            .summary(grouped_count(span.len / 4, "hint", "hints"))
            .lazy(symbols::hints, (m.clone(), span)),
        Item::Note => embedded("Note Data", m.input.nested(span)),
        Item::SymSeg => data_node("Symbol Segment", span, r.len),
    };
    if span.len < r.len {
        node.diag(Diagnostic::truncated(
            Span::new(span.source, span.offset, r.len),
            span.len,
        ))
    } else {
        node
    }
}

fn linkedit_data_node(m: &Macho, cmd: u32, span: Span) -> Node {
    match cmd {
        LC_CODE_SIGNATURE => Node::new("Code Signature")
            .span(span)
            .lazy(codesign::superblob_in, m.input.nested(span)),
        LC_DYLIB_CODE_SIGN_DRS => Node::new("Code Signing Requirements")
            .span(span)
            .desc("Designated requirements of the linked dylibs")
            .lazy(codesign::superblob_in, m.input.nested(span)),
        LC_FUNCTION_STARTS => Node::new("Function Starts")
            .span(span)
            .desc("ULEB128 deltas between function start addresses")
            .lazy(linkedit::function_starts, (m.clone(), span)),
        LC_DATA_IN_CODE => Node::new("Data in Code")
            .span(span)
            .summary(grouped_count(span.len / 8, "entry", "entries"))
            .lazy(linkedit::data_in_code, (m.clone(), span)),
        LC_DYLD_CHAINED_FIXUPS => Node::new("Chained Fixups")
            .span(span)
            .lazy(linkedit::chained_fixups, (m.clone(), span)),
        LC_DYLD_EXPORTS_TRIE => Node::new("Exports Trie")
            .span(span)
            .desc("Exported symbols, as a prefix trie")
            .lazy(linkedit::exports_trie, (m.clone(), span)),
        LC_LINKER_OPTIMIZATION_HINT => Node::new("Linker Optimization Hints")
            .span(span)
            .lazy(linkedit::optimization_hints, (m.clone(), span)),
        LC_SEGMENT_SPLIT_INFO => data_node("Segment Split Info", span, span.len)
            .desc("Where the shared cache builder must adjust references between segments"),
        _ => data_node(
            lookup(LOAD_COMMAND, cmd.into()).unwrap_or("Data"),
            span,
            span.len,
        ),
    }
}

// ---------------------------------------------------------------------------
// Header

fn header_node(span: Span, endian: Endian, wide: bool, header: Option<&Header>) -> Node {
    let node = struct_node("Mach Header", span, endian, wide, mach_header);
    match header {
        Some(h) => node.summary(format!(
            "{}, {}",
            name_or(FILE_TYPE, h.filetype.into(), "filetype"),
            subtype_summary(h.cputype, h.cpusubtype)
        )),
        None => node,
    }
}

fn mach_header(f: &mut Fields<'_>, wide: &bool) -> Result<Header> {
    f.u32("magic")
        .hex()
        .desc("MH_MAGIC (0xfeedface) or MH_MAGIC_64 (0xfeedfacf)")
        .emit()?;
    let cputype = f.u32("cputype").enumeration(CPU_TYPE).emit()?;
    let cpusubtype = f
        .u32("cpusubtype")
        .hex()
        .with(|&v, n| n.summary(subtype_summary(cputype, v)))
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

fn commands_node(m: &Macho, span: Span) -> Node {
    Node::new("Load Commands")
        .span(span)
        .summary(grouped_count(
            to_u64(m.commands.len()),
            "command",
            "commands",
        ))
        .lazy(command_list, m.clone())
}

async fn command_list(cx: Cx, m: Macho) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(m.commands.len())));
    for (index, c) in m.commands.iter().enumerate() {
        let bytes = cx.read_avail(c.span.sub(0, 0x1000)).await?;
        let label = name_or(LOAD_COMMAND, c.cmd.into(), "LC");
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
                "{name} {}  vm {vmaddr:#x}+{vmsize:#x}, file {fileoff:#x}+{filesize:#x}, {}",
                perms(prot & 1 != 0, prot & 2 != 0, prot & 4 != 0),
                grouped_count(nsects, "section", "sections")
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
        LC_LOADFVMLIB | LC_IDFVMLIB => format!("{} (version {})", lc_str(8), w(12)),
        LC_UUID => uuid(b.get(8..24).unwrap_or_default()).to_uppercase(),
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
        LC_SYMTAB => format!(
            "{}, {} of strings",
            grouped_count(w(12), "symbol", "symbols"),
            size(w(20).into())
        ),
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
        LC_FILESET_ENTRY => format!("{} at {:#x}", lc_str(24), q(8)),
        LC_THREAD | LC_UNIXTHREAD => format!("flavor {}", w(8)),
        LC_ROUTINES => format!("init {:#x}", w(8)),
        LC_ROUTINES_64 => format!("init {:#x}", q(8)),
        LC_TWOLEVEL_HINTS => format!("{} hints at {:#x}", w(12), w(8)),
        LC_PREBIND_CKSUM => format!("checksum {:#x}", w(8)),
        LC_PREBOUND_DYLIB => format!("{}, {} modules", lc_str(8), w(12)),
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
            segment_command(&mut f, &ctx)?;
            // Section headers follow the segment command.
            let size: u64 = if m.wide { 80 } else { 68 };
            let base = f.pos();
            for (i, n) in (c.sections.0..c.sections.1).enumerate() {
                let header = c
                    .span
                    .sub(base.saturating_add(to_u64(i).saturating_mul(size)), size);
                let Some(s) = m.sections.get(n) else { break };
                extras.push(
                    Node::new(s.label())
                        .span(header)
                        .summary(section_summary(s))
                        .lazy(section_header_node, (m.clone(), header, n)),
                );
            }
        }
        LC_SYMTAB => {
            symtab_command(&mut f, &ctx)?;
        }
        LC_DYSYMTAB => {
            dysymtab_command(&mut f, &ctx)?;
            if let Some(d) = m.dysymtab {
                for (name, first, n) in [
                    ("Local Symbols", d.ilocalsym, d.nlocalsym),
                    ("Defined External Symbols", d.iextdefsym, d.nextdefsym),
                    ("Undefined Symbols", d.iundefsym, d.nundefsym),
                ] {
                    if n > 0 {
                        extras.push(symbols::symbol_range_node(&m, name, first, n));
                    }
                }
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
            linkedit_data(&mut f, &ctx)?;
        }
        LC_DYLD_INFO | LC_DYLD_INFO_ONLY => {
            dyld_info(&mut f, &ctx)?;
        }
        LC_NOTE => {
            note_command(&mut f, &ctx)?;
        }
        LC_THREAD | LC_UNIXTHREAD => {
            thread_command(&cx, &mut f, c.span.len).await?;
        }
        _ => {
            simple_command(&mut f, &ctx, c.cmd)?;
        }
    }
    if !matches!(c.cmd, LC_SEGMENT | LC_SEGMENT_64) {
        for r in m.regions.get(c.regions.0..c.regions.1).unwrap_or_default() {
            extras.push(item_node(&m, r));
        }
    }
    for node in extras {
        cx.emit(node);
    }
    Ok(())
}

/// A section header in its segment command: the fields, then what the
/// section holds.
async fn section_header_node(cx: Cx, (m, header, index): (Macho, Span, usize)) -> Result<()> {
    let ctx = Ctx {
        wide: m.wide,
        file: m.file(),
    };
    let block = cx.block(header).await?;
    let s = section_header(&mut Fields::emitting(&cx, &block, m.endian), &ctx)?;
    if !s.is_zerofill() && s.size > 0 && s.offset != 0 && m.sections.get(index).is_some() {
        cx.emit(sections::section_node(&m, index).desc("The section's contents"));
    }
    if s.nreloc > 0 {
        let span = m
            .file()
            .sub(s.reloff.into(), u64::from(s.nreloc).saturating_mul(8));
        cx.emit(
            Node::new("Relocations")
                .span(span)
                .summary(grouped_count(s.nreloc, "entry", "entries"))
                .lazy(symbols::relocations, (m.clone(), span, index)),
        );
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

/// Emits the rest of a command after its strings (alignment padding).
fn command_padding(f: &mut Fields<'_>, end: u64) {
    if end < f.block().span.len {
        let rest = f.block().span.len.saturating_sub(end);
        let span = Span::new(
            f.block().span.source,
            f.block().span.offset.saturating_add(end),
            rest,
        );
        f.node(Node::new("padding").span(span).summary(size(rest)));
    }
}

/// The end of the strings an `lc_str` field at the current position and a
/// fixed part of `fixed` bytes leave: where padding starts.
fn string_end(f: &Fields<'_>) -> u64 {
    let data = &f.block().data;
    // The string follows the fixed part; the padding follows its NUL.
    let mut end = to_u64(data.len());
    while end > 0 && data.get(to_usize(end.saturating_sub(1))) == Some(&0) {
        end = end.saturating_sub(1);
    }
    end.saturating_add(1).min(to_u64(data.len()))
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
    let initprot = f.u32("initprot").flags(VM_PROT).emit()?;
    let nsects = f.u32("nsects").emit()?;
    f.u32("flags").flags(SEGMENT_FLAGS).emit()?;
    Ok(SegmentInfo {
        name,
        vmaddr,
        fileoff,
        filesize,
        initprot,
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
    let zerofill = {
        let here = f.pos();
        f.skip(4 * 4);
        let flags = f.u32("").get().unwrap_or(0);
        f.seek(here);
        matches!(
            flags & 0xff,
            S_ZEROFILL | S_GB_ZEROFILL | S_THREAD_LOCAL_ZEROFILL
        )
    };
    let offset = f
        .u32("offset")
        .hex()
        .with(|&v, n| {
            if v == 0 || zerofill {
                n
            } else {
                n.target(file.sub(v.into(), size))
            }
        })
        .emit()?;
    f.u32("align")
        .with(|&v, n| n.summary(format!("2^{v}")))
        .emit()?;
    let nreloc = {
        let here = f.pos();
        f.skip(4);
        let v = f.u32("").get().unwrap_or(0);
        f.seek(here);
        v
    };
    let reloff = f
        .u32("reloff")
        .hex()
        .with(|&v, n| {
            if nreloc == 0 {
                n
            } else {
                n.target(file.sub(v.into(), u64::from(nreloc).saturating_mul(8)))
            }
        })
        .emit()?;
    let nreloc = f.u32("nreloc").emit()?;
    let flags = f.u32("flags").flags(SECTION_FLAGS).emit()?;
    let kind = flags & 0xff;
    let reserved1 = f
        .u32("reserved1")
        .with(|_, n| match kind {
            S_NON_LAZY_SYMBOL_POINTERS
            | S_LAZY_SYMBOL_POINTERS
            | S_SYMBOL_STUBS
            | S_LAZY_DYLIB_SYMBOL_POINTERS
            | S_THREAD_LOCAL_VARIABLE_POINTERS => {
                n.desc("Index of the section's first entry in the indirect symbol table")
            }
            _ => n.desc("Reserved"),
        })
        .emit()?;
    let reserved2 = f
        .u32("reserved2")
        .with(|_, n| match kind {
            S_SYMBOL_STUBS => n.desc("Size of each stub"),
            _ => n.desc("Reserved"),
        })
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
    format!("{kind}, {} at {:#x}", size(s.size), s.addr)
}

fn symtab_command(f: &mut Fields<'_>, c: &Ctx) -> Result<()> {
    command_head(f)?;
    let file = c.file;
    let nlist: u64 = if c.wide { 16 } else { 12 };
    let nsyms = peek_word(f, 4, false);
    f.u32("symoff")
        .hex()
        .with(|&v, n| n.target(file.sub(v.into(), nsyms.saturating_mul(nlist))))
        .emit()?;
    f.u32("nsyms").emit()?;
    let strsize = peek_word(f, 4, false);
    f.u32("stroff")
        .hex()
        .with(|&v, n| n.target(file.sub(v.into(), strsize)))
        .emit()?;
    f.u32("strsize").hex().emit()?;
    Ok(())
}

fn dysymtab_command(f: &mut Fields<'_>, c: &Ctx) -> Result<()> {
    command_head(f)?;
    for (name, desc) in [
        ("ilocalsym", "Index of the first local symbol"),
        ("nlocalsym", "Number of local symbols"),
        ("iextdefsym", "Index of the first defined external symbol"),
        ("nextdefsym", "Number of defined external symbols"),
        ("iundefsym", "Index of the first undefined symbol"),
        ("nundefsym", "Number of undefined symbols"),
    ] {
        f.u32(name).desc(desc).emit()?;
    }
    let file = c.file;
    let module: u64 = if c.wide { 56 } else { 52 };
    for (off, num, size, desc) in [
        ("tocoff", "ntoc", 8, "Table of contents"),
        ("modtaboff", "nmodtab", module, "Module table"),
        ("extrefsymoff", "nextrefsyms", 4, "External reference table"),
        (
            "indirectsymoff",
            "nindirectsyms",
            4,
            "Indirect symbol table",
        ),
        ("extreloff", "nextrel", 8, "External relocations"),
        ("locreloff", "nlocrel", 8, "Local relocations"),
    ] {
        let n = peek_word(f, 4, false);
        f.u32(off)
            .hex()
            .desc(desc)
            .with(|&v, node| {
                if n == 0 {
                    node
                } else {
                    node.target(file.sub(v.into(), n.saturating_mul(size)))
                }
            })
            .emit()?;
        f.u32(num).emit()?;
    }
    Ok(())
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

fn dyld_info(f: &mut Fields<'_>, c: &Ctx) -> Result<()> {
    command_head(f)?;
    let file = c.file;
    for (off, size) in [
        ("rebase_off", "rebase_size"),
        ("bind_off", "bind_size"),
        ("weak_bind_off", "weak_bind_size"),
        ("lazy_bind_off", "lazy_bind_size"),
        ("export_off", "export_size"),
    ] {
        let n = peek_word(f, 4, false);
        f.u32(off)
            .hex()
            .with(|&v, node| {
                if n == 0 {
                    node
                } else {
                    node.target(file.sub(v.into(), n))
                }
            })
            .emit()?;
        f.u32(size).hex().emit()?;
    }
    Ok(())
}

fn note_command(f: &mut Fields<'_>, c: &Ctx) -> Result<()> {
    command_head(f)?;
    f.ascii("data_owner", 16).emit()?;
    let file = c.file;
    let size = peek_word(f, 8, true);
    f.u64("offset")
        .hex()
        .with(|&v, n| n.target(file.sub(v, size)))
        .emit()?;
    f.u64("size").hex().emit()?;
    Ok(())
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

fn version_field(f: &mut Fields<'_>, name: &'static str) -> Result<u32> {
    f.u32(name).hex().with(|&v, n| n.summary(version(v))).emit()
}

/// Fixed-layout commands that need no extra nodes.
fn simple_command(f: &mut Fields<'_>, c: &Ctx, cmd: u32) -> Result<()> {
    command_head(f)?;
    let mut strings = false;
    match cmd {
        LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB | LC_LAZY_LOAD_DYLIB
        | LC_LOAD_UPWARD_DYLIB | LC_ID_DYLIB => {
            lc_str(f, "name.offset", "name")?;
            f.u32("timestamp")
                .timestamp()
                .desc("Build time of the library (usually a placeholder)")
                .emit()?;
            version_field(f, "current_version")?;
            version_field(f, "compatibility_version")?;
            strings = true;
        }
        LC_LOAD_DYLINKER | LC_ID_DYLINKER | LC_DYLD_ENVIRONMENT => {
            lc_str(f, "name.offset", "name")?;
            strings = true;
        }
        LC_RPATH => {
            lc_str(f, "path.offset", "path")?;
            strings = true;
        }
        LC_SUB_FRAMEWORK => {
            lc_str(f, "umbrella.offset", "umbrella")?;
            strings = true;
        }
        LC_SUB_UMBRELLA => {
            lc_str(f, "sub_umbrella.offset", "sub_umbrella")?;
            strings = true;
        }
        LC_SUB_CLIENT => {
            lc_str(f, "client.offset", "client")?;
            strings = true;
        }
        LC_SUB_LIBRARY => {
            lc_str(f, "sub_library.offset", "sub_library")?;
            strings = true;
        }
        LC_TARGET_TRIPLE => {
            lc_str(f, "triple.offset", "triple")?;
            strings = true;
        }
        LC_LOADFVMLIB | LC_IDFVMLIB => {
            lc_str(f, "name.offset", "name")?;
            f.u32("minor_version").emit()?;
            f.u32("header_addr").hex().emit()?;
            strings = true;
        }
        LC_PREBOUND_DYLIB => {
            lc_str(f, "name.offset", "name")?;
            let modules = f.u32("nmodules").emit()?;
            let offset = f.u32("linked_modules.offset").hex().emit()?;
            let here = f.pos();
            f.seek(offset.into());
            f.bytes("linked_modules", u64::from(modules).div_ceil(8))
                .desc("One bit per module of the library: linked or not")
                .emit()?;
            f.seek(here);
            strings = true;
        }
        LC_UUID => {
            f.bytes("uuid", 16)
                .with(|v, n| n.summary(uuid(v).to_uppercase()))
                .emit()?;
        }
        LC_VERSION_MIN_MACOSX
        | LC_VERSION_MIN_IPHONEOS
        | LC_VERSION_MIN_TVOS
        | LC_VERSION_MIN_WATCHOS => {
            version_field(f, "version")?;
            version_field(f, "sdk")?;
        }
        LC_BUILD_VERSION => {
            f.u32("platform").enumeration(PLATFORM).emit()?;
            version_field(f, "minos")?;
            version_field(f, "sdk")?;
            let ntools = f.u32("ntools").emit()?;
            for _ in 0..ntools.min(64) {
                f.u32("tool").enumeration(TOOL).emit()?;
                version_field(f, "version")?;
            }
        }
        LC_MAIN => {
            let file = c.file;
            f.u64("entryoff")
                .hex()
                .desc("File offset of main()")
                .with(|&v, n| n.target(file.sub(v, 0)))
                .emit()?;
            f.u64("stacksize")
                .hex()
                .desc("Initial stack size (0: the default)")
                .emit()?;
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
            f.u32("cryptid")
                .desc("Encryption system; 0: not encrypted")
                .emit()?;
            if cmd == LC_ENCRYPTION_INFO_64 {
                f.u32("pad").emit()?;
            }
        }
        LC_LINKER_OPTION => {
            let count = f.u32("count").emit()?;
            for _ in 0..count.min(256) {
                f.cstr("option").emit()?;
            }
            command_padding(f, f.pos());
        }
        LC_FILESET_ENTRY => {
            f.u64("vmaddr").hex().emit()?;
            f.u64("fileoff").hex().emit()?;
            lc_str(f, "entry_id.offset", "entry_id")?;
            f.u32("reserved").emit()?;
            strings = true;
        }
        LC_ROUTINES | LC_ROUTINES_64 => {
            let wide = cmd == LC_ROUTINES_64;
            f.uword("init_address", wide).hex().emit()?;
            f.uword("init_module", wide).emit()?;
            for name in [
                "reserved1",
                "reserved2",
                "reserved3",
                "reserved4",
                "reserved5",
                "reserved6",
            ] {
                f.uword(name, wide).emit()?;
            }
        }
        LC_TWOLEVEL_HINTS => {
            let file = c.file;
            let n = peek_word(f, 4, false);
            f.u32("offset")
                .hex()
                .with(|&v, node| node.target(file.sub(v.into(), n.saturating_mul(4))))
                .emit()?;
            f.u32("nhints").emit()?;
        }
        LC_PREBIND_CKSUM => {
            f.u32("cksum").hex().emit()?;
        }
        LC_SYMSEG => {
            f.u32("offset").hex().emit()?;
            f.u32("size").hex().emit()?;
        }
        LC_ATOM_INFO | LC_FUNCTION_VARIANTS | LC_FUNCTION_VARIANT_FIXUPS => {}
        _ => {
            let rest = f.remaining();
            if rest > 0 {
                f.bytes("data", rest).emit()?;
            }
        }
    }
    if strings {
        command_padding(f, string_end(f));
    }
    Ok(())
}

async fn libraries(cx: Cx, m: Macho) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(m.dylibs.len())));
    for (i, d) in m.dylibs.iter().enumerate() {
        let kind = name_or(DYLIB_KIND, d.cmd.into(), "kind");
        cx.push(
            Node::new(format!("{}", i.saturating_add(1)))
                .value(text(d.path.clone()))
                .summary(format!("{kind}, version {}", version(d.current)))
                .desc("Library ordinal, as used by symbols and binds"),
        )
        .await;
    }
    Ok(())
}

/// A node whose children are `children`, built already.
fn group(name: impl Into<std::borrow::Cow<'static, str>>, span: Span, children: Vec<Node>) -> Node {
    let node = Node::new(name).span(span);
    if children.is_empty() {
        node
    } else {
        node.lazy(super::push_nodes, Arc::new(children))
    }
}
