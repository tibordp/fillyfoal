//! The DBI (debug information) stream: a header, then substreams in a
//! fixed order (module info, section contributions, section map, source
//! file info, type server map, EC names, optional debug header), and the
//! section header stream the optional debug header points at.

use crate::bytes::{to_u64, to_usize, u16_le, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::executable::pe::tables::{MACHINE, SECTION_CHARACTERISTICS};
use crate::formats::util::val::{hex, text, uint};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, flag};

const LE: Endian = Endian::Little;

record! {
    pub struct DbiHeader {
        signature: i32 "Version signature",
        version: u32 "Version header" .enumeration(DBI_VERSIONS),
        age: u32 "Age",
        globals: u16 "Global symbol stream index",
        build: u16 "Build number" .hex() .with(|&v, n| n.summary(format!("{}.{}{}", (v >> 8) & 0x7f, v & 0xff, if v & 0x8000 != 0 { ", new format" } else { "" }))),
        publics: u16 "Public symbol stream index",
        dll_version: u16 "PDB DLL version",
        symbols: u16 "Symbol record stream index",
        dll_rbld: u16 "PDB DLL rebuild",
        module_info_size: i32 "Module info size",
        section_contribution_size: i32 "Section contribution size",
        section_map_size: i32 "Section map size",
        source_info_size: i32 "Source info size",
        type_server_map_size: i32 "Type server map size",
        mfc_index: u32 "MFC type server index",
        debug_header_size: i32 "Optional debug header size",
        ec_size: i32 "EC substream size",
        flags: u16 "Flags" .flags(DBI_FLAGS),
        machine: u16 "Machine" .enumeration(MACHINE),
        _padding: u32 "Padding",
    }
}

const DBI_VERSIONS: EnumTable = &[
    (930_803, "VC41"),
    (19_960_307, "V50"),
    (19_970_606, "V60"),
    (19_990_903, "V70"),
    (20_091_201, "V110"),
];

const DBI_FLAGS: FlagTable = &[
    flag(0x1, "incrementally linked"),
    flag(0x2, "private symbols stripped"),
    flag(0x4, "conflicting types"),
];

/// What the optional debug header's stream numbers are.
pub(super) const DEBUG_STREAMS: [&str; 11] = [
    "FPO data",
    "Exception data",
    "Fixup data",
    "OMAP to source",
    "OMAP from source",
    "Section headers",
    "Token/RID map",
    "Xdata",
    "Pdata",
    "New FPO data",
    "Original section headers",
];

/// The substream sizes, in stream order.
#[derive(Clone, Copy, Debug)]
pub(super) struct Substreams {
    pub modules: Span,
    pub contributions: Span,
    pub section_map: Span,
    pub files: Span,
    pub type_servers: Span,
    pub ec: Span,
    pub debug: Span,
}

impl Substreams {
    pub fn new(stream: Span, h: &DbiHeader) -> Self {
        let size = |v: i32| u64::try_from(v).unwrap_or(0);
        let mut at = DbiHeader::SIZE;
        let mut next = |v: i32| {
            let s = stream.sub(at, size(v));
            at = at.saturating_add(size(v));
            s
        };
        Substreams {
            modules: next(h.module_info_size),
            contributions: next(h.section_contribution_size),
            section_map: next(h.section_map_size),
            files: next(h.source_info_size),
            type_servers: next(h.type_server_map_size),
            ec: next(h.ec_size),
            debug: next(h.debug_header_size),
        }
    }
}

/// One module's info record, as the stream roles and module streams need.
#[derive(Clone, Debug)]
pub(super) struct Module {
    pub span: Span,
    pub name: String,
    pub object: String,
    pub stream: u16,
    pub symbols: u32,
    pub c11: u32,
    pub c13: u32,
    pub files: u16,
}

/// Parses the module info substream (input-sized: checkpointed).
pub(super) async fn modules(cx: &Cx, span: Span) -> Result<Vec<Module>> {
    let data = cx.read_avail(span).await?;
    let mut out = Vec::new();
    let mut at = 0usize;
    while at.saturating_add(64) <= data.len() {
        cx.checkpoint().await;
        let w16 = |o: usize| u16_le(&data, at.saturating_add(o)).unwrap_or(0);
        let w32 = |o: usize| u32_le(&data, at.saturating_add(o)).unwrap_or(0);
        let rest = data.get(at.saturating_add(64)..).unwrap_or_default();
        let mut strings = rest.splitn(3, |&b| b == 0);
        let name = strings.next().unwrap_or_default();
        let object = strings.next().unwrap_or_default();
        let len = 64usize
            .saturating_add(name.len())
            .saturating_add(object.len())
            .saturating_add(2);
        let len = len.next_multiple_of(4);
        out.push(Module {
            span: span.sub(to_u64(at), to_u64(len)),
            name: String::from_utf8_lossy(name).into_owned(),
            object: String::from_utf8_lossy(object).into_owned(),
            stream: w16(34),
            symbols: w32(36),
            c11: w32(40),
            c13: w32(44),
            files: w16(48),
        });
        at = at.saturating_add(len);
    }
    Ok(out)
}

/// The DBI stream: header and substreams.
pub(super) async fn dbi(cx: Cx, span: Span) -> Result<()> {
    let header = span.sub(0, DbiHeader::SIZE);
    cx.emit(DbiHeader::node("Header", header, LE));
    let h: DbiHeader = crate::dsl::read_record(&cx, header, LE).await?;
    let s = Substreams::new(span, &h);
    if s.modules.len > 0 {
        let list = modules(&cx, s.modules).await?;
        cx.emit(
            Node::new("Module info")
                .span(s.modules)
                .summary(crate::formats::util::arcutil::count(
                    to_u64(list.len()),
                    "module",
                    "modules",
                ))
                .lazy(module_list, s.modules),
        );
    }
    if s.contributions.len > 0 {
        cx.emit(
            Node::new("Section contributions")
                .span(s.contributions)
                .lazy(contributions, s.contributions),
        );
    }
    if s.section_map.len > 0 {
        cx.emit(
            Node::new("Section map")
                .span(s.section_map)
                .lazy(section_map, s.section_map),
        );
    }
    if s.files.len > 0 {
        cx.emit(
            Node::new("Source files")
                .span(s.files)
                .lazy(source_files, s.files),
        );
    }
    if s.type_servers.len > 0 {
        cx.emit(
            Node::new("Type server map")
                .span(s.type_servers)
                .desc("Not decoded"),
        );
    }
    if s.ec.len > 0 {
        cx.emit(
            Node::new("EC names")
                .span(s.ec)
                .desc("Names of Edit and Continue sources, in the /names format")
                .lazy(super::tables::names, s.ec),
        );
    }
    if s.debug.len > 0 {
        cx.emit(
            Node::new("Optional debug header")
                .span(s.debug)
                .lazy(debug_header, s.debug),
        );
    }
    let end = s.debug.end().saturating_sub(span.offset);
    if end < span.len {
        cx.emit(Node::new("Trailing data").span(span.tail(end)));
    }
    Ok(())
}

async fn module_list(cx: Cx, span: Span) -> Result<()> {
    let list = modules(&cx, span).await?;
    cx.set_count(Count::Exact(to_u64(list.len())));
    for (i, m) in list.into_iter().enumerate() {
        let stream = if m.stream == u16::MAX {
            "no stream".to_owned()
        } else {
            format!("stream {}", m.stream)
        };
        cx.push(
            struct_node(format!("Module {i}"), m.span, LE, (), module_info)
                .value(text(m.name.clone()))
                .summary(if m.object.is_empty() || m.object == m.name {
                    format!("{stream}, {} files", m.files)
                } else {
                    format!("{stream}, {} files, from {}", m.files, m.object)
                }),
        )
        .await;
    }
    Ok(())
}

const MODULE_FLAGS: FlagTable = &[flag(0x1, "written"), flag(0x2, "EC symbols")];

fn module_info(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("Unused").hex().emit()?;
    let sc = f.peek_span(28);
    f.node(struct_node(
        "Section contribution",
        sc,
        LE,
        28u32,
        contribution,
    ));
    f.skip(28);
    f.u16("Flags")
        .flags(MODULE_FLAGS)
        .with(|&v, n| n.summary(format!("type server {}", v >> 8)))
        .emit()?;
    f.u16("Symbol stream").emit()?;
    f.u32("Symbol bytes").emit()?;
    f.u32("C11 line bytes").emit()?;
    f.u32("C13 line bytes").emit()?;
    f.u16("Source files").emit()?;
    f.u16("Padding").emit()?;
    f.u32("Unused").hex().emit()?;
    f.u32("Source file name")
        .hex()
        .desc("Offset in /names")
        .emit()?;
    f.u32("PDB file path")
        .hex()
        .desc("Offset in /names")
        .emit()?;
    f.cstr("Module name").emit()?;
    f.cstr("Object file name").emit()?;
    Ok(())
}

/// A section contribution: 28 bytes, or 32 in the V2 layout.
fn contribution(f: &mut Fields<'_>, size: &u32) -> Result<()> {
    f.u16("Section").emit()?;
    f.u16("Padding").emit()?;
    f.i32("Offset").emit()?;
    f.i32("Size").emit()?;
    f.u32("Characteristics")
        .flags(SECTION_CHARACTERISTICS)
        .emit()?;
    f.u16("Module").emit()?;
    f.u16("Padding").emit()?;
    f.u32("Data CRC").hex().emit()?;
    f.u32("Relocation CRC").hex().emit()?;
    if *size >= 32 {
        f.u32("COFF section").emit()?;
    }
    Ok(())
}

const CONTRIBUTION_VERSIONS: EnumTable = &[(0xf12e_ba2d, "V60"), (0xf131_51e4, "V2")];

async fn contributions(cx: Cx, span: Span) -> Result<()> {
    let head = cx.read(span.sub_exact(0, 4)?).await?;
    let version = u32_le(&head, 0).unwrap_or(0);
    cx.emit(
        Node::new("Version")
            .span(span.sub(0, 4))
            .value(crate::value::Value::Enum {
                raw: version.into(),
                bits: 32,
                name: crate::value::lookup(CONTRIBUTION_VERSIONS, version.into()),
            }),
    );
    let size: u32 = if version == 0xf131_51e4 { 32 } else { 28 };
    let entries = span.tail(4);
    let n = entries.len.checked_div(u64::from(size)).unwrap_or(0);
    for i in 0..n {
        let at = entries.sub(i.saturating_mul(size.into()), size.into());
        let data = cx.read(at).await?;
        let section = u16_le(&data, 0).unwrap_or(0);
        let offset = u32_le(&data, 4).unwrap_or(0);
        let len = u32_le(&data, 8).unwrap_or(0);
        let module = u16_le(&data, 16).unwrap_or(0);
        cx.push(
            struct_node(format!("Contribution {i}"), at, LE, size, contribution).summary(format!(
                "{section:04x}:{offset:08x}, {} bytes, module {module}",
                len as i32
            )),
        )
        .await;
    }
    Ok(())
}

const SECTION_MAP_FLAGS: FlagTable = &[
    flag(0x1, "read"),
    flag(0x2, "write"),
    flag(0x4, "execute"),
    flag(0x8, "32-bit address"),
    flag(0x100, "selector"),
    flag(0x200, "absolute address"),
    flag(0x400, "group"),
];

fn section_map_entry(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u16("Flags").flags(SECTION_MAP_FLAGS).emit()?;
    f.u16("Overlay").emit()?;
    f.u16("Group").emit()?;
    f.u16("Frame").emit()?;
    f.u16("Section name").emit()?;
    f.u16("Class name").emit()?;
    f.u32("Offset").hex().emit()?;
    f.u32("Section length").hex().emit()?;
    Ok(())
}

async fn section_map(cx: Cx, span: Span) -> Result<()> {
    let head = cx.block(span.sub(0, 4)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.u16("Count").emit()?;
    f.u16("Logical count").emit()?;
    let entries = span.tail(4);
    for i in 0..entries.len / 20 {
        let at = entries.sub(i.saturating_mul(20), 20);
        let data = cx.read(at).await?;
        let frame = u16_le(&data, 6).unwrap_or(0);
        let len = u32_le(&data, 16).unwrap_or(0);
        cx.push(
            struct_node(format!("Segment {i}"), at, LE, (), section_map_entry)
                .summary(format!("frame {frame}, {len:#x} bytes")),
        )
        .await;
    }
    Ok(())
}

/// The source file info substream: per module, the files it uses, as
/// offsets into a names buffer.
async fn source_files(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read_avail(span).await?;
    let modules = usize::from(u16_le(&data, 0).unwrap_or(0));
    cx.emit(
        Node::new("Modules")
            .span(span.sub(0, 2))
            .value(uint(u32::try_from(modules).unwrap_or(0), 16)),
    );
    cx.emit(
        Node::new("Source files (truncated count)")
            .span(span.sub(2, 2))
            .value(uint(u16_le(&data, 2).unwrap_or(0), 16)),
    );
    let indices = 4usize;
    let counts = indices.saturating_add(modules.saturating_mul(2));
    let offsets = counts.saturating_add(modules.saturating_mul(2));
    let mut total = 0usize;
    for m in 0..modules {
        if m.is_multiple_of(1024) {
            cx.checkpoint().await;
        }
        total = total.saturating_add(usize::from(
            u16_le(&data, counts.saturating_add(m.saturating_mul(2))).unwrap_or(0),
        ));
    }
    let names = offsets.saturating_add(total.saturating_mul(4));
    let names_span = span.tail(to_u64(names));
    // Each module's files follow the previous module's (the legacy index
    // array is not reliable, as LLVM notes).
    let mut first = 0usize;
    for m in 0..modules {
        let n = usize::from(u16_le(&data, counts.saturating_add(m.saturating_mul(2))).unwrap_or(0));
        let mut files = Vec::new();
        for k in 0..n {
            if k.is_multiple_of(256) {
                cx.checkpoint().await;
            }
            let slot = offsets.saturating_add(first.saturating_add(k).saturating_mul(4));
            let Some(off) = u32_le(&data, slot) else {
                break;
            };
            let at = names.saturating_add(to_usize(off.into()));
            let s = data.get(at..).unwrap_or_default();
            let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
            files.push(
                Node::new(format!("{off:#x}"))
                    .span(names_span.sub(off.into(), to_u64(end)))
                    .value(text(String::from_utf8_lossy(
                        s.get(..end).unwrap_or_default(),
                    ))),
            );
        }
        first = first.saturating_add(n);
        cx.push(
            Node::new(format!("Module {m}"))
                .summary(crate::formats::util::arcutil::count(
                    to_u64(n),
                    "file",
                    "files",
                ))
                .lazy(
                    crate::formats::util::arcutil::push_nodes,
                    std::sync::Arc::new(files),
                ),
        )
        .await;
    }
    cx.push(
        Node::new("Names")
            .span(names_span)
            .lazy(crate::formats::util::binutil::cstrings, names_span),
    )
    .await;
    Ok(())
}

async fn debug_header(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read_avail(span).await?;
    for i in 0..data.len() / 2 {
        let v = u16_le(&data, i.saturating_mul(2)).unwrap_or(0);
        let label = DEBUG_STREAMS.get(i).copied().unwrap_or("Unknown");
        let node = Node::new(label).span(span.sub(to_u64(i.saturating_mul(2)), 2));
        cx.emit(if v == u16::MAX {
            node.value(hex(v, 16)).summary("none")
        } else {
            node.value(uint(v, 16)).summary(format!("stream {v}"))
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Section header stream

fn section_header(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.ascii("Name", 8).emit()?;
    f.u32("VirtualSize").hex().emit()?;
    f.u32("VirtualAddress").hex().emit()?;
    f.u32("SizeOfRawData").hex().emit()?;
    f.u32("PointerToRawData")
        .hex()
        .desc("In the image, not in the PDB")
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

/// The image's section headers (copied from the image by the linker).
pub(super) async fn section_headers(cx: Cx, span: Span) -> Result<()> {
    let n = span.len / 40;
    cx.set_count(Count::Exact(n));
    for i in 0..n {
        let at = span.sub(i.saturating_mul(40), 40);
        let data = cx.read(at).await?;
        let name = crate::text::until_nul(data.get(..8).unwrap_or_default());
        let va = u32_le(&data, 12).unwrap_or(0);
        let size = u32_le(&data, 8).unwrap_or(0);
        cx.push(
            struct_node(
                if name.is_empty() {
                    format!("Section {}", i.saturating_add(1))
                } else {
                    name
                },
                at,
                LE,
                (),
                section_header,
            )
            .summary(format!("RVA {va:#x}, {size:#x} bytes")),
        )
        .await;
    }
    if !span.len.is_multiple_of(40) {
        cx.diag(
            Diagnostic::malformed("the stream is not a whole number of section headers")
                .at(span.tail(n.saturating_mul(40))),
        );
    }
    Ok(())
}
