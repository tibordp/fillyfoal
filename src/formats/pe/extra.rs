//! Less common PE structures: the Rich header, plain DOS executables, base
//! relocations, TLS, load configuration, delay imports, exception data and
//! the .NET (CLR) header with its metadata streams.

use super::{Directory, LE, Pe, dos_header, overflow, read_name, rva_field};
use crate::bytes::{to_u64, u16_le, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::error::{Diagnostic, Result};
use crate::fields::{Fields, parse, struct_node};
use crate::formats::{Head, Input, Probe, embedded};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

// ---------------------------------------------------------------------------
// Rich header

/// Selected Visual Studio product ids (the "@comp.id" high word).
const RICH_PRODUCTS: EnumTable = &[
    (0x0001, "Import (old)"),
    (0x0002, "Linker 5.10"),
    (0x0004, "Linker 6.00"),
    (0x0006, "CVTRES 5.00"),
    (0x000a, "C 12.00 (VC6)"),
    (0x000b, "C++ 12.00 (VC6)"),
    (0x005d, "C 13.10 (VS2003)"),
    (0x0083, "C++ 14.00 (VS2005)"),
    (0x0091, "Linker 9.00 (VS2008)"),
    (0x0093, "C++ 15.00 (VS2008)"),
    (0x009d, "Linker 10.00 (VS2010)"),
    (0x00aa, "C 16.00 (VS2010)"),
    (0x00ab, "C++ 16.00 (VS2010)"),
    (0x00cb, "Linker 11.00 (VS2012)"),
    (0x00cc, "MASM 11.00 (VS2012)"),
    (0x00ce, "C 17.00 (VS2012)"),
    (0x00cf, "C++ 17.00 (VS2012)"),
    (0x00dd, "Linker 12.00 (VS2013)"),
    (0x00e0, "C 18.00 (VS2013)"),
    (0x00e1, "C++ 18.00 (VS2013)"),
    (0x00ff, "CVTRES 14.00"),
    (0x0101, "Import (VS2015+)"),
    (0x0102, "Linker 14.00 (VS2015+)"),
    (0x0103, "MASM 14.00 (VS2015+)"),
    (0x0104, "C 19.00 (VS2015+)"),
    (0x0105, "C++ 19.00 (VS2015+)"),
];

/// Finds and decodes the Rich header between the DOS stub and `lfanew`.
pub(super) async fn rich_header(cx: &Cx, file: Span, lfanew: u64) -> Result<Option<Node>> {
    if lfanew <= 0x80 || lfanew > 0x1000 {
        return Ok(None);
    }
    let stub = cx.read(file.sub(0, lfanew)).await?;
    let Some(rich) = stub.windows(4).rposition(|w| w == b"Rich") else {
        return Ok(None);
    };
    let key = u32_le(&stub, rich.saturating_add(4)).unwrap_or(0);
    // Scan back in 4-byte steps for "DanS" xor key.
    let mut start = None;
    let mut at = rich;
    while at >= 4 {
        at = at.saturating_sub(4);
        if u32_le(&stub, at).map(|v| v ^ key) == Some(0x536e_6144) {
            start = Some(at);
            break;
        }
    }
    let Some(start) = start else {
        return Ok(None);
    };
    let span = file.sub(
        to_u64(start),
        to_u64(rich.saturating_add(8).saturating_sub(start)),
    );
    let mut entries = Vec::new();
    // Entries start after "DanS" and three zero padding words.
    let mut e = start.saturating_add(16);
    while e.saturating_add(8) <= rich {
        let comp = u32_le(&stub, e).unwrap_or(0) ^ key;
        let count = u32_le(&stub, e.saturating_add(4)).unwrap_or(0) ^ key;
        entries.push((comp, count, file.sub(to_u64(e), 8)));
        e = e.saturating_add(8);
    }
    let summary = format!("{} entries, key {key:#010x}", entries.len());
    Ok(Some(
        Node::new("Rich Header")
            .span(span)
            .summary(summary)
            .desc("Undocumented record of the Microsoft tools that built the image")
            .lazy(rich_entries, entries),
    ))
}

async fn rich_entries(cx: Cx, entries: Vec<(u32, u32, Span)>) -> Result<()> {
    for (comp, count, span) in entries {
        let product = comp >> 16;
        let build = comp & 0xffff;
        let name = lookup(RICH_PRODUCTS, product.into())
            .map_or_else(|| format!("product {product:#06x}"), str::to_owned);
        cx.push(
            Node::new(name)
                .span(span)
                .summary(format!("build {build}, used {count} time(s)")),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Plain MS-DOS executables (MZ without a PE/NE/LE/LX header)

fn dos_probe(h: &Head<'_>) -> bool {
    if !h.starts_with(b"MZ") && !h.starts_with(b"ZM") {
        return false;
    }
    // A PE/NE/LE/LX signature at e_lfanew means a newer executable format.
    let lfanew = u32_le(h.data, 0x3c).unwrap_or(0);
    let at = usize::try_from(lfanew).unwrap_or(usize::MAX);
    let newer = h.at(at, b"PE\0\0") || h.at(at, b"NE") || h.at(at, b"LE") || h.at(at, b"LX");
    if newer {
        return false;
    }
    // If e_lfanew points beyond what the probe can see, it may still be a
    // PE with a huge stub; only claim it when it cannot be a valid offset.
    at.saturating_add(4) <= h.data.len() || u64::from(lfanew) >= h.len
}

declare_format!(pub DOS_EXE = "dos-exe", "MS-DOS executable", ["exe", "com"], "application/x-dosexec",
    Probe::Custom(dos_probe), dos_exe);

async fn dos_exe(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let header = cx.block(file.sub(0, 0x1c)).await?;
    let pages = u16_le(&header.data, 4).unwrap_or(0);
    let last = u16_le(&header.data, 2).unwrap_or(0);
    let relocations = u16_le(&header.data, 6).unwrap_or(0);
    let paragraphs = u16_le(&header.data, 8).unwrap_or(0);
    let table = u16_le(&header.data, 0x18).unwrap_or(0);
    let cs = u16_le(&header.data, 0x16).unwrap_or(0);
    let ip = u16_le(&header.data, 0x14).unwrap_or(0);
    // A full 64-byte header is only meaningful for "new" executables.
    let header_len = if table >= 0x40 { 64u64 } else { 0x1c };
    cx.emit(struct_node(
        "DOS Header",
        file.sub(0, header_len),
        LE,
        file,
        dos_header,
    ));
    if relocations > 0 {
        let span = file.sub(table.into(), u64::from(relocations).saturating_mul(4));
        cx.emit(
            Node::new("Relocation table")
                .span(span)
                .summary(format!("{relocations} entries"))
                .lazy(dos_relocations, span),
        );
    }
    let image_end = u64::from(pages)
        .saturating_mul(512)
        .saturating_sub(if last == 0 {
            0
        } else {
            512u64.saturating_sub(last.into())
        });
    let module_start = u64::from(paragraphs).saturating_mul(16);
    cx.emit(
        Node::new("Load module")
            .span(file.sub(module_start, image_end.saturating_sub(module_start))),
    );
    if image_end < file.len && image_end > 0 {
        cx.emit(
            embedded("Overlay", input.nested(file.tail(image_end)))
                .summary(format!("{} bytes", file.len.saturating_sub(image_end))),
        );
    }
    cx.annotate(format!(
        "MS-DOS executable, {} bytes of code and data, entry {cs:04x}:{ip:04x}",
        image_end.saturating_sub(module_start)
    ));
    Ok(())
}

async fn dos_relocations(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read_avail(span).await?;
    let count = data.len() / 4;
    cx.set_count(Count::Exact(to_u64(count)));
    for i in 0..count {
        let at = i.saturating_mul(4);
        let offset = u16_le(&data, at).unwrap_or(0);
        let segment = u16_le(&data, at.saturating_add(2)).unwrap_or(0);
        cx.push(Node::new(format!("{segment:04x}:{offset:04x}")).span(span.sub(to_u64(at), 4)))
            .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Base relocations

const RELOCATION_TYPES: EnumTable = &[
    (0, "ABSOLUTE"),
    (1, "HIGH"),
    (2, "LOW"),
    (3, "HIGHLOW"),
    (4, "HIGHADJ"),
    (5, "ARM_MOV32 / MIPS_JMPADDR"),
    (7, "THUMB_MOV32"),
    (9, "MIPS_JMPADDR16"),
    (10, "DIR64"),
];

pub(super) async fn base_relocations(cx: Cx, (_pe, dir): (Pe, Directory)) -> Result<()> {
    let mut pos = 0u64;
    let mut blocks = 0u32;
    while pos.saturating_add(8) <= dir.span.len {
        let head = cx.read(dir.span.sub(pos, 8)).await?;
        let page = u32_le(&head, 0).unwrap_or(0);
        let size = u64::from(u32_le(&head, 4).unwrap_or(0));
        if size < 8 {
            cx.diag(
                Diagnostic::malformed("relocation block smaller than its header")
                    .at(dir.span.sub(pos, 8)),
            );
            break;
        }
        let span = dir.span.sub(pos, size);
        blocks = blocks.saturating_add(1);
        cx.push(
            Node::new(format!("Page {page:#x}"))
                .span(span)
                .summary(format!("{} entries", size.saturating_sub(8) / 2))
                .lazy(relocation_block, (span, page)),
        )
        .await;
        pos = pos.saturating_add(size);
    }
    cx.annotate(format!("{blocks} pages"));
    Ok(())
}

async fn relocation_block(cx: Cx, (span, page): (Span, u32)) -> Result<()> {
    let data = cx.read_avail(span).await?;
    let count = data.len().saturating_sub(8) / 2;
    cx.set_count(Count::Exact(to_u64(count)));
    for i in 0..count {
        let at = 8usize.saturating_add(i.saturating_mul(2));
        let entry = u16_le(&data, at).unwrap_or(0);
        let kind = entry >> 12;
        let rva = page.saturating_add(u32::from(entry & 0x0fff));
        cx.push(
            Node::new(format!("{rva:#x}"))
                .span(span.sub(to_u64(at), 2))
                .value(Value::Enum {
                    raw: kind.into(),
                    bits: 4,
                    name: lookup(RELOCATION_TYPES, kind.into()),
                }),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// TLS directory

fn tls_layout(f: &mut Fields<'_>, pe: &Pe) -> Result<()> {
    let wide = pe.wide;
    f.uword("StartAddressOfRawData", wide).hex().emit()?;
    f.uword("EndAddressOfRawData", wide).hex().emit()?;
    f.uword("AddressOfIndex", wide).hex().emit()?;
    f.uword("AddressOfCallBacks", wide)
        .hex()
        .desc("VA of a NULL-terminated array of TLS callbacks")
        .emit()?;
    f.u32("SizeOfZeroFill").hex().emit()?;
    f.u32("Characteristics").hex().emit()?;
    Ok(())
}

pub(super) async fn tls(cx: Cx, (pe, dir): (Pe, Directory)) -> Result<()> {
    let block = cx.block(dir.span).await?;
    tls_layout(&mut Fields::emitting(&cx, &block, LE), &pe)
}

// ---------------------------------------------------------------------------
// Load configuration

const GUARD_FLAGS: FlagTable = &[
    flag(0x0000_0100, "CF_INSTRUMENTED"),
    flag(0x0000_0200, "CFW_INSTRUMENTED"),
    flag(0x0000_0400, "CF_FUNCTION_TABLE_PRESENT"),
    flag(0x0000_0800, "SECURITY_COOKIE_UNUSED"),
    flag(0x0000_1000, "PROTECT_DELAYLOAD_IAT"),
    flag(0x0000_2000, "DELAYLOAD_IAT_IN_ITS_OWN_SECTION"),
    flag(0x0000_4000, "CF_EXPORT_SUPPRESSION_INFO_PRESENT"),
    flag(0x0000_8000, "CF_ENABLE_EXPORT_SUPPRESSION"),
    flag(0x0001_0000, "CF_LONGJUMP_TABLE_PRESENT"),
    flag(0x0010_0000, "EH_CONTINUATION_TABLE_PRESENT"),
];

fn load_config_layout(f: &mut Fields<'_>, pe: &Pe) -> Result<()> {
    let wide = pe.wide;
    let size = f.u32("Size").emit()?;
    f.u32("TimeDateStamp").timestamp().emit()?;
    f.u16("MajorVersion").emit()?;
    f.u16("MinorVersion").emit()?;
    f.u32("GlobalFlagsClear").hex().emit()?;
    f.u32("GlobalFlagsSet").hex().emit()?;
    f.u32("CriticalSectionDefaultTimeout").emit()?;
    f.uword("DeCommitFreeBlockThreshold", wide).hex().emit()?;
    f.uword("DeCommitTotalFreeThreshold", wide).hex().emit()?;
    f.uword("LockPrefixTable", wide).hex().emit()?;
    f.uword("MaximumAllocationSize", wide).hex().emit()?;
    f.uword("VirtualMemoryThreshold", wide).hex().emit()?;
    if wide {
        f.u64("ProcessAffinityMask").hex().emit()?;
        f.u32("ProcessHeapFlags").hex().emit()?;
    } else {
        f.u32("ProcessHeapFlags").hex().emit()?;
        f.u32("ProcessAffinityMask").hex().emit()?;
    }
    f.u16("CSDVersion").emit()?;
    f.u16("DependentLoadFlags").hex().emit()?;
    f.uword("EditList", wide).hex().emit()?;
    f.uword("SecurityCookie", wide)
        .hex()
        .desc("VA of the /GS stack cookie")
        .emit()?;
    if u64::from(size) <= f.pos() {
        return Ok(());
    }
    f.uword("SEHandlerTable", wide).hex().emit()?;
    f.uword("SEHandlerCount", wide).emit()?;
    if u64::from(size) <= f.pos() {
        return Ok(());
    }
    f.uword("GuardCFCheckFunctionPointer", wide).hex().emit()?;
    f.uword("GuardCFDispatchFunctionPointer", wide)
        .hex()
        .emit()?;
    f.uword("GuardCFFunctionTable", wide).hex().emit()?;
    f.uword("GuardCFFunctionCount", wide).emit()?;
    f.u32("GuardFlags").flags(GUARD_FLAGS).emit()?;
    Ok(())
}

pub(super) async fn load_config(cx: Cx, (pe, dir): (Pe, Directory)) -> Result<()> {
    // The structure's own Size field is authoritative; linkers often record
    // a smaller (legacy) size in the data directory.
    let size = u32_le(&cx.read(dir.span.sub(0, 4)).await?, 0).unwrap_or(0);
    let span = pe.rva_span(dir.rva, u64::from(size.max(dir.size)).min(0x400))?;
    let block = cx.block(span).await?;
    load_config_layout(&mut Fields::emitting(&cx, &block, LE), &pe)
}

// ---------------------------------------------------------------------------
// Delay-load imports

fn delay_descriptor(f: &mut Fields<'_>, pe: &Pe) -> Result<[u32; 8]> {
    let attributes = f
        .u32("Attributes")
        .hex()
        .desc("1 = addresses are RVAs")
        .emit()?;
    let name = rva_field(f.u32("DllNameRVA"), pe).emit()?;
    let module = rva_field(f.u32("ModuleHandleRVA"), pe).emit()?;
    let iat = rva_field(f.u32("ImportAddressTableRVA"), pe).emit()?;
    let int = rva_field(f.u32("ImportNameTableRVA"), pe).emit()?;
    let bound = rva_field(f.u32("BoundImportAddressTableRVA"), pe).emit()?;
    let unload = rva_field(f.u32("UnloadInformationTableRVA"), pe).emit()?;
    let stamp = f.u32("TimeDateStamp").hex().emit()?;
    Ok([attributes, name, module, iat, int, bound, unload, stamp])
}

pub(super) async fn delay_imports(cx: Cx, (pe, dir): (Pe, Directory)) -> Result<()> {
    let mut rva = dir.rva;
    for _ in 0..4096u32 {
        let span = pe.rva_span(rva, 32)?;
        let d = parse(&cx, span, LE, &pe, delay_descriptor).await?;
        if d.iter().all(|&v| v == 0) {
            break;
        }
        let node = match read_name(&cx, &pe, d[1]).await {
            Ok((name, _)) => Node::new(name),
            Err(e) => Node::new("<unreadable name>").diag(e),
        };
        cx.push(node.span(span).lazy(delay_module, (pe.clone(), span, d[4])))
            .await;
        rva = rva.checked_add(32).ok_or_else(overflow)?;
    }
    Ok(())
}

async fn delay_module(cx: Cx, (pe, descriptor, names): (Pe, Span, u32)) -> Result<()> {
    cx.emit(struct_node(
        "Delay Import Descriptor",
        descriptor,
        LE,
        pe.clone(),
        delay_descriptor,
    ));
    let width: u32 = if pe.wide { 8 } else { 4 };
    let ordinal = if pe.wide {
        0x8000_0000_0000_0000u64
    } else {
        0x8000_0000
    };
    let mut index = 0u32;
    loop {
        let rva = index
            .checked_mul(width)
            .and_then(|o| names.checked_add(o))
            .ok_or_else(overflow)?;
        let span = pe.rva_exact(rva, width.into())?;
        let data = cx.read(span).await?;
        let thunk = if pe.wide {
            crate::bytes::u64_le(&data, 0)
        } else {
            u32_le(&data, 0).map(u64::from)
        }
        .unwrap_or(0);
        if thunk == 0 {
            break;
        }
        let node = if thunk & ordinal != 0 {
            Node::new(format!("Ordinal {}", thunk & 0xffff))
        } else {
            let at = u32::try_from(thunk & 0x7fff_ffff)
                .unwrap_or(0)
                .saturating_add(2);
            match read_name(&cx, &pe, at).await {
                Ok((name, span)) => Node::new(name).target(span),
                Err(e) => Node::new("<unreadable>").diag(e),
            }
        };
        cx.push(node.span(span)).await;
        index = index.checked_add(1).ok_or_else(overflow)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Exception data (x64/ARM64 RUNTIME_FUNCTION entries)

pub(super) async fn exceptions(cx: Cx, (pe, dir): (Pe, Directory)) -> Result<()> {
    let entry = if pe.wide { 12u64 } else { 8 };
    let count = dir.span.len.checked_div(entry).unwrap_or(0);
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let span = dir.span.sub(i.saturating_mul(entry), entry);
        let data = cx.read(span).await?;
        let begin = u32_le(&data, 0).unwrap_or(0);
        let end = u32_le(&data, 4).unwrap_or(0);
        let node = if pe.wide {
            Node::new(format!("{begin:#x}..{end:#x}")).summary(format!(
                "unwind info at {:#x}",
                u32_le(&data, 8).unwrap_or(0)
            ))
        } else {
            Node::new(format!("{begin:#x}")).summary(format!("unwind data {end:#x}"))
        };
        let node = match pe.rva_span(begin, u64::from(end.saturating_sub(begin))) {
            Ok(code) => node.target(code),
            Err(_) => node,
        };
        cx.push(node.span(span)).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// .NET: CLR header and metadata root

const CLR_FLAGS: FlagTable = &[
    flag(0x0000_0001, "ILONLY"),
    flag(0x0000_0002, "32BITREQUIRED"),
    flag(0x0000_0004, "IL_LIBRARY"),
    flag(0x0000_0008, "STRONGNAMESIGNED"),
    flag(0x0000_0010, "NATIVE_ENTRYPOINT"),
    flag(0x0001_0000, "TRACKDEBUGDATA"),
    flag(0x0002_0000, "32BITPREFERRED"),
];

fn clr_header(f: &mut Fields<'_>, pe: &Pe) -> Result<(u32, u32, u16, u16)> {
    f.u32("cb").emit()?;
    let major = f.u16("MajorRuntimeVersion").emit()?;
    let minor = f.u16("MinorRuntimeVersion").emit()?;
    let metadata = rva_field(f.u32("MetaData.VirtualAddress"), pe).emit()?;
    let size = f.u32("MetaData.Size").hex().emit()?;
    f.u32("Flags").flags(CLR_FLAGS).emit()?;
    f.u32("EntryPointToken")
        .hex()
        .desc("Method token, or RVA if NATIVE_ENTRYPOINT")
        .emit()?;
    rva_field(f.u32("Resources.VirtualAddress"), pe).emit()?;
    f.u32("Resources.Size").hex().emit()?;
    rva_field(f.u32("StrongNameSignature.VirtualAddress"), pe).emit()?;
    f.u32("StrongNameSignature.Size").hex().emit()?;
    rva_field(f.u32("CodeManagerTable.VirtualAddress"), pe).emit()?;
    f.u32("CodeManagerTable.Size").hex().emit()?;
    rva_field(f.u32("VTableFixups.VirtualAddress"), pe).emit()?;
    f.u32("VTableFixups.Size").hex().emit()?;
    rva_field(f.u32("ExportAddressTableJumps.VirtualAddress"), pe).emit()?;
    f.u32("ExportAddressTableJumps.Size").hex().emit()?;
    rva_field(f.u32("ManagedNativeHeader.VirtualAddress"), pe).emit()?;
    f.u32("ManagedNativeHeader.Size").hex().emit()?;
    Ok((metadata, size, major, minor))
}

pub(super) async fn clr(cx: Cx, (pe, dir): (Pe, Directory)) -> Result<()> {
    let header = dir.span.sub(0, 72);
    cx.emit(struct_node(
        "CLR Header",
        header,
        LE,
        pe.clone(),
        clr_header,
    ));
    let (metadata, size, major, minor) = parse(&cx, header, LE, &pe, clr_header).await?;
    let root = pe.rva_span(metadata, size.into())?;
    let head = cx.read(root.sub(0, 16)).await?;
    if head.get(..4) != Some(b"BSJB") {
        return Err(Diagnostic::malformed("metadata root signature is not BSJB").at(root.sub(0, 4)));
    }
    let version_len = u64::from(u32_le(&head, 12).unwrap_or(0)).min(256);
    let (version, _) = cx.cstr(root.sub(16, version_len)).await?;
    let streams_at = 16u64.saturating_add(version_len);
    let counts = cx.read(root.sub(streams_at, 4)).await?;
    let streams = u16_le(&counts, 2).unwrap_or(0);
    cx.emit(
        Node::new("Metadata")
            .span(root)
            .summary(format!("{version}, {streams} streams"))
            .lazy(
                metadata_streams,
                (root, streams_at.saturating_add(4), streams),
            ),
    );
    cx.annotate(format!(".NET {version} (CLR header {major}.{minor})"));
    Ok(())
}

async fn metadata_streams(cx: Cx, (root, mut at, streams): (Span, u64, u16)) -> Result<()> {
    cx.set_count(Count::Exact(streams.into()));
    for _ in 0..streams {
        let head = cx.read(root.sub(at, 8)).await?;
        let offset = u64::from(u32_le(&head, 0).unwrap_or(0));
        let size = u64::from(u32_le(&head, 4).unwrap_or(0));
        let (name, name_span) = cx.cstr(root.sub(at.saturating_add(8), 32)).await?;
        let header_len = 8u64.saturating_add(name_span.len.next_multiple_of(4));
        let mut node = Node::new(name.clone())
            .span(root.sub(offset, size))
            .summary(format!("{size} bytes"))
            .target(root.sub(at, header_len));
        if name == "#~" || name == "#-" {
            let tables = cx.read_avail(root.sub(offset, 24)).await?;
            let valid = crate::bytes::u64_le(&tables, 8).unwrap_or(0);
            node = node.summary(format!(
                "{} tables present, schema {}.{}",
                valid.count_ones(),
                tables.get(4).copied().unwrap_or(0),
                tables.get(5).copied().unwrap_or(0)
            ));
        } else if name == "#GUID" {
            node = node.summary(format!("{} GUIDs", size / 16));
        }
        cx.push(node).await;
        at = at.saturating_add(header_len);
    }
    Ok(())
}
