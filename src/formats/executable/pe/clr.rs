//! The CLR runtime header (`IMAGE_COR20_HEADER`) of .NET images and what it
//! points to: the metadata root (see [`super::metadata`]), managed
//! resources, the strong name signature, VTable fixups, the ReadyToRun
//! header, and IL method bodies (ECMA-335 partition II, 25.4).

use super::tables::DIR_CLR;
use super::{Directory, LE, Pe, PeInfo, rva_field};
use crate::bytes::{to_u64, u16_le, u32_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Fields, parse, struct_node};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, flag};

const CLR_FLAGS: FlagTable = &[
    flag(0x0000_0001, "ILONLY"),
    flag(0x0000_0002, "32BITREQUIRED"),
    flag(0x0000_0004, "IL_LIBRARY"),
    flag(0x0000_0008, "STRONGNAMESIGNED"),
    flag(0x0000_0010, "NATIVE_ENTRYPOINT"),
    flag(0x0001_0000, "TRACKDEBUGDATA"),
    flag(0x0002_0000, "32BITPREFERRED"),
];

#[derive(Clone, Copy, Debug)]
struct ClrHeader {
    metadata: u32,
    metadata_size: u32,
    flags: u32,
    entry: u32,
    resources: (u32, u32),
    strong_name: (u32, u32),
    vtable_fixups: (u32, u32),
    native_header: (u32, u32),
    major: u16,
    minor: u16,
}

fn clr_header(f: &mut Fields<'_>, pe: &Pe) -> Result<ClrHeader> {
    f.u32("cb").desc("Size of this header (72)").emit()?;
    let major = f.u16("MajorRuntimeVersion").emit()?;
    let minor = f.u16("MinorRuntimeVersion").emit()?;
    let metadata = rva_field(f.u32("MetaData.VirtualAddress"), pe).emit()?;
    let metadata_size = f.u32("MetaData.Size").hex().emit()?;
    let flags = f.u32("Flags").flags(CLR_FLAGS).emit()?;
    let entry = f
        .u32("EntryPointToken")
        .hex()
        .desc("MethodDef or File token of the entry point, or its RVA if NATIVE_ENTRYPOINT")
        .emit()?;
    let mut pair =
        |name: &'static str, size: &'static str, desc: &'static str| -> Result<(u32, u32)> {
            let rva = rva_field(f.u32(name), pe).desc(desc).emit()?;
            let len = f.u32(size).hex().emit()?;
            Ok((rva, len))
        };
    let resources = pair(
        "Resources.VirtualAddress",
        "Resources.Size",
        "Managed resources (length-prefixed blobs)",
    )?;
    let strong_name = pair(
        "StrongNameSignature.VirtualAddress",
        "StrongNameSignature.Size",
        "RSA signature over the image hash",
    )?;
    pair(
        "CodeManagerTable.VirtualAddress",
        "CodeManagerTable.Size",
        "Unused, 0",
    )?;
    let vtable_fixups = pair(
        "VTableFixups.VirtualAddress",
        "VTableFixups.Size",
        "Slots for mixed-mode exports and calls",
    )?;
    pair(
        "ExportAddressTableJumps.VirtualAddress",
        "ExportAddressTableJumps.Size",
        "Unused, 0",
    )?;
    let native_header = pair(
        "ManagedNativeHeader.VirtualAddress",
        "ManagedNativeHeader.Size",
        "ReadyToRun (precompiled code) header, or 0",
    )?;
    Ok(ClrHeader {
        metadata,
        metadata_size,
        flags,
        entry,
        resources,
        strong_name,
        vtable_fixups,
        native_header,
        major,
        minor,
    })
}

/// The runtime version string of the metadata root, for the image summary.
pub(super) async fn runtime_version(cx: &Cx, pe: &PeInfo) -> Result<String> {
    let (rva, size) = pe.directory(DIR_CLR);
    if rva == 0 || size == 0 {
        return Err(Diagnostic::note("not a .NET image"));
    }
    let header = cx.read(pe.rva_exact(rva, 16)?).await?;
    let metadata = u32_le(&header, 8).unwrap_or(0);
    let root = pe.rva_span(metadata, 0x200)?;
    let head = cx.read_avail(root.sub(0, 16)).await?;
    if head.get(..4) != Some(b"BSJB") {
        return Err(Diagnostic::malformed("no metadata root"));
    }
    let len = u64::from(u32_le(&head, 12).unwrap_or(0)).min(256);
    Ok(cx.cstr(root.sub(16, len)).await?.0)
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
    let h = parse(&cx, header, LE, &pe, clr_header).await?;
    let root = pe.rva_span(h.metadata, h.metadata_size.into())?;
    let md = super::metadata::load(&cx, root).await;
    let mut node = Node::new("Metadata")
        .span(root)
        .lazy(super::metadata::root, (pe.clone(), root));
    match &md {
        Ok(md) => {
            node = node.summary(format!("{}, {} streams", md.version, md.streams.len()));
        }
        Err(e) => node = node.diag(e.clone()),
    }
    cx.emit(node);
    let (res_rva, res_size) = h.resources;
    if res_rva != 0 && res_size != 0 {
        let res = pe.rva_span(res_rva, res_size.into())?;
        cx.emit(
            Node::new("Managed Resources")
                .span(res)
                .summary(format!("{res_size} bytes"))
                .lazy(super::managed::resources, (pe.clone(), root, res)),
        );
    }
    let (sn_rva, sn_size) = h.strong_name;
    if sn_rva != 0 && sn_size != 0 {
        match pe.rva_span(sn_rva, sn_size.into()) {
            Ok(span) => cx.emit(
                Node::new("Strong Name Signature")
                    .span(span)
                    .summary(format!(
                        "{} bytes{}",
                        sn_size,
                        if h.flags & 8 != 0 {
                            ""
                        } else {
                            ", not signed (delay-signed)"
                        }
                    ))
                    .desc("RSA signature of the image hash, by the assembly's public key"),
            ),
            Err(e) => cx.diag(e),
        }
    }
    let (vt_rva, vt_size) = h.vtable_fixups;
    if vt_rva != 0 && vt_size != 0 {
        match pe.rva_span(vt_rva, vt_size.into()) {
            Ok(span) => cx.emit(
                Node::new("VTable Fixups")
                    .span(span)
                    .summary(format!("{} entries", vt_size / 8))
                    .lazy(vtable_fixups, (pe.clone(), span)),
            ),
            Err(e) => cx.diag(e),
        }
    }
    let (rtr_rva, rtr_size) = h.native_header;
    if rtr_rva != 0 && rtr_size != 0 {
        match pe.rva_span(rtr_rva, rtr_size.into()) {
            Ok(span) => cx.emit(
                Node::new("ReadyToRun Header")
                    .span(span)
                    .lazy(ready_to_run, (pe.clone(), span)),
            ),
            Err(e) => cx.diag(e),
        }
    }
    let mut summary = format!("CLR header {}.{}", h.major, h.minor);
    if let Ok(md) = &md {
        summary = format!(".NET {}, {summary}", md.version);
        if h.flags & 0x10 == 0 && h.entry >> 24 == 0x06 {
            let name = md.row_label(&cx, 0x06, h.entry & 0x00ff_ffff).await;
            if !name.is_empty() {
                summary.push_str(&format!(", entry point {name}"));
            }
        }
    }
    cx.annotate(summary);
    Ok(())
}

const VTABLE_FLAGS: FlagTable = &[
    flag(0x01, "32BIT"),
    flag(0x02, "64BIT"),
    flag(0x04, "FROM_UNMANAGED"),
    flag(0x08, "FROM_UNMANAGED_RETAIN_APPDOMAIN"),
    flag(0x10, "CALL_MOST_DERIVED"),
];

fn vtable_fixup(f: &mut Fields<'_>, pe: &Pe) -> Result<()> {
    rva_field(f.u32("RVA"), pe)
        .desc("RVA of the slots")
        .emit()?;
    f.u16("Count").desc("Number of slots").emit()?;
    f.u16("Type").flags(VTABLE_FLAGS).emit()?;
    Ok(())
}

async fn vtable_fixups(cx: Cx, (pe, span): (Pe, Span)) -> Result<()> {
    let count = span.len / 8;
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let entry = span.sub(i.saturating_mul(8), 8);
        cx.push(struct_node(
            format!("#{i}"),
            entry,
            LE,
            pe.clone(),
            vtable_fixup,
        ))
        .await;
    }
    Ok(())
}

const R2R_SECTIONS: EnumTable = &[
    (100, "CompilerIdentifier"),
    (101, "ImportSections"),
    (102, "RuntimeFunctions"),
    (103, "MethodDefEntryPoints"),
    (104, "ExceptionInfo"),
    (105, "DebugInfo"),
    (106, "DelayLoadMethodCallThunks"),
    (107, "AvailableTypes (legacy)"),
    (108, "AvailableTypes"),
    (109, "InstanceMethodEntryPoints"),
    (110, "InliningInfo"),
    (111, "ProfileDataInfo"),
    (112, "ManifestMetadata"),
    (113, "AttributePresence"),
    (114, "InliningInfo2"),
    (115, "ComponentAssemblies"),
    (116, "OwnerCompositeExecutable"),
    (117, "PgoInstrumentationData"),
    (118, "ManifestAssemblyMvids"),
    (119, "CrossModuleInlineInfo"),
    (120, "HotColdMap"),
    (121, "MethodIsGenericMap"),
    (122, "EnclosingTypeMap"),
    (123, "TypeGenericInfoMap"),
];

const R2R_FLAGS: FlagTable = &[
    flag(0x01, "PLATFORM_NEUTRAL_SOURCE"),
    flag(0x02, "SKIP_TYPE_VALIDATION"),
    flag(0x04, "PARTIAL"),
    flag(0x08, "NONSHARED_PINVOKE_STUBS"),
    flag(0x10, "EMBEDDED_MSIL"),
    flag(0x20, "COMPONENT"),
    flag(0x40, "MULTIMODULE_VERSION_BUBBLE"),
    flag(0x80, "UNRELATED_R2R_CODE"),
];

/// `READYTORUN_HEADER` (CoreCLR `readytorun.h`): signature "RTR", version,
/// flags and a table of sections.
async fn ready_to_run(cx: Cx, (pe, span): (Pe, Span)) -> Result<()> {
    let block = cx.block(span.sub(0, 16)).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.ascii("Signature", 4).desc("\"RTR\"").emit()?;
    let major = f.u16("MajorVersion").emit()?;
    let minor = f.u16("MinorVersion").emit()?;
    f.u32("Flags").flags(R2R_FLAGS).emit()?;
    let count = f.u32("NumberOfSections").emit()?;
    let table = span.sub(16, u64::from(count.min(256)).saturating_mul(12));
    let data = cx.read_avail(table).await?;
    for i in 0..data.len() / 12 {
        let at = i.saturating_mul(12);
        let kind = u32_le(&data, at).unwrap_or(0);
        let rva = u32_le(&data, at.saturating_add(4)).unwrap_or(0);
        let size = u32_le(&data, at.saturating_add(8)).unwrap_or(0);
        let name = crate::value::lookup(R2R_SECTIONS, kind.into())
            .map_or_else(|| format!("Section {kind}"), str::to_owned);
        let mut node = struct_node(name, table.sub(to_u64(at), 12), LE, pe.clone(), r2r_section)
            .summary(format!("{}, {size:#x} bytes", pe.describe_rva(rva)));
        if let Ok(t) = pe.rva_span(rva, size.into()) {
            node = node.target(t);
        }
        cx.push(node).await;
    }
    cx.annotate(format!("ReadyToRun {major}.{minor}, {count} sections"));
    Ok(())
}

fn r2r_section(f: &mut Fields<'_>, pe: &Pe) -> Result<()> {
    f.u32("Type").enumeration(R2R_SECTIONS).emit()?;
    rva_field(f.u32("Section.VirtualAddress"), pe).emit()?;
    f.u32("Section.Size").hex().emit()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Method bodies

const METHOD_FLAGS: FlagTable = &[flag(0x08, "MoreSects"), flag(0x10, "InitLocals")];

const SECTION_FLAGS: FlagTable = &[
    flag(0x01, "EHTable"),
    flag(0x02, "OptILTable"),
    flag(0x40, "FatFormat"),
    flag(0x80, "MoreSects"),
];

const CLAUSE_KIND: EnumTable = &[(0, "catch"), (1, "filter"), (2, "finally"), (4, "fault")];

/// A method body at `at` (the header's start): tiny (one byte) or fat
/// (12 bytes), the IL code, then optional extra data sections (exception
/// clauses).
pub(super) async fn method_body_node(cx: &Cx, pe: &Pe, at: Span) -> Node {
    let Ok(head) = cx.read_avail(at.sub(0, 12)).await else {
        return Node::new("Body").span(at.sub(0, 0));
    };
    let first = head.first().copied().unwrap_or(0);
    let (header_len, code_len, more) = match first & 3 {
        2 => (1u64, u64::from(first >> 2), false),
        3 => {
            let flags = u16_le(&head, 0).unwrap_or(0);
            let size = u64::from(flags >> 12).saturating_mul(4);
            (
                size.max(12),
                u64::from(u32_le(&head, 4).unwrap_or(0)),
                flags & 0x8 != 0,
            )
        }
        _ => {
            return Node::new("Body")
                .span(at.sub(0, 1))
                .diag(Diagnostic::malformed(format!(
                    "method header byte {first:#04x} is neither tiny nor fat"
                )));
        }
    };
    let body = at.sub(0, header_len.saturating_add(code_len));
    Node::new("Body")
        .span(body)
        .summary(format!(
            "{} header, {code_len} bytes of IL{}",
            if header_len == 1 { "tiny" } else { "fat" },
            if more { ", exception clauses" } else { "" }
        ))
        .lazy(method_body, (pe.clone(), at, header_len, code_len, more))
}

async fn method_body(
    cx: Cx,
    (_pe, at, header_len, code_len, more): (Pe, Span, u64, u64, bool),
) -> Result<()> {
    let block = cx.block(at.sub(0, header_len)).await?;
    {
        let mut f = Fields::emitting(&cx, &block, LE);
        if header_len == 1 {
            f.u8("Header")
                .hex()
                .with(|&v, n| n.summary(format!("tiny, {} bytes of code", v >> 2)))
                .emit()?;
        } else {
            let span = f.peek_span(2);
            let flags = f.u16("Flags").get()?;
            f.node(
                Node::new("Flags / Size")
                    .span(span)
                    .value(crate::formats::util::lines::flags(
                        METHOD_FLAGS,
                        flags.into(),
                        16,
                    ))
                    .summary(format!("header {} bytes", (flags >> 12).saturating_mul(4))),
            );
            f.u16("MaxStack").emit()?;
            f.u32("CodeSize").emit()?;
            f.u32("LocalVarSigTok")
                .hex()
                .desc("StandAloneSig token of the local variables, or 0")
                .emit()?;
        }
    }
    let code = at.sub(header_len, code_len);
    cx.emit(
        Node::new("IL Code")
            .span(code)
            .summary(format!("{code_len} bytes")),
    );
    if !more {
        return Ok(());
    }
    let mut pos = header_len.saturating_add(code_len).next_multiple_of(4);
    for _ in 0..16 {
        let head = cx.read_avail(at.sub(pos, 4)).await?;
        let kind = head.first().copied().unwrap_or(0);
        let fat = kind & 0x40 != 0;
        let size = if fat {
            u64::from(u32_le(&head, 0).unwrap_or(0) >> 8)
        } else {
            u64::from(head.get(1).copied().unwrap_or(0))
        };
        if size < 4 {
            break;
        }
        let section = at.sub(pos, size);
        cx.emit(
            Node::new("Exception Clauses")
                .span(section)
                .summary(format!(
                    "{} clauses, {} format",
                    size.saturating_sub(4)
                        .checked_div(if fat { 24 } else { 12 })
                        .unwrap_or(0),
                    if fat { "fat" } else { "small" }
                ))
                .lazy(eh_section, (section, fat)),
        );
        pos = pos.saturating_add(size).next_multiple_of(4);
        if kind & 0x80 == 0 {
            break;
        }
    }
    Ok(())
}

async fn eh_section(cx: Cx, (span, fat): (Span, bool)) -> Result<()> {
    let block = cx.block(span.sub(0, 4)).await?;
    {
        let mut f = Fields::emitting(&cx, &block, LE);
        f.u8("Kind").flags(SECTION_FLAGS).emit()?;
        if fat {
            let s = f.peek_span(3);
            let raw = block.data.get(1..4).unwrap_or_default();
            let mut b = [0u8; 4];
            for (d, v) in b.iter_mut().zip(raw) {
                *d = *v;
            }
            f.node(
                Node::new("DataSize")
                    .span(s)
                    .value(crate::value::Value::UInt {
                        value: u32::from_le_bytes(b).into(),
                        bits: 24,
                        radix: crate::value::Radix::Dec,
                    }),
            );
        } else {
            f.u8("DataSize").emit()?;
            f.u16("Reserved").emit()?;
        }
    }
    let width = if fat { 24u64 } else { 12 };
    let count = span.len.saturating_sub(4).checked_div(width).unwrap_or(0);
    for i in 0..count {
        let clause = span.sub(4u64.saturating_add(i.saturating_mul(width)), width);
        cx.push(struct_node(
            format!("Clause {i}"),
            clause,
            LE,
            fat,
            eh_clause,
        ))
        .await;
    }
    Ok(())
}

fn eh_clause(f: &mut Fields<'_>, fat: &bool) -> Result<()> {
    if *fat {
        f.u32("Flags").enumeration(CLAUSE_KIND).emit()?;
        f.u32("TryOffset").hex().emit()?;
        f.u32("TryLength").hex().emit()?;
        f.u32("HandlerOffset").hex().emit()?;
        f.u32("HandlerLength").hex().emit()?;
    } else {
        f.u16("Flags").enumeration(CLAUSE_KIND).emit()?;
        f.u16("TryOffset").hex().emit()?;
        f.u8("TryLength").hex().emit()?;
        f.u16("HandlerOffset").hex().emit()?;
        f.u8("HandlerLength").hex().emit()?;
    }
    f.u32("ClassToken / FilterOffset")
        .hex()
        .desc("Catch type token, or the filter's IL offset")
        .emit()?;
    Ok(())
}
