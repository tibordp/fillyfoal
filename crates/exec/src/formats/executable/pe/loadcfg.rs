//! The TLS directory (`IMAGE_TLS_DIRECTORY`, with its callback array and
//! data template) and the load configuration (`IMAGE_LOAD_CONFIG_DIRECTORY`
//! in all its versions, as far as its own `Size` reaches), with the tables
//! it points to: SafeSEH handlers, the Control Flow Guard function,
//! address-taken IAT, long-jump and EH-continuation tables, the lock prefix
//! table, volatile metadata, CHPE / ARM64EC metadata and the dynamic value
//! relocation table.

use super::tables::{MACHINE_AMD64, MACHINE_ARM64, MACHINE_ARM64EC, MACHINE_ARM64X, MACHINE_I386};
use super::{Directory, LE, Pe, PeInfo, padding_node, rva_field, va_field};
use crate::bytes::{to_u64, u32_le, u64_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Fields, struct_node};
use crate::formats::util::fmt::plural;
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Radix, Value, decode_flags, field, flag};

/// Tables longer than this are cut off.
const MAX_ENTRIES: u64 = 1 << 20;

fn read_word(pe: &PeInfo, data: &[u8], at: usize) -> Option<u64> {
    if pe.wide {
        u64_le(data, at)
    } else {
        u32_le(data, at).map(u64::from)
    }
}

// ---------------------------------------------------------------------------
// TLS

#[derive(Clone, Copy, Debug)]
struct Tls {
    start: u64,
    end: u64,
    index: u64,
    callbacks: u64,
}

const TLS_ALIGN: FlagTable = &[
    field(0x00f0_0000, 0x0010_0000, "ALIGN_1BYTES"),
    field(0x00f0_0000, 0x0020_0000, "ALIGN_2BYTES"),
    field(0x00f0_0000, 0x0030_0000, "ALIGN_4BYTES"),
    field(0x00f0_0000, 0x0040_0000, "ALIGN_8BYTES"),
    field(0x00f0_0000, 0x0050_0000, "ALIGN_16BYTES"),
    field(0x00f0_0000, 0x0060_0000, "ALIGN_32BYTES"),
    field(0x00f0_0000, 0x0070_0000, "ALIGN_64BYTES"),
    field(0x00f0_0000, 0x0080_0000, "ALIGN_128BYTES"),
    field(0x00f0_0000, 0x0090_0000, "ALIGN_256BYTES"),
    field(0x00f0_0000, 0x00a0_0000, "ALIGN_512BYTES"),
    field(0x00f0_0000, 0x00b0_0000, "ALIGN_1024BYTES"),
    field(0x00f0_0000, 0x00c0_0000, "ALIGN_2048BYTES"),
    field(0x00f0_0000, 0x00d0_0000, "ALIGN_4096BYTES"),
    field(0x00f0_0000, 0x00e0_0000, "ALIGN_8192BYTES"),
];

fn tls_layout(f: &mut Fields<'_>, pe: &Pe) -> Result<Tls> {
    let wide = pe.wide;
    let start = va_field(f.uword("StartAddressOfRawData", wide), pe)
        .desc("VA of the template copied into each thread's TLS block")
        .emit()?;
    let end = va_field(f.uword("EndAddressOfRawData", wide), pe).emit()?;
    let index = va_field(f.uword("AddressOfIndex", wide), pe)
        .desc("VA of the slot that receives the module's TLS index")
        .emit()?;
    let callbacks = va_field(f.uword("AddressOfCallBacks", wide), pe)
        .desc("VA of a NULL-terminated array of TLS callbacks")
        .emit()?;
    f.u32("SizeOfZeroFill")
        .hex()
        .desc("Zero bytes added after the template")
        .emit()?;
    f.u32("Characteristics").flags(TLS_ALIGN).emit()?;
    Ok(Tls {
        start,
        end,
        index,
        callbacks,
    })
}

pub(super) async fn tls(cx: Cx, (pe, dir): (Pe, Directory)) -> Result<()> {
    let len = if pe.wide { 40 } else { 24 };
    let span = dir.span.sub(0, len);
    let block = cx.block(span).await?;
    let t = tls_layout(&mut Fields::emitting(&cx, &block, LE), &pe)?;
    if t.end > t.start
        && let Ok(template) = pe.va_span(t.start, t.end.saturating_sub(t.start))
    {
        cx.emit(
            Node::new("Template")
                .span(template)
                .summary(format!("{} bytes", template.len))
                .desc("Initial contents of the thread-local variables"),
        );
    }
    if t.index != 0
        && let Ok(slot) = pe.va_span(t.index, 4)
    {
        let raw = cx.read_avail(slot).await?;
        cx.emit(
            Node::new("Index Slot")
                .span(slot)
                .value(Value::UInt {
                    value: u32_le(&raw, 0).unwrap_or(0).into(),
                    bits: 32,
                    radix: Radix::Dec,
                })
                .desc("Filled in by the loader"),
        );
    }
    if t.callbacks != 0 {
        let mut count = 0u64;
        let width = pe.word();
        while count < 4096 {
            let Ok(slot) = pe.va_span(
                t.callbacks.saturating_add(count.saturating_mul(width)),
                width,
            ) else {
                break;
            };
            let raw = cx.read_avail(slot).await?;
            if read_word(&pe, &raw, 0).unwrap_or(0) == 0 {
                break;
            }
            count = count.saturating_add(1);
        }
        if let Ok(array) = pe.va_span(t.callbacks, count.saturating_add(1).saturating_mul(width)) {
            cx.emit(
                Node::new("Callbacks")
                    .span(array)
                    .summary(plural(count, "callback"))
                    .desc("Called on process and thread attach and detach, before the entry point")
                    .lazy(va_list, (pe.clone(), array)),
            );
        }
    }
    cx.annotate(format!(
        "{} bytes of TLS data",
        t.end.saturating_sub(t.start)
    ));
    Ok(())
}

/// A NULL-terminated array of virtual addresses.
async fn va_list(cx: Cx, (pe, span): (Pe, Span)) -> Result<()> {
    let data = cx.read(span).await?;
    let width = pe.word();
    let count = span.len.checked_div(width).unwrap_or(0);
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let at = i.saturating_mul(width);
        let va = read_word(&pe, &data, crate::bytes::to_usize(at)).unwrap_or(0);
        let mut node = Node::new(if va == 0 {
            "End of list".to_owned()
        } else {
            format!("#{i}")
        })
        .span(span.sub(at, width))
        .value(pe.word_value(va));
        if let Some(rva) = pe.va_rva(va).filter(|_| va != 0) {
            node = node.summary(pe.describe_rva(rva));
            if let Ok(t) = pe.rva_span(rva, 0) {
                node = node.target(t);
            }
        }
        cx.push(node).await;
    }
    Ok(())
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
    flag(0x0002_0000, "RF_INSTRUMENTED"),
    flag(0x0004_0000, "RF_ENABLE"),
    flag(0x0008_0000, "RF_STRICT"),
    flag(0x0010_0000, "RETPOLINE_PRESENT"),
    flag(0x0040_0000, "EH_CONTINUATION_TABLE_PRESENT"),
    flag(0x0080_0000, "XFG_ENABLED"),
    flag(0x0100_0000, "CASTGUARD_PRESENT"),
    flag(0x0200_0000, "MEMCPY_PRESENT"),
    field(0xf000_0000, 0x1000_0000, "CF_FUNCTION_TABLE_SIZE_5BYTES"),
    field(0xf000_0000, 0x2000_0000, "CF_FUNCTION_TABLE_SIZE_6BYTES"),
    field(0xf000_0000, 0x3000_0000, "CF_FUNCTION_TABLE_SIZE_7BYTES"),
    field(0xf000_0000, 0x4000_0000, "CF_FUNCTION_TABLE_SIZE_8BYTES"),
];

/// Metadata flags of guard table entries (the bytes after each RVA).
const GFID_FLAGS: FlagTable = &[
    flag(0x01, "FID_SUPPRESSED"),
    flag(0x02, "EXPORT_SUPPRESSED"),
    flag(0x04, "FID_LANGEXCPTHANDLER"),
    flag(0x08, "FID_XFG"),
];

const DEPENDENT_LOAD: FlagTable = &[
    flag(0x0100, "LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR"),
    flag(0x0200, "LOAD_LIBRARY_SEARCH_APPLICATION_DIR"),
    flag(0x0400, "LOAD_LIBRARY_SEARCH_USER_DIRS"),
    flag(0x0800, "LOAD_LIBRARY_SEARCH_SYSTEM32"),
    flag(0x1000, "LOAD_LIBRARY_SEARCH_DEFAULT_DIRS"),
];

/// The values of the load configuration that point to further tables.
#[derive(Clone, Copy, Debug, Default)]
struct LoadConfig {
    size: u32,
    lock_prefix: u64,
    se_table: u64,
    se_count: u64,
    cf_table: u64,
    cf_count: u64,
    guard_flags: u32,
    iat_table: u64,
    iat_count: u64,
    longjmp_table: u64,
    longjmp_count: u64,
    chpe: u64,
    dvrt_offset: u32,
    dvrt_section: u16,
    volatile: u64,
    eh_table: u64,
    eh_count: u64,
}

/// Whether a field of `width` bytes still lies within the declared size.
fn fits(f: &Fields<'_>, size: u32, width: u64) -> bool {
    f.pos().saturating_add(width) <= u64::from(size)
        && f.pos().saturating_add(width) <= f.block().span.len
}

fn load_config_layout(f: &mut Fields<'_>, pe: &Pe) -> Result<LoadConfig> {
    let wide = pe.wide;
    let w = pe.word();
    let mut lc = LoadConfig {
        size: f
            .u32("Size")
            .hex()
            .desc("Size of the structure; newer fields exist only if it reaches them")
            .emit()?,
        ..LoadConfig::default()
    };
    let size = lc.size;
    f.u32("TimeDateStamp").timestamp().emit()?;
    f.u16("MajorVersion").emit()?;
    f.u16("MinorVersion").emit()?;
    f.u32("GlobalFlagsClear")
        .hex()
        .desc("NtGlobalFlag bits cleared for the process")
        .emit()?;
    f.u32("GlobalFlagsSet")
        .hex()
        .desc("NtGlobalFlag bits set for the process")
        .emit()?;
    f.u32("CriticalSectionDefaultTimeout").emit()?;
    f.uword("DeCommitFreeBlockThreshold", wide).hex().emit()?;
    f.uword("DeCommitTotalFreeThreshold", wide).hex().emit()?;
    lc.lock_prefix = va_field(f.uword("LockPrefixTable", wide), pe)
        .desc("VA of a NULL-terminated list of LOCK prefixes to patch out on uniprocessors (x86)")
        .emit()?;
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
    f.u16("DependentLoadFlags").flags(DEPENDENT_LOAD).emit()?;
    va_field(f.uword("EditList", wide), pe).emit()?;
    va_field(f.uword("SecurityCookie", wide), pe)
        .desc("VA of the /GS stack cookie")
        .emit()?;
    if !fits(f, size, w.saturating_mul(2)) {
        return Ok(lc);
    }
    lc.se_table = va_field(f.uword("SEHandlerTable", wide), pe)
        .desc("VA of the sorted SafeSEH handler RVAs (x86)")
        .emit()?;
    lc.se_count = f.uword("SEHandlerCount", wide).emit()?;
    if !fits(f, size, w.saturating_mul(4).saturating_add(4)) {
        return Ok(lc);
    }
    va_field(f.uword("GuardCFCheckFunctionPointer", wide), pe)
        .desc("VA of the pointer to the CFG check routine")
        .emit()?;
    va_field(f.uword("GuardCFDispatchFunctionPointer", wide), pe)
        .desc("VA of the pointer to the CFG dispatch routine")
        .emit()?;
    lc.cf_table = va_field(f.uword("GuardCFFunctionTable", wide), pe)
        .desc("VA of the sorted RVAs of valid indirect call targets")
        .emit()?;
    lc.cf_count = f.uword("GuardCFFunctionCount", wide).emit()?;
    lc.guard_flags = f.u32("GuardFlags").flags(GUARD_FLAGS).emit()?;
    if !fits(f, size, 12) {
        return Ok(lc);
    }
    f.u16("CodeIntegrity.Flags").hex().emit()?;
    f.u16("CodeIntegrity.Catalog").emit()?;
    f.u32("CodeIntegrity.CatalogOffset").hex().emit()?;
    f.u32("CodeIntegrity.Reserved").emit()?;
    if !fits(f, size, w.saturating_mul(4)) {
        return Ok(lc);
    }
    lc.iat_table = va_field(f.uword("GuardAddressTakenIatEntryTable", wide), pe).emit()?;
    lc.iat_count = f.uword("GuardAddressTakenIatEntryCount", wide).emit()?;
    lc.longjmp_table = va_field(f.uword("GuardLongJumpTargetTable", wide), pe).emit()?;
    lc.longjmp_count = f.uword("GuardLongJumpTargetCount", wide).emit()?;
    if !fits(f, size, w.saturating_mul(2)) {
        return Ok(lc);
    }
    va_field(f.uword("DynamicValueRelocTable", wide), pe).emit()?;
    lc.chpe = va_field(f.uword("CHPEMetadataPointer", wide), pe)
        .desc("Hybrid (CHPE / ARM64EC) metadata")
        .emit()?;
    if !fits(f, size, w.saturating_mul(2)) {
        return Ok(lc);
    }
    va_field(f.uword("GuardRFFailureRoutine", wide), pe).emit()?;
    va_field(f.uword("GuardRFFailureRoutineFunctionPointer", wide), pe).emit()?;
    if !fits(f, size, 8) {
        return Ok(lc);
    }
    lc.dvrt_offset = f
        .u32("DynamicValueRelocTableOffset")
        .hex()
        .desc("Offset of the dynamic value relocation table in its section")
        .emit()?;
    lc.dvrt_section = f
        .u16("DynamicValueRelocTableSection")
        .desc("1-based section index")
        .emit()?;
    f.u16("Reserved2").emit()?;
    if !fits(f, size, w) {
        return Ok(lc);
    }
    va_field(
        f.uword("GuardRFVerifyStackPointerFunctionPointer", wide),
        pe,
    )
    .emit()?;
    if !fits(f, size, 8) {
        return Ok(lc);
    }
    f.u32("HotPatchTableOffset").hex().emit()?;
    f.u32("Reserved3").emit()?;
    if !fits(f, size, w) {
        return Ok(lc);
    }
    va_field(f.uword("EnclaveConfigurationPointer", wide), pe).emit()?;
    if !fits(f, size, w) {
        return Ok(lc);
    }
    lc.volatile = va_field(f.uword("VolatileMetadataPointer", wide), pe).emit()?;
    if !fits(f, size, w.saturating_mul(2)) {
        return Ok(lc);
    }
    lc.eh_table = va_field(f.uword("GuardEHContinuationTable", wide), pe)
        .desc("VA of the sorted RVAs of valid exception-handling continuation targets")
        .emit()?;
    lc.eh_count = f.uword("GuardEHContinuationCount", wide).emit()?;
    for (name, desc) in [
        (
            "GuardXFGCheckFunctionPointer",
            "eXtended Flow Guard check routine pointer",
        ),
        (
            "GuardXFGDispatchFunctionPointer",
            "XFG dispatch routine pointer",
        ),
        (
            "GuardXFGTableDispatchFunctionPointer",
            "XFG table dispatch routine pointer",
        ),
        (
            "CastGuardOsDeterminedFailureMode",
            "VA of the CastGuard failure mode",
        ),
        (
            "GuardMemcpyFunctionPointer",
            "Guarded memcpy routine pointer",
        ),
        (
            "UmaFunctionPointers",
            "User-mode accelerator function pointers",
        ),
    ] {
        if !fits(f, size, w) {
            return Ok(lc);
        }
        va_field(f.uword(name, wide), pe).desc(desc).emit()?;
    }
    Ok(lc)
}

pub(super) async fn load_config(cx: Cx, (pe, dir): (Pe, Directory)) -> Result<()> {
    // The structure's own Size field is authoritative; linkers often record
    // a smaller (legacy) size in the data directory.
    let size = u32_le(&cx.read(dir.span.sub(0, 4)).await?, 0).unwrap_or(0);
    let span = pe.rva_span(dir.rva, u64::from(size.max(dir.size)).min(0x400))?;
    let block = cx.block(span).await?;
    let lc = load_config_layout(&mut Fields::emitting(&cx, &block, LE), &pe)?;
    if u64::from(lc.size) < span.len && u64::from(lc.size) >= 4 {
        let rest = span.tail(lc.size.into());
        cx.emit(padding_node(
            "Beyond Size",
            rest,
            "Bytes the data directory counts but the structure's Size does not",
        ));
    }
    let stride = 4u64.saturating_add(u64::from(lc.guard_flags >> 28));
    let tables: [(&'static str, u64, u64, u64, &'static str); 5] = [
        (
            "SafeSEH Handlers",
            lc.se_table,
            lc.se_count,
            4,
            "RVAs of the registered exception handlers",
        ),
        (
            "CFG Function Table",
            lc.cf_table,
            lc.cf_count,
            stride,
            "Valid targets of indirect calls",
        ),
        (
            "CFG Address-Taken IAT Table",
            lc.iat_table,
            lc.iat_count,
            stride,
            "IAT entries whose addresses are taken",
        ),
        (
            "Long Jump Target Table",
            lc.longjmp_table,
            lc.longjmp_count,
            stride,
            "Valid longjmp targets",
        ),
        (
            "EH Continuation Table",
            lc.eh_table,
            lc.eh_count,
            stride,
            "Valid exception-handling continuation targets",
        ),
    ];
    for (name, va, count, width, desc) in tables {
        if va == 0 || count == 0 {
            continue;
        }
        let count = count.min(MAX_ENTRIES);
        let Some(rva) = pe.va_rva(va) else {
            continue;
        };
        match pe.rva_exact(rva, count.saturating_mul(width)) {
            Ok(table) => cx.emit(
                Node::new(name)
                    .span(table)
                    .summary(format!(
                        "{count} entr{}",
                        if count == 1 { "y" } else { "ies" }
                    ))
                    .desc(desc)
                    .lazy(guard_table, (pe.clone(), table, width)),
            ),
            Err(e) => cx.diag(e),
        }
    }
    if lc.lock_prefix != 0
        && pe.machine == MACHINE_I386
        && let Some(node) = lock_prefixes(&cx, &pe, lc.lock_prefix).await
    {
        cx.emit(node);
    }
    if lc.volatile != 0
        && let Ok(span) = pe.va_span(lc.volatile, 24)
    {
        cx.emit(struct_node(
            "Volatile Metadata",
            span,
            LE,
            pe.clone(),
            volatile_metadata,
        ));
    }
    if lc.chpe != 0
        && let Ok(span) = pe.va_span(lc.chpe, 0x5c)
    {
        let node = if matches!(
            pe.machine,
            MACHINE_ARM64 | MACHINE_ARM64EC | MACHINE_ARM64X | MACHINE_AMD64
        ) {
            Node::new("ARM64EC Metadata")
                .span(span)
                .lazy(arm64ec_metadata, (pe.clone(), span))
        } else {
            Node::new("CHPE Metadata")
                .span(span.sub(0, 4))
                .desc("Compiled hybrid PE (x86 on ARM64) metadata")
        };
        cx.emit(node);
    }
    if lc.dvrt_section != 0
        && let Some(section) = pe
            .sections
            .get(usize::from(lc.dvrt_section).saturating_sub(1))
    {
        let at = u64::from(section.raw_pointer).saturating_add(lc.dvrt_offset.into());
        let head = cx.read_avail(pe.file().sub(at, 8)).await?;
        let len = u64::from(u32_le(&head, 4).unwrap_or(0));
        let span = pe.file().sub(at, len.saturating_add(8));
        cx.emit(
            Node::new("Dynamic Value Relocation Table")
                .span(span)
                .lazy(dynamic_relocations, (pe.clone(), span)),
        );
    }
    let (set, _) = decode_flags(GUARD_FLAGS, lc.guard_flags.into());
    let mut summary = format!("{} bytes", lc.size);
    if lc.cf_count > 0 || set.contains(&"CF_INSTRUMENTED") {
        summary.push_str(&format!(", CFG with {} targets", lc.cf_count));
    }
    if lc.se_count > 0 {
        summary.push_str(&format!(", {} SafeSEH handlers", lc.se_count));
    }
    cx.annotate(summary);
    Ok(())
}

/// A guard table: RVAs, each followed by `width - 4` metadata bytes.
async fn guard_table(cx: Cx, (pe, span, width): (Pe, Span, u64)) -> Result<()> {
    let count = span.len.checked_div(width).unwrap_or(0);
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let entry = span.sub(i.saturating_mul(width), width);
        let data = cx.read(entry).await?;
        let rva = u32_le(&data, 0).unwrap_or(0);
        let mut summary = pe.describe_rva(rva);
        if width > 4 {
            let meta = data.get(4).copied().unwrap_or(0);
            let (set, _) = decode_flags(GFID_FLAGS, meta.into());
            if !set.is_empty() {
                summary.push_str(&format!(", {}", set.join(" | ")));
            }
        }
        let mut node = Node::new(format!("#{i}"))
            .span(entry)
            .value(Value::UInt {
                value: rva.into(),
                bits: 32,
                radix: Radix::Hex,
            })
            .summary(summary);
        if let Ok(t) = pe.rva_span(rva, 0) {
            node = node.target(t);
        }
        cx.push(node).await;
    }
    Ok(())
}

/// The lock prefix table: NULL-terminated VAs.
async fn lock_prefixes(cx: &Cx, pe: &Pe, va: u64) -> Option<Node> {
    let mut count = 0u64;
    while count < 65536 {
        let slot = pe
            .va_span(va.saturating_add(count.saturating_mul(4)), 4)
            .ok()?;
        let raw = cx.read_avail(slot).await.ok()?;
        if u32_le(&raw, 0).unwrap_or(0) == 0 {
            break;
        }
        count = count.saturating_add(1);
    }
    let span = pe
        .va_span(va, count.saturating_add(1).saturating_mul(4))
        .ok()?;
    Some(
        Node::new("Lock Prefix Table")
            .span(span)
            .summary(format!("{count} entries"))
            .lazy(va_list, (pe.clone(), span)),
    )
}

fn volatile_metadata(f: &mut Fields<'_>, pe: &Pe) -> Result<()> {
    f.u32("Size").emit()?;
    f.u32("Version").emit()?;
    rva_field(f.u32("VolatileAccessTable"), pe).emit()?;
    f.u32("VolatileAccessTableSize").hex().emit()?;
    rva_field(f.u32("VolatileInfoRangeTable"), pe).emit()?;
    f.u32("VolatileInfoRangeTableSize").hex().emit()?;
    Ok(())
}

const CODE_RANGE: EnumTable = &[(0, "ARM64"), (1, "ARM64EC"), (2, "x64")];

/// `IMAGE_ARM64EC_METADATA` and its code map.
async fn arm64ec_metadata(cx: Cx, (pe, span): (Pe, Span)) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u32("Version").emit()?;
    let map = rva_field(f.u32("CodeMap"), &pe)
        .desc("RVA of the ranges of ARM64, ARM64EC and x64 code")
        .emit()?;
    let count = f.u32("CodeMapCount").emit()?;
    for name in [
        "CodeRangesToEntryPoints",
        "RedirectionMetadata",
        "__os_arm64x_dispatch_call_no_redirect",
        "__os_arm64x_dispatch_ret",
        "__os_arm64x_dispatch_call",
        "__os_arm64x_dispatch_icall",
        "__os_arm64x_dispatch_icall_cfg",
        "AlternateEntryPoint",
        "AuxiliaryIAT",
    ] {
        rva_field(f.u32(name), &pe).emit()?;
    }
    f.u32("CodeRangesToEntryPointsCount").emit()?;
    f.u32("RedirectionMetadataCount").emit()?;
    for name in [
        "GetX64InformationFunctionPointer",
        "SetX64InformationFunctionPointer",
        "ExtraRFETable",
    ] {
        rva_field(f.u32(name), &pe).emit()?;
    }
    f.u32("ExtraRFETableSize").hex().emit()?;
    for name in [
        "__os_arm64x_dispatch_fptr",
        "AuxiliaryIATCopy",
        "AuxDelayloadIAT",
        "AuxDelayloadIATCopy",
    ] {
        rva_field(f.u32(name), &pe).emit()?;
    }
    f.u32("ReservedBitField").hex().emit()?;
    if map != 0
        && count > 0
        && let Ok(table) = pe.table(map, count.min(65536), 8)
    {
        let data = cx.read(table).await?;
        let n = data.len() / 8;
        let mut entries = Vec::new();
        for i in 0..n.min(4096) {
            let at = i.saturating_mul(8);
            let start = u32_le(&data, at).unwrap_or(0);
            let len = u32_le(&data, at.saturating_add(4)).unwrap_or(0);
            entries.push((table.sub(to_u64(at), 8), start, len));
        }
        cx.emit(
            Node::new("Code Map")
                .span(table)
                .summary(format!("{n} ranges"))
                .lazy(code_map, entries),
        );
    }
    Ok(())
}

async fn code_map(cx: Cx, entries: Vec<(Span, u32, u32)>) -> Result<()> {
    for (span, start, len) in entries {
        let kind = start & 3;
        let rva = start & !3;
        cx.push(
            Node::new(format!("{rva:#x}"))
                .span(span)
                .value(Value::Enum {
                    raw: kind.into(),
                    bits: 2,
                    name: crate::value::lookup(CODE_RANGE, kind.into()),
                })
                .summary(format!("{len:#x} bytes")),
        )
        .await;
    }
    Ok(())
}

const DYNAMIC_SYMBOL: EnumTable = &[
    (1, "GUARD_RF_PROLOGUE"),
    (2, "GUARD_RF_EPILOGUE"),
    (3, "GUARD_IMPORT_CONTROL_TRANSFER"),
    (4, "GUARD_INDIR_CONTROL_TRANSFER"),
    (5, "GUARD_SWITCHTABLE_BRANCH"),
    (6, "ARM64X"),
    (7, "FUNCTION_OVERRIDE"),
    (8, "ARM64_KERNEL_IMPORT_CALL_TRANSFER"),
];

/// `IMAGE_DYNAMIC_RELOCATION_TABLE` (version 1): entries of a symbol, a size
/// and base-relocation-style blocks whose records depend on the symbol.
async fn dynamic_relocations(cx: Cx, (pe, span): (Pe, Span)) -> Result<()> {
    let head = cx.block(span.sub(0, 8)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    let version = f.u32("Version").emit()?;
    f.u32("Size").hex().emit()?;
    if version != 1 {
        cx.diag(Diagnostic::unsupported(format!(
            "dynamic relocation table version {version}"
        )));
        return Ok(());
    }
    let width = pe.word();
    let mut at = 8u64;
    while at.saturating_add(width).saturating_add(4) <= span.len {
        cx.checkpoint().await;
        let raw = cx.read(span.sub(at, width.saturating_add(4))).await?;
        let symbol = read_word(&pe, &raw, 0).unwrap_or(0);
        let size = u64::from(u32_le(&raw, crate::bytes::to_usize(width)).unwrap_or(0));
        let len = width.saturating_add(4).saturating_add(size);
        let entry = span.sub(at, len);
        let name = crate::formats::util::val::name_or(DYNAMIC_SYMBOL, symbol, "Symbol");
        cx.push(
            Node::new(name)
                .span(entry)
                .summary(format!("{size:#x} bytes of relocations"))
                .lazy(dynamic_entry, (pe.clone(), entry)),
        )
        .await;
        at = at.saturating_add(len);
    }
    Ok(())
}

async fn dynamic_entry(cx: Cx, (pe, span): (Pe, Span)) -> Result<()> {
    let width = pe.word();
    let block = cx.block(span.sub(0, width.saturating_add(4))).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.uword("Symbol", pe.wide)
        .enumeration(DYNAMIC_SYMBOL)
        .emit()?;
    f.u32("BaseRelocSize").hex().emit()?;
    let body = span.tail(width.saturating_add(4));
    let mut at = 0u64;
    while at.saturating_add(8) <= body.len {
        let head = cx.read(body.sub(at, 8)).await?;
        let page = u32_le(&head, 0).unwrap_or(0);
        let size = u64::from(u32_le(&head, 4).unwrap_or(0));
        if size < 8 {
            break;
        }
        let blk = body.sub(at, size);
        cx.push(
            Node::new(format!("Page {page:#x}"))
                .span(blk)
                .summary(format!("{} bytes of records", size.saturating_sub(8)))
                .lazy(dynamic_block, blk),
        )
        .await;
        at = at.saturating_add(size);
    }
    Ok(())
}

async fn dynamic_block(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span.sub(0, 8)).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u32("VirtualAddress").hex().desc("Page RVA").emit()?;
    f.u32("SizeOfBlock").hex().emit()?;
    if span.len > 8 {
        cx.emit(
            Node::new("Records")
                .span(span.tail(8))
                .desc("Fixup records in the format of the entry's symbol"),
        );
    }
    Ok(())
}
