//! Windows minidumps (`MDMP`), as written by `MiniDumpWriteDump`, crash
//! reporters and Breakpad/Crashpad (which add Linux streams).
//!
//! A header points at a directory of streams; each stream (threads,
//! modules, memory ranges, exception, system information, ...) is decoded
//! when expanded. Strings are `MINIDUMP_STRING`s referenced by RVA.

use crate::bytes::u32_le;
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::util::binutil::{ellipsize, name_or, text};
use crate::formats::{Format, Input, Probe, embedded};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, flag};

const LE: Endian = Endian::Little;

pub static FORMAT: Format = Format {
    name: "minidump",
    title: "Windows minidump",
    extensions: &["dmp", "mdmp"],
    mime: "application/x-dmp",
    probe: Probe::Custom(|h| h.starts_with(b"MDMP") && h.at(4, b"\x93\xa7")),
    dissect: crate::expander!(dissect: Input),
};

const STREAM_TYPE: EnumTable = &[
    (0, "UnusedStream"),
    (3, "ThreadListStream"),
    (4, "ModuleListStream"),
    (5, "MemoryListStream"),
    (6, "ExceptionStream"),
    (7, "SystemInfoStream"),
    (8, "ThreadExListStream"),
    (9, "Memory64ListStream"),
    (10, "CommentStreamA"),
    (11, "CommentStreamW"),
    (12, "HandleDataStream"),
    (13, "FunctionTableStream"),
    (14, "UnloadedModuleListStream"),
    (15, "MiscInfoStream"),
    (16, "MemoryInfoListStream"),
    (17, "ThreadInfoListStream"),
    (18, "HandleOperationListStream"),
    (19, "TokenStream"),
    (20, "JavaScriptDataStream"),
    (21, "SystemMemoryInfoStream"),
    (22, "ProcessVmCountersStream"),
    (23, "IptTraceStream"),
    (24, "ThreadNamesStream"),
    (0x4767_0001, "BreakpadInfoStream"),
    (0x4767_0002, "BreakpadAssertionInfoStream"),
    (0x4767_0003, "LinuxCpuInfo"),
    (0x4767_0004, "LinuxProcStatus"),
    (0x4767_0005, "LinuxLsbRelease"),
    (0x4767_0006, "LinuxCmdLine"),
    (0x4767_0007, "LinuxEnviron"),
    (0x4767_0008, "LinuxAuxv"),
    (0x4767_0009, "LinuxMaps"),
    (0x4767_000a, "LinuxDsoDebug"),
    (0x4350_0001, "CrashpadInfo"),
];

const DUMP_FLAGS: FlagTable = &[
    flag(0x1, "WithDataSegs"),
    flag(0x2, "WithFullMemory"),
    flag(0x4, "WithHandleData"),
    flag(0x8, "FilterMemory"),
    flag(0x10, "ScanMemory"),
    flag(0x20, "WithUnloadedModules"),
    flag(0x40, "WithIndirectlyReferencedMemory"),
    flag(0x80, "FilterModulePaths"),
    flag(0x100, "WithProcessThreadData"),
    flag(0x200, "WithPrivateReadWriteMemory"),
    flag(0x400, "WithoutOptionalData"),
    flag(0x800, "WithFullMemoryInfo"),
    flag(0x1000, "WithThreadInfo"),
    flag(0x2000, "WithCodeSegs"),
    flag(0x4000, "WithoutAuxiliaryState"),
    flag(0x8000, "WithFullAuxiliaryState"),
    flag(0x1_0000, "WithPrivateWriteCopyMemory"),
    flag(0x2_0000, "IgnoreInaccessibleMemory"),
    flag(0x4_0000, "WithTokenInformation"),
    flag(0x8_0000, "WithModuleHeaders"),
    flag(0x10_0000, "FilterTriage"),
    flag(0x20_0000, "WithAvxXStateContext"),
    flag(0x40_0000, "WithIptTrace"),
    flag(0x80_0000, "ScanInaccessiblePartialPages"),
];

const ARCHITECTURE: EnumTable = &[
    (0, "x86"),
    (1, "MIPS"),
    (2, "Alpha"),
    (3, "PowerPC"),
    (4, "SHx"),
    (5, "ARM"),
    (6, "IA-64"),
    (7, "Alpha64"),
    (8, "MSIL"),
    (9, "AMD64"),
    (10, "IA32 on Win64"),
    (12, "ARM64"),
    (0x8001, "SPARC (Breakpad)"),
    (0x8002, "PPC64 (Breakpad)"),
    (0x8003, "ARM64 (Breakpad)"),
    (0x8004, "MIPS64 (Breakpad)"),
    (0x8005, "RISC-V (Breakpad)"),
    (0x8006, "RISC-V 64 (Breakpad)"),
    (0xffff, "unknown"),
];

const PLATFORM: EnumTable = &[
    (0, "Win32s"),
    (1, "Windows 9x"),
    (2, "Windows NT"),
    (3, "Windows CE"),
    (0x8000, "Unix (Breakpad)"),
    (0x8101, "macOS (Breakpad)"),
    (0x8102, "iOS (Breakpad)"),
    (0x8201, "Linux (Breakpad)"),
    (0x8202, "Solaris (Breakpad)"),
    (0x8203, "Android (Breakpad)"),
    (0x8204, "PS3 (Breakpad)"),
    (0x8205, "Native Client (Breakpad)"),
    (0x8206, "Fuchsia (Breakpad)"),
];

const PRODUCT_TYPE: EnumTable = &[(1, "workstation"), (2, "domain controller"), (3, "server")];

const EXCEPTION_CODE: EnumTable = &[
    (0x8000_0001, "GUARD_PAGE_VIOLATION"),
    (0x8000_0002, "DATATYPE_MISALIGNMENT"),
    (0x8000_0003, "BREAKPOINT"),
    (0x8000_0004, "SINGLE_STEP"),
    (0xc000_0005, "ACCESS_VIOLATION"),
    (0xc000_0006, "IN_PAGE_ERROR"),
    (0xc000_0008, "INVALID_HANDLE"),
    (0xc000_001d, "ILLEGAL_INSTRUCTION"),
    (0xc000_0025, "NONCONTINUABLE_EXCEPTION"),
    (0xc000_008c, "ARRAY_BOUNDS_EXCEEDED"),
    (0xc000_008d, "FLOAT_DENORMAL_OPERAND"),
    (0xc000_008e, "FLOAT_DIVIDE_BY_ZERO"),
    (0xc000_0094, "INTEGER_DIVIDE_BY_ZERO"),
    (0xc000_0095, "INTEGER_OVERFLOW"),
    (0xc000_0096, "PRIVILEGED_INSTRUCTION"),
    (0xc000_00fd, "STACK_OVERFLOW"),
    (0xc000_0409, "STACK_BUFFER_OVERRUN"),
    (0xc000_0374, "HEAP_CORRUPTION"),
    (0xe06d_7363, "C++ exception"),
    (0x4000_0015, "FATAL_APP_EXIT"),
];

record! {
    struct Header {
        signature: ascii[4] "Signature",
        version: u16 "Version" .hex() .desc("MINIDUMP_VERSION (0xa793)"),
        implementation: u16 "ImplementationVersion" .hex(),
        streams: u32 "NumberOfStreams",
        directory: u32 "StreamDirectoryRva" .hex(),
        checksum: u32 "CheckSum" .hex(),
        time: u32 "TimeDateStamp" .timestamp(),
        flags: u64 "Flags" .flags(DUMP_FLAGS),
    }
}

record! {
    struct Directory {
        kind: u32 "StreamType" .enumeration(STREAM_TYPE),
        size: u32 "DataSize" .hex(),
        rva: u32 "Rva" .hex(),
    }
}

record! {
    struct SystemInfo {
        arch: u16 "ProcessorArchitecture" .enumeration(ARCHITECTURE),
        level: u16 "ProcessorLevel",
        revision: u16 "ProcessorRevision" .hex(),
        cpus: u8 "NumberOfProcessors",
        product: u8 "ProductType" .enumeration(PRODUCT_TYPE),
        major: u32 "MajorVersion",
        minor: u32 "MinorVersion",
        build: u32 "BuildNumber",
        platform: u32 "PlatformId" .enumeration(PLATFORM),
        csd: u32 "CSDVersionRva" .hex() .desc("Service pack string"),
        suite: u16 "SuiteMask" .hex(),
        reserved: u16 "Reserved2",
        cpu: bytes[24] "Cpu",
    }
}

record! {
    struct Thread {
        id: u32 "ThreadId",
        suspend: u32 "SuspendCount",
        class: u32 "PriorityClass",
        priority: u32 "Priority",
        teb: u64 "Teb" .hex(),
        stack_start: u64 "Stack.StartOfMemoryRange" .hex(),
        stack_size: u32 "Stack.DataSize" .hex(),
        stack_rva: u32 "Stack.Rva" .hex(),
        context_size: u32 "ThreadContext.DataSize" .hex(),
        context_rva: u32 "ThreadContext.Rva" .hex(),
    }
}

record! {
    struct Module {
        base: u64 "BaseOfImage" .hex(),
        size: u32 "SizeOfImage" .hex(),
        checksum: u32 "CheckSum" .hex(),
        time: u32 "TimeDateStamp" .timestamp(),
        name: u32 "ModuleNameRva" .hex(),
        version: bytes[52] "VersionInfo" .desc("VS_FIXEDFILEINFO"),
        cv_size: u32 "CvRecord.DataSize" .hex(),
        cv_rva: u32 "CvRecord.Rva" .hex(),
        misc_size: u32 "MiscRecord.DataSize" .hex(),
        misc_rva: u32 "MiscRecord.Rva" .hex(),
        reserved0: u64 "Reserved0",
        reserved1: u64 "Reserved1",
    }
}

record! {
    struct ExceptionStream {
        thread: u32 "ThreadId",
        align: u32 "__alignment",
        code: u32 "ExceptionCode" .enumeration(EXCEPTION_CODE),
        flags: u32 "ExceptionFlags" .hex(),
        record: u64 "ExceptionRecord" .hex(),
        address: u64 "ExceptionAddress" .hex(),
        parameters: u32 "NumberParameters",
        unused: u32 "__unusedAlignment",
        information: bytes[120] "ExceptionInformation",
        context_size: u32 "ThreadContext.DataSize" .hex(),
        context_rva: u32 "ThreadContext.Rva" .hex(),
    }
}

record! {
    struct MemoryDescriptor {
        start: u64 "StartOfMemoryRange" .hex(),
        size: u32 "DataSize" .hex(),
        rva: u32 "Rva" .hex(),
    }
}

record! {
    struct Memory64Descriptor {
        start: u64 "StartOfMemoryRange" .hex(),
        size: u64 "DataSize" .hex(),
    }
}

/// A `MINIDUMP_STRING`: byte length, then UTF-16.
async fn string(cx: &Cx, file: Span, rva: u32) -> Result<(String, Span)> {
    let len = cx.read(file.sub(rva.into(), 4)).await?;
    let len = u32_le(&len, 0).unwrap_or(0).min(0x10000);
    let span = file.sub(u64::from(rva).saturating_add(4), len.into());
    let data = cx.read(span).await?;
    Ok((
        crate::text::utf16(&data, LE),
        file.sub(rva.into(), u64::from(len).saturating_add(4)),
    ))
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let hspan = file.sub(0, Header::SIZE);
    cx.emit(Header::node("Header", hspan, LE));
    let h = parse(&cx, hspan, LE, &(), Header::layout).await?;
    let table = file.sub(
        h.directory.into(),
        u64::from(h.streams).saturating_mul(Directory::SIZE),
    );
    let count = table.len.checked_div(Directory::SIZE).unwrap_or(0);
    let mut streams = Vec::new();
    for i in 0..count {
        let at = table.sub(i.saturating_mul(Directory::SIZE), Directory::SIZE);
        streams.push((at, parse(&cx, at, LE, &(), Directory::layout).await?));
    }

    // Summary: architecture and OS, thread and module counts, exception.
    let mut parts = vec!["Windows minidump".to_owned()];
    for (_, d) in &streams {
        cx.checkpoint().await;
        let span = file.sub(d.rva.into(), d.size.into());
        match d.kind {
            7 => {
                if let Ok(s) = parse(
                    &cx,
                    span.sub(0, SystemInfo::SIZE),
                    LE,
                    &(),
                    SystemInfo::layout,
                )
                .await
                {
                    parts.push(format!(
                        "{}, {} {}.{}.{}",
                        name_or(ARCHITECTURE, s.arch.into(), "arch"),
                        name_or(PLATFORM, s.platform.into(), "platform"),
                        s.major,
                        s.minor,
                        s.build
                    ));
                }
            }
            3 | 4 => {
                if let Ok(n) = cx.read(span.sub(0, 4)).await {
                    let n = u32_le(&n, 0).unwrap_or(0);
                    parts.push(format!(
                        "{n} {}",
                        if d.kind == 3 { "threads" } else { "modules" }
                    ));
                }
            }
            6 => {
                if let Ok(e) = parse(&cx, span.sub(0, 32), LE, &(), exception_head).await {
                    parts.push(format!(
                        "exception {:#010x} ({}) at {:#x}",
                        e.0,
                        name_or(EXCEPTION_CODE, e.0.into(), "unknown"),
                        e.1
                    ));
                }
            }
            _ => {}
        }
    }
    cx.annotate(parts.join(", "));

    cx.emit(
        Node::new("Stream Directory")
            .span(table)
            .summary(format!("{count} streams")),
    );
    // The streams are a collection: pushed, so a large directory pages.
    for (entry, d) in streams {
        let span = file.sub(d.rva.into(), d.size.into());
        let name = crate::value::lookup(STREAM_TYPE, d.kind.into())
            .map_or_else(|| format!("Stream {:#x}", d.kind), str::to_owned);
        cx.push(
            Node::new(name)
                .span(span)
                .summary(format!("{:#x} bytes", d.size))
                .target(entry)
                .lazy(stream, (input, entry, d.kind, span)),
        )
        .await;
    }
    Ok(())
}

fn exception_head(f: &mut Fields<'_>, _: &()) -> Result<(u32, u64)> {
    f.u32("ThreadId").get()?;
    f.u32("align").get()?;
    let code = f.u32("ExceptionCode").get()?;
    f.u32("ExceptionFlags").get()?;
    f.u64("ExceptionRecord").get()?;
    let address = f.u64("ExceptionAddress").get()?;
    Ok((code, address))
}

async fn stream(cx: Cx, (input, entry, kind, span): (Input, Span, u32, Span)) -> Result<()> {
    let file = input.span;
    cx.emit(Directory::node("Directory Entry", entry, LE));
    match kind {
        3 => {
            for at in list(&cx, span, Thread::SIZE).await? {
                let t = parse(&cx, at, LE, &(), Thread::layout).await?;
                cx.push(
                    Thread::node(format!("Thread {}", t.id), at, LE).summary(format!(
                        "stack {:#x}+{:#x}, priority {}",
                        t.stack_start, t.stack_size, t.priority
                    )),
                )
                .await;
            }
            Ok(())
        }
        4 => {
            for at in list(&cx, span, Module::SIZE).await? {
                let m = parse(&cx, at, LE, &(), Module::layout).await?;
                let name = string(&cx, file, m.name)
                    .await
                    .map_or_else(|_| "?".to_owned(), |(s, _)| s);
                let short = name.rsplit(['\\', '/']).next().unwrap_or(&name).to_owned();
                let mut node = Module::node(short, at, LE)
                    .value(text(name))
                    .summary(format!("{:#x}+{:#x}", m.base, m.size));
                if m.cv_size > 0 {
                    node = node.target(file.sub(m.cv_rva.into(), m.cv_size.into()));
                }
                cx.push(node).await;
            }
            Ok(())
        }
        5 => {
            for at in list(&cx, span, MemoryDescriptor::SIZE).await? {
                let m = parse(&cx, at, LE, &(), MemoryDescriptor::layout).await?;
                cx.push(
                    MemoryDescriptor::node(format!("{:#x}", m.start), at, LE)
                        .summary(format!("{:#x} bytes", m.size))
                        .target(file.sub(m.rva.into(), m.size.into())),
                )
                .await;
            }
            Ok(())
        }
        9 => {
            let head = cx.block(span.sub(0, 16)).await?;
            let mut f = Fields::emitting(&cx, &head, LE);
            f.u64("NumberOfMemoryRanges").emit()?;
            let mut rva = f.u64("BaseRva").hex().emit()?;
            let table = span.tail(16);
            let count = table.len.checked_div(Memory64Descriptor::SIZE).unwrap_or(0);
            for i in 0..count {
                let at = table.sub(
                    i.saturating_mul(Memory64Descriptor::SIZE),
                    Memory64Descriptor::SIZE,
                );
                let m = parse(&cx, at, LE, &(), Memory64Descriptor::layout).await?;
                cx.push(
                    Memory64Descriptor::node(format!("{:#x}", m.start), at, LE)
                        .summary(format!("{:#x} bytes at file {rva:#x}", m.size))
                        .target(file.sub(rva, m.size)),
                )
                .await;
                rva = rva.saturating_add(m.size);
            }
            Ok(())
        }
        6 => {
            cx.emit(ExceptionStream::node(
                "Exception",
                span.sub(0, ExceptionStream::SIZE),
                LE,
            ));
            Ok(())
        }
        7 => {
            cx.emit(SystemInfo::node(
                "System Info",
                span.sub(0, SystemInfo::SIZE),
                LE,
            ));
            let s = parse(
                &cx,
                span.sub(0, SystemInfo::SIZE),
                LE,
                &(),
                SystemInfo::layout,
            )
            .await?;
            if s.csd != 0
                && let Ok((t, at)) = string(&cx, file, s.csd).await
            {
                cx.emit(Node::new("CSDVersion").span(at).value(text(t)));
            }
            Ok(())
        }
        10 => {
            let data = cx.read_avail(span.sub(0, 0x10000)).await?;
            cx.emit(
                Node::new("Comment")
                    .span(span)
                    .value(text(crate::text::until_nul(&data))),
            );
            Ok(())
        }
        11 => {
            let data = cx.read_avail(span.sub(0, 0x20000)).await?;
            cx.emit(
                Node::new("Comment")
                    .span(span)
                    .value(text(crate::text::utf16z(&data, LE).0)),
            );
            Ok(())
        }
        15 => {
            cx.emit(struct_node("Misc Info", span, LE, (), misc_info));
            Ok(())
        }
        0x4767_0003..=0x4767_0007 | 0x4767_0009 => {
            let data = cx.read_avail(span.sub(0, 0x10_0000)).await?;
            let t = String::from_utf8_lossy(&data).replace('\0', " ");
            cx.emit(
                Node::new("Text")
                    .span(span)
                    .value(text(ellipsize(t.trim_end(), 0x4000))),
            );
            Ok(())
        }
        _ => {
            cx.emit(embedded("Data", input.nested(span)).summary(format!("{:#x} bytes", span.len)));
            Ok(())
        }
    }
}

/// Emits the 32-bit count of a list stream and returns the entries' spans
/// (bounded by the stream size).
async fn list(cx: &Cx, span: Span, size: u64) -> Result<impl Iterator<Item = Span>> {
    let head = cx.block(span.sub(0, 4)).await?;
    let n = Fields::emitting(cx, &head, LE).u32("Count").emit()?;
    let table = span.tail(4);
    let count = u64::from(n).min(table.len.checked_div(size).unwrap_or(0));
    if count < n.into() {
        cx.diag(Diagnostic::truncated(table, table.len));
    }
    Ok((0..count).map(move |i| table.sub(i.saturating_mul(size), size)))
}

fn misc_info(f: &mut Fields<'_>, _: &()) -> Result<()> {
    let size = f.u32("SizeOfInfo").emit()?;
    f.u32("Flags1").hex().emit()?;
    f.u32("ProcessId").emit()?;
    f.u32("ProcessCreateTime").timestamp().emit()?;
    f.u32("ProcessUserTime").emit()?;
    f.u32("ProcessKernelTime").emit()?;
    if size >= 44 {
        f.u32("ProcessorMaxMhz").emit()?;
        f.u32("ProcessorCurrentMhz").emit()?;
        f.u32("ProcessorMhzLimit").emit()?;
        f.u32("ProcessorMaxIdleState").emit()?;
        f.u32("ProcessorCurrentIdleState").emit()?;
    }
    Ok(())
}
