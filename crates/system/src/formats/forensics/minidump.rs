//! Windows minidumps (`MDMP`), as written by `MiniDumpWriteDump`, crash
//! reporters and Breakpad/Crashpad (which add Linux streams).
//!
//! A header points at a directory of streams; each stream (threads with
//! their stacks and register contexts, modules with version information and
//! CodeView records, memory ranges, exception, system and process
//! information, handles, function tables, unloaded modules, memory regions,
//! thread times, tokens, ...) is decoded when expanded, and every reference
//! (an RVA and a size) points at the data it describes. Strings are
//! `MINIDUMP_STRING`s referenced by RVA. Structures are packed to 4 bytes.

use crate::bytes::{to_u64, u32_le, u64_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::executable::pe::version::FixedFileInfo;
use crate::formats::util::binutil::{ellipsize, name_or, text};
use crate::formats::util::datakit::hex;
use crate::formats::{Format, Input, Probe, embedded};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

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

const SUITE_MASK: FlagTable = &[
    flag(0x0001, "SMALLBUSINESS"),
    flag(0x0002, "ENTERPRISE"),
    flag(0x0004, "BACKOFFICE"),
    flag(0x0008, "COMMUNICATIONS"),
    flag(0x0010, "TERMINAL"),
    flag(0x0020, "SMALLBUSINESS_RESTRICTED"),
    flag(0x0040, "EMBEDDEDNT"),
    flag(0x0080, "DATACENTER"),
    flag(0x0100, "SINGLEUSERTS"),
    flag(0x0200, "PERSONAL"),
    flag(0x0400, "BLADE"),
    flag(0x2000, "STORAGE_SERVER"),
    flag(0x4000, "COMPUTE_SERVER"),
    flag(0x8000, "WH_SERVER"),
];

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

const EXCEPTION_FLAGS: FlagTable = &[flag(0x1, "NONCONTINUABLE")];

const MISC_FLAGS: FlagTable = &[
    flag(0x001, "PROCESS_ID"),
    flag(0x002, "PROCESS_TIMES"),
    flag(0x004, "PROCESSOR_POWER_INFO"),
    flag(0x010, "PROCESS_INTEGRITY"),
    flag(0x020, "PROCESS_EXECUTE_FLAGS"),
    flag(0x040, "TIMEZONE"),
    flag(0x080, "PROTECTED_PROCESS"),
    flag(0x100, "BUILDSTRING"),
    flag(0x200, "PROCESS_COOKIE"),
];

const INTEGRITY: EnumTable = &[
    (0x0000, "untrusted"),
    (0x1000, "low"),
    (0x2000, "medium"),
    (0x2100, "medium plus"),
    (0x3000, "high"),
    (0x4000, "system"),
    (0x5000, "protected process"),
];

const TIME_ZONE_ID: EnumTable = &[(0, "unknown"), (1, "standard"), (2, "daylight")];

const MEM_STATE: EnumTable = &[
    (0x1000, "MEM_COMMIT"),
    (0x2000, "MEM_RESERVE"),
    (0x1_0000, "MEM_FREE"),
];

const MEM_TYPE: EnumTable = &[
    (0, "none"),
    (0x2_0000, "MEM_PRIVATE"),
    (0x4_0000, "MEM_MAPPED"),
    (0x100_0000, "MEM_IMAGE"),
];

const PAGE_PROTECT: FlagTable = &[
    flag(0x01, "PAGE_NOACCESS"),
    flag(0x02, "PAGE_READONLY"),
    flag(0x04, "PAGE_READWRITE"),
    flag(0x08, "PAGE_WRITECOPY"),
    flag(0x10, "PAGE_EXECUTE"),
    flag(0x20, "PAGE_EXECUTE_READ"),
    flag(0x40, "PAGE_EXECUTE_READWRITE"),
    flag(0x80, "PAGE_EXECUTE_WRITECOPY"),
    flag(0x100, "PAGE_GUARD"),
    flag(0x200, "PAGE_NOCACHE"),
    flag(0x400, "PAGE_WRITECOMBINE"),
    flag(0x4000_0000, "PAGE_TARGETS_INVALID"),
];

const THREAD_INFO_FLAGS: FlagTable = &[
    flag(0x01, "ERROR_THREAD"),
    flag(0x02, "WRITING_THREAD"),
    flag(0x04, "EXITED_THREAD"),
    flag(0x08, "INVALID_INFO"),
    flag(0x10, "INVALID_CONTEXT"),
    flag(0x20, "INVALID_TEB"),
];

const VM_COUNTER_FLAGS: FlagTable = &[
    flag(0x01, "VM_COUNTERS"),
    flag(0x02, "VIRTUALSIZE"),
    flag(0x04, "EX"),
    flag(0x08, "EX2"),
    flag(0x10, "JOB"),
];

const SYSMEM_FLAGS: FlagTable = &[
    flag(0x01, "TRANSITION_REPURPOSE_COUNT_VALID"),
    flag(0x02, "BASIC_PERF_INFO"),
    flag(0x04, "PERF_CC_TOTAL_DIRTY_PAGES_THRESHOLD"),
    flag(0x08, "PERF_RESIDENT_AVAILABLE_PAGES"),
    flag(0x10, "PERF_SHARED_COMMITTED_PAGES"),
    flag(0x20, "PERF_EXTENDED"),
];

/// Context flags shared by every architecture.
macro_rules! context_flags {
    ($($arch:expr),* $(,)?) => {
        &[
            $($arch,)*
            flag(0x0800_0000, "EXCEPTION_ACTIVE"),
            flag(0x1000_0000, "SERVICE_ACTIVE"),
            flag(0x2000_0000, "UNWOUND_TO_CALL"),
            flag(0x4000_0000, "EXCEPTION_REQUEST"),
            flag(0x8000_0000, "EXCEPTION_REPORTING"),
        ]
    };
}

const CONTEXT_FLAGS_ARM64: FlagTable = context_flags![
    flag(0x0040_0000, "CONTEXT_ARM64"),
    flag(0x01, "CONTROL"),
    flag(0x02, "INTEGER"),
    flag(0x04, "FLOATING_POINT"),
    flag(0x08, "DEBUG"),
    flag(0x10, "X18"),
];

const CONTEXT_FLAGS_AMD64: FlagTable = context_flags![
    flag(0x0010_0000, "CONTEXT_AMD64"),
    flag(0x01, "CONTROL"),
    flag(0x02, "INTEGER"),
    flag(0x04, "SEGMENTS"),
    flag(0x08, "FLOATING_POINT"),
    flag(0x10, "DEBUG_REGISTERS"),
    flag(0x40, "XSTATE"),
    flag(0x80, "KERNEL_CET"),
];

const CONTEXT_FLAGS_X86: FlagTable = context_flags![
    flag(0x0001_0000, "CONTEXT_i386"),
    flag(0x01, "CONTROL"),
    flag(0x02, "INTEGER"),
    flag(0x04, "SEGMENTS"),
    flag(0x08, "FLOATING_POINT"),
    flag(0x10, "DEBUG_REGISTERS"),
    flag(0x20, "EXTENDED_REGISTERS"),
    flag(0x40, "XSTATE"),
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
        suite: u16 "SuiteMask" .flags(SUITE_MASK),
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
        flags: u32 "ExceptionFlags" .flags(EXCEPTION_FLAGS),
        record: u64 "ExceptionRecord" .hex() .desc("Address of a chained EXCEPTION_RECORD"),
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

/// A field of a table-driven structure.
#[derive(Clone, Copy)]
enum F {
    U16(&'static str),
    U32(&'static str),
    I32(&'static str),
    U64(&'static str),
    X16(&'static str),
    X32(&'static str),
    X64(&'static str),
    Time32(&'static str),
    Filetime(&'static str),
    /// 100-nanosecond ticks.
    Ticks(&'static str),
    Enum32(&'static str, EnumTable),
    Flags16(&'static str, FlagTable),
    Flags32(&'static str, FlagTable),
    Utf16(&'static str, u64),
    SystemTime(&'static str),
    Bytes(&'static str, u64),
}

impl F {
    fn size(self) -> u64 {
        match self {
            F::U16(_) | F::X16(_) | F::Flags16(..) => 2,
            F::U32(_) | F::I32(_) | F::X32(_) | F::Time32(_) | F::Enum32(..) | F::Flags32(..) => 4,
            F::U64(_) | F::X64(_) | F::Filetime(_) | F::Ticks(_) => 8,
            F::Utf16(_, n) => n.saturating_mul(2),
            F::SystemTime(_) => 16,
            F::Bytes(_, n) => n,
        }
    }
}

/// Emits `table`'s fields while they fit in the block.
fn layout_table(f: &mut Fields<'_>, table: &&'static [F]) -> Result<()> {
    for field in table.iter() {
        if f.remaining() < field.size() {
            break;
        }
        emit_field(f, *field)?;
    }
    Ok(())
}

fn emit_field(f: &mut Fields<'_>, field: F) -> Result<()> {
    match field {
        F::U16(n) => {
            f.u16(n).emit()?;
        }
        F::U32(n) => {
            f.u32(n).emit()?;
        }
        F::I32(n) => {
            f.i32(n).emit()?;
        }
        F::U64(n) => {
            f.u64(n).emit()?;
        }
        F::X16(n) => {
            f.u16(n).hex().emit()?;
        }
        F::X32(n) => {
            f.u32(n).hex().emit()?;
        }
        F::X64(n) => {
            f.u64(n).hex().emit()?;
        }
        F::Time32(n) => {
            f.u32(n).timestamp().emit()?;
        }
        F::Filetime(n) => {
            f.u64(n)
                .with(|&v, node| {
                    if v == 0 {
                        node.summary("not set")
                    } else {
                        node.value(Value::Timestamp {
                            unix_seconds: crate::text::filetime_to_unix(v),
                        })
                    }
                })
                .emit()?;
        }
        F::Ticks(n) => {
            f.u64(n)
                .with(|&v, node| {
                    node.summary(format!("{}.{:07} s", v / 10_000_000, v % 10_000_000))
                })
                .emit()?;
        }
        F::Enum32(n, t) => {
            f.u32(n).enumeration(t).emit()?;
        }
        F::Flags16(n, t) => {
            f.u16(n).flags(t).emit()?;
        }
        F::Flags32(n, t) => {
            f.u32(n).flags(t).emit()?;
        }
        F::Utf16(n, chars) => {
            f.utf16(n, chars).emit()?;
        }
        F::SystemTime(n) => {
            let at = f.peek_span(16);
            let b = f.bytes(n, 16).get()?;
            let w = |i: usize| crate::bytes::u16_le(&b, i.saturating_mul(2)).unwrap_or(0);
            let shown = if b.iter().all(|&x| x == 0) {
                "not set".to_owned()
            } else {
                format!(
                    "year {}, month {}, day-of-week {}, day {}, {:02}:{:02}:{:02}.{:03}",
                    w(0),
                    w(1),
                    w(2),
                    w(3),
                    w(4),
                    w(5),
                    w(6),
                    w(7)
                )
            };
            f.node(Node::new(n).span(at).value(Value::Text(shown)));
        }
        F::Bytes(n, len) => {
            f.bytes(n, len).emit()?;
        }
    }
    Ok(())
}

const MISC_INFO: &[F] = &[
    F::U32("SizeOfInfo"),
    F::Flags32("Flags1", MISC_FLAGS),
    F::U32("ProcessId"),
    F::Time32("ProcessCreateTime"),
    F::U32("ProcessUserTime"),
    F::U32("ProcessKernelTime"),
    // MINIDUMP_MISC_INFO_2
    F::U32("ProcessorMaxMhz"),
    F::U32("ProcessorCurrentMhz"),
    F::U32("ProcessorMhzLimit"),
    F::U32("ProcessorMaxIdleState"),
    F::U32("ProcessorCurrentIdleState"),
    // _3
    F::Enum32("ProcessIntegrityLevel", INTEGRITY),
    F::X32("ProcessExecuteFlags"),
    F::U32("ProtectedProcess"),
    F::Enum32("TimeZoneId", TIME_ZONE_ID),
    F::I32("TimeZone.Bias"),
    F::Utf16("TimeZone.StandardName", 32),
    F::SystemTime("TimeZone.StandardDate"),
    F::I32("TimeZone.StandardBias"),
    F::Utf16("TimeZone.DaylightName", 32),
    F::SystemTime("TimeZone.DaylightDate"),
    F::I32("TimeZone.DaylightBias"),
    // _4
    F::Utf16("BuildString", 260),
    F::Utf16("DbgBldStr", 40),
    // _5
    F::U32("XStateData.SizeOfInfo"),
    F::U32("XStateData.ContextSize"),
    F::X64("XStateData.EnabledFeatures"),
    F::Bytes("XStateData.Features", 512),
    F::X32("ProcessCookie"),
];

const THREAD_INFO: &[F] = &[
    F::U32("ThreadId"),
    F::Flags32("DumpFlags", THREAD_INFO_FLAGS),
    F::X32("DumpError"),
    F::X32("ExitStatus"),
    F::Filetime("CreateTime"),
    F::Filetime("ExitTime"),
    F::Ticks("KernelTime"),
    F::Ticks("UserTime"),
    F::X64("StartAddress"),
    F::X64("Affinity"),
];

const MEMORY_INFO: &[F] = &[
    F::X64("BaseAddress"),
    F::X64("AllocationBase"),
    F::Flags32("AllocationProtect", PAGE_PROTECT),
    F::U32("__alignment1"),
    F::X64("RegionSize"),
    F::Enum32("State", MEM_STATE),
    F::Flags32("Protect", PAGE_PROTECT),
    F::Enum32("Type", MEM_TYPE),
    F::U32("__alignment2"),
];

const UNLOADED_MODULE: &[F] = &[
    F::X64("BaseOfImage"),
    F::X32("SizeOfImage"),
    F::X32("CheckSum"),
    F::Time32("TimeDateStamp"),
    F::X32("ModuleNameRva"),
];

const HANDLE: &[F] = &[
    F::X64("Handle"),
    F::X32("TypeNameRva"),
    F::X32("ObjectNameRva"),
    F::X32("Attributes"),
    F::X32("GrantedAccess"),
    F::U32("HandleCount"),
    F::U32("PointerCount"),
    // MINIDUMP_HANDLE_DESCRIPTOR_2
    F::X32("ObjectInfoRva"),
    F::U32("Reserved0"),
];

const VM_COUNTERS: &[F] = &[
    F::U16("Revision"),
    F::Flags16("Flags", VM_COUNTER_FLAGS),
    F::U32("PageFaultCount"),
    F::X64("PeakWorkingSetSize"),
    F::X64("WorkingSetSize"),
    F::X64("QuotaPeakPagedPoolUsage"),
    F::X64("QuotaPagedPoolUsage"),
    F::X64("QuotaPeakNonPagedPoolUsage"),
    F::X64("QuotaNonPagedPoolUsage"),
    F::X64("PagefileUsage"),
    F::X64("PeakPagefileUsage"),
    F::X64("PrivateUsage"),
];

const VM_COUNTERS_2: &[F] = &[
    F::U16("Revision"),
    F::Flags16("Flags", VM_COUNTER_FLAGS),
    F::U32("PageFaultCount"),
    F::X64("PeakWorkingSetSize"),
    F::X64("WorkingSetSize"),
    F::X64("QuotaPeakPagedPoolUsage"),
    F::X64("QuotaPagedPoolUsage"),
    F::X64("QuotaPeakNonPagedPoolUsage"),
    F::X64("QuotaNonPagedPoolUsage"),
    F::X64("PagefileUsage"),
    F::X64("PeakPagefileUsage"),
    F::X64("PeakVirtualSize"),
    F::X64("VirtualSize"),
    F::X64("PrivateUsage"),
    F::X64("PrivateWorkingSetSize"),
    F::X64("SharedCommitUsage"),
    F::X64("JobSharedCommitUsage"),
    F::X64("JobPrivateCommitUsage"),
    F::X64("JobPeakPrivateCommitUsage"),
    F::X64("JobPrivateCommitLimit"),
    F::X64("JobTotalCommitLimit"),
];

const SYSTEM_MEMORY: &[F] = &[
    F::U16("Revision"),
    F::Flags16("Flags", SYSMEM_FLAGS),
    F::U32("BasicInfo.TimerResolution"),
    F::X32("BasicInfo.PageSize"),
    F::U32("BasicInfo.NumberOfPhysicalPages"),
    F::X32("BasicInfo.LowestPhysicalPageNumber"),
    F::X32("BasicInfo.HighestPhysicalPageNumber"),
    F::X32("BasicInfo.AllocationGranularity"),
    F::X64("BasicInfo.MinimumUserModeAddress"),
    F::X64("BasicInfo.MaximumUserModeAddress"),
    F::X64("BasicInfo.ActiveProcessorsAffinityMask"),
    F::U32("BasicInfo.NumberOfProcessors"),
    F::X64("FileCacheInfo.CurrentSize"),
    F::X64("FileCacheInfo.PeakSize"),
    F::U32("FileCacheInfo.PageFaultCount"),
    F::X64("FileCacheInfo.MinimumWorkingSet"),
    F::X64("FileCacheInfo.MaximumWorkingSet"),
    F::U64("FileCacheInfo.CurrentSizeIncludingTransitionInPages"),
    F::U64("FileCacheInfo.PeakSizeIncludingTransitionInPages"),
    F::U32("FileCacheInfo.TransitionRePurposeCount"),
    F::X32("FileCacheInfo.Flags"),
    F::U64("BasicPerfInfo.AvailablePages"),
    F::U64("BasicPerfInfo.CommittedPages"),
    F::U64("BasicPerfInfo.CommitLimit"),
    F::U64("BasicPerfInfo.PeakCommitment"),
    F::Ticks("PerfInfo.IdleProcessTime"),
    F::U64("PerfInfo.IoReadTransferCount"),
    F::U64("PerfInfo.IoWriteTransferCount"),
    F::U64("PerfInfo.IoOtherTransferCount"),
    F::U32("PerfInfo.IoReadOperationCount"),
    F::U32("PerfInfo.IoWriteOperationCount"),
    F::U32("PerfInfo.IoOtherOperationCount"),
    F::U32("PerfInfo.AvailablePages"),
    F::U32("PerfInfo.CommittedPages"),
    F::U32("PerfInfo.CommitLimit"),
    F::U32("PerfInfo.PeakCommitment"),
    F::U32("PerfInfo.PageFaultCount"),
    F::U32("PerfInfo.CopyOnWriteCount"),
    F::U32("PerfInfo.TransitionCount"),
    F::U32("PerfInfo.CacheTransitionCount"),
    F::U32("PerfInfo.DemandZeroCount"),
    F::U32("PerfInfo.PageReadCount"),
    F::U32("PerfInfo.PageReadIoCount"),
    F::U32("PerfInfo.CacheReadCount"),
    F::U32("PerfInfo.CacheIoCount"),
    F::U32("PerfInfo.DirtyPagesWriteCount"),
    F::U32("PerfInfo.DirtyWriteIoCount"),
    F::U32("PerfInfo.MappedPagesWriteCount"),
    F::U32("PerfInfo.MappedWriteIoCount"),
    F::U32("PerfInfo.PagedPoolPages"),
    F::U32("PerfInfo.NonPagedPoolPages"),
    F::U32("PerfInfo.PagedPoolAllocs"),
    F::U32("PerfInfo.PagedPoolFrees"),
    F::U32("PerfInfo.NonPagedPoolAllocs"),
    F::U32("PerfInfo.NonPagedPoolFrees"),
    F::U32("PerfInfo.FreeSystemPtes"),
    F::U32("PerfInfo.ResidentSystemCodePage"),
    F::U32("PerfInfo.TotalSystemDriverPages"),
    F::U32("PerfInfo.TotalSystemCodePages"),
    F::U32("PerfInfo.NonPagedPoolLookasideHits"),
    F::U32("PerfInfo.PagedPoolLookasideHits"),
    F::U32("PerfInfo.AvailablePagedPoolPages"),
    F::U32("PerfInfo.ResidentSystemCachePage"),
    F::U32("PerfInfo.ResidentPagedPoolPage"),
    F::U32("PerfInfo.ResidentSystemDriverPage"),
    F::U32("PerfInfo.CcFastReadNoWait"),
    F::U32("PerfInfo.CcFastReadWait"),
    F::U32("PerfInfo.CcFastReadResourceMiss"),
    F::U32("PerfInfo.CcFastReadNotPossible"),
    F::U32("PerfInfo.CcFastMdlReadNoWait"),
    F::U32("PerfInfo.CcFastMdlReadWait"),
    F::U32("PerfInfo.CcFastMdlReadResourceMiss"),
    F::U32("PerfInfo.CcFastMdlReadNotPossible"),
    F::U32("PerfInfo.CcMapDataNoWait"),
    F::U32("PerfInfo.CcMapDataWait"),
    F::U32("PerfInfo.CcMapDataNoWaitMiss"),
    F::U32("PerfInfo.CcMapDataWaitMiss"),
    F::U32("PerfInfo.CcPinMappedDataCount"),
    F::U32("PerfInfo.CcPinReadNoWait"),
    F::U32("PerfInfo.CcPinReadWait"),
    F::U32("PerfInfo.CcPinReadNoWaitMiss"),
    F::U32("PerfInfo.CcPinReadWaitMiss"),
    F::U32("PerfInfo.CcCopyReadNoWait"),
    F::U32("PerfInfo.CcCopyReadWait"),
    F::U32("PerfInfo.CcCopyReadNoWaitMiss"),
    F::U32("PerfInfo.CcCopyReadWaitMiss"),
    F::U32("PerfInfo.CcMdlReadNoWait"),
    F::U32("PerfInfo.CcMdlReadWait"),
    F::U32("PerfInfo.CcMdlReadNoWaitMiss"),
    F::U32("PerfInfo.CcMdlReadWaitMiss"),
    F::U32("PerfInfo.CcReadAheadIos"),
    F::U32("PerfInfo.CcLazyWriteIos"),
    F::U32("PerfInfo.CcLazyWritePages"),
    F::U32("PerfInfo.CcDataFlushes"),
    F::U32("PerfInfo.CcDataPages"),
    F::U32("PerfInfo.ContextSwitches"),
    F::U32("PerfInfo.FirstLevelTbFills"),
    F::U32("PerfInfo.SecondLevelTbFills"),
    F::U32("PerfInfo.SystemCalls"),
    F::U64("PerfInfo.CcTotalDirtyPages"),
    F::U64("PerfInfo.CcDirtyPageThreshold"),
    F::U64("PerfInfo.ResidentAvailablePages"),
    F::U64("PerfInfo.SharedCommittedPages"),
    F::U64("PerfInfo.MdlPagesAllocated"),
    F::U64("PerfInfo.PfnDatabaseCommittedPages"),
    F::U64("PerfInfo.SystemPageTableCommittedPages"),
    F::U64("PerfInfo.ContiguousPagesAllocated"),
];

const CONTEXT_ARM64: &[F] = &[
    F::Flags32("ContextFlags", CONTEXT_FLAGS_ARM64),
    F::X32("Cpsr"),
    F::X64("X0"),
    F::X64("X1"),
    F::X64("X2"),
    F::X64("X3"),
    F::X64("X4"),
    F::X64("X5"),
    F::X64("X6"),
    F::X64("X7"),
    F::X64("X8"),
    F::X64("X9"),
    F::X64("X10"),
    F::X64("X11"),
    F::X64("X12"),
    F::X64("X13"),
    F::X64("X14"),
    F::X64("X15"),
    F::X64("X16"),
    F::X64("X17"),
    F::X64("X18"),
    F::X64("X19"),
    F::X64("X20"),
    F::X64("X21"),
    F::X64("X22"),
    F::X64("X23"),
    F::X64("X24"),
    F::X64("X25"),
    F::X64("X26"),
    F::X64("X27"),
    F::X64("X28"),
    F::X64("Fp"),
    F::X64("Lr"),
    F::X64("Sp"),
    F::X64("Pc"),
    F::Bytes("V0–V31", 512),
    F::X32("Fpcr"),
    F::X32("Fpsr"),
    F::Bytes("Bcr[8]", 32),
    F::Bytes("Bvr[8]", 64),
    F::Bytes("Wcr[2]", 8),
    F::Bytes("Wvr[2]", 16),
];

const CONTEXT_AMD64: &[F] = &[
    F::X64("P1Home"),
    F::X64("P2Home"),
    F::X64("P3Home"),
    F::X64("P4Home"),
    F::X64("P5Home"),
    F::X64("P6Home"),
    F::Flags32("ContextFlags", CONTEXT_FLAGS_AMD64),
    F::X32("MxCsr"),
    F::X16("SegCs"),
    F::X16("SegDs"),
    F::X16("SegEs"),
    F::X16("SegFs"),
    F::X16("SegGs"),
    F::X16("SegSs"),
    F::X32("EFlags"),
    F::X64("Dr0"),
    F::X64("Dr1"),
    F::X64("Dr2"),
    F::X64("Dr3"),
    F::X64("Dr6"),
    F::X64("Dr7"),
    F::X64("Rax"),
    F::X64("Rcx"),
    F::X64("Rdx"),
    F::X64("Rbx"),
    F::X64("Rsp"),
    F::X64("Rbp"),
    F::X64("Rsi"),
    F::X64("Rdi"),
    F::X64("R8"),
    F::X64("R9"),
    F::X64("R10"),
    F::X64("R11"),
    F::X64("R12"),
    F::X64("R13"),
    F::X64("R14"),
    F::X64("R15"),
    F::X64("Rip"),
    F::Bytes("FltSave (XMM_SAVE_AREA32)", 512),
    F::Bytes("VectorRegister[26]", 416),
    F::X64("VectorControl"),
    F::X64("DebugControl"),
    F::X64("LastBranchToRip"),
    F::X64("LastBranchFromRip"),
    F::X64("LastExceptionToRip"),
    F::X64("LastExceptionFromRip"),
];

const CONTEXT_X86: &[F] = &[
    F::Flags32("ContextFlags", CONTEXT_FLAGS_X86),
    F::X32("Dr0"),
    F::X32("Dr1"),
    F::X32("Dr2"),
    F::X32("Dr3"),
    F::X32("Dr6"),
    F::X32("Dr7"),
    F::Bytes("FloatSave", 112),
    F::X32("SegGs"),
    F::X32("SegFs"),
    F::X32("SegEs"),
    F::X32("SegDs"),
    F::X32("Edi"),
    F::X32("Esi"),
    F::X32("Ebx"),
    F::X32("Edx"),
    F::X32("Ecx"),
    F::X32("Eax"),
    F::X32("Ebp"),
    F::X32("Eip"),
    F::X32("SegCs"),
    F::X32("EFlags"),
    F::X32("Esp"),
    F::X32("SegSs"),
    F::Bytes("ExtendedRegisters", 512),
];

/// The register layout of a thread context, by its size.
fn context_layout(size: u64) -> Option<(&'static [F], &'static str, usize, usize)> {
    // (fields, architecture, offset of PC, offset of SP)
    match size {
        0x390 => Some((CONTEXT_ARM64, "ARM64", 0x108, 0x100)),
        0x4d0 => Some((CONTEXT_AMD64, "AMD64", 0xf8, 0x98)),
        0x2cc => Some((CONTEXT_X86, "x86", 0xb8, 0xc4)),
        _ => None,
    }
}

/// A node for a thread context at `span`.
async fn context_node(cx: &Cx, span: Span) -> Node {
    let Some((layout, arch, pc, sp)) = context_layout(span.len) else {
        return Node::new("Context")
            .span(span)
            .summary(format!("{} bytes (unknown layout)", span.len));
    };
    let mut node = struct_node("Context", span, LE, layout, layout_table);
    if let Ok(b) = cx.read(span).await {
        let reg = |o: usize| -> u64 {
            if arch == "x86" {
                u32_le(&b, o).map_or(0, u64::from)
            } else {
                u64_le(&b, o).unwrap_or(0)
            }
        };
        node = node.summary(format!("{arch}, PC {:#x}, SP {:#x}", reg(pc), reg(sp)));
    }
    node
}

/// A `MINIDUMP_STRING`: byte length, then UTF-16.
async fn string(cx: &Cx, file: Span, rva: u32) -> Result<(String, Span)> {
    let len = cx.read(file.sub(rva.into(), 4)).await?;
    let len = u32_le(&len, 0).unwrap_or(0).min(0x10000);
    let span = file.sub(u64::from(rva).saturating_add(4), len.into());
    let data = cx.read(span).await?;
    Ok((
        crate::text::utf16(&data, LE),
        file.sub(rva.into(), u64::from(len).saturating_add(6)),
    ))
}

/// A leaf for the string at `rva` (none for RVA 0).
async fn string_node(cx: &Cx, file: Span, name: &'static str, rva: u32) -> Option<Node> {
    if rva == 0 {
        return None;
    }
    Some(match string(cx, file, rva).await {
        Ok((s, span)) => Node::new(name)
            .span(span)
            .value(text(s))
            .desc("MINIDUMP_STRING: byte length, UTF-16 text, terminator"),
        Err(e) => Node::new(name).diag(e),
    })
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
            15 => {
                if let Ok(b) = cx.read(span.sub(0, 12)).await
                    && u32_le(&b, 4).unwrap_or(0) & 1 != 0
                {
                    parts.push(format!("process {}", u32_le(&b, 8).unwrap_or(0)));
                }
            }
            _ => {}
        }
    }
    cx.annotate(parts.join(", "));

    let used = streams.iter().filter(|(_, d)| d.kind != 0).count();
    cx.emit(
        Node::new("Stream Directory")
            .span(table)
            .summary(format!("{count} entries, {used} streams")),
    );
    // The streams are a collection: pushed, so a large directory pages.
    for (entry, d) in streams {
        let span = file.sub(d.rva.into(), d.size.into());
        let name = crate::value::lookup(STREAM_TYPE, d.kind.into())
            .map_or_else(|| format!("Stream {:#x}", d.kind), str::to_owned);
        let mut node = Node::new(name)
            .span(span)
            .summary(format!("{:#x} bytes", d.size))
            .target(entry)
            .lazy(stream, (input, entry, d.kind, span));
        if d.kind == 0 {
            node.target = None;
            node = node.span(entry).summary("unused directory entry");
        }
        cx.push(node).await;
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

/// Emits a list header of the "size of header, size of entry, count" kind
/// and returns the entries' spans.
async fn sized_list(cx: &Cx, span: Span, count64: bool) -> Result<(u64, Vec<Span>)> {
    let head_len = if count64 { 16 } else { 12 };
    let block = cx.block(span.sub(0, head_len)).await?;
    let mut f = Fields::emitting(cx, &block, LE);
    let header = f.u32("SizeOfHeader").emit()?;
    let entry = f.u32("SizeOfEntry").emit()?;
    let count = if count64 {
        f.u64("NumberOfEntries").emit()?
    } else {
        u64::from(f.u32("NumberOfEntries").emit()?)
    };
    if u64::from(header) > head_len {
        cx.emit(
            Node::new("Header extension")
                .span(span.sub(head_len, u64::from(header).saturating_sub(head_len))),
        );
    }
    let entries = span.tail(header.into());
    let fit = entries.len.checked_div(entry.into()).unwrap_or(0);
    if fit < count {
        cx.diag(Diagnostic::truncated(
            entries.sub(0, count.saturating_mul(entry.into())),
            entries.len,
        ));
    }
    let n = count.min(fit);
    Ok((
        n,
        (0..n)
            .map(|i| entries.sub(i.saturating_mul(entry.into()), entry.into()))
            .collect(),
    ))
}

async fn stream(cx: Cx, (input, entry, kind, span): (Input, Span, u32, Span)) -> Result<()> {
    let file = input.span;
    cx.emit(Directory::node("Directory Entry", entry, LE));
    match kind {
        0 => Ok(()),
        3 | 8 => {
            let size = if kind == 3 {
                Thread::SIZE
            } else {
                Thread::SIZE.saturating_add(16)
            };
            for at in list(&cx, span, size).await? {
                let t = parse(&cx, at, LE, &(), Thread::layout).await?;
                cx.push(
                    Node::new(format!("Thread {}", t.id))
                        .span(at)
                        .summary(format!(
                            "stack {:#x}+{:#x}, priority {}",
                            t.stack_start, t.stack_size, t.priority
                        ))
                        .lazy(thread_fields, (file, at, kind == 8)),
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
                let mut summary = format!("{:#x}+{:#x}", m.base, m.size);
                if let Ok(v) = parse(
                    &cx,
                    at.sub(24, FixedFileInfo::SIZE),
                    LE,
                    &(),
                    FixedFileInfo::layout,
                )
                .await
                    && v.signature == 0xfeef_04bd
                {
                    summary.push_str(&format!(", version {}", v.file_version()));
                }
                cx.push(
                    Node::new(short)
                        .span(at)
                        .value(text(name))
                        .summary(summary)
                        .lazy(module_fields, (file, at)),
                )
                .await;
            }
            Ok(())
        }
        5 => {
            for at in list(&cx, span, MemoryDescriptor::SIZE).await? {
                let m = parse(&cx, at, LE, &(), MemoryDescriptor::layout).await?;
                let data = file.sub(m.rva.into(), m.size.into());
                cx.push(
                    struct_node(format!("{:#x}", m.start), at, LE, data, memory_fields)
                        .summary(format!("{:#x} bytes", m.size))
                        .target(data),
                )
                .await;
            }
            Ok(())
        }
        9 => {
            let head = cx.block(span.sub(0, 16)).await?;
            let mut f = Fields::emitting(&cx, &head, LE);
            let n = f.u64("NumberOfMemoryRanges").emit()?;
            let mut rva = f.u64("BaseRva").hex().emit()?;
            let table = span.tail(16);
            let count = table
                .len
                .checked_div(Memory64Descriptor::SIZE)
                .unwrap_or(0)
                .min(n);
            for i in 0..count {
                let at = table.sub(
                    i.saturating_mul(Memory64Descriptor::SIZE),
                    Memory64Descriptor::SIZE,
                );
                let m = parse(&cx, at, LE, &(), Memory64Descriptor::layout).await?;
                let data = file.sub(rva, m.size);
                cx.push(
                    struct_node(format!("{:#x}", m.start), at, LE, data, memory64_fields)
                        .summary(format!("{:#x} bytes at file {rva:#x}", m.size))
                        .target(data),
                )
                .await;
                rva = rva.saturating_add(m.size);
            }
            Ok(())
        }
        6 => {
            let at = span.sub(0, ExceptionStream::SIZE);
            cx.emit(ExceptionStream::node("Exception", at, LE));
            let e = parse(&cx, at, LE, &(), ExceptionStream::layout).await?;
            let params = cx.read_avail(at.sub(40, 120)).await?;
            for i in 0..usize::try_from(e.parameters.min(15)).unwrap_or(0) {
                let v = u64_le(&params, i.saturating_mul(8)).unwrap_or(0);
                cx.emit(
                    Node::new(format!("ExceptionInformation[{i}]"))
                        .span(at.sub(40u64.saturating_add(to_u64(i).saturating_mul(8)), 8))
                        .value(hex(v, 64))
                        .summary(exception_parameter(e.code, i, v)),
                );
            }
            if e.context_size > 0 {
                cx.emit(
                    context_node(&cx, file.sub(e.context_rva.into(), e.context_size.into())).await,
                );
            }
            Ok(())
        }
        7 => {
            let at = span.sub(0, SystemInfo::SIZE);
            let s = parse(&cx, at, LE, &(), SystemInfo::layout).await?;
            cx.emit(struct_node(
                "System Info",
                at,
                LE,
                s.arch,
                system_info_fields,
            ));
            if let Some(n) = string_node(&cx, file, "CSDVersion", s.csd).await {
                cx.emit(n);
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
        12 => {
            let block = cx.block(span.sub(0, 16)).await?;
            let mut f = Fields::emitting(&cx, &block, LE);
            let header = f.u32("SizeOfHeader").emit()?;
            let size = f.u32("SizeOfDescriptor").emit()?;
            let n = f.u32("NumberOfDescriptors").emit()?;
            f.u32("Reserved").emit()?;
            let entries = span.tail(header.into());
            let count = u64::from(n).min(entries.len.checked_div(size.into()).unwrap_or(0));
            for i in 0..count {
                let at = entries.sub(i.saturating_mul(size.into()), size.into());
                let b = cx.read_avail(at).await?;
                let handle = u64_le(&b, 0).unwrap_or(0);
                let type_name = match u32_le(&b, 8) {
                    Some(r) if r != 0 => string(&cx, file, r)
                        .await
                        .map(|(s, _)| s)
                        .unwrap_or_default(),
                    _ => String::new(),
                };
                let object = match u32_le(&b, 12) {
                    Some(r) if r != 0 => string(&cx, file, r)
                        .await
                        .map(|(s, _)| s)
                        .unwrap_or_default(),
                    _ => String::new(),
                };
                let summary = [type_name, object]
                    .into_iter()
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
                    .join(" ");
                cx.push(
                    struct_node(format!("Handle {handle:#x}"), at, LE, HANDLE, layout_table)
                        .summary(summary),
                )
                .await;
            }
            Ok(())
        }
        13 => function_tables(&cx, span).await,
        14 => {
            let (_, entries) = sized_list(&cx, span, false).await?;
            for at in entries {
                let b = cx.read_avail(at).await?;
                let name = match u32_le(&b, 20) {
                    Some(r) if r != 0 => string(&cx, file, r)
                        .await
                        .map(|(s, _)| s)
                        .unwrap_or_default(),
                    _ => String::new(),
                };
                let short = name.rsplit(['\\', '/']).next().unwrap_or(&name).to_owned();
                cx.push(
                    struct_node(short, at, LE, UNLOADED_MODULE, layout_table)
                        .value(text(name))
                        .summary(format!(
                            "{:#x}+{:#x}",
                            u64_le(&b, 0).unwrap_or(0),
                            u32_le(&b, 8).unwrap_or(0)
                        )),
                )
                .await;
            }
            Ok(())
        }
        15 => {
            let size = u32_le(&cx.read_avail(span.sub(0, 4)).await?, 0).unwrap_or(0);
            let version = match size {
                24 => "MINIDUMP_MISC_INFO",
                44 => "MINIDUMP_MISC_INFO_2",
                232 => "MINIDUMP_MISC_INFO_3",
                832 => "MINIDUMP_MISC_INFO_4",
                1364 => "MINIDUMP_MISC_INFO_5",
                _ => "unknown version",
            };
            let info = span.sub(0, size.into());
            cx.emit(struct_node("Misc Info", info, LE, MISC_INFO, layout_table).summary(version));
            Ok(())
        }
        16 => {
            let (_, entries) = sized_list(&cx, span, true).await?;
            for at in entries {
                let b = cx.read_avail(at).await?;
                let base = u64_le(&b, 0).unwrap_or(0);
                let size = u64_le(&b, 24).unwrap_or(0);
                let state = u32_le(&b, 32).unwrap_or(0);
                let protect = u32_le(&b, 36).unwrap_or(0);
                let kind = u32_le(&b, 40).unwrap_or(0);
                let mut parts = vec![
                    format!("{size:#x} bytes"),
                    lookup(MEM_STATE, state.into()).unwrap_or("?").to_owned(),
                ];
                if state != 0x1_0000 {
                    let (set, _) = crate::value::decode_flags(PAGE_PROTECT, protect.into());
                    if !set.is_empty() {
                        parts.push(set.join(" | "));
                    }
                    if kind != 0 {
                        parts.push(lookup(MEM_TYPE, kind.into()).unwrap_or("?").to_owned());
                    }
                }
                cx.push(
                    struct_node(format!("{base:#x}"), at, LE, MEMORY_INFO, layout_table)
                        .summary(parts.join(", ")),
                )
                .await;
            }
            Ok(())
        }
        17 => {
            let (_, entries) = sized_list(&cx, span, false).await?;
            for at in entries {
                let b = cx.read_avail(at.sub(0, 8)).await?;
                let (set, _) = crate::value::decode_flags(
                    THREAD_INFO_FLAGS,
                    u32_le(&b, 4).unwrap_or(0).into(),
                );
                let mut node = struct_node(
                    format!("Thread {}", u32_le(&b, 0).unwrap_or(0)),
                    at,
                    LE,
                    THREAD_INFO,
                    layout_table,
                );
                if !set.is_empty() {
                    node = node.summary(set.join(" | "));
                }
                cx.push(node).await;
            }
            Ok(())
        }
        18 => {
            let block = cx.block(span.sub(0, 16)).await?;
            let mut f = Fields::emitting(&cx, &block, LE);
            let header = f.u32("SizeOfHeader").emit()?;
            let size = f.u32("SizeOfEntry").emit()?;
            let n = f.u32("NumberOfEntries").emit()?;
            f.u32("Reserved").emit()?;
            let entries = span.tail(header.into());
            let count = u64::from(n).min(entries.len.checked_div(size.into()).unwrap_or(0));
            for i in 0..count {
                let at = entries.sub(i.saturating_mul(size.into()), size.into());
                let b = cx.read_avail(at.sub(0, 24)).await?;
                cx.push(
                    struct_node(
                        format!("Operation {i}"),
                        at,
                        LE,
                        HANDLE_OPERATION,
                        layout_table,
                    )
                    .summary(format!(
                        "handle {:#x}, process {}, thread {}, {}",
                        u64_le(&b, 0).unwrap_or(0),
                        u32_le(&b, 8).unwrap_or(0),
                        u32_le(&b, 12).unwrap_or(0),
                        lookup(HANDLE_OPERATIONS, u32_le(&b, 16).unwrap_or(0).into())
                            .unwrap_or("?")
                    )),
                )
                .await;
            }
            Ok(())
        }
        19 => tokens(&cx, span).await,
        21 => {
            cx.emit(struct_node(
                "System Memory Info",
                span,
                LE,
                SYSTEM_MEMORY,
                layout_table,
            ));
            Ok(())
        }
        22 => {
            let layout = if span.len >= 152 {
                VM_COUNTERS_2
            } else {
                VM_COUNTERS
            };
            cx.emit(struct_node(
                "Process VM Counters",
                span,
                LE,
                layout,
                layout_table,
            ));
            Ok(())
        }
        24 => {
            let head = cx.block(span.sub(0, 4)).await?;
            let n = Fields::emitting(&cx, &head, LE)
                .u32("NumberOfThreadNames")
                .emit()?;
            let entries = span.tail(4);
            let count = u64::from(n).min(entries.len / 12);
            for i in 0..count {
                let at = entries.sub(i.saturating_mul(12), 12);
                let b = cx.read_avail(at).await?;
                let id = u32_le(&b, 0).unwrap_or(0);
                let rva = u64_le(&b, 4).unwrap_or(0);
                let name = match u32::try_from(rva) {
                    Ok(r) if r != 0 => string(&cx, file, r)
                        .await
                        .map(|(s, _)| s)
                        .unwrap_or_default(),
                    _ => String::new(),
                };
                cx.push(
                    struct_node(format!("Thread {id}"), at, LE, THREAD_NAME, layout_table)
                        .value(text(name)),
                )
                .await;
            }
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

const HANDLE_OPERATIONS: EnumTable = &[
    (0, "OperationDbUnused"),
    (1, "OperationDbOPEN"),
    (2, "OperationDbCLOSE"),
    (3, "OperationDbBADREF"),
];

const HANDLE_OPERATION: &[F] = &[
    F::X64("Handle"),
    F::U32("ProcessId"),
    F::U32("ThreadId"),
    F::Enum32("OperationType", HANDLE_OPERATIONS),
    F::U32("Spare0"),
    F::U32("BackTraceInformation.Index"),
    F::U32("BackTraceInformation.Depth"),
    F::Bytes("BackTraceInformation.ReturnAddresses", 256),
];

const THREAD_NAME: &[F] = &[F::U32("ThreadId"), F::X64("RvaOfThreadName")];

/// What an exception parameter means, for the common codes.
fn exception_parameter(code: u32, i: usize, v: u64) -> String {
    match (code, i) {
        (0xc000_0005 | 0xc000_0006, 0) => match v {
            0 => "read".into(),
            1 => "write".into(),
            8 => "execute (DEP)".into(),
            _ => String::new(),
        },
        (0xc000_0005 | 0xc000_0006, 1) => "faulting address".into(),
        (0xc000_0006, 2) => "NTSTATUS of the failed I/O".into(),
        (0xe06d_7363, 0) => "magic (0x19930520)".into(),
        (0xe06d_7363, 1) => "thrown object".into(),
        (0xe06d_7363, 2) => "ThrowInfo".into(),
        (0xe06d_7363, 3) => "image base".into(),
        _ => String::new(),
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

async fn thread_fields(cx: Cx, (file, at, ex): (Span, Span, bool)) -> Result<()> {
    let block = cx.block(at).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    let t = Thread::read(&mut f)?;
    let stack = file.sub(t.stack_rva.into(), t.stack_size.into());
    cx.emit(
        Node::new("Stack")
            .span(stack)
            .summary(format!("{:#x}+{:#x}", t.stack_start, t.stack_size))
            .desc("The captured stack memory"),
    );
    if ex {
        f.u64("BackingStore.StartOfMemoryRange").hex().emit()?;
        f.u32("BackingStore.DataSize").hex().emit()?;
        f.u32("BackingStore.Rva").hex().emit()?;
    }
    if t.context_size > 0 {
        cx.emit(context_node(&cx, file.sub(t.context_rva.into(), t.context_size.into())).await);
    }
    Ok(())
}

async fn module_fields(cx: Cx, (file, at): (Span, Span)) -> Result<()> {
    let block = cx.block(at).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u64("BaseOfImage").hex().emit()?;
    f.u32("SizeOfImage").hex().emit()?;
    f.u32("CheckSum").hex().emit()?;
    f.u32("TimeDateStamp").timestamp().emit()?;
    let name = f.u32("ModuleNameRva").hex().emit()?;
    let version = f.peek_span(FixedFileInfo::SIZE);
    let fixed = parse(&cx, version, LE, &(), FixedFileInfo::layout).await;
    match fixed {
        Ok(v) if v.signature == 0xfeef_04bd => {
            f.node(
                FixedFileInfo::node("VersionInfo", version, LE).summary(format!(
                    "file {}, product {}",
                    v.file_version(),
                    v.product_version()
                )),
            );
        }
        _ => f.node(
            Node::new("VersionInfo")
                .span(version)
                .value(Value::Bytes(Vec::new()))
                .summary("not present"),
        ),
    }
    f.skip(FixedFileInfo::SIZE);
    let cv_size = f.u32("CvRecord.DataSize").hex().emit()?;
    let cv_rva = f.u32("CvRecord.Rva").hex().emit()?;
    let misc_size = f.u32("MiscRecord.DataSize").hex().emit()?;
    let misc_rva = f.u32("MiscRecord.Rva").hex().emit()?;
    f.u64("Reserved0").emit()?;
    f.u64("Reserved1").emit()?;
    if let Some(n) = string_node(&cx, file, "ModuleName", name).await {
        cx.emit(n);
    }
    if cv_size > 0 {
        let cv = file.sub(cv_rva.into(), cv_size.into());
        let head = cx.read_avail(cv.sub(0, 4)).await?;
        cx.emit(
            Node::new("CvRecord")
                .span(cv)
                .summary(String::from_utf8_lossy(&head).into_owned())
                .lazy(codeview, cv),
        );
    }
    if misc_size > 0 {
        let misc = file.sub(misc_rva.into(), misc_size.into());
        cx.emit(struct_node("MiscRecord", misc, LE, (), misc_record));
    }
    Ok(())
}

/// A CodeView record: `RSDS` (GUID, age, PDB path) or `NB10`.
async fn codeview(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    let signature = f.ascii("Signature", 4).emit()?;
    match signature.as_str() {
        "RSDS" => {
            f.guid("Guid").emit()?;
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

/// `IMAGE_DEBUG_MISC`.
fn misc_record(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("DataType")
        .desc("1 = IMAGE_DEBUG_MISC_EXENAME")
        .emit()?;
    let len = f.u32("Length").emit()?;
    let unicode = f.u8("Unicode").emit()?;
    f.bytes("Reserved", 3).emit()?;
    let left = u64::from(len).saturating_sub(12).min(f.remaining());
    if unicode != 0 {
        f.utf16("Data", left / 2).emit()?;
    } else {
        f.ascii("Data", left).emit()?;
    }
    Ok(())
}

fn memory_fields(f: &mut Fields<'_>, data: &Span) -> Result<()> {
    f.u64("StartOfMemoryRange").hex().emit()?;
    f.u32("DataSize").hex().emit()?;
    f.u32("Rva").hex().emit()?;
    f.node(Node::new("Memory").span(*data).desc("The captured bytes"));
    Ok(())
}

fn memory64_fields(f: &mut Fields<'_>, data: &Span) -> Result<()> {
    f.u64("StartOfMemoryRange").hex().emit()?;
    f.u64("DataSize").hex().emit()?;
    f.node(Node::new("Memory").span(*data).desc("The captured bytes"));
    Ok(())
}

fn system_info_fields(f: &mut Fields<'_>, arch: &u16) -> Result<()> {
    f.u16("ProcessorArchitecture")
        .enumeration(ARCHITECTURE)
        .emit()?;
    f.u16("ProcessorLevel").emit()?;
    f.u16("ProcessorRevision").hex().emit()?;
    f.u8("NumberOfProcessors").emit()?;
    f.u8("ProductType").enumeration(PRODUCT_TYPE).emit()?;
    f.u32("MajorVersion").emit()?;
    f.u32("MinorVersion").emit()?;
    f.u32("BuildNumber").emit()?;
    f.u32("PlatformId").enumeration(PLATFORM).emit()?;
    f.u32("CSDVersionRva").hex().emit()?;
    f.u16("SuiteMask").flags(SUITE_MASK).emit()?;
    f.u16("Reserved2").emit()?;
    // dbghelp and Breakpad write the CPUID vendor and features for x86 and
    // x64 alike.
    if matches!(*arch, 0 | 9 | 10) {
        f.ascii("Cpu.X86CpuInfo.VendorId", 12).emit()?;
        f.u32("Cpu.X86CpuInfo.VersionInformation").hex().emit()?;
        f.u32("Cpu.X86CpuInfo.FeatureInformation").hex().emit()?;
        f.u32("Cpu.X86CpuInfo.AMDExtendedCpuFeatures")
            .hex()
            .emit()?;
    } else {
        f.u64("Cpu.OtherCpuInfo.ProcessorFeatures[0]")
            .hex()
            .emit()?;
        f.u64("Cpu.OtherCpuInfo.ProcessorFeatures[1]")
            .hex()
            .emit()?;
        f.bytes("Unused", 8).emit()?;
    }
    Ok(())
}

/// The function table stream: per table, a descriptor, the native
/// descriptor and the function entries.
async fn function_tables(cx: &Cx, span: Span) -> Result<()> {
    let block = cx.block(span.sub(0, 24)).await?;
    let mut f = Fields::emitting(cx, &block, LE);
    let header = f.u32("SizeOfHeader").emit()?;
    let desc = f.u32("SizeOfDescriptor").emit()?;
    let native = f.u32("SizeOfNativeDescriptor").emit()?;
    let entry = f.u32("SizeOfFunctionEntry").emit()?;
    let n = f.u32("NumberOfDescriptors").emit()?;
    f.u32("SizeOfAlignPad").emit()?;
    let mut pos = u64::from(header);
    for i in 0..n {
        cx.checkpoint().await;
        let d = cx.read_avail(span.sub(pos, desc.into())).await?;
        if to_u64(d.len()) < u64::from(desc) || desc < 32 {
            break;
        }
        let count = u32_le(&d, 24).unwrap_or(0);
        let pad = u32_le(&d, 28).unwrap_or(0);
        let total = u64::from(desc)
            .saturating_add(native.into())
            .saturating_add(u64::from(count).saturating_mul(entry.into()))
            .saturating_add(pad.into());
        let at = span.sub(pos, total);
        cx.push(
            Node::new(format!("Table {i}"))
                .span(at)
                .summary(format!(
                    "{:#x}–{:#x}, {count} functions",
                    u64_le(&d, 0).unwrap_or(0),
                    u64_le(&d, 8).unwrap_or(0)
                ))
                .lazy(function_table, (at, desc, native, entry, count)),
        )
        .await;
        pos = pos.saturating_add(total);
    }
    Ok(())
}

async fn function_table(
    cx: Cx,
    (span, desc, native, entry, count): (Span, u32, u32, u32, u32),
) -> Result<()> {
    let block = cx.block(span.sub(0, desc.into())).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u64("MinimumAddress").hex().emit()?;
    f.u64("MaximumAddress").hex().emit()?;
    f.u64("BaseAddress").hex().emit()?;
    f.u32("EntryCount").emit()?;
    let pad = f.u32("SizeOfAlignPad").emit()?;
    let mut pos = u64::from(desc);
    cx.emit(
        Node::new("Native descriptor")
            .span(span.sub(pos, native.into()))
            .desc("The OS's own function table descriptor (DYNAMIC_FUNCTION_TABLE)"),
    );
    pos = pos.saturating_add(native.into());
    let entries = span.sub(pos, u64::from(count).saturating_mul(entry.into()));
    cx.emit(
        Node::new("Function entries")
            .span(entries)
            .value(crate::formats::util::datakit::uint(count, 32))
            .summary(format!("{entry} bytes each (RUNTIME_FUNCTION)")),
    );
    pos = pos.saturating_add(entries.len);
    if pad > 0 {
        cx.emit(Node::new("Alignment padding").span(span.sub(pos, pad.into())));
    }
    Ok(())
}

/// The token stream: a list header, then tokens with their own headers.
async fn tokens(cx: &Cx, span: Span) -> Result<()> {
    let block = cx.block(span.sub(0, 16)).await?;
    let mut f = Fields::emitting(cx, &block, LE);
    f.u32("TokenListSize").emit()?;
    let n = f.u32("TokenListEntries").emit()?;
    let header = f.u32("ListHeaderSize").emit()?;
    let element = f.u32("ElementHeaderSize").emit()?;
    let mut pos = u64::from(header);
    for i in 0..n {
        cx.checkpoint().await;
        let h = cx.read_avail(span.sub(pos, 16)).await?;
        let Some(size) = u32_le(&h, 0) else { break };
        if size < element || pos.saturating_add(size.into()) > span.len {
            cx.diag(Diagnostic::malformed(format!("token {i} has size {size}")));
            break;
        }
        let at = span.sub(pos, size.into());
        cx.push(
            Node::new(format!("Token {i}"))
                .span(at)
                .summary(format!(
                    "id {}, handle {:#x}, {} bytes",
                    u32_le(&h, 4).unwrap_or(0),
                    u64_le(&h, 8).unwrap_or(0),
                    size
                ))
                .lazy(token, (at, element)),
        )
        .await;
        pos = pos.saturating_add(size.into());
    }
    Ok(())
}

async fn token(cx: Cx, (span, element): (Span, u32)) -> Result<()> {
    let block = cx.block(span.sub(0, element.into())).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u32("TokenSize").emit()?;
    f.u32("TokenId").emit()?;
    f.u64("TokenHandle").hex().emit()?;
    if span.len > u64::from(element) {
        cx.emit(
            Node::new("Token data")
                .span(span.tail(element.into()))
                .desc("The token's information as captured by dbghelp"),
        );
    }
    Ok(())
}
