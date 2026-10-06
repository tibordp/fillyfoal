//! Windows crash and program artifacts: user-mode minidumps (`MDMP`),
//! Windows Error Reporting reports (`.wer`) and Program Information Files
//! (`.pif`).

use crate::bytes::{to_u64, u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::datakit::{clip, hex, size, text};
use crate::formats::{Head, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

const LE: Endian = Endian::Little;

// ---------------------------------------------------------------------------
// Minidumps

declare_format!(pub MINIDUMP = "minidump", "Windows minidump", ["dmp", "mdmp", "hdmp"], "application/x-dmp",
    Probe::Custom(minidump_probe), minidump);

fn minidump_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"MDMP") && u16_le(h.data, 4) == Some(0xa793)
}

record! {
    pub struct MinidumpHeader {
        signature: ascii[4] "Signature",
        version: u32 "Version" .hex(),
        streams: u32 "Number of streams",
        directory: u32 "Stream directory RVA" .hex(),
        checksum: u32 "Checksum" .hex(),
        time: u32 "Time" .timestamp(),
        flags: u64 "Flags" .flags(MINIDUMP_FLAGS),
    }
}

const MINIDUMP_FLAGS: FlagTable = &[
    flag(0x0000_0001, "WithDataSegs"),
    flag(0x0000_0002, "WithFullMemory"),
    flag(0x0000_0004, "WithHandleData"),
    flag(0x0000_0008, "FilterMemory"),
    flag(0x0000_0010, "ScanMemory"),
    flag(0x0000_0020, "WithUnloadedModules"),
    flag(0x0000_0040, "WithIndirectlyReferencedMemory"),
    flag(0x0000_0080, "FilterModulePaths"),
    flag(0x0000_0100, "WithProcessThreadData"),
    flag(0x0000_0200, "WithPrivateReadWriteMemory"),
    flag(0x0000_0400, "WithoutOptionalData"),
    flag(0x0000_0800, "WithFullMemoryInfo"),
    flag(0x0000_1000, "WithThreadInfo"),
    flag(0x0000_2000, "WithCodeSegs"),
    flag(0x0000_4000, "WithoutAuxiliaryState"),
    flag(0x0000_8000, "WithFullAuxiliaryState"),
    flag(0x0001_0000, "WithPrivateWriteCopyMemory"),
    flag(0x0002_0000, "IgnoreInaccessibleMemory"),
    flag(0x0004_0000, "WithTokenInformation"),
    flag(0x0008_0000, "WithModuleHeaders"),
    flag(0x0010_0000, "FilterTriage"),
    flag(0x0020_0000, "WithAvxXStateContext"),
    flag(0x0040_0000, "WithIptTrace"),
];

const STREAM_TYPES: EnumTable = &[
    (0, "Unused"),
    (3, "ThreadList"),
    (4, "ModuleList"),
    (5, "MemoryList"),
    (6, "Exception"),
    (7, "SystemInfo"),
    (8, "ThreadExList"),
    (9, "Memory64List"),
    (10, "CommentA"),
    (11, "CommentW"),
    (12, "HandleData"),
    (13, "FunctionTable"),
    (14, "UnloadedModuleList"),
    (15, "MiscInfo"),
    (16, "MemoryInfoList"),
    (17, "ThreadInfoList"),
    (18, "HandleOperationList"),
    (19, "Token"),
    (20, "JavaScriptData"),
    (21, "SystemMemoryInfo"),
    (22, "ProcessVmCounters"),
    (23, "IptTrace"),
    (24, "ThreadNames"),
    (0x4767_0001, "BreakpadInfo"),
    (0x4767_0002, "AssertionInfo"),
    (0x4767_0003, "LinuxCpuInfo"),
    (0x4767_0004, "LinuxProcStatus"),
    (0x4767_0005, "LinuxLsbRelease"),
    (0x4767_0006, "LinuxCmdLine"),
    (0x4767_0007, "LinuxEnviron"),
    (0x4767_0008, "LinuxAuxv"),
    (0x4767_0009, "LinuxMaps"),
    (0x4767_000a, "LinuxDsoDebug"),
];

const ARCHITECTURES: EnumTable = &[(0, "x86"), (5, "ARM"), (6, "IA-64"), (9, "AMD64"), (12, "ARM64"), (0xffff, "unknown")];
const PRODUCT_TYPES: EnumTable = &[(1, "workstation"), (2, "domain controller"), (3, "server")];
const PLATFORMS: EnumTable = &[(0, "Win32s"), (1, "Windows 9x"), (2, "Windows NT"), (0x8101, "Linux"), (0x8102, "Solaris"), (0x8103, "Android"), (0x8201, "macOS"), (0x8202, "iOS")];

const EXCEPTION_CODES: EnumTable = &[
    (0x8000_0003, "EXCEPTION_BREAKPOINT"),
    (0x8000_0004, "EXCEPTION_SINGLE_STEP"),
    (0xc000_0005, "EXCEPTION_ACCESS_VIOLATION"),
    (0xc000_001d, "EXCEPTION_ILLEGAL_INSTRUCTION"),
    (0xc000_008c, "EXCEPTION_ARRAY_BOUNDS_EXCEEDED"),
    (0xc000_0094, "EXCEPTION_INT_DIVIDE_BY_ZERO"),
    (0xc000_0096, "EXCEPTION_PRIV_INSTRUCTION"),
    (0xc000_00fd, "EXCEPTION_STACK_OVERFLOW"),
    (0xc000_0374, "STATUS_HEAP_CORRUPTION"),
    (0xc000_0409, "STATUS_STACK_BUFFER_OVERRUN"),
    (0xe06d_7363, "C++ exception"),
];

/// A MINIDUMP_STRING (byte length, then UTF-16LE) at `rva`.
async fn md_string(cx: &Cx, file: Span, rva: u32) -> Result<(String, Span)> {
    if rva == 0 {
        return Ok((String::new(), file.sub(0, 0)));
    }
    let head = cx.read(file.sub(rva.into(), 4)).await?;
    let len = u64::from(u32_le(&head, 0).unwrap_or(0)).min(0x10000);
    let span = file.sub(rva.into(), len.saturating_add(4));
    let raw = cx.read_avail(file.sub(u64::from(rva).saturating_add(4), len)).await?;
    Ok((crate::text::utf16(&raw, LE), span))
}

/// The base name of a Windows path.
fn base_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

async fn minidump(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, MinidumpHeader::SIZE);
    let h: MinidumpHeader = read_record(&cx, span, LE).await?;
    cx.emit(MinidumpHeader::node("Header", span, LE));
    let dir = file.sub_exact(h.directory.into(), u64::from(h.streams).saturating_mul(12))?;
    let entries = cx.read(dir).await?;
    let mut process = String::new();
    let mut system = String::new();
    let mut exception = String::new();
    for (i, e) in entries.as_chunks::<12>().0.iter().enumerate() {
        let kind = u32_le(e, 0).unwrap_or(0);
        let len = u64::from(u32_le(e, 4).unwrap_or(0));
        let rva = u64::from(u32_le(e, 8).unwrap_or(0));
        let data = file.sub(rva, len);
        let name = lookup(STREAM_TYPES, kind.into()).map_or_else(|| format!("Stream {kind:#x}"), str::to_owned);
        let head = cx.read_avail(data.sub(0, 128)).await?;
        let summary = match kind {
            4 => {
                let count = u32_le(&head, 0).unwrap_or(0);
                if let Some(rva) = u32_le(&head, 4 + 20) {
                    process = base_name(&md_string(&cx, file, rva).await?.0).to_owned();
                }
                format!("{count} modules")
            }
            3 => format!("{} threads", u32_le(&head, 0).unwrap_or(0)),
            5 => format!("{} ranges", u32_le(&head, 0).unwrap_or(0)),
            9 => format!("{} ranges", u64_le(&head, 0).unwrap_or(0)),
            7 => {
                let arch = lookup(ARCHITECTURES, u16_le(&head, 0).unwrap_or(0xffff).into()).unwrap_or("?");
                system = format!("{arch}, OS {}.{}.{}", u32_le(&head, 8).unwrap_or(0), u32_le(&head, 12).unwrap_or(0), u32_le(&head, 16).unwrap_or(0));
                system.clone()
            }
            6 => {
                let code = u32_le(&head, 8).unwrap_or(0);
                let address = u64_le(&head, 24).unwrap_or(0);
                exception = format!("{} at {address:#x}", lookup(EXCEPTION_CODES, code.into()).map_or_else(|| format!("exception {code:#x}"), str::to_owned));
                exception.clone()
            }
            _ => size(len),
        };
        cx.push(
            Node::new(name)
                .span(data)
                .target(dir.sub(to_u64(i).saturating_mul(12), 12))
                .summary(summary)
                .lazy(md_stream, (input, kind, data)),
        )
        .await;
    }
    let mut parts = vec![if process.is_empty() { "Minidump".to_owned() } else { format!("Minidump of {process}") }];
    if !system.is_empty() {
        parts.push(system);
    }
    if !exception.is_empty() {
        parts.push(exception);
    }
    parts.push(format!("{} streams", h.streams));
    cx.annotate(parts.join(", "));
    Ok(())
}

fn location(f: &mut Fields<'_>, prefix: &'static str, size_name: &'static str) -> Result<(u32, u32)> {
    let len = f.u32(size_name).emit()?;
    let rva = f.u32(prefix).hex().emit()?;
    Ok((len, rva))
}

fn system_info(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u16("Processor architecture").enumeration(ARCHITECTURES).emit()?;
    f.u16("Processor level").emit()?;
    f.u16("Processor revision").hex().emit()?;
    f.u8("Number of processors").emit()?;
    f.u8("Product type").enumeration(PRODUCT_TYPES).emit()?;
    f.u32("Major version").emit()?;
    f.u32("Minor version").emit()?;
    f.u32("Build number").emit()?;
    f.u32("Platform").enumeration(PLATFORMS).emit()?;
    f.u32("Service pack string RVA").hex().emit()?;
    f.u16("Suite mask").hex().emit()?;
    f.u16("Reserved").emit()?;
    f.bytes("CPU information", 24).emit()?;
    Ok(())
}

fn exception_stream(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("Thread ID").emit()?;
    f.u32("Alignment").emit()?;
    f.u32("Exception code").enumeration(EXCEPTION_CODES).emit()?;
    f.u32("Exception flags").hex().emit()?;
    f.u64("Exception record").hex().emit()?;
    f.u64("Exception address").hex().emit()?;
    let params = f.u32("Number of parameters").emit()?;
    f.u32("Alignment").emit()?;
    for _ in 0..params.min(15) {
        f.u64("Parameter").hex().emit()?;
    }
    f.seek(160);
    location(f, "Thread context RVA", "Thread context size")?;
    Ok(())
}

const MISC_FLAGS: FlagTable = &[flag(1, "PROCESS_ID"), flag(2, "PROCESS_TIMES"), flag(4, "PROCESSOR_POWER_INFO")];

fn misc_info(f: &mut Fields<'_>, _: &()) -> Result<()> {
    let len = f.u32("Size of info").emit()?;
    f.u32("Flags").flags(MISC_FLAGS).emit()?;
    f.u32("Process ID").emit()?;
    f.u32("Process create time").timestamp().emit()?;
    f.u32("Process user time (s)").emit()?;
    f.u32("Process kernel time (s)").emit()?;
    if len >= 44 {
        f.u32("Processor max MHz").emit()?;
        f.u32("Processor current MHz").emit()?;
        f.u32("Processor MHz limit").emit()?;
        f.u32("Processor max idle state").emit()?;
        f.u32("Processor current idle state").emit()?;
    }
    Ok(())
}

fn module_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u64("Base of image").hex().emit()?;
    f.u32("Size of image").with(|&v, n| n.summary(size(v.into()))).emit()?;
    f.u32("Checksum").hex().emit()?;
    f.u32("Time stamp").timestamp().emit()?;
    f.u32("Module name RVA").hex().emit()?;
    f.u32("Version info signature").hex().emit()?;
    f.u32("Version info struct version").hex().emit()?;
    let ms = f.u32("File version (MS)").hex().emit()?;
    let ls = f.u32("File version (LS)").hex().emit()?;
    f.node(Node::new("File version").value(text(format!("{}.{}.{}.{}", ms >> 16, ms & 0xffff, ls >> 16, ls & 0xffff))));
    f.u32("Product version (MS)").hex().emit()?;
    f.u32("Product version (LS)").hex().emit()?;
    f.u32("File flags mask").hex().emit()?;
    f.u32("File flags").hex().emit()?;
    f.u32("File OS").hex().emit()?;
    f.u32("File type").hex().emit()?;
    f.u32("File subtype").hex().emit()?;
    f.u64("File date").emit()?;
    location(f, "CodeView record RVA", "CodeView record size")?;
    location(f, "Misc record RVA", "Misc record size")?;
    f.u64("Reserved").emit()?;
    f.u64("Reserved").emit()?;
    Ok(())
}

fn thread_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("Thread ID").emit()?;
    f.u32("Suspend count").emit()?;
    f.u32("Priority class").hex().emit()?;
    f.u32("Priority").emit()?;
    f.u64("TEB").hex().emit()?;
    f.u64("Stack start").hex().emit()?;
    location(f, "Stack RVA", "Stack size")?;
    location(f, "Context RVA", "Context size")?;
    Ok(())
}

async fn md_stream(cx: Cx, (input, kind, data): (Input, u32, Span)) -> Result<()> {
    let file = input.span;
    match kind {
        7 => {
            let block = cx.block(data.sub(0, 56)).await?;
            system_info(&mut Fields::emitting(&cx, &block, LE), &())?;
            let rva = u32_le(&block.data, 24).unwrap_or(0);
            if rva != 0 {
                let (sp, span) = md_string(&cx, file, rva).await?;
                cx.emit(Node::new("Service pack").span(span).value(text(sp)));
            }
        }
        6 => {
            let block = cx.block(data.sub(0, 168)).await?;
            exception_stream(&mut Fields::emitting(&cx, &block, LE), &())?;
        }
        15 => {
            let block = cx.block(data).await?;
            misc_info(&mut Fields::emitting(&cx, &block, LE), &())?;
        }
        4 | 14 => {
            let head = cx.read(data.sub(0, 4)).await?;
            let count = u64::from(u32_le(&head, 0).unwrap_or(0));
            // Unloaded module lists carry a header (size, entry size, count).
            let (first, entry) = if kind == 4 { (4u64, 108u64) } else { (12, 24) };
            let count = if kind == 14 { u64::from(u32_le(&cx.read(data.sub(8, 4)).await?, 0).unwrap_or(0)) } else { count };
            let list = data.sub_exact(first, count.saturating_mul(entry))?;
            cx.set_count(Count::Exact(count));
            for i in 0..count {
                let span = list.sub(i.saturating_mul(entry), entry);
                let m = cx.read(span).await?;
                // Both module kinds start with base, size, checksum, time
                // stamp and the name's RVA.
                let (name, _) = md_string(&cx, file, u32_le(&m, 20).unwrap_or(0)).await?;
                let base = u64_le(&m, 0).unwrap_or(0);
                let short = base_name(&name).to_owned();
                let node = if kind == 4 {
                    let cv = (u32_le(&m, 76).unwrap_or(0), u32_le(&m, 80).unwrap_or(0));
                    let node = struct_node(short, span, LE, (), module_layout).value(hex(base, 64));
                    match codeview_pdb(&cx, file, cv).await? {
                        Some(p) => node.summary(format!("{name} — {p}")),
                        None => node.summary(name),
                    }
                } else {
                    Node::new(short).span(span).value(hex(base, 64)).summary(name)
                };
                cx.push(node).await;
            }
        }
        3 => {
            let head = cx.read(data.sub(0, 4)).await?;
            let count = u64::from(u32_le(&head, 0).unwrap_or(0));
            let list = data.sub_exact(4, count.saturating_mul(48))?;
            cx.set_count(Count::Exact(count));
            for i in 0..count {
                let span = list.sub(i.saturating_mul(48), 48);
                let t = cx.read(span).await?;
                let id = u32_le(&t, 0).unwrap_or(0);
                let stack = u32_le(&t, 32).unwrap_or(0);
                cx.push(struct_node(format!("Thread {id}"), span, LE, (), thread_layout).summary(format!("stack {}", size(stack.into())))).await;
            }
        }
        5 | 9 => {
            let head = cx.read(data.sub(0, 16)).await?;
            let (count, entry, first) = if kind == 5 { (u64::from(u32_le(&head, 0).unwrap_or(0)), 16u64, 4u64) } else { (u64_le(&head, 0).unwrap_or(0), 16, 16) };
            let mut rva = u64_le(&head, 8).unwrap_or(0);
            let list = data.sub_exact(first, count.saturating_mul(entry))?;
            cx.set_count(Count::Exact(count));
            for i in 0..count {
                let span = list.sub(i.saturating_mul(entry), entry);
                let d = cx.read(span).await?;
                let start = u64_le(&d, 0).unwrap_or(0);
                let (len, at) = if kind == 5 {
                    (u64::from(u32_le(&d, 8).unwrap_or(0)), u64::from(u32_le(&d, 12).unwrap_or(0)))
                } else {
                    let len = u64_le(&d, 8).unwrap_or(0);
                    let at = rva;
                    rva = rva.saturating_add(len);
                    (len, at)
                };
                cx.push(Node::new(format!("{start:#x}")).span(span).target(file.sub(at, len)).summary(size(len))).await;
            }
        }
        10 => {
            let raw = cx.read_avail(data.sub(0, 0x10000)).await?;
            cx.emit(Node::new("Comment").span(data).value(text(crate::text::until_nul(&raw))));
        }
        11 => {
            let raw = cx.read_avail(data.sub(0, 0x10000)).await?;
            cx.emit(Node::new("Comment").span(data).value(text(crate::text::utf16z(&raw, LE).0)));
        }
        _ => cx.emit(Node::new("Data").span(data)),
    }
    Ok(())
}

/// The PDB path from a CodeView (RSDS) record.
async fn codeview_pdb(cx: &Cx, file: Span, (len, rva): (u32, u32)) -> Result<Option<String>> {
    if len < 24 || rva == 0 {
        return Ok(None);
    }
    let raw = cx.read_avail(file.sub(rva.into(), u64::from(len).min(1024))).await?;
    if raw.get(..4) != Some(b"RSDS") {
        return Ok(None);
    }
    Ok(Some(crate::text::until_nul(raw.get(24..).unwrap_or_default())))
}

// ---------------------------------------------------------------------------
// Windows Error Reporting (.wer)

declare_format!(pub WER = "wer-report", "Windows Error Reporting report (.wer)", ["wer"], "application/x-ms-wer",
    Probe::Magic(&[(0, b"\xff\xfeV\0e\0r\0s\0i\0o\0n\0=\0")]), wer);

async fn wer(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let raw = cx.read_avail(file.sub(2, 0x40000)).await?;
    let units: Vec<u16> = raw.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
    let mut at = 0usize;
    let mut entries: Vec<(String, String, Span)> = Vec::new();
    while at < units.len() {
        let end = units.get(at..).and_then(|r| r.iter().position(|&u| u == u16::from(b'\n'))).map_or(units.len(), |p| at.saturating_add(p).saturating_add(1));
        let line = String::from_utf16_lossy(units.get(at..end).unwrap_or_default());
        let span = file.sub(2u64.saturating_add(to_u64(at).saturating_mul(2)), to_u64(end.saturating_sub(at)).saturating_mul(2));
        if let Some((k, v)) = line.trim_end().split_once('=') {
            entries.push((k.to_owned(), v.to_owned(), span));
        }
        at = end;
        if entries.len() > 100_000 {
            break;
        }
    }
    let get = |key: &str| entries.iter().find(|(k, _, _)| k == key).map(|(_, v, _)| v.clone()).unwrap_or_default();
    let event = get("EventType");
    let app = get("AppName");
    let app = if app.is_empty() { get("Sig[0].Value") } else { app };
    cx.set_count(Count::Exact(to_u64(entries.len())));
    for (k, v, span) in &entries {
        let node = Node::new(k.clone()).span(*span);
        let node = if k.ends_with("Time") && let Ok(t) = v.parse::<u64>() {
            node.value(Value::Timestamp { unix_seconds: crate::text::filetime_to_unix(t) })
        } else {
            node.value(text(v.clone()))
        };
        cx.push(node).await;
    }
    let mut summary = format!("WER report: {}", if event.is_empty() { "event" } else { &event });
    if !app.is_empty() {
        summary.push_str(&format!(" in {app}"));
    }
    summary.push_str(&format!(", {} entries", entries.len()));
    cx.annotate(summary);
    Ok(())
}

// ---------------------------------------------------------------------------
// Program Information Files (.pif)

declare_format!(pub PIF = "pif", "Windows Program Information File (.pif)", ["pif"], "application/x-ms-pif",
    Probe::Magic(&[(0x171, b"MICROSOFT PIFEX\0")]), pif);

record! {
    pub struct PifBasic {
        _reserved: u8 "Reserved",
        checksum: u8 "Checksum" .hex(),
        title: ascii[30] "Window title",
        max_memory: u16 "Maximum memory (KiB)",
        min_memory: u16 "Minimum memory (KiB)",
        program: ascii[63] "Program filename",
        flags1: u8 "Flags" .hex(),
        _reserved2: u8 "Reserved",
        directory: ascii[64] "Startup directory",
        parameters: ascii[64] "Parameters",
        video: u8 "Video mode",
        pages: u8 "Text pages",
        first_irq: u8 "First interrupt",
        last_irq: u8 "Last interrupt",
        rows: u8 "Screen rows",
        columns: u8 "Screen columns",
        window_row: u8 "Window row",
        window_column: u8 "Window column",
        system_memory: u16 "System memory",
        shared_name: ascii[64] "Shared program name",
        shared_data: ascii[64] "Shared program data file",
        flags2: u8 "Flags 2" .hex(),
        flags3: u8 "Flags 3" .hex(),
    }
}

const PIF_SECTIONS: &[(&str, &str)] = &[
    ("MICROSOFT PIFEX", "Basic section"),
    ("WINDOWS 286 3.0", "Windows 286 settings"),
    ("WINDOWS 386 3.0", "Windows 386 enhanced-mode settings"),
    ("WINDOWS VMM 4.0", "Windows 95 settings"),
    ("WINDOWS NT  3.1", "Windows NT settings"),
    ("WINDOWS NT  4.0", "Windows NT 4 settings"),
    ("CONFIG  SYS 4.0", "CONFIG.SYS for MS-DOS mode"),
    ("AUTOEXECBAT 4.0", "AUTOEXEC.BAT for MS-DOS mode"),
];

async fn pif(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, PifBasic::SIZE);
    let basic: PifBasic = read_record(&cx, span, LE).await?;
    cx.emit(PifBasic::node("Basic section", span, LE));
    let mut at = 0x171u64;
    let mut seen = Vec::new();
    let mut names = Vec::new();
    while at != 0xffff && at.saturating_add(22) <= file.len {
        if seen.contains(&at) || seen.len() > 64 {
            cx.diag(Diagnostic::malformed("section headings loop").at(file.sub(at, 22)));
            break;
        }
        seen.push(at);
        let head = cx.read(file.sub(at, 22)).await?;
        let name = crate::text::until_nul(head.get(..16).unwrap_or_default());
        let next = u64::from(u16_le(&head, 16).unwrap_or(0xffff));
        let data_at = u64::from(u16_le(&head, 18).unwrap_or(0));
        let len = u64::from(u16_le(&head, 20).unwrap_or(0));
        let data = file.sub(data_at, len);
        let title = PIF_SECTIONS.iter().find(|(k, _)| *k == name).map(|(_, t)| *t);
        names.push(name.clone());
        let mut node = Node::new(name).span(file.sub(at, 22)).target(data).summary(size(len)).lazy(pif_section, (file.sub(at, 22), data));
        if let Some(t) = title {
            node = node.desc(t);
        }
        cx.push(node).await;
        at = next;
    }
    let program = basic.program.trim().to_owned();
    cx.annotate(format!(
        "PIF for {}{}, sections: {}",
        if program.is_empty() { "?" } else { &program },
        if basic.parameters.trim().is_empty() { String::new() } else { format!(" {}", basic.parameters.trim()) },
        clip(&names.join(", "), 120)
    ));
    Ok(())
}

fn pif_heading(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.ascii("Section name", 16).emit()?;
    f.u16("Next heading offset").hex().emit()?;
    f.u16("Data offset").hex().emit()?;
    f.u16("Data length").emit()?;
    Ok(())
}

async fn pif_section(cx: Cx, (heading, data): (Span, Span)) -> Result<()> {
    cx.emit(struct_node("Heading", heading, LE, (), pif_heading));
    let raw = cx.read_avail(data.sub(0, 0x1000)).await?;
    // NT sections name the CONFIG.NT / AUTOEXEC.NT replacements.
    let strings: Vec<String> = raw
        .split(|&b| b == 0)
        .filter(|s| s.len() >= 4 && s.iter().all(|&b| (0x20..0x7f).contains(&b)))
        .map(crate::text::latin1)
        .collect();
    let mut node = Node::new("Data").span(data);
    if !strings.is_empty() {
        node = node.summary(clip(&strings.join(", "), 120));
    }
    cx.emit(node);
    Ok(())
}
