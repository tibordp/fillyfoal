//! ELF notes (`PT_NOTE` segments, `SHT_NOTE` sections): build IDs, ABI
//! tags, GNU properties, Go build IDs, SystemTap probes, and the process
//! state recorded in core dumps.

use super::tables::*;
use super::{Class, Elf, ElfInfo};
use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::util::binutil::{NodeExt, data_node, get_at};
use crate::formats::util::val::{hex, name_or, text};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::text::hex_lower;
use crate::value::{EnumTable, decode_flags, lookup};

/// Bytes of a note description read to summarise it.
const SUMMARY_READ: u64 = 512;

/// A region of consecutive notes.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Region {
    pub span: Span,
    /// 4, or 8 for notes in 8-aligned segments (GNU properties).
    align: u64,
    class: Class,
    machine: u16,
}

impl Region {
    pub(super) fn new(elf: &ElfInfo, span: Span, align: u64) -> Self {
        Region {
            span,
            align: if align == 8 { 8 } else { 4 },
            class: elf.class,
            machine: elf.header.machine,
        }
    }
}

/// One note's location and identity.
#[derive(Clone, Debug)]
pub(super) struct Note {
    pub name: String,
    pub kind: u32,
    pub span: Span,
    pub desc: Span,
}

/// Decodes the note at `offset`, returning it and the offset of the next.
async fn read_note(cx: &Cx, region: &Region, offset: u64) -> Result<(Note, u64)> {
    let header = region.span.sub(offset, 12);
    let data = cx.read(header).await?;
    let e = region.class.endian;
    let namesz = u64::from(get_at::<u32>(&data, 0, e).unwrap_or(0));
    let descsz = u64::from(get_at::<u32>(&data, 4, e).unwrap_or(0));
    let kind = get_at::<u32>(&data, 8, e).unwrap_or(0);
    let overflow = || Diagnostic::malformed("note size overflows").at(header);
    let name_span = region.span.sub_exact(offset.saturating_add(12), namesz)?;
    let name = crate::text::until_nul(&cx.read(name_span.sub(0, 256)).await?);
    let desc_offset = 12u64
        .saturating_add(namesz)
        .checked_next_multiple_of(region.align)
        .and_then(|o| o.checked_add(offset))
        .ok_or_else(overflow)?;
    let desc = region.span.sub_exact(desc_offset, descsz)?;
    let next = desc_offset
        .checked_add(descsz)
        .and_then(|end| end.checked_next_multiple_of(region.align))
        .ok_or_else(overflow)?;
    let span = region.span.sub(offset, next.saturating_sub(offset));
    Ok((
        Note {
            name,
            kind,
            span,
            desc,
        },
        next,
    ))
}

/// Up to `max` notes of a region, silently.
pub(super) async fn scan(cx: &Cx, region: &Region, max: usize) -> Result<Vec<Note>> {
    let mut out = Vec::new();
    let mut offset = 0u64;
    while offset.saturating_add(12) <= region.span.len && out.len() < max {
        let (note, next) = read_note(cx, region, offset).await?;
        out.push(note);
        offset = next;
    }
    Ok(out)
}

fn types_for(owner: &str) -> EnumTable {
    match owner {
        "GNU" => NOTE_GNU,
        "CORE" | "LINUX" => NOTE_CORE,
        "FreeBSD" => NOTE_FREEBSD,
        "stapsdt" => NOTE_STAPSDT,
        "Go" => NOTE_GO,
        "Android" => NOTE_ANDROID,
        "FDO" => NOTE_FDO,
        "Xen" => NOTE_XEN,
        _ => &[],
    }
}

fn label(note: &Note) -> String {
    match lookup(types_for(&note.name), note.kind.into()) {
        Some(name) => name.to_owned(),
        None => format!("{} note type {:#x}", note.name, note.kind),
    }
}

pub(super) async fn list(cx: Cx, (elf, region): (Elf, Region)) -> Result<()> {
    emit_all(&cx, &elf, &region).await
}

pub(super) async fn emit_all(cx: &Cx, elf: &Elf, region: &Region) -> Result<()> {
    let _ = elf;
    let mut offset = 0u64;
    while offset.saturating_add(12) <= region.span.len {
        let (note, next) = read_note(cx, region, offset).await?;
        let summary = summarise(cx, region, &note).await;
        cx.push(
            Node::new(label(&note))
                .span(note.span)
                .maybe_summary(summary)
                .lazy(
                    detail,
                    (*region, note.span, note.name.clone(), note.desc, note.kind),
                ),
        )
        .await;
        offset = next;
    }
    Ok(())
}

/// The OS and version of an `NT_GNU_ABI_TAG` description.
pub(super) fn abi_tag(desc: &[u8], endian: Endian) -> Option<String> {
    let os = get_at::<u32>(desc, 0, endian)?;
    let major = get_at::<u32>(desc, 4, endian)?;
    let minor = get_at::<u32>(desc, 8, endian)?;
    let sub = get_at::<u32>(desc, 12, endian)?;
    let os = match os {
        0 => "GNU/Linux".to_owned(),
        other => name_or(GNU_ABI_TAG_OS, other.into(), "OS"),
    };
    Some(format!("{os} {major}.{minor}.{sub}"))
}

async fn summarise(cx: &Cx, region: &Region, note: &Note) -> String {
    let Ok(desc) = cx.read_avail(note.desc.sub(0, SUMMARY_READ)).await else {
        return String::new();
    };
    let e = region.class.endian;
    let word = |at: u64| super::word(&desc, at, region.class);
    match (note.name.as_str(), note.kind) {
        ("GNU", 1) => abi_tag(&desc, e).unwrap_or_default(),
        ("GNU", 3) => hex_lower(&desc),
        ("GNU", 4) | ("Go", 4) => crate::text::until_nul(&desc),
        ("GNU", 5) => properties(&desc, region)
            .iter()
            .map(|p| p.summary.clone())
            .collect::<Vec<_>>()
            .join("; "),
        ("Android", 1) => get_at::<u32>(&desc, 0, e)
            .map(|api| format!("API level {api}"))
            .unwrap_or_default(),
        ("FreeBSD" | "NetBSD" | "OpenBSD", 1) => get_at::<u32>(&desc, 0, e)
            .map(|v| format!("version {v}"))
            .unwrap_or_default(),
        ("stapsdt", 3) => {
            let strings = desc.get(to_usize3(region.class)..).unwrap_or_default();
            let mut parts = strings.split(|&b| b == 0).map(String::from_utf8_lossy);
            let provider = parts.next().unwrap_or_default();
            let name = parts.next().unwrap_or_default();
            format!("{provider}:{name}")
        }
        ("CORE", NT_PRSTATUS) => {
            let (pid_at, sig_at) = if region.class.wide {
                (32, 12)
            } else {
                (24, 12)
            };
            let pid = get_at::<u32>(&desc, pid_at, e).unwrap_or(0);
            let sig = get_at::<u16>(&desc, sig_at, e).unwrap_or(0);
            format!("pid {pid}, signal {}", name_or(SIGNAL, sig.into(), ""))
        }
        ("CORE", NT_PRPSINFO) => {
            let at: usize = if region.class.wide { 40 } else { 28 };
            let fname = desc.get(at..at.saturating_add(16)).unwrap_or_default();
            let args_at: usize = if region.class.wide { 56 } else { 44 };
            let args = desc
                .get(args_at..args_at.saturating_add(80))
                .unwrap_or_default();
            let args = crate::text::until_nul(args);
            if args.is_empty() {
                crate::text::until_nul(fname)
            } else {
                args
            }
        }
        ("CORE", NT_FILE) => word(0)
            .map(|n| format!("{n} mapped files"))
            .unwrap_or_default(),
        _ => format!("{:#x} bytes", note.desc.len),
    }
}

/// Bytes before the strings of a SystemTap probe (three addresses).
fn to_usize3(class: Class) -> usize {
    if class.wide { 24 } else { 12 }
}

async fn detail(
    cx: Cx,
    (region, span, owner, desc, kind): (Region, Span, String, Span, u32),
) -> Result<()> {
    let e = region.class.endian;
    let header = cx.block(span.sub(0, 12)).await?;
    let mut f = Fields::emitting(&cx, &header, e);
    f.u32("n_namesz").emit()?;
    f.u32("n_descsz").emit()?;
    f.u32("n_type").enumeration(types_for(&owner)).emit()?;
    let name_len = desc.offset.saturating_sub(span.offset).saturating_sub(12);
    let name_span = span.sub(12, name_len);
    cx.emit(Node::new("Name").span(name_span).value(text(owner.clone())));
    if desc.len == 0 {
        return Ok(());
    }
    let class = region.class;
    let rec = |name: &'static str, layout: crate::fields::Layout<Class, ()>| {
        struct_node(name, desc, e, class, layout)
    };
    match (owner.as_str(), kind) {
        ("GNU", 1) => cx.emit(rec("ABI Tag", abi_tag_layout)),
        ("GNU", 3) => {
            let bytes = cx.read(desc.sub(0, 256)).await?;
            cx.emit(
                Node::new("Build ID")
                    .span(desc)
                    .value(text(hex_lower(&bytes))),
            );
        }
        ("GNU", 4) | ("Go", 4) | ("FDO", 0xcafe_1a7e) => {
            let bytes = cx.read(desc.sub(0, 0x10000)).await?;
            cx.emit(
                Node::new(if owner == "Go" {
                    "Go Build ID"
                } else if owner == "FDO" {
                    "Packaging Metadata"
                } else {
                    "Version"
                })
                .span(desc)
                .value(text(crate::text::until_nul(&bytes))),
            );
        }
        ("GNU", 5) => {
            let bytes = cx.read(desc.sub(0, 0x10000)).await?;
            for p in properties(&bytes, &region) {
                let mut node = Node::new(p.name)
                    .span(desc.sub(p.offset, p.len))
                    .summary(p.summary);
                if let Some(v) = p.value {
                    node = node.value(v);
                }
                cx.emit(node);
            }
        }
        ("Android", 1) => cx.emit(rec("Android Ident", android_ident)),
        ("FreeBSD" | "NetBSD" | "OpenBSD", 1) => cx.emit(rec("ABI Tag", os_version)),
        ("stapsdt", 3) => cx.emit(rec("SystemTap Probe", stapsdt)),
        ("CORE", NT_PRSTATUS) => {
            cx.emit(rec("prstatus", prstatus));
            let regs = desc.sub(prstatus_regs_offset(class), registers_len(&region));
            if let Some(names) = register_names(region.machine) {
                cx.emit(struct_node("pr_reg", regs, e, (class, names), registers));
            }
        }
        ("CORE", NT_PRPSINFO) => cx.emit(rec("prpsinfo", prpsinfo)),
        ("CORE", 0x5349_4749) => cx.emit(rec("siginfo", siginfo)),
        ("CORE", NT_AUXV) => cx.emit(
            Node::new("Auxiliary Vector")
                .span(desc)
                .lazy(auxv, (class, desc)),
        ),
        ("CORE", NT_FILE) => cx.emit(
            Node::new("Mapped Files")
                .span(desc)
                .lazy(mapped_files, (class, desc)),
        ),
        _ => cx.emit(data_node("Description", desc, desc.len)),
    }
    Ok(())
}

fn abi_tag_layout(f: &mut Fields<'_>, _: &Class) -> Result<()> {
    f.u32("OS").enumeration(GNU_ABI_TAG_OS).emit()?;
    f.u32("Major").emit()?;
    f.u32("Minor").emit()?;
    f.u32("Subminor").emit()?;
    Ok(())
}

fn os_version(f: &mut Fields<'_>, _: &Class) -> Result<()> {
    f.u32("Version").emit()?;
    Ok(())
}

fn android_ident(f: &mut Fields<'_>, _: &Class) -> Result<()> {
    f.u32("API level").emit()?;
    if f.remaining() >= 128 {
        f.ascii("NDK version", 64).emit()?;
        f.ascii("NDK build number", 64).emit()?;
    }
    Ok(())
}

fn stapsdt(f: &mut Fields<'_>, c: &Class) -> Result<()> {
    f.uword("pc", c.wide).hex().desc("Probe address").emit()?;
    f.uword("base", c.wide)
        .hex()
        .desc("Address of .stapsdt.base")
        .emit()?;
    f.uword("semaphore", c.wide).hex().emit()?;
    f.cstr("Provider").emit()?;
    f.cstr("Name").emit()?;
    f.cstr("Arguments").emit()?;
    Ok(())
}

// --- GNU properties

struct Property {
    name: String,
    offset: u64,
    len: u64,
    summary: String,
    value: Option<crate::value::Value>,
}

fn properties(desc: &[u8], region: &Region) -> Vec<Property> {
    let e = region.class.endian;
    let align = if region.class.wide { 8 } else { 4 };
    let mut out = Vec::new();
    let mut at = 0u64;
    while let (Some(kind), Some(size)) = (
        get_at::<u32>(desc, at, e),
        get_at::<u32>(desc, at.saturating_add(4), e),
    ) {
        let data_at = at.saturating_add(8);
        let len = 8u64.saturating_add(size.into());
        let value = get_at::<u32>(desc, data_at, e).unwrap_or(0);
        let table = match kind {
            GNU_PROPERTY_X86_FEATURE_1_AND => Some(X86_FEATURE_1),
            GNU_PROPERTY_AARCH64_FEATURE_1_AND => Some(AARCH64_FEATURE_1),
            GNU_PROPERTY_X86_ISA_1_NEEDED | GNU_PROPERTY_X86_ISA_1_USED => Some(X86_ISA_1),
            _ => None,
        };
        let name = name_or(GNU_PROPERTY, kind.into(), "property");
        let (summary, value) = match table {
            Some(t) if size == 4 => {
                let (set, unknown) = decode_flags(t, value.into());
                (
                    format!("{}: {}", short_property(&name), set.join(", ")),
                    Some(crate::value::Value::Flags {
                        raw: value.into(),
                        bits: 32,
                        set,
                        unknown,
                    }),
                )
            }
            _ if size == 4 => (
                format!("{}: {value:#x}", short_property(&name)),
                Some(hex(value, 32)),
            ),
            _ => (short_property(&name).to_owned(), None),
        };
        out.push(Property {
            name,
            offset: at,
            len,
            summary,
            value,
        });
        let Some(next) = at
            .checked_add(len)
            .and_then(|n| n.checked_next_multiple_of(align))
        else {
            break;
        };
        if next <= at || out.len() >= 256 {
            break;
        }
        at = next;
    }
    out
}

fn short_property(name: &str) -> &str {
    name.strip_prefix("GNU_PROPERTY_").unwrap_or(name)
}

// --- Core dump notes

fn prstatus_regs_offset(c: Class) -> u64 {
    if c.wide { 112 } else { 72 }
}

fn registers_len(region: &Region) -> u64 {
    let names = register_names(region.machine).map_or(0, |n| to_u64(n.len()));
    names.saturating_mul(region.class.word())
}

fn timeval(f: &mut Fields<'_>, c: &Class, sec: &'static str, usec: &'static str) -> Result<()> {
    f.uword(sec, c.wide).emit()?;
    f.uword(usec, c.wide).emit()?;
    Ok(())
}

fn prstatus(f: &mut Fields<'_>, c: &Class) -> Result<()> {
    f.i32("si_signo")
        .with(|&v, n| n.summary(name_or(SIGNAL, u64::try_from(v).unwrap_or(0), "")))
        .emit()?;
    f.i32("si_code").emit()?;
    f.i32("si_errno").emit()?;
    f.u16("pr_cursig").enumeration(SIGNAL).emit()?;
    f.skip(2);
    f.uword("pr_sigpend", c.wide).hex().emit()?;
    f.uword("pr_sighold", c.wide).hex().emit()?;
    f.u32("pr_pid").emit()?;
    f.u32("pr_ppid").emit()?;
    f.u32("pr_pgrp").emit()?;
    f.u32("pr_sid").emit()?;
    timeval(f, c, "pr_utime.tv_sec", "pr_utime.tv_usec")?;
    timeval(f, c, "pr_stime.tv_sec", "pr_stime.tv_usec")?;
    timeval(f, c, "pr_cutime.tv_sec", "pr_cutime.tv_usec")?;
    timeval(f, c, "pr_cstime.tv_sec", "pr_cstime.tv_usec")?;
    Ok(())
}

const REGS_X86_64: &[&str] = &[
    "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax", "rcx", "rdx", "rsi",
    "rdi", "orig_rax", "rip", "cs", "eflags", "rsp", "ss", "fs_base", "gs_base", "ds", "es", "fs",
    "gs",
];

const REGS_I386: &[&str] = &[
    "ebx", "ecx", "edx", "esi", "edi", "ebp", "eax", "xds", "xes", "xfs", "xgs", "orig_eax", "eip",
    "xcs", "eflags", "esp", "xss",
];

const REGS_AARCH64: &[&str] = &[
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14",
    "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27",
    "x28", "x29 (fp)", "x30 (lr)", "sp", "pc", "pstate",
];

const REGS_ARM: &[&str] = &[
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "fp", "ip", "sp", "lr",
    "pc", "cpsr", "orig_r0",
];

const REGS_RISCV: &[&str] = &[
    "pc", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5",
    "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4", "t5",
    "t6",
];

fn register_names(machine: u16) -> Option<&'static [&'static str]> {
    match machine {
        EM_X86_64 => Some(REGS_X86_64),
        EM_386 => Some(REGS_I386),
        EM_AARCH64 => Some(REGS_AARCH64),
        EM_ARM => Some(REGS_ARM),
        EM_RISCV => Some(REGS_RISCV),
        _ => None,
    }
}

fn registers(f: &mut Fields<'_>, (c, names): &(Class, &'static [&'static str])) -> Result<()> {
    for name in names.iter() {
        f.uword(name, c.wide).hex().emit()?;
    }
    Ok(())
}

fn prpsinfo(f: &mut Fields<'_>, c: &Class) -> Result<()> {
    f.int::<i8>("pr_state").emit()?;
    f.ascii("pr_sname", 1).emit()?;
    f.u8("pr_zomb").emit()?;
    f.int::<i8>("pr_nice").emit()?;
    if c.wide {
        f.skip(4);
        f.u64("pr_flag").hex().emit()?;
        f.u32("pr_uid").emit()?;
        f.u32("pr_gid").emit()?;
    } else {
        f.u32("pr_flag").hex().emit()?;
        f.u16("pr_uid").emit()?;
        f.u16("pr_gid").emit()?;
    }
    f.i32("pr_pid").emit()?;
    f.i32("pr_ppid").emit()?;
    f.i32("pr_pgrp").emit()?;
    f.i32("pr_sid").emit()?;
    f.ascii("pr_fname", 16).desc("Executable name").emit()?;
    f.ascii("pr_psargs", 80).desc("Command line").emit()?;
    Ok(())
}

fn siginfo(f: &mut Fields<'_>, _: &Class) -> Result<()> {
    f.i32("si_signo")
        .with(|&v, n| n.summary(name_or(SIGNAL, u64::try_from(v).unwrap_or(0), "")))
        .emit()?;
    f.i32("si_errno").emit()?;
    f.i32("si_code").emit()?;
    Ok(())
}

async fn auxv(cx: Cx, (class, span): (Class, Span)) -> Result<()> {
    let size = class.word().saturating_mul(2);
    let count = span.len.checked_div(size).unwrap_or(0);
    for i in 0..count {
        let at = span.sub(i.saturating_mul(size), size);
        let data = cx.read(at).await?;
        let kind = super::word(&data, 0, class).unwrap_or(0);
        let value = super::word(&data, class.word(), class).unwrap_or(0);
        cx.push(
            Node::new(name_or(AUXV, kind, "AT"))
                .span(at)
                .value(hex(value, class.bits())),
        )
        .await;
        if kind == 0 {
            break;
        }
    }
    Ok(())
}

/// `NT_FILE`: count, page size, `count` (start, end, file offset in pages)
/// triples, then as many NUL-terminated paths.
async fn mapped_files(cx: Cx, (class, span): (Class, Span)) -> Result<()> {
    let w = class.word();
    let head = cx.read(span.sub(0, w.saturating_mul(2))).await?;
    let count = super::word(&head, 0, class).unwrap_or(0);
    let page = super::word(&head, w, class).unwrap_or(0);
    let triple = w.saturating_mul(3);
    let table = span.sub_exact(w.saturating_mul(2), count.saturating_mul(triple))?;
    let mut names = span.tail(w.saturating_mul(2).saturating_add(table.len));
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let at = table.sub(i.saturating_mul(triple), triple);
        let data = cx.read(at).await?;
        let start = super::word(&data, 0, class).unwrap_or(0);
        let end = super::word(&data, w, class).unwrap_or(0);
        let offset = super::word(&data, w.saturating_mul(2), class).unwrap_or(0);
        let (name, name_span) = cx.cstr(names.sub(0, 4096)).await?;
        names = names.tail(name_span.len);
        cx.push(
            Node::new(name)
                .span(at)
                .summary(format!(
                    "{start:#x}-{end:#x}, file offset {:#x}",
                    offset.saturating_mul(page)
                ))
                .target(name_span),
        )
        .await;
    }
    Ok(())
}
