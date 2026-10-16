//! TempleOS binary modules (`.BIN`, `CBinFile`) and the boot kernel image
//! (`0000Kernel.BIN.C`), as written by the HolyC compiler's `Cmp` and read
//! by the loader's `Load`.
//!
//! A module is a 32-byte header, the code and data image (loaded right
//! after the header, so offsets in the patch table count from byte 0x20),
//! then the patch table: a stream of entries, each a type byte (`IET_*`), a
//! 32-bit value and a NUL-terminated name, some followed by more data. The
//! compiler writes absolute relocations first (one `IET_ABS_ADDR` entry
//! listing every 32-bit location to add the load address to), then heap
//! globals, exports, imports, and `IET_MAIN` entries, ended by `IET_END`;
//! the file is padded with zeros to 16 bytes. An import names its symbol
//! in its first entry and follows it with unnamed entries for the other
//! places the same symbol is patched into; those runs are shown as one node
//! per symbol. The table is shown as groups of heap globals, exports and
//! imports (counted in one pass over the table, for its summary), then the
//! other entries in table order.
//!
//! The kernel is a module too: its code starts with the rest of `CKernel`
//! (`KStart16.HC`), a 16-bit near jump past the boot loader's variables and
//! the build time. Boot loaders (`Adam/Opt/Boot`) load the contiguous file
//! and jump to its first byte in real mode; the header's short jump lands
//! on that near jump.
//!
//! Ported from the public-domain TempleOS V5.03 sources: `CBinFile`,
//! `CKernel`, `IET_*` and `RLf_*` in `Kernel/KernelA.HH`, `Load`,
//! `LoadPass1` and `LoadOneImport` in `Kernel/KLoad.HC`, `Cmp` in
//! `Compiler/CMain.HC`, `CDate` arithmetic in `Kernel/KDate.HC`. Checked
//! against the kernel and compiler of the official V5.03 ISO. The code is
//! not disassembled.

use crate::bytes::{u16_le, u64_le};
use crate::cx::Cx;
use crate::dsl::{Cursor, Record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::binutil::data_node;
use crate::formats::util::civil;
use crate::formats::util::fmt::{grouped_count, plural};
use crate::formats::util::val::hex;
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

const LE: Endian = Endian::Little;

pub static FORMAT: Format = Format {
    name: "templeos-bin",
    title: "TempleOS binary module",
    extensions: &["bin"],
    mime: "application/octet-stream",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

pub static KERNEL: Format = Format {
    name: "templeos-kernel",
    title: "TempleOS kernel image",
    extensions: &["bin"],
    mime: "application/octet-stream",
    probe: Probe::Custom(probe_kernel),
    dissect: crate::expander!(dissect_kernel: Input),
};

/// `sizeof(CBinFile)`: the header, and where offsets in the patch table
/// start counting.
const HEADER: u64 = 0x20;

/// `INVALID_PTR` (`I64_MAX`) in `org`: the module is relocatable.
const INVALID_PTR: u64 = 0x7fff_ffff_ffff_ffff;

/// Longest symbol name looked at.
const MAX_NAME: u64 = 4096;

fn probe(h: &Head<'_>) -> bool {
    // `jmp` is `EB 1E` (short JMP over the 32-byte header), `reserved` is 0.
    if !(h.starts_with(&[0xeb, 0x1e]) && h.at(3, &[0]) && h.at(4, b"TOSB")) {
        return false;
    }
    let align = h.data.get(2).copied().unwrap_or(u8::MAX);
    let table = u64_le(h.data, 0x10).unwrap_or(0);
    let size = u64_le(h.data, 0x18).unwrap_or(0);
    align < 64 && table >= HEADER && table < size && size.is_multiple_of(16)
}

fn probe_kernel(h: &Head<'_>) -> bool {
    // `CKernel.jmp`: `JMP I16 CORE0_16BIT_INIT` then a NOP of `ALIGN 4`,
    // jumping forward inside the image.
    let target = u16_le(h.data, 0x21).map_or(0, |rel| 0x23u64.saturating_add(rel.into()));
    let table = u64_le(h.data, 0x10).unwrap_or(0);
    probe(h) && h.at(0x20, &[0xe9]) && h.at(0x23, &[0x90]) && target > 0x3c && target < table
}

const BOOT_SRC: EnumTable = &[
    (0, "BOOT_SRC_NULL"),
    (1, "BOOT_SRC_ROM"),
    (2, "BOOT_SRC_RAM"),
    (3, "BOOT_SRC_HARDDRV"),
    (4, "BOOT_SRC_DVD"),
];

const RUN_LEVEL: FlagTable = &[
    flag(1 << 0, "RLf_16BIT"),
    flag(1 << 1, "RLf_VGA"),
    flag(1 << 2, "RLf_32BIT"),
    flag(1 << 3, "RLf_PATCHED"),
    flag(1 << 4, "RLf_16MEG_SYS_CODE_BP"),
    flag(1 << 5, "RLf_64BIT"),
    flag(1 << 6, "RLf_16MEG_ADAM_HEAP_CTRL"),
    flag(1 << 7, "RLf_FULL_HEAPS"),
    flag(1 << 8, "RLf_RAW"),
    flag(1 << 9, "RLf_INTERRUPTS"),
    flag(1 << 10, "RLf_BLKDEV"),
    flag(1 << 11, "RLf_MP"),
    flag(1 << 12, "RLf_COMPILER"),
    flag(1 << 13, "RLf_DOC"),
    flag(1 << 14, "RLf_WINMGR"),
    flag(1 << 15, "RLf_REGISTRY"),
    flag(1 << 16, "RLf_HOME"),
    flag(1 << 17, "RLf_AUTO_COMPLETE"),
    flag(1 << 18, "RLf_ADAM_SERVER"),
    flag(1 << 19, "RLf_ONCE_ADAM"),
    flag(1 << 20, "RLf_ONCE_USER"),
];

const IET_END: u8 = 0;
const IET_ABS_ADDR: u8 = 20;
const IET_CODE_HEAP: u8 = 21;
const IET_ZEROED_CODE_HEAP: u8 = 22;
const IET_DATA_HEAP: u8 = 23;
const IET_ZEROED_DATA_HEAP: u8 = 24;
const IET_MAIN: u8 = 25;

const IET: EnumTable = &[
    (0, "IET_END"),
    (2, "IET_REL_I0"),
    (3, "IET_IMM_U0"),
    (4, "IET_REL_I8"),
    (5, "IET_IMM_U8"),
    (6, "IET_REL_I16"),
    (7, "IET_IMM_U16"),
    (8, "IET_REL_I32"),
    (9, "IET_IMM_U32"),
    (10, "IET_REL_I64"),
    (11, "IET_IMM_I64"),
    (16, "IET_REL32_EXPORT"),
    (17, "IET_IMM32_EXPORT"),
    (18, "IET_REL64_EXPORT"),
    (19, "IET_IMM64_EXPORT"),
    (20, "IET_ABS_ADDR"),
    (21, "IET_CODE_HEAP"),
    (22, "IET_ZEROED_CODE_HEAP"),
    (23, "IET_DATA_HEAP"),
    (24, "IET_ZEROED_DATA_HEAP"),
    (25, "IET_MAIN"),
];

fn is_import(kind: u8) -> bool {
    (2..=11).contains(&kind)
}

fn is_export(kind: u8) -> bool {
    (16..=19).contains(&kind)
}

/// Bytes an import patches (0 for the fictitious `I0`/`U0` kinds).
fn import_width(kind: u8) -> u64 {
    match kind {
        4 | 5 => 1,
        6 | 7 => 2,
        8 | 9 => 4,
        10 | 11 => 8,
        _ => 0,
    }
}

/// An entry kind without the `IET_` prefix.
fn short(kind: u8) -> &'static str {
    lookup(IET, kind.into()).map_or("unknown", |n| n.strip_prefix("IET_").unwrap_or(n))
}

record! {
    /// `CBinFile`
    struct BinHeader {
        jmp: u16 "jmp" .hex() .desc("Short JMP over the header (EB 1E), so the image runs from its first byte"),
        align_bits: u8 "module_align_bits" .with(|&v, n| n.summary(plural(1u64.checked_shl(v.into()).unwrap_or(0), "byte"))),
        reserved: u8 "reserved",
        signature: ascii[4] "bin_signature",
        org: u64 "org" .hex() .with(|&v, n| if v == INVALID_PTR { n.summary("INVALID_PTR: relocatable") } else { n.summary("fixed load address") }),
        table: u64 "patch_table_offset" .hex(),
        size: u64 "file_size" .with(|&v, n| n.summary(crate::formats::util::fmt::size(v))),
    }
}

record! {
    /// The start of `CKernel` after its `CBinFile` (`KStart16.HC`).
    struct KernelHeader {
        jmp: u32 "jmp" .hex() .desc("JMP I16 CORE0_16BIT_INIT, then a NOP"),
        boot_src: u32 "boot_src" .enumeration(BOOT_SRC) .desc("Set at boot"),
        boot_blk: u32 "boot_blk" .desc("Set at boot"),
        patch_base: u32 "boot_patch_table_base" .hex() .desc("Set at boot"),
        run_level: u32 "sys_run_level" .flags(RUN_LEVEL) .desc("Set at boot"),
        compile_time: u64 "compile_time" .hex() .desc("CDate of the build; boot loaders match it to find their kernel") .with(|&v, n| n.value(Value::Timestamp(crate::value::Time::local(civil::templeos_cdate_raw(v))))),
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    dissect_as(cx, input, false).await
}

pub async fn dissect_kernel(cx: Cx, input: Input) -> Result<()> {
    dissect_as(cx, input, true).await
}

async fn dissect_as(cx: Cx, input: Input, kernel: bool) -> Result<()> {
    let file = input.span;
    let hspan = file.sub(0, BinHeader::SIZE);
    cx.emit(BinHeader::node("Header", hspan, LE));
    let h = crate::fields::parse(&cx, hspan, LE, &(), BinHeader::layout).await?;

    let size = h.size.min(file.len);
    let table_at = h.table.min(size);
    let code = file.sub(HEADER, table_at.saturating_sub(HEADER));
    let mut summary = format!(
        "{}, {} code and data, {}",
        if kernel {
            "TempleOS kernel image"
        } else {
            "TempleOS binary module"
        },
        crate::formats::util::fmt::size(code.len),
        if h.org == INVALID_PTR {
            "relocatable".to_string()
        } else {
            format!("at {:#x}", h.org)
        }
    );
    if kernel {
        let kspan = code.sub(0, KernelHeader::SIZE);
        let mut node = KernelHeader::node("Kernel header", kspan, LE);
        match crate::fields::parse(&cx, kspan, LE, &(), KernelHeader::layout).await {
            Ok(k) => {
                let built = civil::date(civil::templeos_cdate_raw(k.compile_time));
                summary.push_str(&format!(", built {built}"));
                node = node.summary(format!("built {built}"));
            }
            Err(e) => node = node.diag(e),
        }
        cx.emit(node);
    }
    cx.annotate(summary);

    let mut code_node = data_node("Code", code, h.table.saturating_sub(HEADER))
        .summary(crate::formats::util::fmt::size(code.len));
    if h.table < HEADER {
        code_node = code_node.diag(Diagnostic::malformed(
            "patch table starts inside the header",
        ));
    }
    cx.emit(code_node);

    let table = file.sub(table_at, size.saturating_sub(table_at));
    cx.emit(
        Node::new("Patch table")
            .span(table)
            .lazy(patch_table, (code, table)),
    );
    if h.size != file.len {
        cx.diag(Diagnostic::warning(format!(
            "file_size is {:#x}, the file {:#x} bytes",
            h.size, file.len
        )));
    }
    if h.size < file.len {
        cx.emit(Node::new("Trailing data").span(file.tail(h.size)));
    }
    Ok(())
}

/// One patch table entry's head: type, value and name.
struct Entry {
    kind: u8,
    value: u32,
    name: String,
}

/// Bytes after an entry's name: a heap size, then `value` 32-bit offsets.
fn extra_len(kind: u8, value: u32) -> u64 {
    let prefix = match kind {
        IET_CODE_HEAP | IET_ZEROED_CODE_HEAP => 4,
        IET_DATA_HEAP | IET_ZEROED_DATA_HEAP => 8,
        _ => 0,
    };
    let count = match kind {
        IET_ABS_ADDR..=IET_ZEROED_DATA_HEAP => u64::from(value),
        _ => 0,
    };
    count.saturating_mul(4).saturating_add(prefix)
}

/// Reads the entry at the cursor and steps past it and its data.
async fn read_entry(cur: &mut Cursor<'_>) -> Result<Entry> {
    let kind = cur.u8().await?;
    if kind == IET_END {
        return Ok(Entry {
            kind,
            value: 0,
            name: String::new(),
        });
    }
    let value = cur.u32().await?;
    let (name, _) = cur.cstr(MAX_NAME).await?;
    let len = extra_len(kind, value);
    if len > cur.remaining() {
        return Err(Diagnostic::truncated(cur.span(len), cur.remaining()));
    }
    cur.skip(len);
    Ok(Entry { kind, value, name })
}

/// Which group of the patch table an entry is shown in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    HeapGlobal,
    Export,
    Import,
    /// Shown in the table itself: `IET_ABS_ADDR`, `IET_MAIN`, `IET_END`
    /// and unknown types.
    Other,
}

fn class(kind: u8) -> Class {
    if is_import(kind) {
        Class::Import
    } else if is_export(kind) {
        Class::Export
    } else if (IET_CODE_HEAP..=IET_ZEROED_DATA_HEAP).contains(&kind) {
        Class::HeapGlobal
    } else {
        Class::Other
    }
}

/// Steps past the unnamed import entries after an import, which patch the
/// same symbol (`LoadOneImport`); returns how many entries the run has.
async fn import_run(cur: &mut Cursor<'_>) -> u64 {
    let mut refs = 1u64;
    while !cur.at_end() {
        let at = cur.pos();
        match read_entry(cur).await {
            Ok(next) if is_import(next.kind) && next.name.is_empty() => {
                refs = refs.saturating_add(1);
            }
            // The next entry (or its error) is the walk's.
            _ => {
                cur.seek(at);
                break;
            }
        }
    }
    refs
}

/// The patch table: groups of heap globals, exports and imports (counted
/// in one pass over the table), then the other entries in table order.
async fn patch_table(cx: Cx, (code, table): (Span, Span)) -> Result<()> {
    let (mut heap, mut exports, mut imports, mut refs) = (0u64, 0u64, 0u64, 0u64);
    let mut cur = Cursor::new(&cx, table, LE);
    while !cur.at_end() {
        // A damaged entry ends the count; the walk below reports it.
        let Ok(e) = read_entry(&mut cur).await else {
            break;
        };
        match class(e.kind) {
            Class::HeapGlobal => heap = heap.saturating_add(1),
            Class::Export => exports = exports.saturating_add(1),
            Class::Import => {
                imports = imports.saturating_add(1);
                refs = refs.saturating_add(import_run(&mut cur).await);
            }
            Class::Other if e.kind == IET_END => break,
            Class::Other => {}
        }
    }
    let mut summary = vec![plural(exports, "export")];
    summary.push(format!(
        "{} ({})",
        grouped_count(imports, "imported symbol", "imported symbols"),
        plural(refs, "reference")
    ));
    if heap > 0 {
        summary.push(plural(heap, "heap global"));
    }
    cx.annotate(summary.join(", "));
    let groups = [
        (
            Class::HeapGlobal,
            "Heap globals",
            heap,
            plural(heap, "global"),
        ),
        (Class::Export, "Exports", exports, plural(exports, "export")),
        (
            Class::Import,
            "Imports",
            imports,
            format!(
                "{}, {}",
                plural(imports, "symbol"),
                plural(refs, "reference")
            ),
        ),
    ];
    for (which, name, n, summary) in groups {
        if n > 0 {
            cx.emit(
                Node::new(name)
                    .summary(summary)
                    .lazy(group, (code, table, which)),
            );
        }
    }

    let mut cur = Cursor::new(&cx, table, LE);
    loop {
        if cur.at_end() {
            cx.diag(Diagnostic::malformed("patch table not ended by IET_END").at(table));
            break;
        }
        let start = cur.pos();
        let e = read_entry(&mut cur).await?;
        if e.kind == IET_END {
            let span = cur.since(start);
            cx.push(Node::new("End").span(span).value(Value::Enum {
                raw: 0,
                bits: 8,
                name: Some("IET_END".into()),
            }))
            .await;
            let pad = table.tail(cur.pos());
            if pad.len > 0 {
                cx.push(Node::new("Padding").span(pad)).await;
            }
            break;
        }
        if class(e.kind) == Class::Other {
            cx.push(entry_node(&e, code, cur.since(start))).await;
        }
        cx.progress_in(table, table.offset.saturating_add(cur.pos()));
    }
    Ok(())
}

/// The entries of one group of the patch table, in table order.
async fn group(cx: Cx, (code, table, which): (Span, Span, Class)) -> Result<()> {
    let mut cur = Cursor::new(&cx, table, LE);
    cur.seek(cx.resume::<u64>().unwrap_or(0));
    while !cur.at_end() {
        let start = cur.pos();
        let e = read_entry(&mut cur).await?;
        if e.kind == IET_END {
            break;
        }
        let kind = class(e.kind);
        if kind == Class::Import {
            let refs = import_run(&mut cur).await;
            if which == Class::Import {
                let span = cur.since(start);
                cx.mark(move || start);
                cx.push(
                    Node::new(if e.name.is_empty() {
                        "(no symbol)".to_string()
                    } else {
                        e.name.clone()
                    })
                    .span(span)
                    .summary(format!("import, {}", plural(refs, "reference")))
                    .lazy(import_refs, (code, span)),
                )
                .await;
            }
        } else if kind == which {
            cx.mark(move || start);
            cx.push(entry_node(&e, code, cur.since(start))).await;
        }
        cx.progress_in(table, table.offset.saturating_add(cur.pos()));
    }
    Ok(())
}

/// The node of an entry other than an import run.
fn entry_node(e: &Entry, code: Span, span: Span) -> Node {
    let value = u64::from(e.value);
    let named = |fallback: &str| {
        if e.name.is_empty() {
            fallback.to_string()
        } else {
            e.name.clone()
        }
    };
    let node = match e.kind {
        16 | 18 => Node::new(named("(no name)"))
            .summary(format!("export, offset {value:#x}"))
            .target(code.sub(value, 1)),
        17 | 19 => Node::new(named("(no name)")).summary(format!("export, value {value:#x}")),
        IET_ABS_ADDR => Node::new("Absolute addresses").summary(grouped_count(
            value,
            "location gets the load address",
            "locations get the load address",
        )),
        IET_CODE_HEAP..=IET_ZEROED_DATA_HEAP => {
            let kind = match e.kind {
                IET_CODE_HEAP => "code heap",
                IET_ZEROED_CODE_HEAP => "zeroed code heap",
                IET_DATA_HEAP => "data heap",
                _ => "zeroed data heap",
            };
            Node::new(named("(heap global)"))
                .summary(format!("{kind} global, {}", plural(value, "reference")))
        }
        IET_MAIN => Node::new("Main")
            .summary(format!("called at {value:#x} after loading"))
            .target(code.sub(value, 1)),
        _ => Node::new(format!("Entry type {}", e.kind))
            .diag(Diagnostic::warning("unknown patch table entry type")),
    };
    node.span(span).lazy(entry_fields, (code, span))
}

/// Decodes an entry's head into `f`; returns its kind and value.
fn entry_head(f: &mut Fields<'_>) -> Result<(u8, u32)> {
    let kind = f.u8("type").enumeration(IET).emit()?;
    let value = f
        .u32("value")
        .hex()
        .desc(match kind {
            2..=11 => "Offset of the patched location",
            16 | 18 => "Offset of the exported symbol",
            17 | 19 => "Value of the exported symbol",
            IET_ABS_ADDR..=IET_ZEROED_DATA_HEAP => "Count of offsets that follow",
            IET_MAIN => "Offset of the routine",
            _ => "",
        })
        .emit()?;
    f.cstr("name").emit()?;
    Ok((kind, value))
}

async fn entry_fields(cx: Cx, (code, span): (Span, Span)) -> Result<()> {
    let block = cx.block(span.sub(0, 5u64.saturating_add(MAX_NAME))).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    let (kind, value) = entry_head(&mut f)?;
    let mut at = f.pos();
    let width = match kind {
        IET_CODE_HEAP | IET_ZEROED_CODE_HEAP => {
            f.int::<i32>("size").emit()?;
            at = at.saturating_add(4);
            4
        }
        IET_DATA_HEAP | IET_ZEROED_DATA_HEAP => {
            f.int::<i64>("size").emit()?;
            at = at.saturating_add(8);
            8
        }
        IET_ABS_ADDR => 4,
        _ => return Ok(()),
    };
    let list = span.tail(at);
    cx.emit(
        Node::new(if kind == IET_ABS_ADDR {
            "Locations"
        } else {
            "References"
        })
        .span(list)
        .summary(plural(value, "offset"))
        .lazy(locations, (code, list, width)),
    );
    Ok(())
}

/// A list of 32-bit offsets into the image, each patched `width` bytes.
async fn locations(cx: Cx, (code, list, width): (Span, Span, u64)) -> Result<()> {
    const CHUNK: u64 = 1024;
    let count = list.len / 4;
    cx.set_count(Count::Exact(count));
    let mut i = cx.resume::<u64>().unwrap_or(0);
    while i < count {
        let chunk = CHUNK.min(count.saturating_sub(i));
        let data = cx
            .read(list.sub_exact(i.saturating_mul(4), chunk.saturating_mul(4))?)
            .await?;
        let (words, _) = data.as_chunks::<4>();
        if words.is_empty() {
            break;
        }
        for word in words {
            let at = i;
            cx.mark(move || at);
            let off = u64::from(u32::from_le_bytes(*word));
            cx.push(
                Node::new(format!("[{i}]"))
                    .span(list.sub(i.saturating_mul(4), 4))
                    .value(hex(off, 32))
                    .target(code.sub(off, width)),
            )
            .await;
            i = i.saturating_add(1);
        }
    }
    Ok(())
}

/// The entries of one import run: where the symbol is patched in.
async fn import_refs(cx: Cx, (code, span): (Span, Span)) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, LE);
    let mut i = 0u64;
    if let Some((pos, n)) = cx.resume::<(u64, u64)>() {
        cur.seek(pos);
        i = n;
    }
    while !cur.at_end() {
        let start = cur.pos();
        cx.mark(move || (start, i));
        let e = read_entry(&mut cur).await?;
        let espan = cur.since(start);
        let off = u64::from(e.value);
        cx.push(
            Node::new(format!("[{i}]"))
                .span(espan)
                .value(hex(off, 32))
                .summary(format!(
                    "{}{}",
                    short(e.kind),
                    if e.name.is_empty() {
                        String::new()
                    } else {
                        format!(" {}", e.name)
                    }
                ))
                .target(code.sub(off, import_width(e.kind)))
                .lazy(entry_fields, (code, espan)),
        )
        .await;
        i = i.saturating_add(1);
    }
    Ok(())
}
