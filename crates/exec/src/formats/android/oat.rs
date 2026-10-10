//! Android OAT files (`.odex`, `.oat`): ELF shared objects written by
//! `dex2oat` whose dynamic symbols locate the OAT data (`oatdata`, in
//! `.rodata`), the compiled code (`oatexec` to `oatlastword`, in `.text`)
//! and the boot image relocations (`oatdataimgrelro`).
//!
//! The ELF itself is shown by the ELF dissector; this adds the OAT data:
//! the OAT header and its key-value store (compiler filter, class path,
//! boot class path checksums, the dex2oat command line), the OatDexFile
//! records (location, DEX checksum and SHA-1, offsets into the VDEX and the
//! OAT data), per-class OatClass records (class status, which methods are
//! compiled and where their code is), CodeInfo headers and the compiled
//! methods. Layouts follow ART's `oat.h`, `oat_file.cc` and
//! `stack_map.h` for OAT version 279 (Android 17); other versions are shown
//! down to the header fields every version shares. Checked against
//! `oatdump`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::util::binutil::data_node;
use crate::formats::util::fmt::{clip, count, plural, size};
use crate::formats::util::val::{hex, name_or, text};
use crate::formats::{Format, Head, Input, Probe, embedded_as};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, flag, lookup};

const LE: Endian = Endian::Little;

pub static FORMAT: Format = Format {
    name: "oat",
    title: "Android OAT file",
    extensions: &["odex", "oat"],
    mime: "application/x-android-oat",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

/// The newest OAT layout decoded field by field.
const KNOWN_VERSION: u32 = 279;
/// Largest ELF table (section headers, dynamic symbols, strings) read.
const MAX_TABLE: u64 = 1 << 20;
/// Largest OAT data decoded in memory.
const MAX_OATDATA: u64 = 64 << 20;

fn probe(h: &Head<'_>) -> bool {
    h.starts_with(b"\x7fELF") && find_magic(h.data).is_some()
}

/// The first 4-aligned `oat\n` + three digits + NUL.
fn find_magic(data: &[u8]) -> Option<usize> {
    (0..data.len().saturating_sub(8)).step_by(4).find(|&i| {
        data.get(i..i.saturating_add(4)) == Some(b"oat\n")
            && data
                .get(i.saturating_add(4)..i.saturating_add(7))
                .is_some_and(|d| d.iter().all(u8::is_ascii_digit))
            && data.get(i.saturating_add(7)) == Some(&0)
    })
}

const ISA: EnumTable = &[
    (0, "None"),
    (1, "Arm"),
    (2, "Arm64"),
    (3, "Thumb2"),
    (4, "Riscv64"),
    (5, "X86"),
    (6, "X86_64"),
];

const ARM64_FEATURES: FlagTable = &[
    flag(1, "a53"),
    flag(2, "crc"),
    flag(4, "lse"),
    flag(8, "fp16"),
    flag(16, "dotprod"),
    flag(32, "sve"),
];

const CLASS_STATUS: EnumTable = &[
    (0, "NotReady"),
    (1, "Retired"),
    (2, "ErrorResolved"),
    (3, "ErrorUnresolved"),
    (4, "Idx"),
    (5, "Loaded"),
    (6, "Resolving"),
    (7, "Resolved"),
    (8, "Verifying"),
    (9, "RetryVerificationAtRuntime"),
    (10, "VerifiedNeedsAccessChecks"),
    (11, "Verified"),
    (12, "SuperclassValidated"),
    (13, "Initializing"),
    (14, "Initialized"),
    (15, "VisiblyInitialized"),
];

const CLASS_TYPE: EnumTable = &[(0, "AllCompiled"), (1, "SomeCompiled"), (2, "NoneCompiled")];

const TRAMPOLINES: &[&str] = &[
    "jni_dlsym_lookup_trampoline_offset",
    "jni_dlsym_lookup_critical_trampoline_offset",
    "quick_generic_jni_trampoline_offset",
    "quick_imt_conflict_trampoline_offset",
    "quick_resolution_trampoline_offset",
    "quick_to_interpreter_bridge_offset",
    "nterp_trampoline_offset",
];

// ---------------------------------------------------------------------------
// Just enough ELF to find the OAT symbols.

#[derive(Clone, Copy, Debug)]
struct Section {
    kind: u32,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32,
}

/// The file offset of virtual address `addr`.
fn file_offset(sections: &[Section], addr: u64) -> Option<u64> {
    sections
        .iter()
        .filter(|s| s.kind != 8 && s.addr != 0 || s.kind == 1)
        .find(|s| addr >= s.addr && addr.saturating_sub(s.addr) < s.size.max(1))
        .map(|s| s.offset.saturating_add(addr.saturating_sub(s.addr)))
}

/// Dynamic symbols by name: (value, size).
async fn symbols(cx: &Cx, file: Span) -> Result<(Vec<Section>, BTreeMap<String, (u64, u64)>)> {
    let head = cx.read(file.sub(0, 64)).await?;
    let wide = head.get(4) == Some(&2);
    let (shoff, shentsize, shnum) = if wide {
        (
            u64_le(&head, 0x28).unwrap_or(0),
            u16_le(&head, 0x3a).unwrap_or(0),
            u16_le(&head, 0x3c).unwrap_or(0),
        )
    } else {
        (
            u32_le(&head, 0x20).map_or(0, u64::from),
            u16_le(&head, 0x2e).unwrap_or(0),
            u16_le(&head, 0x30).unwrap_or(0),
        )
    };
    let entsize = u64::from(shentsize);
    let table_len = entsize.saturating_mul(shnum.into()).min(MAX_TABLE);
    let table = cx.read(file.sub(shoff, table_len)).await?;
    let mut sections = Vec::new();
    for i in 0..usize::from(shnum) {
        let at = i.saturating_mul(usize::from(shentsize));
        let Some(raw) = table.get(at..at.saturating_add(usize::from(shentsize))) else {
            break;
        };
        let s = if wide {
            Section {
                kind: u32_le(raw, 4).unwrap_or(0),
                addr: u64_le(raw, 0x10).unwrap_or(0),
                offset: u64_le(raw, 0x18).unwrap_or(0),
                size: u64_le(raw, 0x20).unwrap_or(0),
                link: u32_le(raw, 0x28).unwrap_or(0),
            }
        } else {
            Section {
                kind: u32_le(raw, 4).unwrap_or(0),
                addr: u32_le(raw, 0xc).map_or(0, u64::from),
                offset: u32_le(raw, 0x10).map_or(0, u64::from),
                size: u32_le(raw, 0x14).map_or(0, u64::from),
                link: u32_le(raw, 0x18).unwrap_or(0),
            }
        };
        sections.push(s);
    }
    let mut out = BTreeMap::new();
    // SHT_DYNSYM and its string table.
    let Some(dynsym) = sections.iter().find(|s| s.kind == 11).copied() else {
        return Ok((sections, out));
    };
    let Some(strtab) = sections.get(to_usize(dynsym.link.into())).copied() else {
        return Ok((sections, out));
    };
    let syms = cx
        .read(file.sub(dynsym.offset, dynsym.size.min(MAX_TABLE)))
        .await?;
    let strings = cx
        .read(file.sub(strtab.offset, strtab.size.min(MAX_TABLE)))
        .await?;
    let step = if wide { 24 } else { 16 };
    for (i, sym) in syms.chunks(step).enumerate() {
        if i.is_multiple_of(256) {
            cx.checkpoint().await;
        }
        let name_at = to_usize(u32_le(sym, 0).unwrap_or(0).into());
        let (value, size) = if wide {
            (u64_le(sym, 8).unwrap_or(0), u64_le(sym, 16).unwrap_or(0))
        } else {
            (
                u32_le(sym, 4).map_or(0, u64::from),
                u32_le(sym, 8).map_or(0, u64::from),
            )
        };
        let name = crate::text::until_nul(strings.get(name_at..).unwrap_or_default());
        if name.starts_with("oat") {
            out.insert(name, (value, size));
        }
    }
    Ok((sections, out))
}

// ---------------------------------------------------------------------------
// The OAT data

/// An OatClass record: offset, size, status, type, method code offsets.
type OatClassInfo = (u64, u64, u16, u16, Vec<u32>);

/// What the OAT data holds, parsed once.
#[derive(Clone, Debug, Default)]
struct Layout {
    version: u32,
    isa: u32,
    header_end: u64,
    kv: (u64, u64),
    dex_files: Vec<DexEntry>,
    /// OatClass records: offset, size, status, type, method code offsets.
    classes: Vec<OatClassInfo>,
}

#[derive(Clone, Debug, Default)]
struct DexEntry {
    offset: u64,
    size: u64,
    location: String,
    class_offsets: u64,
    class_count: u64,
    layout_sections: u64,
}

fn read_u32(data: &[u8], at: u64) -> Option<u32> {
    u32_le(data, to_usize(at))
}

/// Parses the OAT data in memory (bounded by `MAX_OATDATA`).
async fn parse_layout(cx: &Cx, data: &[u8], oatdata_at: u64) -> Layout {
    let mut l = Layout {
        version: crate::text::until_nul(data.get(4..8).unwrap_or_default())
            .parse()
            .unwrap_or(0),
        isa: read_u32(data, 12).unwrap_or(0),
        ..Layout::default()
    };
    if l.version < KNOWN_VERSION {
        return l;
    }
    let dex_count = read_u32(data, 20).unwrap_or(0);
    let dex_files_at = u64::from(read_u32(data, 24).unwrap_or(0));
    // base_oat_offset is present when it equals oatdata's file offset.
    let base = read_u32(data, 32).is_some_and(|v| u64::from(v) == oatdata_at);
    let kv_size_at = if base { 68 } else { 64 };
    let kv_size = u64::from(read_u32(data, kv_size_at).unwrap_or(0));
    l.header_end = kv_size_at.saturating_add(4);
    l.kv = (l.header_end, kv_size);
    let mut at = dex_files_at;
    for _ in 0..dex_count.min(4096) {
        let start = at;
        let Some(loc_len) = read_u32(data, at) else {
            break;
        };
        let loc_at = at.saturating_add(4);
        let location = String::from_utf8_lossy(
            data.get(to_usize(loc_at)..to_usize(loc_at.saturating_add(loc_len.into())))
                .unwrap_or_default(),
        )
        .into_owned();
        // magic (8), checksum, SHA-1 (20), then u32 offsets.
        let fixed = loc_at.saturating_add(loc_len.into()).saturating_add(32);
        let word = |i: u64| read_u32(data, fixed.saturating_add(i.saturating_mul(4))).unwrap_or(0);
        let class_offsets = u64::from(word(1));
        let layout_sections = u64::from(word(3));
        at = fixed.saturating_add(40);
        l.dex_files.push(DexEntry {
            offset: start,
            size: at.saturating_sub(start),
            location,
            class_offsets,
            class_count: 0,
            layout_sections,
        });
    }
    // Class offsets: u32s until the first OatClass they point at.
    let mut seen = BTreeSet::new();
    for (n, d) in l.dex_files.iter_mut().enumerate() {
        if d.class_offsets == 0 {
            continue;
        }
        let mut first = u64::MAX;
        let mut i = 0u64;
        loop {
            let pos = d.class_offsets.saturating_add(i.saturating_mul(4));
            if pos >= first || pos >= to_u64(data.len()) || i > 1 << 20 {
                break;
            }
            let Some(v) = read_u32(data, pos) else { break };
            let v = u64::from(v);
            if v != 0 {
                first = first.min(v);
                seen.insert(v);
            }
            i = i.saturating_add(1);
            if i.is_multiple_of(1024) {
                cx.checkpoint().await;
            }
        }
        d.class_count = i;
        if n.is_multiple_of(64) {
            cx.checkpoint().await;
        }
    }
    for (n, &off) in seen.iter().enumerate() {
        if n.is_multiple_of(256) {
            cx.checkpoint().await;
        }
        let status = u16_le(data, to_usize(off)).unwrap_or(0);
        let kind = u16_le(data, to_usize(off.saturating_add(2))).unwrap_or(0);
        let mut size = 4u64;
        let mut methods = Vec::new();
        if kind != 2 {
            let count = read_u32(data, off.saturating_add(4)).unwrap_or(0);
            size = 8;
            let compiled: Vec<u32> = if kind == 1 {
                let words = u64::from(count.div_ceil(32));
                let bitmap_at = off.saturating_add(8);
                size = size.saturating_add(words.saturating_mul(4));
                (0..count.min(1 << 16))
                    .filter(|&m| {
                        read_u32(
                            data,
                            bitmap_at.saturating_add(u64::from(m / 32).saturating_mul(4)),
                        )
                        .is_some_and(|w| w & (1 << (m % 32)) != 0)
                    })
                    .collect()
            } else {
                (0..count.min(1 << 16)).collect()
            };
            for (k, _) in compiled.iter().enumerate() {
                let o = read_u32(
                    data,
                    off.saturating_add(size)
                        .saturating_add(to_u64(k).saturating_mul(4)),
                )
                .unwrap_or(0);
                methods.push(o);
            }
            size = size.saturating_add(to_u64(compiled.len()).saturating_mul(4));
        }
        l.classes.push((off, size, status, kind, methods));
    }
    l
}

fn header(f: &mut Fields<'_>, base: &u64) -> Result<()> {
    f.ascii("magic", 4).emit()?;
    let version: u32 = f.ascii("version", 4).emit()?.parse().unwrap_or(0);
    f.u32("oat_checksum").hex().emit()?;
    let isa = f.u32("instruction_set").enumeration(ISA).emit()?;
    let features = f.u32("instruction_set_features_bitmap");
    if isa == 2 {
        features.flags(ARM64_FEATURES).emit()?;
    } else {
        features.hex().emit()?;
    }
    f.u32("dex_file_count").emit()?;
    f.u32("oat_dex_files_offset").hex().emit()?;
    f.u32("bcp_bss_info_offset").hex().emit()?;
    if version < KNOWN_VERSION {
        return Ok(());
    }
    let next = f
        .block()
        .data
        .get(32..36)
        .and_then(|b| u32_le(b, 0))
        .map_or(0, u64::from);
    if next == *base {
        f.u32("base_oat_offset")
            .hex()
            .desc("File offset of the OAT data in the ELF")
            .emit()?;
    }
    f.u32("executable_offset")
        .hex()
        .desc("Offset of the code (oatexec) from the OAT data")
        .emit()?;
    for name in TRAMPOLINES {
        f.u32(name).hex().emit()?;
    }
    f.u32("key_value_store_size").emit()?;
    Ok(())
}

/// `key\0value\0` pairs; values reserved for later updates are padded with
/// NULs.
async fn key_values(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read(span).await?;
    let mut at = 0usize;
    while at < data.len() {
        let start = at;
        let key_end = data
            .get(at..)
            .and_then(|d| d.iter().position(|&b| b == 0))
            .map_or(data.len(), |p| at.saturating_add(p));
        let value_at = key_end.saturating_add(1);
        let value_end = data
            .get(value_at..)
            .and_then(|d| d.iter().position(|&b| b == 0))
            .map_or(data.len(), |p| value_at.saturating_add(p));
        let mut end = value_end.saturating_add(1).min(data.len());
        while data.get(end) == Some(&0) {
            end = end.saturating_add(1);
        }
        let key =
            String::from_utf8_lossy(data.get(start..key_end).unwrap_or_default()).into_owned();
        let value = String::from_utf8_lossy(
            data.get(value_at.min(value_end)..value_end)
                .unwrap_or_default(),
        )
        .into_owned();
        let mut node = Node::new(key)
            .span(span.sub(to_u64(start), to_u64(end.saturating_sub(start))))
            .value(text(value.clone()));
        if value.len() > 120 && value.contains(':') {
            node = node.summary(plural(to_u64(value.split(':').count()), "path"));
        }

        cx.push(node).await;
        if end <= start {
            break;
        }
        at = end;
    }
    Ok(())
}

fn dex_file(f: &mut Fields<'_>, _: &()) -> Result<()> {
    let len = f.u32("dex_file_location_size").emit()?;
    f.ascii("dex_file_location", len.into()).emit()?;
    f.ascii("dex_file_magic", 8).emit()?;
    f.u32("dex_file_location_checksum").hex().emit()?;
    f.bytes("dex_file_sha1", 20).emit()?;
    f.u32("dex_file_offset")
        .hex()
        .desc("Offset of the DEX file in the VDEX")
        .emit()?;
    f.u32("class_offsets_offset").hex().emit()?;
    f.u32("lookup_table_offset")
        .hex()
        .desc("Offset of the type lookup table in the VDEX")
        .emit()?;
    f.u32("dex_sections_layout_offset").hex().emit()?;
    for name in [
        "method_bss_mapping_offset",
        "type_bss_mapping_offset",
        "public_type_bss_mapping_offset",
        "package_type_bss_mapping_offset",
        "string_bss_mapping_offset",
        "method_type_bss_mapping_offset",
    ] {
        f.u32(name).hex().emit()?;
    }
    Ok(())
}

fn oat_class(f: &mut Fields<'_>, base: &u64) -> Result<()> {
    f.u16("status").enumeration(CLASS_STATUS).emit()?;
    let kind = f.u16("type").enumeration(CLASS_TYPE).emit()?;
    if kind == 2 {
        return Ok(());
    }
    let count = f.u32("num_methods").emit()?;
    let compiled = if kind == 1 {
        let words = count.div_ceil(32);
        let bitmap = f
            .bytes("bitmap", u64::from(words).saturating_mul(4))
            .emit()?;
        bitmap.iter().map(|b| b.count_ones()).sum::<u32>()
    } else {
        count
    };
    for _ in 0..compiled.min(1 << 16) {
        let base = *base;
        f.u32("code_offset")
            .hex()
            .with(move |&v, n| {
                n.summary(format!("file offset {:#x}", base.saturating_add(v.into())))
            })
            .emit()?;
    }
    Ok(())
}

/// The seven interleaved varints at the start of a CodeInfo: 4-bit values,
/// and for each value above 11, that many bytes minus 11 after the nibbles.
fn code_info_header(data: &[u8]) -> Option<[u32; 7]> {
    let bit = |i: usize| -> Option<u32> {
        let byte = data.get(i / 8)?;
        Some(u32::from((byte >> (i % 8)) & 1))
    };
    let bits = |at: usize, n: usize| -> Option<u32> {
        let mut v = 0u32;
        for k in 0..n.min(32) {
            v |= bit(at.checked_add(k)?)? << k;
        }
        Some(v)
    };
    let mut out = [0u32; 7];
    let mut pos = 28usize;
    for (i, slot) in out.iter_mut().enumerate() {
        let nib = bits(i.checked_mul(4)?, 4)?;
        *slot = nib;
    }
    for slot in &mut out {
        if *slot > 11 {
            let n = usize::try_from(slot.checked_sub(11)?)
                .ok()?
                .checked_mul(8)?;
            *slot = bits(pos, n)?;
            pos = pos.checked_add(n)?;
        }
    }
    Some(out)
}

const CODE_INFO_FIELDS: &[&str] = &[
    "flags",
    "code_size",
    "packed_frame_size",
    "core_spill_mask",
    "fp_spill_mask",
    "number_of_dex_registers",
    "bit_table_flags",
];

async fn code_info(cx: Cx, (span, values): (Span, [u32; 7])) -> Result<()> {
    for (name, v) in CODE_INFO_FIELDS.iter().zip(values) {
        let node = Node::new(*name).value(if name.ends_with("mask") {
            hex(v, 32)
        } else {
            crate::formats::util::val::uint(v, 32)
        });
        let node = if *name == "packed_frame_size" {
            node.summary(format!("{} bytes", u64::from(v).saturating_mul(16)))
        } else {
            node
        };
        cx.emit(node);
    }
    cx.emit(data_node("Encoded data", span, span.len).desc(
        "The header above as interleaved varints, then bit tables (stack maps, register masks, inline info, dex register maps)",
    ));
    Ok(())
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(embedded_as(
        "ELF",
        input.nested(file),
        &crate::formats::executable::elf::FORMAT,
    ));
    let (sections, syms) = symbols(&cx, file).await?;
    let sym_off = |name: &str| {
        syms.get(name)
            .and_then(|&(v, s)| Some((file_offset(&sections, v)?, s)))
    };
    let (oatdata_at, oatdata_len) = match sym_off("oatdata") {
        Some(v) => v,
        None => {
            let head = cx.read(file.sub(0, 64 << 10)).await?;
            let at = find_magic(&head)
                .ok_or_else(|| Diagnostic::malformed("no oatdata symbol or OAT header"))?;
            (to_u64(at), file.len.saturating_sub(to_u64(at)))
        }
    };
    let oatdata = file.sub(oatdata_at, oatdata_len.min(MAX_OATDATA));
    let data = cx.read(oatdata).await?;
    let l = parse_layout(&cx, &data, oatdata_at).await;
    let isa = name_or(ISA, l.isa.into(), "ISA");
    let dex_count = read_u32(&data, 20).unwrap_or(0);
    // Compiler filter from the key-value store.
    let kv = data
        .get(to_usize(l.kv.0)..to_usize(l.kv.0.saturating_add(l.kv.1)))
        .unwrap_or_default();
    let filter = kv
        .windows(16)
        .position(|w| w == b"compiler-filter\0")
        .map(|p| crate::text::until_nul(kv.get(p.saturating_add(16)..).unwrap_or_default()));
    let mut summary = format!(
        "Android OAT v{}, {isa}, {}",
        l.version,
        plural(dex_count, "DEX file")
    );
    if let Some(f) = &filter {
        summary = format!("{summary}, compiler filter {f}");
    }
    cx.annotate(summary);
    cx.emit(
        Node::new("OAT data")
            .span(oatdata)
            .summary(format!("{} at {oatdata_at:#x}", size(oatdata.len)))
            .lazy(oat_data, (oatdata, oatdata_at, l.clone())),
    );
    if let (Some((exec_at, _)), Some((last_at, _))) = (sym_off("oatexec"), sym_off("oatlastword")) {
        let code = file.sub(exec_at, last_at.saturating_add(4).saturating_sub(exec_at));
        let methods: BTreeSet<u32> = l
            .classes
            .iter()
            .flat_map(|c| c.4.iter().copied())
            .filter(|&o| o != 0)
            .collect();
        cx.emit(
            Node::new("Code")
                .span(code)
                .summary(format!(
                    "{}, {}",
                    size(code.len),
                    plural(to_u64(methods.len()), "compiled method")
                ))
                .lazy(
                    code_region,
                    (
                        code,
                        oatdata_at,
                        methods.into_iter().collect::<Vec<_>>(),
                        oatdata,
                    ),
                ),
        );
    }
    if let (Some((rel_at, _)), Some((rel_last, _))) = (
        sym_off("oatdataimgrelro"),
        sym_off("oatdataimgrelrolastword"),
    ) {
        let span = file.sub(rel_at, rel_last.saturating_add(4).saturating_sub(rel_at));
        cx.emit(
            Node::new("Boot image relocations")
                .span(span)
                .summary(count(span.len / 4, "entry", "entries"))
                .desc("Offsets of boot image ArtMethods and classes, patched at load time")
                .lazy(words, span),
        );
    }
    Ok(())
}

async fn words(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read(span).await?;
    for (i, w) in data.chunks(4).enumerate() {
        cx.push(
            Node::new(format!("{i}"))
                .span(span.sub(to_u64(i).saturating_mul(4), 4))
                .value(hex(u32_le(w, 0).unwrap_or(0), 32)),
        )
        .await;
    }
    Ok(())
}

async fn oat_data(cx: Cx, (span, base, l): (Span, u64, Layout)) -> Result<()> {
    let header_len = if l.header_end > 0 { l.header_end } else { 32 };
    cx.emit(struct_node(
        "Header",
        span.sub(0, header_len),
        LE,
        base,
        header,
    ));
    if l.version < KNOWN_VERSION {
        let rest = span.tail(header_len);
        cx.emit(
            data_node("Contents", rest, rest.len).diag(Diagnostic::unsupported(format!(
                "OAT version {}",
                l.version
            ))),
        );
        return Ok(());
    }
    // Everything else, in file order; the rest is padding.
    let mut parts: Vec<(u64, u64, Node)> = Vec::new();
    let kv_span = span.sub(l.kv.0, l.kv.1);
    parts.push((
        l.kv.0,
        l.kv.1,
        Node::new("Key-value store")
            .span(kv_span)
            .lazy(key_values, kv_span),
    ));
    for d in &l.dex_files {
        let s = span.sub(d.offset, d.size);
        parts.push((
            d.offset,
            d.size,
            struct_node(
                format!("OatDexFile {}", clip(&d.location, 80)),
                s,
                LE,
                (),
                dex_file,
            ),
        ));
        if d.class_count > 0 {
            let len = d.class_count.saturating_mul(4);
            let cs = span.sub(d.class_offsets, len);
            parts.push((
                d.class_offsets,
                len,
                Node::new("Class offsets")
                    .span(cs)
                    .summary(format!(
                        "{} classes of {}",
                        d.class_count,
                        clip(&d.location, 60)
                    ))
                    .lazy(words, cs),
            ));
        }
        if d.layout_sections > 0 && d.layout_sections < d.class_offsets {
            let len = d.class_offsets.saturating_sub(d.layout_sections).min(64);
            parts.push((
                d.layout_sections,
                len,
                data_node("Dex layout sections", span.sub(d.layout_sections, len), len)
                    .desc("Start and end of the DEX code sections by expected use, for madvise"),
            ));
        }
    }
    let class_span = l
        .classes
        .first()
        .zip(l.classes.last())
        .map(|(a, b)| (a.0, b.0.saturating_add(b.1)));
    if let Some((start, end)) = class_span {
        parts.push((
            start,
            end.saturating_sub(start),
            Node::new("OAT classes")
                .span(span.sub(start, end.saturating_sub(start)))
                .summary(count(to_u64(l.classes.len()), "class", "classes"))
                .lazy(oat_classes, (span, base, l.classes.clone())),
        ));
    }
    parts.sort_by_key(|p| p.0);
    let methods: Arc<Vec<u32>> = Arc::new(
        l.classes
            .iter()
            .flat_map(|c| c.4.iter().copied())
            .filter(|&o| o != 0)
            .collect::<BTreeSet<u32>>()
            .into_iter()
            .collect(),
    );
    let mut pos = header_len;
    for (at, len, node) in parts {
        if at > pos {
            cx.emit(gap(&cx, span, pos, at, &methods).await);
        }
        cx.emit(node);
        pos = pos.max(at.saturating_add(len));
    }
    if pos < span.len {
        cx.emit(gap(&cx, span, pos, span.len, &methods).await);
    }
    Ok(())
}

/// A stretch between known structures: padding when all zeros, otherwise
/// CodeInfo and other compiler metadata.
async fn gap(cx: &Cx, span: Span, from: u64, to: u64, methods: &Arc<Vec<u32>>) -> Node {
    let s = span.sub(from, to.saturating_sub(from));
    let zeros = cx.read(s).await.is_ok_and(|d| d.iter().all(|&b| b == 0));
    if zeros {
        Node::new("Padding").span(s).summary(size(s.len))
    } else {
        Node::new("Compiler metadata")
            .span(s)
            .summary(size(s.len))
            .desc("CodeInfo (stack maps) of the compiled methods and other compiler output")
            .lazy(metadata, (s, span, methods.clone()))
    }
}

/// The CodeInfo blobs that method headers point into `gap`, each up to the
/// next one.
async fn metadata(cx: Cx, (gap, oatdata, methods): (Span, Span, Arc<Vec<u32>>)) -> Result<()> {
    let mut starts = BTreeSet::new();
    for (i, &m) in methods.iter().enumerate() {
        if i.is_multiple_of(256) {
            cx.checkpoint().await;
        }
        let code_at = oatdata.offset.saturating_add(m.into());
        let Some(header_at) = code_at.checked_sub(4) else {
            continue;
        };
        let Ok(h) = cx.read(Span::new(oatdata.source, header_at, 4)).await else {
            continue;
        };
        let info_at = code_at.saturating_sub(u32_le(&h, 0).unwrap_or(0).into());
        if info_at >= gap.offset && info_at < gap.offset.saturating_add(gap.len) {
            starts.insert(info_at);
        }
    }
    let end = gap.offset.saturating_add(gap.len);
    let mut pos = gap.offset;
    let list: Vec<u64> = starts.into_iter().collect();
    for (i, &at) in list.iter().enumerate() {
        if at > pos {
            let s = Span::new(gap.source, pos, at.saturating_sub(pos));
            cx.push(data_node("Unknown", s, s.len)).await;
        }
        let next = list.get(i.saturating_add(1)).copied().unwrap_or(end);
        let s = Span::new(gap.source, at, next.saturating_sub(at));
        let head = cx.read(s.sub(0, 64)).await?;
        let mut node = Node::new(format!("CodeInfo at {at:#x}")).span(s);
        if let Some(values) = code_info_header(&head) {
            node = node
                .summary(format!(
                    "code {} bytes, frame {} bytes",
                    values[1],
                    u64::from(values[2]).saturating_mul(16)
                ))
                .lazy(code_info, (s, values));
        }
        cx.push(node).await;
        pos = next;
    }
    if pos < end {
        let s = Span::new(gap.source, pos, end.saturating_sub(pos));
        cx.push(data_node("Unknown", s, s.len)).await;
    }
    Ok(())
}

async fn oat_classes(cx: Cx, (span, base, classes): (Span, u64, Vec<OatClassInfo>)) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(classes.len())));
    for (i, (off, len, status, kind, methods)) in classes.into_iter().enumerate() {
        cx.push(
            struct_node(
                format!("OatClass {i}"),
                span.sub(off, len),
                LE,
                base,
                oat_class,
            )
            .summary(format!(
                "{}, {}, {}",
                lookup(CLASS_STATUS, status.into()).unwrap_or("?"),
                lookup(CLASS_TYPE, kind.into()).unwrap_or("?"),
                plural(to_u64(methods.len()), "compiled method")
            )),
        )
        .await;
    }
    Ok(())
}

/// The compiled methods: an `OatQuickMethodHeader` (the distance back to the
/// method's CodeInfo in the OAT data) right before each method's code.
async fn code_region(
    cx: Cx,
    (code, base, methods, oatdata): (Span, u64, Vec<u32>, Span),
) -> Result<()> {
    let file_start = code.offset;
    let mut pos = code.offset;
    let end = code.offset.saturating_add(code.len);
    let rel = |abs: u64| abs.saturating_sub(file_start);
    for (i, &m) in methods.iter().enumerate() {
        if i.is_multiple_of(256) {
            cx.checkpoint().await;
        }
        // Code offsets are relative to the OAT data.
        let code_at = oatdata.offset.saturating_add(m.into());
        let header_at = code_at.saturating_sub(4);
        if header_at < pos || code_at > end {
            continue;
        }
        if header_at > pos {
            let s = code.sub(rel(pos), header_at.saturating_sub(pos));
            cx.push(Node::new("Padding").span(s).summary(size(s.len)))
                .await;
        }
        let h = cx.read(code.sub(rel(header_at), 4)).await?;
        let info_offset = u32_le(&h, 0).unwrap_or(0);
        let info_at = code_at.saturating_sub(info_offset.into());
        let info = cx
            .read(Span::new(code.source, info_at, 64))
            .await
            .ok()
            .and_then(|d| code_info_header(&d));
        let code_size = info.map_or(0, |v| u64::from(v[1]));
        let next = methods.get(i.saturating_add(1)).map_or(end, |&n| {
            oatdata.offset.saturating_add(n.into()).saturating_sub(4)
        });
        let len = if code_size > 0 {
            code_size.min(end.saturating_sub(code_at))
        } else {
            next.saturating_sub(code_at)
        };
        let base_rel = code_at.saturating_sub(base);
        let mut node = Node::new(format!("Method at {code_at:#x}"))
            .span(code.sub(rel(header_at), len.saturating_add(4)))
            .summary(format!("{len} bytes of code"))
            .lazy(
                method,
                (
                    code.sub(rel(header_at), len.saturating_add(4)),
                    info_at,
                    info,
                    base_rel,
                ),
            );
        if code_size == 0 {
            node = node.diag(Diagnostic::warning("CodeInfo header unreadable"));
        }
        cx.push(node).await;
        pos = code_at.saturating_add(len);
    }
    if pos < end {
        let s = code.sub(rel(pos), end.saturating_sub(pos));
        cx.push(Node::new("Padding").span(s).summary(size(s.len)))
            .await;
    }
    Ok(())
}

async fn method(
    cx: Cx,
    (span, info_at, info, _rel): (Span, u64, Option<[u32; 7]>, u64),
) -> Result<()> {
    let block = cx.block(span.sub(0, 4)).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u32("code_info_offset")
        .hex()
        .with(|_, n| n.summary(format!("CodeInfo at {info_at:#x}")))
        .emit()?;
    let _ = info;
    let code = span.tail(4);
    cx.emit(data_node("Code", code, code.len).desc("Native code"));
    Ok(())
}
