//! `a.out` executables: the classic Unix format (OMAGIC, NMAGIC, ZMAGIC,
//! QMAGIC, as used by early Linux and the BSDs) and Plan 9's `a.out`.
//!
//! Both are a fixed header with segment sizes, followed by text, data,
//! (relocations,) a symbol table and, for Unix, a string table.

use crate::bytes::{to_u64, u32_be, u32_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::binutil::{data_node, hex, name_or};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::EnumTable;

pub static FORMAT: Format = Format {
    name: "aout",
    title: "Unix a.out executable",
    extensions: &["out", "o"],
    mime: "application/x-aout",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

pub static PLAN9: Format = Format {
    name: "plan9-aout",
    title: "Plan 9 a.out executable",
    extensions: &["out"],
    mime: "application/x-aout",
    probe: Probe::Custom(plan9_probe),
    dissect: crate::expander!(plan9: Input),
};

const OMAGIC: u32 = 0o407;
const NMAGIC: u32 = 0o410;
const ZMAGIC: u32 = 0o413;
const QMAGIC: u32 = 0o314;

const MAGIC: EnumTable = &[
    (0o407, "OMAGIC (impure)"),
    (0o410, "NMAGIC (pure text)"),
    (0o413, "ZMAGIC (demand paged)"),
    (0o314, "QMAGIC (compact demand paged)"),
];

const MACHINE: EnumTable = &[
    (0, "unknown"),
    (1, "M68010"),
    (2, "M68020"),
    (3, "SPARC"),
    (100, "i386"),
    (103, "i386 (NetBSD)"),
    (134, "i386 (NetBSD)"),
    (135, "M68K (NetBSD)"),
    (136, "M68K4K (NetBSD)"),
    (137, "NS32532 (NetBSD)"),
    (138, "SPARC (NetBSD)"),
    (139, "PMAX (NetBSD)"),
    (140, "VAX (NetBSD)"),
    (141, "Alpha (NetBSD)"),
    (142, "MIPS (NetBSD)"),
    (143, "ARM6 (NetBSD)"),
    (151, "MIPS1"),
    (152, "MIPS2"),
];

const SYMBOL_TYPE: EnumTable = &[
    (0x0, "N_UNDF"),
    (0x2, "N_ABS"),
    (0x4, "N_TEXT"),
    (0x6, "N_DATA"),
    (0x8, "N_BSS"),
    (0xa, "N_INDR"),
    (0x12, "N_COMM"),
    (0x14, "N_SETA"),
    (0x16, "N_SETT"),
    (0x18, "N_SETD"),
    (0x1a, "N_SETB"),
    (0x1e, "N_FN"),
];

/// How the header is stored: Linux keeps `a_info` little-endian with the
/// machine in bits 16..24; NetBSD stores `a_midmag` big-endian with the
/// machine in bits 16..26.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flavor {
    Linux,
    NetBsd,
}

fn flavor(data: &[u8]) -> Option<Flavor> {
    let le = u32_le(data, 0)?;
    let be = u32_be(data, 0)?;
    let ok = |m: u32| matches!(m & 0xffff, OMAGIC | NMAGIC | ZMAGIC | QMAGIC);
    if ok(le) && le >> 24 == 0 {
        Some(Flavor::Linux)
    } else if ok(be) {
        Some(Flavor::NetBsd)
    } else {
        None
    }
}

fn endian(f: Flavor) -> Endian {
    match f {
        Flavor::Linux => Endian::Little,
        Flavor::NetBsd => Endian::Big,
    }
}

#[derive(Clone, Copy, Debug)]
struct Exec {
    magic: u32,
    machine: u32,
    text: u32,
    data: u32,
    bss: u32,
    syms: u32,
    entry: u32,
    trsize: u32,
    drsize: u32,
}

impl Exec {
    fn text_offset(&self, flavor: Flavor) -> u64 {
        match (self.magic, flavor) {
            (ZMAGIC, Flavor::Linux) => 1024,
            (ZMAGIC | QMAGIC, _) => 0,
            _ => 32,
        }
    }

    /// Offsets of text, data, text relocations, data relocations, symbols
    /// and strings.
    fn layout(&self, flavor: Flavor) -> [u64; 6] {
        let text = self.text_offset(flavor);
        let data = text.saturating_add(self.text.into());
        let trel = data.saturating_add(self.data.into());
        let drel = trel.saturating_add(self.trsize.into());
        let syms = drel.saturating_add(self.drsize.into());
        let strs = syms.saturating_add(self.syms.into());
        [text, data, trel, drel, syms, strs]
    }
}

fn header(f: &mut Fields<'_>, flavor: &Flavor) -> Result<Exec> {
    let span = f.peek_span(4);
    let raw = f
        .u32(if *flavor == Flavor::Linux { "a_info" } else { "a_midmag" })
        .hex()
        .emit()?;
    let magic = raw & 0xffff;
    let machine = match flavor {
        Flavor::Linux => (raw >> 16) & 0xff,
        Flavor::NetBsd => (raw >> 16) & 0x3ff,
    };
    f.node(
        Node::new("magic")
            .span(span)
            .value(crate::value::Value::Enum {
                raw: magic.into(),
                bits: 16,
                name: crate::value::lookup(MAGIC, magic.into()),
            }),
    );
    f.node(
        Node::new("machine")
            .span(span)
            .value(crate::value::Value::Enum {
                raw: machine.into(),
                bits: 16,
                name: crate::value::lookup(MACHINE, machine.into()),
            }),
    );
    let text = f.u32("a_text").hex().desc("Text segment size").emit()?;
    let data = f.u32("a_data").hex().desc("Initialized data size").emit()?;
    let bss = f.u32("a_bss").hex().desc("Uninitialized data size").emit()?;
    let syms = f.u32("a_syms").hex().desc("Symbol table size").emit()?;
    let entry = f.u32("a_entry").hex().desc("Entry point").emit()?;
    let trsize = f.u32("a_trsize").hex().desc("Text relocation size").emit()?;
    let drsize = f.u32("a_drsize").hex().desc("Data relocation size").emit()?;
    Ok(Exec {
        magic,
        machine,
        text,
        data,
        bss,
        syms,
        entry,
        trsize,
        drsize,
    })
}

fn probe(h: &Head<'_>) -> bool {
    let Some(flavor) = flavor(h.data) else {
        return false;
    };
    let word = |i: usize| match flavor {
        Flavor::Linux => u32_le(h.data, i.saturating_mul(4)),
        Flavor::NetBsd => u32_be(h.data, i.saturating_mul(4)),
    };
    let (Some(text), Some(data), Some(syms), Some(trsize), Some(drsize)) =
        (word(1), word(2), word(4), word(6), word(7))
    else {
        return false;
    };
    let magic = word(0).unwrap_or(0) & 0xffff;
    let start = match (magic, flavor) {
        (ZMAGIC, Flavor::Linux) => 1024u64,
        (ZMAGIC | QMAGIC, _) => 0,
        _ => 32,
    };
    let total = [text, data, syms, trsize, drsize]
        .iter()
        .fold(start, |acc, &v| acc.saturating_add(v.into()));
    let machine = match flavor {
        Flavor::Linux => (word(0).unwrap_or(0) >> 16) & 0xff,
        Flavor::NetBsd => (word(0).unwrap_or(0) >> 16) & 0x3ff,
    };
    text > 0
        && total <= h.len
        && machine != 0
        && crate::value::lookup(MACHINE, machine.into()).is_some()
        && h.len >= 32
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 4)).await?;
    let flavor = flavor(&head).ok_or_else(|| Diagnostic::malformed("not an a.out header"))?;
    let e = endian(flavor);
    let hspan = file.sub(0, 32);
    cx.emit(struct_node("Exec Header", hspan, e, flavor, header));
    let x = parse(&cx, hspan, e, &flavor, header).await?;
    cx.annotate(format!(
        "a.out {}, {}, {}, text {:#x}, data {:#x}, bss {:#x}, entry {:#x}{}",
        name_or(MAGIC, x.magic.into(), "magic"),
        name_or(MACHINE, x.machine.into(), "machine"),
        if flavor == Flavor::Linux { "little-endian" } else { "big-endian" },
        x.text,
        x.data,
        x.bss,
        x.entry,
        if x.syms == 0 { ", stripped" } else { "" }
    ));
    let [text, data, trel, drel, syms, strs] = x.layout(flavor);
    for (name, at, size) in [
        ("Text", text, x.text),
        ("Data", data, x.data),
        ("Text Relocations", trel, x.trsize),
        ("Data Relocations", drel, x.drsize),
    ] {
        if size > 0 {
            cx.emit(data_node(name, file.sub(at, size.into()), size.into()));
        }
    }
    if x.syms > 0 {
        let table = file.sub(syms, x.syms.into());
        let size = cx.read_avail(file.sub(strs, 4)).await?;
        let size = match flavor {
            Flavor::Linux => u32_le(&size, 0),
            Flavor::NetBsd => u32_be(&size, 0),
        }
        .unwrap_or(0);
        let strings = file.sub(strs, size.into());
        cx.emit(
            Node::new("Symbols")
                .span(table)
                .summary(format!("{} symbols", table.len / 12))
                .lazy(symbols, (table, strings, e)),
        );
        cx.emit(
            Node::new("String Table")
                .span(strings)
                .lazy(crate::formats::binutil::cstrings, strings.tail(4)),
        );
    }
    Ok(())
}

async fn symbols(cx: Cx, (table, strings, e): (Span, Span, Endian)) -> Result<()> {
    let count = table.len / 12;
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let at = table.sub(i.saturating_mul(12), 12);
        let block = cx.block(at).await?;
        let mut f = Fields::new(&block, e);
        let strx = f.u32("n_strx").get()?;
        let kind = f.u8("n_type").get()?;
        f.u8("n_other").get()?;
        f.u16("n_desc").get()?;
        let value = f.u32("n_value").get()?;
        let name = if strx >= 4 {
            crate::formats::binutil::string_at(&cx, strings, strx.into())
                .await
                .map_or_else(|_| format!("#{i}"), |(s, _)| s)
        } else {
            format!("#{i}")
        };
        let mut summary = if kind >= 0x20 {
            format!("stab {kind:#x}")
        } else {
            name_or(SYMBOL_TYPE, (kind & 0x1e).into(), "type")
        };
        if kind & 1 != 0 && kind < 0x20 {
            summary.push_str(" | N_EXT");
        }
        cx.push(
            struct_node(name, at, e, (), nlist)
                .value(hex(value.into(), 32))
                .summary(summary),
        )
        .await;
    }
    Ok(())
}

fn nlist(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("n_strx").hex().emit()?;
    f.u8("n_type").hex().emit()?;
    f.u8("n_other").emit()?;
    f.u16("n_desc").hex().emit()?;
    f.u32("n_value").hex().emit()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Plan 9

const HDR_MAGIC: u32 = 0x8000;

/// `_MAGIC(b)`: `((4 * b) + 0) * b + 7`.
fn plan9_magic(b: u32) -> Option<u32> {
    b.checked_mul(b)?.checked_mul(4)?.checked_add(7)
}

const PLAN9_MACHINES: &[(u32, &str)] = &[
    (8, "68020"),
    (11, "386"),
    (12, "Intel 960"),
    (13, "SPARC"),
    (16, "MIPS 3000"),
    (17, "AT&T DSP 3210"),
    (18, "MIPS 4000 (big-endian)"),
    (19, "AMD 29000"),
    (20, "ARM"),
    (21, "PowerPC"),
    (22, "MIPS 4000 (little-endian)"),
    (23, "DEC Alpha"),
    (24, "MIPS 3000 (little-endian)"),
    (25, "SPARC64"),
    (26, "AMD64"),
    (27, "PowerPC64"),
    (28, "ARM64"),
];

fn plan9_machine(magic: u32) -> Option<&'static str> {
    let base = magic & !HDR_MAGIC;
    PLAN9_MACHINES
        .iter()
        .find(|(b, _)| plan9_magic(*b) == Some(base))
        .map(|(_, n)| *n)
}

fn plan9_probe(h: &Head<'_>) -> bool {
    let Some(magic) = u32_be(h.data, 0) else {
        return false;
    };
    let words: Vec<u64> = (1..8)
        .filter_map(|i: usize| u32_be(h.data, i.saturating_mul(4)).map(u64::from))
        .collect();
    let header = if magic & HDR_MAGIC != 0 { 40 } else { 32 };
    let sizes = [1usize, 2, 4, 6, 7]
        .iter()
        .filter_map(|&i| words.get(i.saturating_sub(1)))
        .fold(header as u64, |acc, &v| acc.saturating_add(v));
    plan9_machine(magic).is_some() && words.len() == 7 && sizes <= h.len && words.first().is_some_and(|&t| t > 0)
}

fn plan9_header(f: &mut Fields<'_>, _: &()) -> Result<[u32; 8]> {
    let magic = f
        .u32("magic")
        .hex()
        .with(|&v, n| n.summary(plan9_machine(v).unwrap_or("unknown")))
        .emit()?;
    let text = f.u32("text").hex().emit()?;
    let data = f.u32("data").hex().emit()?;
    let bss = f.u32("bss").hex().emit()?;
    let syms = f.u32("syms").hex().desc("Symbol table size").emit()?;
    let entry = f.u32("entry").hex().emit()?;
    let spsz = f.u32("spsz").hex().emit()?;
    let pcsz = f.u32("pcsz").hex().desc("PC/line table size").emit()?;
    if magic & HDR_MAGIC != 0 {
        f.u64("entry (64-bit)").hex().emit()?;
    }
    Ok([magic, text, data, bss, syms, entry, spsz, pcsz])
}

pub async fn plan9(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 4)).await?;
    let wide = u32_be(&head, 0).is_some_and(|m| m & HDR_MAGIC != 0);
    let hlen: u64 = if wide { 40 } else { 32 };
    let hspan = file.sub(0, hlen);
    cx.emit(struct_node("Header", hspan, Endian::Big, (), plan9_header));
    let [magic, text, data, bss, syms, entry, _spsz, pcsz] =
        parse(&cx, hspan, Endian::Big, &(), plan9_header).await?;
    cx.annotate(format!(
        "Plan 9 a.out, {}, text {text:#x}, data {data:#x}, bss {bss:#x}, entry {entry:#x}",
        plan9_machine(magic).unwrap_or("unknown machine")
    ));
    let mut at = hlen;
    for (name, size) in [("Text", text), ("Data", data)] {
        cx.emit(data_node(name, file.sub(at, size.into()), size.into()));
        at = at.saturating_add(size.into());
    }
    let table = file.sub(at, syms.into());
    if syms > 0 {
        cx.emit(
            Node::new("Symbols")
                .span(table)
                .lazy(plan9_symbols, (table, wide)),
        );
    }
    at = at.saturating_add(syms.into());
    if pcsz > 0 {
        cx.emit(data_node("PC/Line Table", file.sub(at, pcsz.into()), pcsz.into()));
    }
    Ok(())
}

async fn plan9_symbols(cx: Cx, (table, wide): (Span, bool)) -> Result<()> {
    let data = cx.read(table).await?;
    let width = if wide { 8 } else { 4 };
    let mut pos = 0usize;
    while pos < data.len() {
        let start = pos;
        let value = if wide {
            crate::bytes::u64_be(&data, pos)
        } else {
            u32_be(&data, pos).map(u64::from)
        };
        let (Some(value), Some(&kind)) = (value, data.get(pos.saturating_add(width))) else {
            return Err(Diagnostic::truncated(table.sub(to_u64(pos), 0), 0));
        };
        pos = pos.saturating_add(width).saturating_add(1);
        let kind = kind & 0x7f;
        let name = if matches!(kind, b'z' | b'Z') {
            // File names: a NUL then 16-bit indices of path components,
            // terminated by a zero index.
            pos = pos.saturating_add(1);
            let mut parts = Vec::new();
            while let Some(i) = crate::bytes::u16_be(&data, pos) {
                pos = pos.saturating_add(2);
                if i == 0 {
                    break;
                }
                parts.push(i.to_string());
            }
            format!("path [{}]", parts.join(" "))
        } else {
            let rest = data.get(pos..).unwrap_or_default();
            let n = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
            pos = pos.saturating_add(n).saturating_add(1);
            String::from_utf8_lossy(rest.get(..n).unwrap_or_default()).into_owned()
        };
        let kind_name = match kind {
            b'T' => "text (global)",
            b't' => "text (static)",
            b'L' => "leaf function (global)",
            b'l' => "leaf function (static)",
            b'D' => "data (global)",
            b'd' => "data (static)",
            b'B' => "bss (global)",
            b'b' => "bss (static)",
            b'a' => "automatic variable",
            b'p' => "parameter",
            b'f' => "file name index",
            b'z' | b'Z' => "source file",
            b'm' => "frame size",
            _ => "symbol",
        };
        cx.push(
            Node::new(name)
                .span(table.sub(to_u64(start), to_u64(pos.saturating_sub(start))))
                .value(hex(value, if wide { 64 } else { 32 }))
                .summary(format!("{} ({kind_name})", char::from(kind))),
        )
        .await;
    }
    Ok(())
}
