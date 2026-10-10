//! Universal ("fat") binaries: a big-endian header listing per-architecture
//! slices, each a complete Mach-O file.
//!
//! The magic `0xcafebabe` is shared with Java class files; there the next
//! word is the class version (major version 45 or more), here it is a small
//! architecture count.

use super::tables::{CPU_TYPE, arch_name, subtype_summary};
use crate::bytes::u32_be;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::util::fmt;
use crate::formats::{Format, Head, Input, Probe, embedded};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::lookup;

const BE: Endian = Endian::Big;
const FAT_MAGIC: u32 = 0xcafe_babe;
const FAT_MAGIC_64: u32 = 0xcafe_babf;
/// More architectures than this would be a Java class file.
const MAX_ARCHS: u32 = 30;

pub static FORMAT: Format = Format {
    name: "macho-fat",
    title: "Mach-O universal binary",
    extensions: &["dylib", "bundle", "a"],
    mime: "application/x-mach-binary",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    let magic = u32_be(h.data, 0);
    let count = u32_be(h.data, 4).unwrap_or(0);
    let cputype = u32_be(h.data, 8).unwrap_or(0);
    matches!(magic, Some(FAT_MAGIC | FAT_MAGIC_64))
        && (1..=MAX_ARCHS).contains(&count)
        && lookup(CPU_TYPE, cputype.into()).is_some()
}

#[derive(Clone, Copy, Debug)]
struct Arch {
    cputype: u32,
    cpusubtype: u32,
    offset: u64,
    size: u64,
    align: u32,
}

fn fat_header(f: &mut Fields<'_>, _: &()) -> Result<(bool, u32)> {
    let magic = f
        .u32("magic")
        .hex()
        .desc("FAT_MAGIC (0xcafebabe) or FAT_MAGIC_64 (0xcafebabf)")
        .emit()?;
    let count = f.u32("nfat_arch").emit()?;
    Ok((magic == FAT_MAGIC_64, count))
}

fn fat_arch(f: &mut Fields<'_>, (wide, file): &(bool, Span)) -> Result<Arch> {
    let cputype = f.u32("cputype").enumeration(CPU_TYPE).emit()?;
    let cpusubtype = f
        .u32("cpusubtype")
        .hex()
        .with(|&v, n| n.summary(subtype_summary(cputype, v)))
        .emit()?;
    let size = {
        let here = f.pos();
        f.skip(if *wide { 8 } else { 4 });
        let v = f.uword("", *wide).get().unwrap_or(0);
        f.seek(here);
        v
    };
    let offset = f
        .uword("offset", *wide)
        .hex()
        .with(|&v, n| n.target(file.sub(v, size)))
        .emit()?;
    let size = f.uword("size", *wide).hex().emit()?;
    let align = f
        .u32("align")
        .with(|&v, n| n.summary(format!("2^{v}")))
        .emit()?;
    if *wide {
        f.u32("reserved").emit()?;
    }
    Ok(Arch {
        cputype,
        cpusubtype,
        offset,
        size,
        align,
    })
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let header = file.sub(0, 8);
    cx.emit(struct_node("Fat Header", header, BE, (), fat_header));
    let (wide, count) = parse(&cx, header, BE, &(), fat_header).await?;
    if count > MAX_ARCHS {
        return Err(Diagnostic::malformed(format!("{count} architectures")).at(header));
    }
    let size: u64 = if wide { 32 } else { 20 };
    let table = file.sub_exact(8, u64::from(count).saturating_mul(size))?;
    let mut archs = Vec::new();
    for i in 0..u64::from(count) {
        let span = table.sub(i.saturating_mul(size), size);
        archs.push((span, parse(&cx, span, BE, &(wide, file), fat_arch).await?));
    }
    let names: Vec<String> = archs
        .iter()
        .map(|(_, a)| arch_name(a.cputype, a.cpusubtype))
        .collect();
    cx.annotate(format!(
        "Mach-O universal binary with {} architectures: {}",
        archs.len(),
        names.join(", ")
    ));
    cx.emit(
        Node::new("Architectures")
            .span(table)
            .summary(format!("{count} entries"))
            .lazy(arch_table, (table, wide, file)),
    );
    // The slices in file order, with the alignment padding before each.
    let mut slices: Vec<(Arch, String)> = archs.iter().map(|(_, a)| *a).zip(names).collect();
    slices.sort_by_key(|(a, _)| a.offset);
    let mut cursor = table.end().saturating_sub(file.offset);
    for (arch, name) in slices {
        if arch.offset > cursor && arch.offset <= file.len {
            let gap = file.sub(cursor, arch.offset.saturating_sub(cursor));
            let data = cx.read_avail(gap.sub(0, 0x1_0000)).await?;
            let zeros = data.iter().all(|&b| b == 0);
            cx.emit(
                Node::new(if zeros {
                    "Padding"
                } else {
                    "Unreferenced Data"
                })
                .span(gap)
                .summary(fmt::size(gap.len)),
            );
        }
        let slice = file.sub(arch.offset, arch.size);
        let mut node = embedded(name, input.nested(slice)).summary(format!(
            "{} at {:#x}, aligned to {:#x}",
            fmt::size(arch.size),
            arch.offset,
            1u64 << arch.align.min(63)
        ));
        if slice.len < arch.size {
            node = node.diag(Diagnostic::truncated(
                Span::new(slice.source, slice.offset, arch.size),
                slice.len,
            ));
        }
        cx.emit(node);
        cursor = cursor.max(arch.offset.saturating_add(arch.size));
    }
    if cursor < file.len {
        let rest = file.tail(cursor);
        cx.emit(
            Node::new("Trailing Data")
                .span(rest)
                .summary(fmt::size(rest.len)),
        );
    }
    Ok(())
}

async fn arch_table(cx: Cx, (table, wide, file): (Span, bool, Span)) -> Result<()> {
    let size: u64 = if wide { 32 } else { 20 };
    let count = table.len.checked_div(size).unwrap_or(0);
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let span = table.sub(i.saturating_mul(size), size);
        let arch = parse(&cx, span, BE, &(wide, file), fat_arch).await?;
        cx.push(
            struct_node(
                arch_name(arch.cputype, arch.cpusubtype),
                span,
                BE,
                (wide, file),
                fat_arch,
            )
            .summary(format!("{} at {:#x}", fmt::size(arch.size), arch.offset)),
        )
        .await;
    }
    Ok(())
}
