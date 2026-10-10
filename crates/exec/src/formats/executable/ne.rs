//! 16-bit "New Executable" files (Windows 3.x, OS/2 1.x): an MZ stub whose
//! `e_lfanew` points at an `NE` header with tables of segments, resources,
//! names, module references and entry points.
//!
//! Reached from the PE dissector, which recognises the `NE` signature.

use std::sync::Arc;

use super::pe::resource::content16;
use super::pe::tables::RESOURCE_TYPE;
use super::push_nodes;
use crate::bytes::{to_u64, u16_le, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::util::fmt::clip;
use crate::formats::util::val::name_or;
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, field, flag};

const LE: Endian = Endian::Little;

pub static FORMAT: Format = Format {
    name: "ne",
    title: "16-bit New Executable (Windows 3.x, OS/2)",
    extensions: &["exe", "dll", "drv", "fon", "mod", "386"],
    mime: "application/x-dosexec",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    h.starts_with(b"MZ")
        && u32_le(h.data, 0x3c).is_some_and(|o| h.at(crate::bytes::to_usize(o.into()), b"NE"))
}

const TARGET_OS: EnumTable = &[
    (0, "unknown"),
    (1, "OS/2"),
    (2, "Windows"),
    (3, "European MS-DOS 4.x"),
    (4, "Windows 386"),
    (5, "Borland Operating System Services"),
];

const FLAGS: FlagTable = &[
    field(0x3, 0x1, "SINGLEDATA"),
    field(0x3, 0x2, "MULTIPLEDATA"),
    flag(0x4, "GLOBALINIT"),
    flag(0x8, "PROTMODE"),
    flag(0x10, "8086"),
    flag(0x20, "80286"),
    flag(0x40, "80386"),
    flag(0x80, "80x87"),
    field(0x700, 0x100, "FULLSCREEN"),
    field(0x700, 0x200, "PM_COMPATIBLE"),
    field(0x700, 0x300, "PM_APP"),
    flag(0x800, "OS2_FAMILY"),
    flag(0x2000, "IMAGE_ERROR"),
    flag(0x4000, "NONCONFORMING"),
    flag(0x8000, "DLL"),
];

const SEGMENT_FLAGS: FlagTable = &[
    flag(0x1, "DATA"),
    flag(0x10, "MOVEABLE"),
    flag(0x20, "SHAREABLE"),
    flag(0x40, "PRELOAD"),
    flag(0x80, "READONLY/EXECUTEONLY"),
    flag(0x100, "RELOCINFO"),
    field(0xc00, 0x400, "DPL1"),
    field(0xc00, 0x800, "DPL2"),
    field(0xc00, 0xc00, "DPL3"),
    flag(0x1000, "DISCARDABLE"),
];

record! {
    struct NeHeader {
        magic: ascii[2] "ne_magic",
        ver: u8 "ne_ver" .desc("Linker version"),
        rev: u8 "ne_rev",
        enttab: u16 "ne_enttab" .hex() .desc("Entry table offset (from the NE header)"),
        cbenttab: u16 "ne_cbenttab" .hex(),
        crc: u32 "ne_crc" .hex(),
        flags: u16 "ne_flags" .flags(FLAGS),
        autodata: u16 "ne_autodata" .desc("Automatic data segment number"),
        heap: u16 "ne_heap" .hex(),
        stack: u16 "ne_stack" .hex(),
        csip: u32 "ne_csip" .hex() .desc("Initial CS:IP (segment number:offset)"),
        sssp: u32 "ne_sssp" .hex(),
        cseg: u16 "ne_cseg" .desc("Number of segments"),
        cmod: u16 "ne_cmod" .desc("Number of module references"),
        cbnrestab: u16 "ne_cbnrestab" .hex(),
        segtab: u16 "ne_segtab" .hex(),
        rsrctab: u16 "ne_rsrctab" .hex(),
        restab: u16 "ne_restab" .hex(),
        modtab: u16 "ne_modtab" .hex(),
        imptab: u16 "ne_imptab" .hex(),
        nrestab: u32 "ne_nrestab" .hex() .desc("Non-resident names (from the file start)"),
        cmovent: u16 "ne_cmovent",
        align: u16 "ne_align" .desc("Sector alignment shift"),
        cres: u16 "ne_cres",
        exetyp: u8 "ne_exetyp" .enumeration(TARGET_OS),
        flagsothers: u8 "ne_flagsothers" .hex(),
        pretthunks: u16 "ne_pretthunks" .hex(),
        psegrefbytes: u16 "ne_psegrefbytes" .hex(),
        swaparea: u16 "ne_swaparea" .hex(),
        expver: u16 "ne_expver" .hex() .with(|&v, n| n.summary(format!("{}.{}", v >> 8, v & 0xff))),
    }
}

record! {
    struct SegmentEntry {
        sector: u16 "Offset (sectors)" .hex(),
        length: u16 "Length" .hex() .desc("0 means 64 KiB"),
        flags: u16 "Flags" .flags(SEGMENT_FLAGS),
        min_alloc: u16 "MinAlloc" .hex(),
    }
}

/// A length-prefixed string at `at`, and the bytes it takes (NE and LX
/// name tables).
pub(super) fn pascal(data: &[u8], at: usize) -> Option<(String, usize)> {
    let n = usize::from(*data.get(at)?);
    let s = data.get(at.checked_add(1)?..at.checked_add(1)?.checked_add(n)?)?;
    Some((String::from_utf8_lossy(s).into_owned(), n.checked_add(1)?))
}

/// A names table: (name, ordinal) pairs ending at a zero length.
fn names(data: &[u8], mut at: usize) -> Vec<(String, u16, usize, usize)> {
    let mut out = Vec::new();
    while let Some((s, len)) = pascal(data, at) {
        if len <= 1 || out.len() >= 0x10000 {
            break;
        }
        let ordinal = u16_le(data, at.saturating_add(len)).unwrap_or(0);
        out.push((s, ordinal, at, len.saturating_add(2)));
        at = at.saturating_add(len).saturating_add(2);
    }
    out
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mz = cx.read_avail(file.sub(0, 64)).await?;
    let lfanew = u64::from(u32_le(&mz, 0x3c).unwrap_or(0));
    cx.emit(
        Node::new("MZ Header")
            .span(file.sub(0, 64))
            .desc("DOS header; e_lfanew points at the NE header"),
    );
    if lfanew > 64 {
        cx.emit(Node::new("DOS Stub").span(file.sub(64, lfanew.saturating_sub(64))));
    }
    let ne = file.tail(lfanew);
    let hspan = ne.sub(0, NeHeader::SIZE);
    cx.emit(NeHeader::node("NE Header", hspan, LE));
    let h = parse(&cx, hspan, LE, &(), NeHeader::layout).await?;
    // The tables (except non-resident names) lie between the header and
    // the first segment; read that region once.
    let tables = cx.read_avail(ne.sub(0, 0x1_0000)).await?;
    let shift = u32::from(h.align.min(16));

    let resident = names(&tables, h.restab.into());
    let module = resident
        .first()
        .map(|(s, ..)| s.clone())
        .unwrap_or_default();
    let nonres = cx
        .read_avail(file.sub(h.nrestab.into(), h.cbnrestab.into()))
        .await?;
    let description = pascal(&nonres, 0).map(|(s, _)| s).unwrap_or_default();
    let kind = if h.flags & 0x8000 != 0 {
        "DLL"
    } else {
        "executable"
    };
    cx.annotate(format!(
        "NE {kind} ({} {}), module {module}{}, {} segments",
        name_or(TARGET_OS, h.exetyp.into(), "OS"),
        format_args!("{}.{}", h.expver >> 8, h.expver & 0xff),
        if description.is_empty() {
            String::new()
        } else {
            format!(", {:?}", clip(&description, 80))
        },
        h.cseg
    ));

    // Segments.
    let segtab = ne.sub(h.segtab.into(), u64::from(h.cseg).saturating_mul(8));
    cx.emit(
        Node::new("Segment Table")
            .span(segtab)
            .summary(format!("{} segments", h.cseg))
            .lazy(segments, (file, segtab, shift)),
    );
    // Resources.
    if h.rsrctab != h.restab {
        let span = ne.sub(
            h.rsrctab.into(),
            u64::from(h.restab.saturating_sub(h.rsrctab)),
        );
        cx.emit(
            Node::new("Resource Table")
                .span(span)
                .lazy(resources, (input, span, h.expver >= 0x300)),
        );
    }
    // Names.
    let resident_span = ne.sub(
        h.restab.into(),
        u64::from(h.modtab.saturating_sub(h.restab)),
    );
    cx.emit(name_list("Resident Names", resident_span, &resident, ne));
    let nonres_span = file.sub(h.nrestab.into(), h.cbnrestab.into());
    let nonresident = names(&nonres, 0);
    cx.emit(name_list(
        "Non-resident Names",
        nonres_span,
        &nonresident,
        nonres_span,
    ));
    // Imported modules.
    let mut modules = Vec::new();
    for i in 0..usize::from(h.cmod) {
        let off = u16_le(
            &tables,
            usize::from(h.modtab).saturating_add(i.saturating_mul(2)),
        )
        .unwrap_or(0);
        let at = usize::from(h.imptab).saturating_add(off.into());
        if let Some((s, len)) = pascal(&tables, at) {
            modules.push(Node::new(s).span(ne.sub(to_u64(at), to_u64(len))));
        }
    }
    let modtab = ne.sub(h.modtab.into(), u64::from(h.cmod).saturating_mul(2));
    let names_list: Vec<String> = modules.iter().map(|n| n.name.to_string()).collect();
    cx.emit(
        Node::new("Module References")
            .span(modtab)
            .summary(clip(&names_list.join(", "), 120))
            .lazy(push_nodes, Arc::new(modules)),
    );
    // Entry points.
    let enttab = ne.sub(h.enttab.into(), h.cbenttab.into());
    cx.emit(Node::new("Entry Table").span(enttab).lazy(entries, enttab));
    Ok(())
}

fn name_list(
    label: &'static str,
    span: Span,
    list: &[(String, u16, usize, usize)],
    base: Span,
) -> Node {
    let nodes: Vec<Node> = list
        .iter()
        .enumerate()
        .map(|(i, (s, ord, at, len))| {
            let node = Node::new(s.clone()).span(base.sub(to_u64(*at), to_u64(*len)));
            if i == 0 {
                node.summary("module name / description")
            } else {
                node.summary(format!("ordinal {ord}"))
            }
        })
        .collect();
    Node::new(label)
        .span(span)
        .summary(format!("{} names", nodes.len()))
        .lazy(push_nodes, Arc::new(nodes))
}

async fn segments(cx: Cx, (file, table, shift): (Span, Span, u32)) -> Result<()> {
    let count = table.len / 8;
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let at = table.sub(i.saturating_mul(8), 8);
        let s = parse(&cx, at, LE, &(), SegmentEntry::layout).await?;
        let offset = u64::from(s.sector).checked_shl(shift).unwrap_or(0);
        let len = if s.length == 0 && s.sector != 0 {
            0x1_0000
        } else {
            u64::from(s.length)
        };
        let kind = if s.flags & 1 != 0 { "DATA" } else { "CODE" };
        let mut node = SegmentEntry::node(format!("Segment {}", i.saturating_add(1)), at, LE)
            .summary(format!("{kind}, {len:#x} bytes at {offset:#x}"));
        if s.sector != 0 {
            node = node.target(file.sub(offset, len));
        }
        cx.push(node).await;
    }
    Ok(())
}

/// The resource table. With `typed` (Windows 3.0 and later), resources of
/// the standard types are decoded as their type says.
async fn resources(cx: Cx, (input, span, typed): (Input, Span, bool)) -> Result<()> {
    let data = cx.read_avail(span).await?;
    let shift = u32::from(u16_le(&data, 0).unwrap_or(0).min(16));
    let file = input.span;
    cx.emit(
        Node::new("rscAlignShift")
            .span(span.sub(0, 2))
            .value(crate::formats::util::val::uint(shift, 16)),
    );
    let mut at = 2usize;
    while let Some(kind) = u16_le(&data, at) {
        if kind == 0 {
            break;
        }
        let count = usize::from(u16_le(&data, at.saturating_add(2)).unwrap_or(0));
        let ordinal_type = (kind & 0x8000 != 0).then_some(u32::from(kind & 0x7fff));
        let type_name = if let Some(t) = ordinal_type {
            name_or(RESOURCE_TYPE, t.into(), "type")
        } else {
            pascal(&data, kind.into()).map_or_else(|| format!("#{kind}"), |(s, _)| s)
        };
        let mut items = Vec::new();
        for i in 0..count {
            let e = at.saturating_add(8).saturating_add(i.saturating_mul(12));
            let w = |o: usize| u16_le(&data, e.saturating_add(o)).unwrap_or(0);
            let offset = u64::from(w(0)).checked_shl(shift).unwrap_or(0);
            let len = u64::from(w(2)).checked_shl(shift).unwrap_or(0);
            let id = w(6);
            let ordinal = (id & 0x8000 != 0).then_some(u32::from(id & 0x7fff));
            let name = if id & 0x8000 != 0 {
                format!("#{}", id & 0x7fff)
            } else {
                pascal(&data, id.into()).map_or_else(|| format!("@{id}"), |(s, _)| s)
            };
            let content = file.sub(offset, len);
            items.push(
                Node::new(name)
                    .span(content)
                    .lazy(
                        resource,
                        (input, content, ordinal_type.filter(|_| typed), ordinal),
                    )
                    .summary(format!("{len:#x} bytes at {offset:#x}"))
                    .target(span.sub(to_u64(e), 12)),
            );
        }
        let end = at
            .saturating_add(8)
            .saturating_add(count.saturating_mul(12));
        cx.push(
            Node::new(type_name)
                .span(span.sub(to_u64(at), to_u64(end.saturating_sub(at))))
                .summary(format!("{count} resources"))
                .lazy(push_nodes, Arc::new(items)),
        )
        .await;
        if end <= at {
            break;
        }
        at = end;
    }
    Ok(())
}

/// One resource's data, decoded by its type.
async fn resource(
    cx: Cx,
    (input, span, kind, name): (Input, Span, Option<u32>, Option<u32>),
) -> Result<()> {
    cx.emit(content16(&cx, input, span, kind, name).await);
    Ok(())
}

async fn entries(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read_avail(span).await?;
    let mut at = 0usize;
    let mut ordinal = 1u32;
    while let Some(&count) = data.get(at) {
        if count == 0 {
            break;
        }
        cx.checkpoint().await;
        let indicator = data.get(at.saturating_add(1)).copied().unwrap_or(0);
        at = at.saturating_add(2);
        for _ in 0..count {
            let (len, desc) = match indicator {
                0 => (0, None),
                0xff => {
                    let seg = data.get(at.saturating_add(3)).copied().unwrap_or(0);
                    let off = u16_le(&data, at.saturating_add(4)).unwrap_or(0);
                    (6, Some(format!("movable, segment {seg}:{off:#06x}")))
                }
                seg => {
                    let off = u16_le(&data, at.saturating_add(1)).unwrap_or(0);
                    (3, Some(format!("fixed, segment {seg}:{off:#06x}")))
                }
            };
            if let Some(d) = desc {
                let flags = data.get(at).copied().unwrap_or(0);
                let mut d = d;
                if flags & 1 != 0 {
                    d.push_str(", exported");
                }
                cx.push(
                    Node::new(format!("Ordinal {ordinal}"))
                        .span(span.sub(to_u64(at), len))
                        .summary(d),
                )
                .await;
            }
            at = at.saturating_add(crate::bytes::to_usize(len));
            ordinal = ordinal.saturating_add(1);
        }
        if at > data.len() {
            return Err(Diagnostic::truncated(span, to_u64(data.len())));
        }
    }
    Ok(())
}
