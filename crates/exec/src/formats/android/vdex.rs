//! Android VDEX files (`vdex`): verified DEX files and verifier
//! dependencies written by `dex2oat` next to OAT files.
//!
//! Version 027 (Android 12 and later) is a header and a section table: DEX
//! checksums, the DEX files back to back (shown as embedded DEX), the
//! verifier dependencies (per class: whether it verified, and which types
//! it relies on being assignable to which) and the type lookup tables (a
//! hash table from class descriptor to class definition per DEX). Names are
//! resolved through the DEX files' string, type and class tables. Older
//! versions are shown down to the header. Checked against `oatdump`.

use crate::bytes::{to_u64, to_usize, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse};
use crate::formats::util::binutil::{data_node, mutf8};
use crate::formats::util::fmt::{clip, count, plural};
use crate::formats::util::val::{hex, name_or, text, uint};
use crate::formats::{Format, Input, Probe, embedded_as};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::EnumTable;

const LE: Endian = Endian::Little;

pub static FORMAT: Format = Format {
    name: "vdex",
    title: "Android verified DEX container",
    extensions: &["vdex"],
    mime: "application/octet-stream",
    probe: Probe::Custom(|h| h.starts_with(b"vdex") && h.at(7, b"\0")),
    dissect: crate::expander!(dissect: Input),
};

const SECTION: EnumTable = &[
    (0, "kChecksumSection"),
    (1, "kDexFileSection"),
    (2, "kVerifierDepsSection"),
    (3, "kTypeLookupTableSection"),
];

/// Extra strings: offset in the section, length, text.
type Extra = std::sync::Arc<Vec<(u32, usize, String)>>;

/// Offset of a class that failed verification.
const NOT_VERIFIED: u32 = u32::MAX;
/// Largest section decoded in memory.
const MAX_SECTION: u64 = 64 << 20;

record! {
    struct Section {
        kind: u32 "section_kind" .enumeration(SECTION),
        offset: u32 "section_offset" .hex(),
        size: u32 "section_size" .hex(),
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 12)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("magic", 4).emit()?;
    let version = f.ascii("version", 4).emit()?;
    let number: u32 = version.parse().unwrap_or(0);
    if number < 27 {
        let rest = cx.block(file.sub(8, 20)).await?;
        let mut f = Fields::emitting(&cx, &rest, LE);
        f.ascii("dex_section_version", 4).emit()?;
        let dexes = f.u32("number_of_dex_files").emit()?;
        f.u32("verifier_deps_size").hex().emit()?;
        f.u32("bootclasspath_checksums_size").hex().emit()?;
        f.u32("class_loader_context_size").hex().emit()?;
        cx.annotate(format!(
            "Android VDEX v{version}, {}",
            plural(dexes, "DEX file")
        ));
        cx.emit(data_node(
            "Contents",
            file.tail(28),
            file.len.saturating_sub(28),
        ));
        return Ok(());
    }
    let n_sections = f.u32("number_of_sections").emit()?;
    let table = file.sub(12, u64::from(n_sections).saturating_mul(Section::SIZE));
    let n = table.len.checked_div(Section::SIZE).unwrap_or(0);
    let mut dexes = 0u64;
    let mut sections = Vec::new();
    for i in 0..n {
        let at = table.sub(i.saturating_mul(Section::SIZE), Section::SIZE);
        let s = parse(&cx, at, LE, &(), Section::layout).await?;
        if s.kind == 0 {
            dexes = u64::from(s.size) / 4;
        }
        sections.push((at, s));
    }
    cx.annotate(format!(
        "Android VDEX v{version}, {}",
        plural(dexes, "DEX file")
    ));
    let dex_section = sections
        .iter()
        .find(|(_, s)| s.kind == 1)
        .map(|(_, s)| file.sub(s.offset.into(), s.size.into()));
    let mut end = 12u64.saturating_add(table.len);
    for (at, s) in sections {
        let span = file.sub(s.offset.into(), s.size.into());
        let label = name_or(SECTION, s.kind.into(), "section");
        let node = Section::node(label, at, LE)
            .summary(format!("{:#x} bytes at {:#x}", s.size, s.offset))
            .target(span);
        cx.emit(node);
        end = end.max(u64::from(s.offset).saturating_add(s.size.into()));
        let dex = dex_section.unwrap_or(Span::new(file.source, file.offset, 0));
        match s.kind {
            0 => cx.emit(Node::new("Checksums").span(span).lazy(checksums, span)),
            1 if s.size > 0 => cx.emit(
                Node::new("DEX Files")
                    .span(span)
                    .lazy(dex_files, (input, span)),
            ),
            2 if s.size > 0 => cx.emit(
                Node::new("Verifier dependencies")
                    .span(span)
                    .summary(plural(dexes, "DEX file"))
                    .lazy(verifier_deps, (span, dex, dexes)),
            ),
            3 if s.size > 0 => cx.emit(
                Node::new("Type lookup tables")
                    .span(span)
                    .summary(plural(dexes, "DEX file"))
                    .lazy(lookup_tables, (span, dex)),
            ),
            _ if s.size > 0 => cx.emit(data_node(
                name_or(SECTION, s.kind.into(), "section"),
                span,
                s.size.into(),
            )),
            _ => {}
        }
    }
    // Section padding before the next one is aligned; anything after the
    // last section is reported.
    if end < file.len {
        let rest = file.tail(end);
        cx.emit(data_node("Trailing data", rest, rest.len));
    }
    Ok(())
}

async fn checksums(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read(span).await?;
    let count = to_u64(data.len()) / 4;
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let v = u32_le(&data, crate::bytes::to_usize(i.saturating_mul(4))).unwrap_or(0);
        cx.push(
            Node::new(format!("DEX {i}"))
                .span(span.sub(i.saturating_mul(4), 4))
                .value(hex(v, 32)),
        )
        .await;
    }
    Ok(())
}

/// The DEX files in the DEX section: back to back, each 4-aligned, sizes
/// from their headers.
async fn dex_spans(cx: &Cx, span: Span) -> Result<Vec<Span>> {
    let mut out = Vec::new();
    let mut offset = 0u64;
    while offset.saturating_add(0x70) <= span.len {
        let head = cx.read(span.sub(offset, 0x24)).await?;
        let size = u64::from(u32_le(&head, 0x20).unwrap_or(0));
        if size < 0x70 {
            break;
        }
        out.push(span.sub(offset, size));
        offset = offset
            .saturating_add(size)
            .checked_next_multiple_of(4)
            .unwrap_or(u64::MAX);
        if out.len() >= 4096 {
            break;
        }
    }
    Ok(out)
}

async fn dex_files(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    for (index, dex) in dex_spans(&cx, span).await?.into_iter().enumerate() {
        cx.push(embedded_as(
            format!("DEX {index}"),
            input.nested(dex),
            &super::dex::FORMAT,
        ))
        .await;
    }
    Ok(())
}

/// The tables of one DEX file needed to name strings and classes.
#[derive(Clone, Copy, Debug)]
struct DexRef {
    span: Span,
    strings: (u32, u32),
    types: (u32, u32),
    class_defs: (u32, u32),
}

impl DexRef {
    /// No DEX file to resolve names with.
    fn none() -> Self {
        DexRef {
            span: Span::zeros(0),
            strings: (0, 0),
            types: (0, 0),
            class_defs: (0, 0),
        }
    }
}

async fn dex_ref(cx: &Cx, span: Span) -> Result<DexRef> {
    let h = cx.read(span.sub(0, 0x70)).await?;
    let pair = |at: usize| {
        (
            u32_le(&h, at).unwrap_or(0),
            u32_le(&h, at.saturating_add(4)).unwrap_or(0),
        )
    };
    Ok(DexRef {
        span,
        strings: pair(0x38),
        types: pair(0x40),
        class_defs: pair(0x60),
    })
}

/// The MUTF-8 string whose `string_data_item` is at `off` in the DEX.
async fn string_at(cx: &Cx, dex: &DexRef, off: u32) -> Option<String> {
    let data = cx.read(dex.span.sub(off.into(), 520)).await.ok()?;
    let mut at = 0usize;
    // The UTF-16 length (ULEB128).
    while data.get(at).is_some_and(|&b| b & 0x80 != 0) {
        at = at.saturating_add(1);
    }
    at = at.saturating_add(1);
    let rest = data.get(at..)?;
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    Some(mutf8(rest.get(..end)?))
}

async fn string(cx: &Cx, dex: &DexRef, index: u32) -> Option<String> {
    if index >= dex.strings.0 {
        return None;
    }
    let at = u64::from(dex.strings.1).saturating_add(u64::from(index).saturating_mul(4));
    let off = u32_le(&cx.read(dex.span.sub(at, 4)).await.ok()?, 0)?;
    string_at(cx, dex, off).await
}

/// The descriptor of class definition `index`.
async fn class_name(cx: &Cx, dex: &DexRef, index: u32) -> Option<String> {
    if index >= dex.class_defs.0 {
        return None;
    }
    let at = u64::from(dex.class_defs.1).saturating_add(u64::from(index).saturating_mul(32));
    let type_idx = u32_le(&cx.read(dex.span.sub(at, 4)).await.ok()?, 0)?;
    if type_idx >= dex.types.0 {
        return None;
    }
    let at = u64::from(dex.types.1).saturating_add(u64::from(type_idx).saturating_mul(4));
    let string_idx = u32_le(&cx.read(dex.span.sub(at, 4)).await.ok()?, 0)?;
    string(cx, dex, string_idx).await
}

/// Per DEX file: an offset, then per class definition the offset of its
/// assignability set (or `0xFFFFFFFF` when it failed verification) plus an
/// end offset, the sets as ULEB128 (destination, source) string indices,
/// and the extra strings those indices may refer to past the DEX's own.
async fn verifier_deps(cx: Cx, (span, dex_section, dexes): (Span, Span, u64)) -> Result<()> {
    let data = cx.read(span.sub(0, span.len.min(MAX_SECTION))).await?;
    let dex_spans = dex_spans(&cx, dex_section).await?;
    let mut ends = Vec::new();
    for i in 0..dexes.min(4096) {
        ends.push(u32_le(&data, to_usize(i.saturating_mul(4))).unwrap_or(0));
    }
    cx.emit(
        Node::new("DEX offsets")
            .span(span.sub(0, dexes.saturating_mul(4)))
            .summary(plural(dexes, "offset")),
    );
    for (i, &start) in ends.iter().enumerate() {
        let next = ends
            .get(i.saturating_add(1))
            .map_or(span.len, |&n| u64::from(n));
        let part = span.sub(start.into(), next.saturating_sub(start.into()));
        let dex = match dex_spans.get(i) {
            Some(&d) => dex_ref(&cx, d).await?,
            None => DexRef::none(),
        };
        cx.push(
            Node::new(format!("DEX {i}"))
                .span(part)
                .summary(count(dex.class_defs.0, "class", "classes"))
                .lazy(deps_of_dex, (span, start, dex)),
        )
        .await;
    }
    Ok(())
}

async fn deps_of_dex(cx: Cx, (section, start, dex): (Span, u32, DexRef)) -> Result<()> {
    let data = cx
        .read(section.sub(0, section.len.min(MAX_SECTION)))
        .await?;
    let classes = dex.class_defs.0;
    let start = u64::from(start);
    let word = |at: u64| u32_le(&data, to_usize(at));
    let offsets_len = u64::from(classes).saturating_add(1).saturating_mul(4);
    let table = section.sub(start, offsets_len);
    let end = word(start.saturating_add(u64::from(classes).saturating_mul(4))).unwrap_or(0);
    // Extra strings follow the sets, 4-aligned.
    let strings_at = u64::from(end).next_multiple_of(4);
    let len = to_u64(data.len());
    if start >= len || u64::from(end) > len || strings_at.saturating_add(4) > len {
        cx.emit(
            data_node(
                "Dependencies",
                section.tail(start.min(len)),
                len.saturating_sub(start),
            )
            .diag(Diagnostic::malformed("offsets outside the section")),
        );
        return Ok(());
    }
    // Every string needs at least a u32 offset after the count.
    let room = len.saturating_sub(strings_at.saturating_add(4)) / 4;
    let extra_count = word(strings_at)
        .unwrap_or(0)
        .min(u32::try_from(room).unwrap_or(u32::MAX));
    let mut extra = Vec::new();
    for k in 0..extra_count.min(1 << 16) {
        if k.is_multiple_of(256) {
            cx.checkpoint().await;
        }
        let off = word(strings_at.saturating_add(u64::from(k).saturating_add(1).saturating_mul(4)))
            .unwrap_or(0);
        let rest = data.get(to_usize(off.into())..).unwrap_or_default();
        let rest = rest.get(..rest.len().min(4096)).unwrap_or_default();
        let len = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        extra.push((
            off,
            len,
            String::from_utf8_lossy(rest.get(..len).unwrap_or_default()).into_owned(),
        ));
    }
    let mut offsets = Vec::new();
    for c in 0..classes.min(1 << 20) {
        if c.is_multiple_of(1024) {
            cx.checkpoint().await;
        }
        offsets.push(
            word(start.saturating_add(u64::from(c).saturating_mul(4))).unwrap_or(NOT_VERIFIED),
        );
    }
    let verified = offsets.iter().filter(|&&o| o != NOT_VERIFIED).count();
    // Each set runs to the next verified class's offset (or the end).
    let mut sets = Vec::new();
    let mut next = end;
    for (c, &off) in offsets.iter().enumerate().rev() {
        if off != NOT_VERIFIED {
            if next > off && u64::from(next) <= len {
                sets.push((u32::try_from(c).unwrap_or(0), off, next));
            }
            next = off;
        }
    }
    sets.reverse();
    cx.emit(
        Node::new("Class offsets")
            .span(table)
            .summary(format!("{verified} of {classes} classes verified"))
            .lazy(class_offsets, (section, start, dex)),
    );
    let extra: Extra = std::sync::Arc::new(extra);
    for (c, off, next) in sets {
        let name = class_name(&cx, &dex, c)
            .await
            .unwrap_or_else(|| format!("class {c}"));
        let s = section.sub(off.into(), u64::from(next.saturating_sub(off)));
        let bytes = data
            .get(to_usize(off.into())..to_usize(next.into()))
            .unwrap_or_default();
        let pairs = uleb_pairs(bytes);
        cx.push(
            Node::new(format!("Assignability of {}", clip(&name, 100)))
                .span(s)
                .summary(plural(to_u64(pairs.len()), "pair"))
                .lazy(assignability, (s, dex, extra.clone())),
        )
        .await;
    }
    let after_sets = u64::from(end);
    if strings_at > after_sets {
        cx.push(
            Node::new("Padding")
                .span(section.sub(after_sets, strings_at.saturating_sub(after_sets))),
        )
        .await;
    }
    let mut strings_end =
        strings_at.saturating_add(u64::from(extra_count).saturating_add(1).saturating_mul(4));
    for (off, len, _) in extra.iter() {
        strings_end = strings_end.max(
            u64::from(*off)
                .saturating_add(to_u64(*len))
                .saturating_add(1),
        );
    }
    let strings = section.sub(strings_at, strings_end.saturating_sub(strings_at));
    cx.push(
        Node::new("Extra strings")
            .span(strings)
            .summary(plural(extra_count, "string"))
            .lazy(extra_strings, (strings, extra, strings_at)),
    )
    .await;
    Ok(())
}

/// ULEB128 pairs with their byte ranges.
fn uleb_pairs(bytes: &[u8]) -> Vec<(u32, u32, usize, usize)> {
    let mut out = Vec::new();
    let mut at = 0usize;
    let read = |at: &mut usize| -> Option<u32> {
        let mut v = 0u32;
        for shift in (0..35).step_by(7) {
            let b = *bytes.get(*at)?;
            *at = at.saturating_add(1);
            v |= u32::from(b & 0x7f).checked_shl(shift).unwrap_or(0);
            if b & 0x80 == 0 {
                return Some(v);
            }
        }
        Some(v)
    };
    while at < bytes.len() && out.len() < 1 << 16 {
        let start = at;
        let (Some(a), Some(b)) = (read(&mut at), read(&mut at)) else {
            break;
        };
        out.push((a, b, start, at.saturating_sub(start)));
    }
    out
}

async fn assignability(cx: Cx, (span, dex, extra): (Span, DexRef, Extra)) -> Result<()> {
    let bytes = cx.read(span).await?;
    for (dest, src, at, len) in uleb_pairs(&bytes) {
        let d = string_or_extra(&cx, &dex, &extra, dest).await;
        let s = string_or_extra(&cx, &dex, &extra, src).await;
        cx.push(
            Node::new(clip(&s, 100))
                .span(span.sub(to_u64(at), to_u64(len)))
                .value(text(format!("assignable to {d}")))
                .summary(format!("strings {src} → {dest}")),
        )
        .await;
    }
    Ok(())
}

/// A string index of the verifier dependencies: the DEX's own strings,
/// then the extra strings.
async fn string_or_extra(cx: &Cx, dex: &DexRef, extra: &[(u32, usize, String)], i: u32) -> String {
    match string(cx, dex, i).await {
        Some(s) => s,
        None => i
            .checked_sub(dex.strings.0)
            .and_then(|k| extra.get(to_usize(k.into())))
            .map_or_else(|| format!("string {i}"), |e| e.2.clone()),
    }
}

async fn class_offsets(cx: Cx, (section, start, dex): (Span, u64, DexRef)) -> Result<()> {
    let classes = dex.class_defs.0;
    let data = cx
        .read(section.sub(
            start,
            u64::from(classes).saturating_add(1).saturating_mul(4),
        ))
        .await?;
    for c in 0..=classes.min(1 << 20) {
        let v = u32_le(&data, to_usize(u64::from(c).saturating_mul(4))).unwrap_or(0);
        let span = section.sub(start.saturating_add(u64::from(c).saturating_mul(4)), 4);
        let node = if c == classes {
            Node::new("End").span(span).value(hex(v, 32))
        } else {
            let name = class_name(&cx, &dex, c)
                .await
                .unwrap_or_else(|| format!("class {c}"));
            let node = Node::new(clip(&name, 100)).span(span).value(hex(v, 32));
            if v == NOT_VERIFIED {
                node.summary("not verified")
            } else {
                node.summary("verified")
            }
        };
        cx.push(node).await;
    }
    Ok(())
}

async fn extra_strings(cx: Cx, (span, extra, base): (Span, Extra, u64)) -> Result<()> {
    let block = cx.block(span.sub(0, 4)).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u32("count").emit()?;
    for (k, (off, len, s)) in extra.iter().enumerate() {
        cx.push(
            Node::new(format!("{k}"))
                .span(Span::new(
                    span.source,
                    span.offset
                        .saturating_sub(base)
                        .saturating_add(u64::from(*off)),
                    to_u64(*len).saturating_add(1),
                ))
                .value(text(s.clone())),
        )
        .await;
    }
    Ok(())
}

/// Per DEX file: the table size, then `Entry { str_offset, data }` slots
/// (a power of two); `data` packs the hash bits, the class definition index
/// and the distance to the next entry of the chain.
async fn lookup_tables(cx: Cx, (span, dex_section): (Span, Span)) -> Result<()> {
    let dexes = dex_spans(&cx, dex_section).await?;
    let mut at = 0u64;
    let mut i = 0usize;
    while at.saturating_add(4) <= span.len {
        let size = u64::from(u32_le(&cx.read(span.sub(at, 4)).await?, 0).unwrap_or(0));
        let part = span.sub(at, size.saturating_add(4));
        let dex = match dexes.get(i) {
            Some(&d) => dex_ref(&cx, d).await?,
            None => DexRef::none(),
        };
        cx.push(
            Node::new(format!("DEX {i}"))
                .span(part)
                .summary(plural(size / 8, "slot"))
                .lazy(lookup_table, (part, dex)),
        )
        .await;
        at = at.saturating_add(size).saturating_add(4);
        i = i.saturating_add(1);
        if i >= 4096 {
            break;
        }
    }
    if at < span.len {
        let rest = span.tail(at);
        cx.push(data_node("Trailing data", rest, rest.len)).await;
    }
    Ok(())
}

async fn lookup_table(cx: Cx, (span, dex): (Span, DexRef)) -> Result<()> {
    let block = cx.block(span.sub(0, 4)).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    let size = f.u32("size").emit()?;
    let slots = size / 8;
    let mask_bits = slots.checked_ilog2().unwrap_or(0);
    let mask = (1u32 << mask_bits).saturating_sub(1);
    let data = cx.read(span.sub(4, u64::from(size))).await?;
    cx.set_count(Count::Exact(u64::from(slots).saturating_add(1)));
    for k in 0..slots.min(1 << 22) {
        let at = to_usize(u64::from(k).saturating_mul(8));
        let str_offset = u32_le(&data, at).unwrap_or(0);
        let value = u32_le(&data, at.saturating_add(4)).unwrap_or(0);
        let entry = span.sub(4u64.saturating_add(u64::from(k).saturating_mul(8)), 8);
        let node = if str_offset == 0 {
            Node::new(format!("{k}")).span(entry).summary("empty")
        } else {
            let delta = value & mask;
            let class_def = (value >> mask_bits) & mask;
            let name = string_at(&cx, &dex, str_offset)
                .await
                .unwrap_or_else(|| format!("string at {str_offset:#x}"));
            let mut s = format!("class def {class_def}");
            if delta != 0 {
                s = format!("{s}, next +{delta}");
            }
            Node::new(format!("{k}"))
                .span(entry)
                .value(text(name))
                .summary(s)
                .lazy(lookup_entry, (entry, mask_bits))
        };
        cx.push(node).await;
    }
    Ok(())
}

async fn lookup_entry(cx: Cx, (span, mask_bits): (Span, u32)) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u32("str_offset")
        .hex()
        .desc("Offset of the descriptor's string data in the DEX")
        .emit()?;
    let data = f.u32("data").hex().emit()?;
    let mask = (1u32 << mask_bits).saturating_sub(1);
    cx.emit(Node::new("next_pos_delta").value(uint(data & mask, 32)));
    cx.emit(Node::new("class_def_idx").value(uint((data >> mask_bits) & mask, 32)));
    cx.emit(Node::new("hash_bits").value(hex(
        data.checked_shr(mask_bits.saturating_mul(2)).unwrap_or(0),
        32,
    )));
    Ok(())
}
