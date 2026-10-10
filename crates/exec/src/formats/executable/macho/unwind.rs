//! Unwind information: the compact `__unwind_info` section (header, common
//! encodings, personalities, the first-level index, LSDA index and
//! second-level pages), DWARF `__eh_frame` (CIE and FDE headers) and the
//! object-file `__compact_unwind` entries.

use std::collections::BTreeMap;

use super::tables::*;
use super::{MachInfo, Macho, group};
use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::util::binutil::{Reader, get_at};
use crate::formats::util::fmt::size;
use crate::formats::util::val::{hex, text, uint};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::Value;

/// Describes a compact unwind encoding for the image's architecture.
pub(super) fn encoding_summary(cputype: u32, enc: u32) -> String {
    if enc == 0 {
        return "no unwind information".to_owned();
    }
    let mode = enc & 0x0f00_0000;
    let mut parts = Vec::new();
    match cputype {
        CPU_TYPE_ARM64 | CPU_TYPE_ARM64_32 => match mode {
            0x0200_0000 => parts.push(format!(
                "frameless, stack size {:#x}",
                ((enc >> 12) & 0xfff).saturating_mul(16)
            )),
            0x0300_0000 => parts.push(format!("DWARF FDE at {:#x}", enc & 0x00ff_ffff)),
            0x0400_0000 => {
                let mut s = "frame (fp, lr)".to_owned();
                for (bit, pair) in [
                    (0x1, "x19/x20"),
                    (0x2, "x21/x22"),
                    (0x4, "x23/x24"),
                    (0x8, "x25/x26"),
                    (0x10, "x27/x28"),
                    (0x100, "d8/d9"),
                    (0x200, "d10/d11"),
                    (0x400, "d12/d13"),
                    (0x800, "d14/d15"),
                ] {
                    if enc & bit != 0 {
                        s.push_str(&format!(", {pair}"));
                    }
                }
                parts.push(s);
            }
            m => parts.push(format!("mode {:#x}", m >> 24)),
        },
        CPU_TYPE_X86_64 | CPU_TYPE_X86 => {
            let names: &[&str] = if cputype == CPU_TYPE_X86_64 {
                &["-", "rbx", "r12", "r13", "r14", "r15", "rbp"]
            } else {
                &["-", "ebx", "ecx", "edx", "edi", "esi", "ebp"]
            };
            let word: u32 = if cputype == CPU_TYPE_X86_64 { 8 } else { 4 };
            match mode {
                0x0100_0000 => {
                    let offset = (enc >> 16) & 0xff;
                    let mut regs = Vec::new();
                    for i in 0..5u32 {
                        let r = (enc >> i.saturating_mul(3)) & 7;
                        if r != 0 {
                            regs.push(names.get(to_usize(r.into())).copied().unwrap_or("?"));
                        }
                    }
                    parts.push(format!(
                        "frame ({}), saved {} at {}-{:#x}",
                        names.get(6).copied().unwrap_or("bp"),
                        if regs.is_empty() {
                            "nothing".to_owned()
                        } else {
                            regs.join(", ")
                        },
                        names.get(6).copied().unwrap_or("bp"),
                        offset.saturating_mul(word)
                    ));
                }
                0x0200_0000 => parts.push(format!(
                    "frameless, stack size {:#x}",
                    ((enc >> 16) & 0xff).saturating_mul(word)
                )),
                0x0300_0000 => parts.push(format!(
                    "frameless, stack size in the sub instruction at +{:#x}",
                    (enc >> 16) & 0xff
                )),
                0x0400_0000 => parts.push(format!("DWARF FDE at {:#x}", enc & 0x00ff_ffff)),
                m => parts.push(format!("mode {:#x}", m >> 24)),
            }
        }
        _ => parts.push(format!("encoding {enc:#010x}")),
    }
    if enc & 0x4000_0000 != 0 {
        parts.push("has LSDA".to_owned());
    }
    let personality = (enc >> 28) & 3;
    if personality != 0 {
        parts.push(format!("personality {personality}"));
    }
    if enc & 0x8000_0000 != 0 {
        parts.push("not a function start".to_owned());
    }
    parts.join(", ")
}

fn encoding_node(
    name: impl Into<std::borrow::Cow<'static, str>>,
    span: Span,
    cputype: u32,
    enc: u32,
) -> Node {
    Node::new(name)
        .span(span)
        .value(hex(enc, 32))
        .summary(encoding_summary(cputype, enc))
}

// ---------------------------------------------------------------------------
// __unwind_info

record! {
    struct UnwindHeader {
        version: u32 "version",
        common_offset: u32 "commonEncodingsArraySectionOffset" .hex(),
        common_count: u32 "commonEncodingsArrayCount",
        personality_offset: u32 "personalityArraySectionOffset" .hex(),
        personality_count: u32 "personalityArrayCount",
        index_offset: u32 "indexSectionOffset" .hex(),
        index_count: u32 "indexCount" .desc("First-level index entries, including the sentinel"),
    }
}

#[derive(Clone, Copy, Debug)]
struct IndexEntry {
    function: u32,
    second_level: u32,
    lsda: u32,
}

pub(super) async fn unwind_info(cx: Cx, (m, index): (Macho, usize)) -> Result<()> {
    let s = m
        .sections
        .get(index)
        .ok_or_else(|| Diagnostic::internal("section index out of range"))?;
    let span = m.file().sub(s.offset.into(), s.size);
    let e = m.endian;
    let header = span.sub(0, UnwindHeader::SIZE);
    let h = parse(&cx, header, e, &(), UnwindHeader::layout).await?;
    cx.emit(UnwindHeader::node("Header", header, e).summary(format!("version {}", h.version)));
    if h.version != 1 {
        return Err(Diagnostic::unsupported(format!(
            "unwind info version {}",
            h.version
        )));
    }
    let common = span.sub(
        h.common_offset.into(),
        u64::from(h.common_count).saturating_mul(4),
    );
    if common.len > 0 {
        cx.emit(
            Node::new("Common Encodings")
                .span(common)
                .summary(grouped_count(h.common_count, "encoding", "encodings"))
                .desc("Encodings shared by all pages, referenced by index")
                .lazy(encodings, (m.clone(), common, 0u32)),
        );
    }
    let personalities = span.sub(
        h.personality_offset.into(),
        u64::from(h.personality_count).saturating_mul(4),
    );
    if personalities.len > 0 {
        cx.emit(
            Node::new("Personalities")
                .span(personalities)
                .summary(grouped_count(
                    h.personality_count,
                    "personality",
                    "personalities",
                ))
                .desc("Offsets of the GOT entries holding the personality routines (1-based)")
                .lazy(personality_list, (m.clone(), personalities)),
        );
    }
    let table = span.sub(
        h.index_offset.into(),
        u64::from(h.index_count).saturating_mul(12),
    );
    let raw = cx.read_avail(table).await?;
    let entries: Vec<IndexEntry> = raw
        .as_chunks::<12>()
        .0
        .iter()
        .map(|c| IndexEntry {
            function: get_at::<u32>(c, 0, e).unwrap_or(0),
            second_level: get_at::<u32>(c, 4, e).unwrap_or(0),
            lsda: get_at::<u32>(c, 8, e).unwrap_or(0),
        })
        .collect();
    let base = m.text_vmaddr();
    let mut index_nodes = Vec::new();
    for (i, entry) in entries.iter().enumerate() {
        cx.checkpoint().await;
        let at = table.sub(to_u64(i).saturating_mul(12), 12);
        let addr = base.saturating_add(entry.function.into());
        let sentinel = i.saturating_add(1) == entries.len();
        let mut fields = vec![
            Node::new("functionOffset")
                .span(at.sub(0, 4))
                .value(hex(entry.function, 32))
                .summary(m.describe(addr)),
            Node::new("secondLevelPagesSectionOffset")
                .span(at.sub(4, 4))
                .value(hex(entry.second_level, 32)),
            Node::new("lsdaIndexArraySectionOffset")
                .span(at.sub(8, 4))
                .value(hex(entry.lsda, 32)),
        ];
        if entry.second_level != 0
            && let Some(f) = fields.get_mut(1)
        {
            *f = f.clone().target(span.sub(entry.second_level.into(), 0));
        }
        index_nodes.push(
            group(format!("[{i}]"), at, fields)
                .value(hex(addr, 64))
                .summary(if sentinel {
                    "sentinel: end of the last function".to_owned()
                } else {
                    m.describe(addr)
                }),
        );
    }
    cx.emit(
        group("First-Level Index", table, index_nodes).summary(grouped_count(
            to_u64(entries.len()),
            "entry",
            "entries",
        )),
    );
    if let (Some(first), Some(last)) = (entries.first(), entries.last())
        && last.lsda > first.lsda
    {
        let lsda = span.sub(
            first.lsda.into(),
            u64::from(last.lsda.saturating_sub(first.lsda)),
        );
        cx.emit(
            Node::new("LSDA Index")
                .span(lsda)
                .summary(grouped_count(lsda.len / 8, "entry", "entries"))
                .desc("Functions with language-specific data (exception tables)")
                .lazy(lsda_index, (m.clone(), lsda)),
        );
    }
    let mut pages = Vec::new();
    for (i, entry) in entries.iter().enumerate() {
        cx.checkpoint().await;
        if entry.second_level == 0 {
            continue;
        }
        let page = span.tail(entry.second_level.into());
        let head = cx.read_avail(page.sub(0, 12)).await?;
        let kind = get_at::<u32>(&head, 0, e).unwrap_or(0);
        let entry_offset = get_at::<u16>(&head, 4, e).unwrap_or(0);
        let entry_count = get_at::<u16>(&head, 6, e).unwrap_or(0);
        let (len, label) = match kind {
            2 => (
                u64::from(entry_offset).saturating_add(u64::from(entry_count).saturating_mul(8)),
                "regular",
            ),
            3 => {
                let enc_offset = get_at::<u16>(&head, 8, e).unwrap_or(0);
                let enc_count = get_at::<u16>(&head, 10, e).unwrap_or(0);
                (
                    u64::from(entry_offset)
                        .saturating_add(u64::from(entry_count).saturating_mul(4))
                        .max(
                            u64::from(enc_offset)
                                .saturating_add(u64::from(enc_count).saturating_mul(4)),
                        ),
                    "compressed",
                )
            }
            _ => (8, "unknown kind"),
        };
        let page = page.sub(0, len);
        pages.push(
            Node::new(format!("Page {i}"))
                .span(page)
                .summary(format!(
                    "{label}, {}",
                    grouped_count(entry_count, "function", "functions")
                ))
                .lazy(
                    second_level_page,
                    (m.clone(), page, entry.function, h.common_count, common),
                ),
        );
    }
    if !pages.is_empty() {
        let first = pages.first().and_then(|p| p.span).map_or(0, |s| s.offset);
        let last = pages.last().and_then(|p| p.span).map_or(0, |s| s.end());
        let n = pages.len();
        cx.emit(
            group(
                "Second-Level Pages",
                Span::new(span.source, first, last.saturating_sub(first)),
                pages,
            )
            .summary(grouped_count(to_u64(n), "page", "pages")),
        );
    }
    Ok(())
}

async fn encodings(cx: Cx, (m, span, first): (Macho, Span, u32)) -> Result<()> {
    let data = cx.read_avail(span).await?;
    let n = to_u64(data.len()) / 4;
    cx.set_count(Count::Exact(n));
    for i in 0..n {
        let enc = get_at::<u32>(&data, i.saturating_mul(4), m.endian).unwrap_or(0);
        cx.push(encoding_node(
            format!("[{}]", u64::from(first).saturating_add(i)),
            span.sub(i.saturating_mul(4), 4),
            m.header.cputype,
            enc,
        ))
        .await;
    }
    Ok(())
}

async fn personality_list(cx: Cx, (m, span): (Macho, Span)) -> Result<()> {
    let data = cx.read_avail(span).await?;
    let n = to_u64(data.len()) / 4;
    for i in 0..n {
        let off = get_at::<u32>(&data, i.saturating_mul(4), m.endian).unwrap_or(0);
        let addr = m.text_vmaddr().saturating_add(off.into());
        let mut node = Node::new(format!("[{}]", i.saturating_add(1)))
            .span(span.sub(i.saturating_mul(4), 4))
            .value(hex(off, 32))
            .summary(m.describe(addr));
        if let Some(t) = m.vm_span(addr, m.word()) {
            node = node.target(t);
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn lsda_index(cx: Cx, (m, span): (Macho, Span)) -> Result<()> {
    let n = span.len / 8;
    cx.set_count(Count::Exact(n));
    let base = m.text_vmaddr();
    for i in 0..n {
        let at = span.sub(i.saturating_mul(8), 8);
        let data = cx.read(at).await?;
        let function = get_at::<u32>(&data, 0, m.endian).unwrap_or(0);
        let lsda = get_at::<u32>(&data, 4, m.endian).unwrap_or(0);
        let f = base.saturating_add(function.into());
        let l = base.saturating_add(lsda.into());
        cx.push(
            group(
                format!("[{i}]"),
                at,
                vec![
                    Node::new("functionOffset")
                        .span(at.sub(0, 4))
                        .value(hex(function, 32))
                        .summary(m.describe(f)),
                    Node::new("lsdaOffset")
                        .span(at.sub(4, 4))
                        .value(hex(lsda, 32))
                        .summary(m.describe(l)),
                ],
            )
            .value(hex(f, 64))
            .summary(format!("LSDA at {}", m.describe(l))),
        )
        .await;
    }
    Ok(())
}

async fn second_level_page(
    cx: Cx,
    (m, page, first_function, common_count, common): (Macho, Span, u32, u32, Span),
) -> Result<()> {
    let e = m.endian;
    let head = cx.read_avail(page.sub(0, 12)).await?;
    let kind = get_at::<u32>(&head, 0, e).unwrap_or(0);
    let entry_offset = get_at::<u16>(&head, 4, e).unwrap_or(0);
    let entry_count = get_at::<u16>(&head, 6, e).unwrap_or(0);
    let field = |name: &'static str, off: u64, len: u64, v: Value| {
        Node::new(name).span(page.sub(off, len)).value(v)
    };
    cx.emit(field(
        "kind",
        0,
        4,
        Value::Enum {
            raw: kind.into(),
            bits: 32,
            name: match kind {
                2 => Some("UNWIND_SECOND_LEVEL_REGULAR"),
                3 => Some("UNWIND_SECOND_LEVEL_COMPRESSED"),
                _ => None,
            },
        },
    ));
    cx.emit(field("entryPageOffset", 4, 2, hex(entry_offset, 16)));
    cx.emit(field("entryCount", 6, 2, uint(entry_count, 16)));
    match kind {
        2 => {
            let entries = page.sub(
                entry_offset.into(),
                u64::from(entry_count).saturating_mul(8),
            );
            cx.emit(
                Node::new("Entries")
                    .span(entries)
                    .summary(grouped_count(entry_count, "function", "functions"))
                    .lazy(regular_entries, (m.clone(), entries)),
            );
        }
        3 => {
            let enc_offset = get_at::<u16>(&head, 8, e).unwrap_or(0);
            let enc_count = get_at::<u16>(&head, 10, e).unwrap_or(0);
            cx.emit(field("encodingsPageOffset", 8, 2, hex(enc_offset, 16)));
            cx.emit(field("encodingsCount", 10, 2, uint(enc_count, 16)));
            let entries = page.sub(
                entry_offset.into(),
                u64::from(entry_count).saturating_mul(4),
            );
            let local = page.sub(enc_offset.into(), u64::from(enc_count).saturating_mul(4));
            cx.emit(
                Node::new("Entries")
                    .span(entries)
                    .summary(grouped_count(entry_count, "function", "functions"))
                    .desc("Function offset from the page's first function (24 bits), encoding index (8 bits)")
                    .lazy(
                        compressed_entries,
                        (m.clone(), entries, first_function, common_count, common, local),
                    ),
            );
            if local.len > 0 {
                cx.emit(
                    Node::new("Page Encodings")
                        .span(local)
                        .summary(grouped_count(enc_count, "encoding", "encodings"))
                        .lazy(encodings, (m.clone(), local, common_count)),
                );
            }
        }
        _ => {}
    }
    Ok(())
}

async fn regular_entries(cx: Cx, (m, span): (Macho, Span)) -> Result<()> {
    let n = span.len / 8;
    cx.set_count(Count::Exact(n));
    let base = m.text_vmaddr();
    for i in 0..n {
        let at = span.sub(i.saturating_mul(8), 8);
        let data = cx.read(at).await?;
        let function = get_at::<u32>(&data, 0, m.endian).unwrap_or(0);
        let enc = get_at::<u32>(&data, 4, m.endian).unwrap_or(0);
        let addr = base.saturating_add(function.into());
        cx.push(
            group(
                m.describe(addr),
                at,
                vec![
                    Node::new("functionOffset")
                        .span(at.sub(0, 4))
                        .value(hex(function, 32)),
                    encoding_node("encoding", at.sub(4, 4), m.header.cputype, enc),
                ],
            )
            .value(hex(addr, 64))
            .summary(encoding_summary(m.header.cputype, enc)),
        )
        .await;
    }
    Ok(())
}

async fn compressed_entries(
    cx: Cx,
    (m, span, first, common_count, common, local): (Macho, Span, u32, u32, Span, Span),
) -> Result<()> {
    let n = span.len / 4;
    cx.set_count(Count::Exact(n));
    let base = m.text_vmaddr().saturating_add(first.into());
    for i in 0..n {
        let at = span.sub(i.saturating_mul(4), 4);
        let data = cx.read(at).await?;
        let raw = get_at::<u32>(&data, 0, m.endian).unwrap_or(0);
        let offset = raw & 0x00ff_ffff;
        let index = raw >> 24;
        let (table, slot) = if index < common_count {
            (common, index)
        } else {
            (local, index.saturating_sub(common_count))
        };
        let enc_span = table.sub(u64::from(slot).saturating_mul(4), 4);
        let enc = match cx.read(enc_span).await {
            Ok(b) => get_at::<u32>(&b, 0, m.endian),
            Err(_) => None,
        };
        let addr = base.saturating_add(offset.into());
        let mut node = Node::new(m.describe(addr))
            .span(at)
            .value(hex(addr, 64))
            .summary(match enc {
                Some(enc) => format!(
                    "encoding {index} ({}): {}",
                    if index < common_count {
                        "common"
                    } else {
                        "page"
                    },
                    encoding_summary(m.header.cputype, enc)
                ),
                None => format!("encoding {index} (out of range)"),
            });
        if enc.is_some() {
            node = node.target(enc_span);
        }
        cx.push(node).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// __compact_unwind (object files)

pub(super) async fn compact_unwind(cx: Cx, (m, index): (Macho, usize)) -> Result<()> {
    let s = m
        .sections
        .get(index)
        .ok_or_else(|| Diagnostic::internal("section index out of range"))?;
    let span = m.file().sub(s.offset.into(), s.size);
    let w = m.word();
    let size = w.saturating_mul(3).saturating_add(8);
    let n = span.len.checked_div(size).unwrap_or(0);
    cx.set_count(Count::Exact(n));
    for i in 0..n {
        let at = span.sub(i.saturating_mul(size), size);
        let data = cx.read(at).await?;
        let word = |off: u64| {
            if m.wide {
                get_at::<u64>(&data, off, m.endian).unwrap_or(0)
            } else {
                get_at::<u32>(&data, off, m.endian).map_or(0, u64::from)
            }
        };
        let length = get_at::<u32>(&data, w, m.endian).unwrap_or(0);
        let enc = get_at::<u32>(&data, w.saturating_add(4), m.endian).unwrap_or(0);
        let p = w.saturating_add(8);
        cx.push(
            group(
                format!("[{i}]"),
                at,
                vec![
                    Node::new("functionStart")
                        .span(at.sub(0, w))
                        .value(hex(word(0), m.bits()))
                        .desc("Usually 0 here, set by a relocation"),
                    Node::new("length")
                        .span(at.sub(w, 4))
                        .value(hex(length, 32)),
                    encoding_node(
                        "encoding",
                        at.sub(w.saturating_add(4), 4),
                        m.header.cputype,
                        enc,
                    ),
                    Node::new("personality")
                        .span(at.sub(p, w))
                        .value(hex(word(p), m.bits())),
                    Node::new("lsda")
                        .span(at.sub(p.saturating_add(w), w))
                        .value(hex(word(p.saturating_add(w)), m.bits())),
                ],
            )
            .summary(format!(
                "{} bytes, {}",
                length,
                encoding_summary(m.header.cputype, enc)
            )),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// __eh_frame

#[derive(Clone, Copy, Debug, Default)]
struct Cie {
    augmented: bool,
    fde_encoding: u8,
    lsda_encoding: u8,
}

/// Reads a DWARF-encoded pointer (`DW_EH_PE_*`); `here` is the address of
/// the field, for pc-relative encodings.
fn encoded(r: &mut Reader<'_>, enc: u8, wide: bool, endian: Endian, here: u64) -> Option<u64> {
    if enc == 0xff {
        return None;
    }
    let value: i64 = match enc & 0x0f {
        0x00 => {
            if wide {
                i64::from_ne_bytes(r.int::<u64>(endian)?.to_ne_bytes())
            } else {
                r.int::<u32>(endian)?.into()
            }
        }
        0x01 => i64::from_ne_bytes(r.uleb()?.to_ne_bytes()),
        0x02 => r.int::<u16>(endian)?.into(),
        0x03 => r.int::<u32>(endian)?.into(),
        0x04 => i64::from_ne_bytes(r.int::<u64>(endian)?.to_ne_bytes()),
        0x09 => r.sleb()?,
        0x0a => r.int::<i16>(endian)?.into(),
        0x0b => r.int::<i32>(endian)?.into(),
        0x0c => r.int::<i64>(endian)?,
        _ => return None,
    };
    Some(if enc & 0x70 == 0x10 {
        here.wrapping_add_signed(value)
    } else {
        u64::from_ne_bytes(value.to_ne_bytes())
    })
}

fn encoding_name(enc: u8) -> String {
    if enc == 0xff {
        return "DW_EH_PE_omit".to_owned();
    }
    let format = match enc & 0x0f {
        0x00 => "absptr",
        0x01 => "uleb128",
        0x02 => "udata2",
        0x03 => "udata4",
        0x04 => "udata8",
        0x09 => "sleb128",
        0x0a => "sdata2",
        0x0b => "sdata4",
        0x0c => "sdata8",
        _ => "?",
    };
    let mut s = format!("DW_EH_PE_{format}");
    match enc & 0x70 {
        0x10 => s.push_str(" | pcrel"),
        0x20 => s.push_str(" | textrel"),
        0x30 => s.push_str(" | datarel"),
        0x40 => s.push_str(" | funcrel"),
        0x50 => s.push_str(" | aligned"),
        _ => {}
    }
    if enc & 0x80 != 0 {
        s.push_str(" | indirect");
    }
    s
}

/// How much of a record is read to decode its header.
const RECORD_HEAD: u64 = 0x400;

/// Parses a CIE's header from `data` (the record from its length field);
/// returns what FDEs need and the field nodes. `at` maps a range of `data`
/// to a span.
fn parse_cie(
    data: &[u8],
    header: usize,
    m: &MachInfo,
    at: &dyn Fn(usize, usize) -> Span,
    addr: u64,
) -> (Cie, Vec<Node>, String, usize) {
    let mut cie = Cie {
        fde_encoding: 0,
        lsda_encoding: 0xff,
        augmented: false,
    };
    let mut nodes = Vec::new();
    let mut r = Reader::at(data, header);
    let mut summary = Vec::new();
    let mut s = r.pos();
    let Some(version) = r.u8() else {
        return (cie, nodes, String::new(), r.pos());
    };
    nodes.push(
        Node::new("version")
            .span(at(s, r.pos()))
            .value(uint(version, 8)),
    );
    s = r.pos();
    let aug = r.cstr().unwrap_or_default();
    let aug = String::from_utf8_lossy(aug).into_owned();
    nodes.push(
        Node::new("augmentation")
            .span(at(s, r.pos()))
            .value(text(aug.clone())),
    );
    summary.push(format!("version {version}, augmentation \"{aug}\""));
    if aug.contains("eh") {
        s = r.pos();
        let v = if m.wide {
            r.int::<u64>(m.endian)
        } else {
            r.int::<u32>(m.endian).map(u64::from)
        };
        nodes.push(
            Node::new("eh_data")
                .span(at(s, r.pos()))
                .value(hex(v.unwrap_or(0), m.bits())),
        );
    }
    s = r.pos();
    if let Some(v) = r.uleb() {
        nodes.push(
            Node::new("code_alignment_factor")
                .span(at(s, r.pos()))
                .value(uint(v, 64)),
        );
    }
    s = r.pos();
    if let Some(v) = r.sleb() {
        nodes.push(
            Node::new("data_alignment_factor")
                .span(at(s, r.pos()))
                .value(Value::Int { value: v, bits: 64 }),
        );
        summary.push(format!("data alignment {v}"));
    }
    s = r.pos();
    let ra = if version == 1 {
        r.u8().map(u64::from)
    } else {
        r.uleb()
    };
    if let Some(v) = ra {
        nodes.push(
            Node::new("return_address_register")
                .span(at(s, r.pos()))
                .value(uint(v, 64)),
        );
    }
    if aug.starts_with('z') {
        cie.augmented = true;
        s = r.pos();
        let len = r.uleb().unwrap_or(0);
        nodes.push(
            Node::new("augmentation_length")
                .span(at(s, r.pos()))
                .value(uint(len, 64)),
        );
        let end = r.pos().saturating_add(to_usize(len));
        for c in aug.chars().skip(1) {
            s = r.pos();
            match c {
                'P' => {
                    let enc = r.u8().unwrap_or(0xff);
                    nodes.push(
                        Node::new("personality_encoding")
                            .span(at(s, r.pos()))
                            .value(hex(enc, 8))
                            .summary(encoding_name(enc)),
                    );
                    s = r.pos();
                    let here = addr.saturating_add(to_u64(s));
                    let p = encoded(&mut r, enc & 0x7f, m.wide, m.endian, here);
                    let mut node = Node::new("personality")
                        .span(at(s, r.pos()))
                        .value(hex(p.unwrap_or(0), 64));
                    if let Some(p) = p {
                        node = node.summary(m.describe(p));
                    }
                    nodes.push(node);
                }
                'L' => {
                    cie.lsda_encoding = r.u8().unwrap_or(0xff);
                    nodes.push(
                        Node::new("lsda_encoding")
                            .span(at(s, r.pos()))
                            .value(hex(cie.lsda_encoding, 8))
                            .summary(encoding_name(cie.lsda_encoding)),
                    );
                }
                'R' => {
                    cie.fde_encoding = r.u8().unwrap_or(0);
                    nodes.push(
                        Node::new("fde_encoding")
                            .span(at(s, r.pos()))
                            .value(hex(cie.fde_encoding, 8))
                            .summary(encoding_name(cie.fde_encoding)),
                    );
                }
                _ => {}
            }
            if r.pos() >= end {
                break;
            }
        }
        r = Reader::at(data, end);
    }
    (cie, nodes, summary.join(", "), r.pos())
}

pub(super) async fn eh_frame(cx: Cx, (m, index): (Macho, usize)) -> Result<()> {
    let s = m
        .sections
        .get(index)
        .ok_or_else(|| Diagnostic::internal("section index out of range"))?;
    let span = m.file().sub(s.offset.into(), s.size);
    let section_addr = s.addr;
    let mut cies: BTreeMap<u64, Cie> = BTreeMap::new();
    let mut pos = 0u64;
    while pos < span.len {
        let head = cx.read_avail(span.sub(pos, 12)).await?;
        let len32 = get_at::<u32>(&head, 0, m.endian).unwrap_or(0);
        if len32 == 0 {
            cx.push(
                Node::new("Terminator")
                    .span(span.sub(pos, 4))
                    .value(hex(0u32, 32))
                    .desc("A zero length ends the frame information"),
            )
            .await;
            pos = pos.saturating_add(4);
            if let Some(rest) = (pos < span.len).then(|| span.tail(pos)) {
                cx.push(Node::new("Padding").span(rest).summary(size(rest.len)))
                    .await;
            }
            break;
        }
        let (length, header) = if len32 == 0xffff_ffff {
            (get_at::<u64>(&head, 4, m.endian).unwrap_or(0), 12usize)
        } else {
            (u64::from(len32), 4usize)
        };
        let total = to_u64(header).saturating_add(length);
        let record = span.sub(pos, total);
        let data = cx.read_avail(record.sub(0, RECORD_HEAD)).await?;
        let at = |a: usize, b: usize| record.sub(to_u64(a), to_u64(b.saturating_sub(a)));
        let id_at = header;
        let id = get_at::<u32>(&data, to_u64(id_at), m.endian).unwrap_or(0);
        let mut nodes = vec![
            Node::new("length")
                .span(at(0, header))
                .value(hex(length, if header == 4 { 32 } else { 64 })),
        ];
        let record_addr = section_addr.saturating_add(pos);
        let (node, end) = if id == 0 {
            nodes.push(
                Node::new("CIE_id")
                    .span(at(id_at, id_at.saturating_add(4)))
                    .value(hex(0u32, 32)),
            );
            let (cie, fields, summary, end) =
                parse_cie(&data, id_at.saturating_add(4), &m, &at, record_addr);
            cies.insert(pos, cie);
            nodes.extend(fields);
            (("CIE", summary), end)
        } else {
            let cie_pos = pos.saturating_add(to_u64(id_at)).wrapping_sub(id.into());
            nodes.push(
                Node::new("CIE_pointer")
                    .span(at(id_at, id_at.saturating_add(4)))
                    .value(hex(id, 32))
                    .summary(format!("CIE at {cie_pos:#x}"))
                    .target(span.sub(cie_pos, 0)),
            );
            let cie = match cies.get(&cie_pos) {
                Some(c) => *c,
                None => {
                    // A CIE after its FDEs: read it on demand.
                    let cie_data = cx.read_avail(span.sub(cie_pos, RECORD_HEAD)).await?;
                    let cie_record = span.sub(cie_pos, RECORD_HEAD);
                    let cat =
                        |a: usize, b: usize| cie_record.sub(to_u64(a), to_u64(b.saturating_sub(a)));
                    let cie =
                        parse_cie(&cie_data, 8, &m, &cat, section_addr.saturating_add(cie_pos)).0;
                    cies.insert(cie_pos, cie);
                    cie
                }
            };
            let mut r = Reader::at(&data, id_at.saturating_add(4));
            let s = r.pos();
            let begin = encoded(
                &mut r,
                cie.fde_encoding,
                m.wide,
                m.endian,
                record_addr.saturating_add(to_u64(s)),
            )
            .unwrap_or(0);
            let mut field = Node::new("pc_begin")
                .span(at(s, r.pos()))
                .value(hex(begin, 64))
                .summary(m.describe(begin));
            if let Some(t) = m.vm_span(begin, 0) {
                field = field.target(t);
            }
            nodes.push(field);
            let s = r.pos();
            let range = encoded(&mut r, cie.fde_encoding & 0x0f, m.wide, m.endian, 0).unwrap_or(0);
            nodes.push(
                Node::new("pc_range")
                    .span(at(s, r.pos()))
                    .value(hex(range, 64)),
            );
            if cie.augmented {
                let s = r.pos();
                let len = r.uleb().unwrap_or(0);
                nodes.push(
                    Node::new("augmentation_length")
                        .span(at(s, r.pos()))
                        .value(uint(len, 64)),
                );
                let end = r.pos().saturating_add(to_usize(len));
                if cie.lsda_encoding != 0xff && len > 0 {
                    let s = r.pos();
                    let lsda = encoded(
                        &mut r,
                        cie.lsda_encoding,
                        m.wide,
                        m.endian,
                        record_addr.saturating_add(to_u64(s)),
                    )
                    .unwrap_or(0);
                    nodes.push(
                        Node::new("lsda")
                            .span(at(s, r.pos()))
                            .value(hex(lsda, 64))
                            .summary(m.describe(lsda)),
                    );
                }
                r = Reader::at(&data, end);
            }
            (
                (
                    "FDE",
                    format!("{}..{:#x}", m.describe(begin), begin.saturating_add(range)),
                ),
                r.pos(),
            )
        };
        let instructions = record.tail(to_u64(end));
        if instructions.len > 0 {
            nodes.push(
                Node::new("Call Frame Instructions")
                    .span(instructions)
                    .summary(size(instructions.len)),
            );
        }
        let (name, summary) = node;
        cx.progress_in(span, record.end());
        cx.push(group(name, record, nodes).summary(summary)).await;
        if total == 0 {
            break;
        }
        pos = pos.saturating_add(total);
    }
    Ok(())
}
