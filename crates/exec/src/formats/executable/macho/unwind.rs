//! Unwind information: the compact `__unwind_info` section (header, common
//! encodings, personalities, the first-level index, LSDA index and
//! second-level pages), DWARF `__eh_frame` (walked by
//! [`crate::formats::executable::eh_frame`]) and the
//! object-file `__compact_unwind` entries.

use super::tables::*;
use super::{MachInfo, Macho, group};
use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::util::binutil::get_at;
use crate::formats::util::val::{hex, uint};
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
                2 => Some("UNWIND_SECOND_LEVEL_REGULAR".into()),
                3 => Some("UNWIND_SECOND_LEVEL_COMPRESSED".into()),
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

impl crate::formats::executable::eh_frame::Image for MachInfo {
    fn endian(&self) -> Endian {
        self.endian
    }

    fn wide(&self) -> bool {
        self.wide
    }

    fn describe(&self, addr: u64) -> String {
        MachInfo::describe(self, addr)
    }

    fn target(&self, addr: u64) -> Option<Span> {
        self.vm_span(addr, 0)
    }

    fn arch(&self, eh: bool) -> crate::formats::executable::dwarf::Arch {
        use crate::formats::executable::dwarf::Arch;
        match self.arch() {
            Arch::X86 if eh => Arch::X86DarwinEh,
            arch => arch,
        }
    }
}

pub(super) async fn eh_frame(cx: Cx, (m, index): (Macho, usize)) -> Result<()> {
    let s = m
        .sections
        .get(index)
        .ok_or_else(|| Diagnostic::internal("section index out of range"))?;
    let span = m.file().sub(s.offset.into(), s.size);
    crate::formats::executable::eh_frame::walk(&cx, &*m, span, s.addr).await
}
