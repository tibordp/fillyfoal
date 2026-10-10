//! Section contents: strings, pointer and stub tables (with the symbols the
//! indirect symbol table assigns them and the fixups that rewrite them),
//! literals, initializers, thread-local descriptors, CFStrings, Objective-C
//! image info, Swift relative-pointer tables, unwind information and
//! embedded property lists or bitcode. Code and plain data are leaves.

use super::linkedit::pointer;
use super::symbols::indirect_entry;
use super::tables::*;
use super::{MachInfo, Macho, SectionInfo, group, section_summary};
use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Fields, struct_node};
use crate::formats::util::binutil::{Reader, cstrings, get_at};
use crate::formats::util::val::{hex, text};
use crate::formats::{embedded, embedded_as};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::text::hex_lower;

/// How a section's contents are shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Content {
    Strings,
    /// Pointers; `true` when the indirect symbol table names them.
    Pointers(bool),
    Stubs,
    Literals(u64),
    InitOffsets,
    ThreadVars,
    CfStrings,
    ObjcImageInfo,
    /// 32-bit self-relative offsets, with this many low bits of flags.
    Relative(u8),
    UnwindInfo,
    EhFrame,
    CompactUnwind,
    AddrSig,
    Plist,
    Embedded,
    Opaque,
}

fn content(s: &SectionInfo) -> Content {
    match s.kind() {
        S_CSTRING_LITERALS => return Content::Strings,
        S_NON_LAZY_SYMBOL_POINTERS
        | S_LAZY_SYMBOL_POINTERS
        | S_LAZY_DYLIB_SYMBOL_POINTERS
        | S_THREAD_LOCAL_VARIABLE_POINTERS => return Content::Pointers(true),
        S_MOD_INIT_FUNC_POINTERS
        | S_MOD_TERM_FUNC_POINTERS
        | S_LITERAL_POINTERS
        | S_INTERPOSING
        | S_THREAD_LOCAL_INIT_FUNCTION_POINTERS => return Content::Pointers(false),
        S_SYMBOL_STUBS => return Content::Stubs,
        S_4BYTE_LITERALS => return Content::Literals(4),
        S_8BYTE_LITERALS => return Content::Literals(8),
        S_16BYTE_LITERALS => return Content::Literals(16),
        S_INIT_FUNC_OFFSETS => return Content::InitOffsets,
        S_THREAD_LOCAL_VARIABLES => return Content::ThreadVars,
        _ => {}
    }
    match s.sectname.as_str() {
        "__objc_classlist" | "__objc_nlclslist" | "__objc_catlist" | "__objc_nlcatlist"
        | "__objc_catlist2" | "__objc_protolist" | "__objc_classrefs" | "__objc_superrefs"
        | "__objc_protorefs" | "__objc_selrefs" | "__auth_ptr" => Content::Pointers(false),
        "__objc_imageinfo" | "__image_info" => Content::ObjcImageInfo,
        "__cfstring" => Content::CfStrings,
        "__swift5_types" | "__swift5_types2" => Content::Relative(2),
        "__swift5_protos" => Content::Relative(1),
        "__swift5_proto" | "__swift5_entry" => Content::Relative(0),
        "__swift5_reflstr" | "__cmdline" => Content::Strings,
        "__unwind_info" => Content::UnwindInfo,
        "__eh_frame" => Content::EhFrame,
        "__compact_unwind" => Content::CompactUnwind,
        "__llvm_addrsig" => Content::AddrSig,
        "__info_plist" => Content::Plist,
        "__bitcode" => Content::Embedded,
        _ => Content::Opaque,
    }
}

/// The node for a section's contents.
pub(super) fn section_node(m: &Macho, index: usize) -> Node {
    let Some(s) = m.sections.get(index) else {
        return Node::new("?");
    };
    let span = m.file().sub(s.offset.into(), s.size);
    let in_own_segment = m
        .file_index
        .find(s.offset.into())
        .and_then(|i| m.segments.get(i))
        .is_some_and(|seg| seg.name == s.segname);
    let label = if in_own_segment {
        s.sectname.clone()
    } else {
        s.label()
    };
    let mut node = Node::new(label).span(span).summary(section_summary(s));
    if let Some(d) = section_description(&s.segname, &s.sectname) {
        node = node.desc(d);
    }
    if span.len < s.size {
        node = node.diag(Diagnostic::truncated(
            Span::new(span.source, span.offset, s.size),
            span.len,
        ));
    }
    let state = (m.clone(), index);
    match content(s) {
        Content::Strings => node.lazy(cstrings, span),
        Content::Pointers(_)
        | Content::Stubs
        | Content::Literals(_)
        | Content::InitOffsets
        | Content::ThreadVars
        | Content::CfStrings
        | Content::Relative(_) => node.lazy(entries, state),
        Content::ObjcImageInfo => node.lazy(objc_image_info, state),
        Content::UnwindInfo => node.lazy(super::unwind::unwind_info, state),
        Content::EhFrame => node.lazy(super::unwind::eh_frame, state),
        Content::CompactUnwind => node.lazy(super::unwind::compact_unwind, state),
        Content::AddrSig => node.lazy(addrsig, state),
        Content::Plist => {
            let summary = section_summary(s);
            embedded_as(
                "Info.plist",
                m.input.nested(span),
                &crate::formats::text::plist::FORMAT,
            )
            .summary(summary)
        }
        Content::Embedded => {
            let summary = section_summary(s);
            embedded(s.sectname.clone(), m.input.nested(span)).summary(summary)
        }
        Content::Opaque => node,
    }
}

/// The size of one entry of a table section.
fn stride(m: &MachInfo, s: &SectionInfo, kind: Content) -> u64 {
    match kind {
        Content::Stubs => s.reserved2.into(),
        Content::Literals(n) => n,
        Content::InitOffsets | Content::Relative(_) => 4,
        Content::ThreadVars => m.word().saturating_mul(3),
        Content::CfStrings => m.word().saturating_mul(4),
        _ => m.word(),
    }
}

/// Fixed-size entries of a table section, paged.
async fn entries(cx: Cx, (m, index): (Macho, usize)) -> Result<()> {
    let s = m
        .sections
        .get(index)
        .ok_or_else(|| Diagnostic::internal("section index out of range"))?;
    let kind = content(s);
    let data = m.file().sub(s.offset.into(), s.size);
    let size = stride(&m, s, kind);
    if size == 0 {
        return Err(Diagnostic::malformed("stub size is zero").at(data));
    }
    let count = data.len.checked_div(size).unwrap_or(0);
    if data.len.checked_rem(size).unwrap_or(0) != 0 {
        cx.diag(Diagnostic::malformed(format!(
            "section size {:#x} is not a multiple of the entry size {size:#x}",
            s.size
        )));
    }
    cx.set_count(Count::Exact(count));
    let start = cx.resume::<u64>().unwrap_or(0);
    for i in start..count {
        cx.mark(move || i);
        if cx.skipping() {
            cx.push(Node::new("")).await;
            continue;
        }
        let at = data.sub(i.saturating_mul(size), size);
        let addr = s.addr.saturating_add(i.saturating_mul(size));
        let node = entry(&cx, &m, s, kind, i, at, addr).await?;
        cx.push(node).await;
    }
    Ok(())
}

async fn entry(
    cx: &Cx,
    m: &MachInfo,
    s: &SectionInfo,
    kind: Content,
    i: u64,
    at: Span,
    addr: u64,
) -> Result<Node> {
    let bytes = cx.read(at).await?;
    let word = |off: u64| -> u64 {
        if m.wide {
            get_at::<u64>(&bytes, off, m.endian).unwrap_or(0)
        } else {
            get_at::<u32>(&bytes, off, m.endian).map_or(0, u64::from)
        }
    };
    let indirect = || u32::try_from(i).ok().map(|i| s.reserved1.saturating_add(i));
    Ok(match kind {
        Content::Pointers(named) => {
            let raw = word(0);
            let p = pointer(cx, m, addr, raw).await;
            let name = match (named, indirect()) {
                (true, Some(n)) => match indirect_entry(cx, m, n).await {
                    Ok(e) => e.label(),
                    Err(_) => format!("[{i}]"),
                },
                _ => format!("[{i}]"),
            };
            p.apply(Node::new(name).span(at))
        }
        Content::Stubs => {
            let name = match indirect().map(|n| indirect_entry(cx, m, n)) {
                Some(f) => f.await.map_or_else(|_| format!("[{i}]"), |e| e.label()),
                None => format!("[{i}]"),
            };
            Node::new(name)
                .span(at)
                .value(hex(addr, m.bits()))
                .summary(format!("stub {i}"))
        }
        Content::Literals(16) => Node::new(format!("[{i}]"))
            .span(at)
            .value(text(hex_lower(&bytes))),
        Content::Literals(width) => {
            let v = if width == 8 {
                get_at::<u64>(&bytes, 0, m.endian).unwrap_or(0)
            } else {
                get_at::<u32>(&bytes, 0, m.endian).map_or(0, u64::from)
            };
            let bits = if width == 8 { 64 } else { 32 };
            let float = if width == 8 {
                f64::from_bits(v)
            } else {
                f64::from(f32::from_bits(u32::try_from(v).unwrap_or(0)))
            };
            Node::new(format!("[{i}]"))
                .span(at)
                .value(hex(v, bits))
                .summary(format!("as floating point: {float}"))
        }
        Content::InitOffsets => {
            let off = get_at::<u32>(&bytes, 0, m.endian).unwrap_or(0);
            let target = m.text_vmaddr().saturating_add(off.into());
            let mut node = Node::new(format!("[{i}]"))
                .span(at)
                .value(hex(target, 64))
                .summary(format!("offset {off:#x}"));
            if let Some(t) = m.vm_span(target, 0) {
                node = node.target(t);
            }
            node
        }
        Content::ThreadVars => {
            let w = m.word();
            let mut fields = Vec::new();
            let mut summary = String::new();
            for (k, name) in ["thunk", "key", "offset"].into_iter().enumerate() {
                let off = to_u64(k).saturating_mul(w);
                let raw = word(off);
                let field = Node::new(name).span(at.sub(off, w));
                let field = if name == "thunk" {
                    let p = pointer(cx, m, addr.saturating_add(off), raw).await;
                    summary = p.summary.clone();
                    p.apply(field)
                        .desc("Function that finds the variable (tlv_get_addr)")
                } else if name == "key" {
                    field
                        .value(hex(raw, m.bits()))
                        .desc("pthread key, set by dyld")
                } else {
                    field
                        .value(hex(raw, m.bits()))
                        .desc("Offset of the variable in the thread's storage")
                };
                fields.push(field);
            }
            let name = format!("[{i}]");
            let offset = word(w.saturating_mul(2));
            group(name, at, fields)
                .value(hex(offset, m.bits()))
                .summary(if summary.is_empty() {
                    format!("offset {offset:#x}")
                } else {
                    format!("offset {offset:#x}, thunk {summary}")
                })
        }
        Content::CfStrings => {
            let w = m.word();
            let mut fields = Vec::new();
            let mut string = None;
            for (k, name) in ["isa", "flags", "str", "length"].into_iter().enumerate() {
                let off = to_u64(k).saturating_mul(w);
                let raw = word(off);
                let field = Node::new(name).span(at.sub(off, w));
                fields.push(match name {
                    "isa" | "str" => {
                        let p = pointer(cx, m, addr.saturating_add(off), raw).await;
                        if name == "str" {
                            string = p.address;
                        }
                        p.apply(field)
                    }
                    "flags" => field.value(hex(raw, m.bits())).summary(if raw & 0x4 != 0 {
                        "UTF-16"
                    } else {
                        "8-bit"
                    }),
                    _ => field.value(crate::formats::util::val::uint(raw, m.bits())),
                });
            }
            let len = word(w.saturating_mul(3));
            let utf16 = word(w) & 0x4 != 0;
            let wanted = if utf16 {
                len.saturating_mul(2)
            } else {
                len.saturating_add(1)
            };
            let value = match string.and_then(|a| m.vm_span(a, wanted)) {
                Some(t) if !utf16 => cx.cstr(t.sub(0, 4096)).await.map(|(s, _)| s).ok(),
                Some(t) => {
                    let b = cx.read_avail(t.sub(0, 8192)).await?;
                    Some(crate::text::utf16z(&b, m.endian).0)
                }
                None => None,
            };
            let node = group(format!("[{i}]"), at, fields);
            match value {
                Some(v) => node.value(text(v)).summary(format!("{len} characters")),
                None => node.summary(format!("{len} characters")),
            }
        }
        Content::Relative(flag_bits) => {
            let rel = get_at::<i32>(&bytes, 0, m.endian).unwrap_or(0);
            let mask = (1u32 << flag_bits).wrapping_sub(1);
            let flags = u32::from_ne_bytes(rel.to_ne_bytes()) & mask;
            let offset = i64::from(rel) & !i64::from(mask);
            if rel == 0 {
                return Ok(Node::new(format!("[{i}]"))
                    .span(at)
                    .value(text("null"))
                    .summary("no target"));
            }
            let target = addr.saturating_add_signed(offset);
            let delta = if rel < 0 {
                format!("-{:#x}", rel.unsigned_abs())
            } else {
                format!("+{rel:#x}")
            };
            let mut summary = format!("{} ({delta})", m.describe(target));
            if flag_bits == 2 {
                summary.push_str(match flags {
                    0 => ", direct type descriptor",
                    1 => ", indirect type descriptor",
                    2 => ", direct Objective-C class name",
                    _ => ", indirect Objective-C class",
                });
            } else if flag_bits == 1 && flags == 1 {
                summary.push_str(", indirect");
            }
            let mut node = Node::new(format!("[{i}]"))
                .span(at)
                .value(hex(target, 64))
                .summary(summary);
            if let Some(t) = m.vm_span(target, 0) {
                node = node.target(t);
            }
            node
        }
        _ => Node::new(format!("[{i}]")).span(at),
    })
}

fn objc_image_info_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("version").emit()?;
    f.u32("flags")
        .flags(OBJC_IMAGE_FLAGS)
        .with(|&v, n| {
            let stable = v >> 16;
            let unstable = (v >> 8) & 0xff;
            match (stable, unstable) {
                (0, 0) => n,
                (s, 0) => n.summary(format!("Swift ABI {s}")),
                (s, u) => n.summary(format!("Swift ABI {s}, pre-stable version {u}")),
            }
        })
        .emit()?;
    Ok(())
}

async fn objc_image_info(cx: Cx, (m, index): (Macho, usize)) -> Result<()> {
    let s = m
        .sections
        .get(index)
        .ok_or_else(|| Diagnostic::internal("section index out of range"))?;
    let span = m.file().sub(s.offset.into(), s.size.min(8));
    cx.emit(struct_node(
        "objc_image_info",
        span,
        m.endian,
        (),
        objc_image_info_layout,
    ));
    Ok(())
}

/// `__llvm_addrsig`: ULEB128 symbol table indices.
async fn addrsig(cx: Cx, (m, index): (Macho, usize)) -> Result<()> {
    let s = m
        .sections
        .get(index)
        .ok_or_else(|| Diagnostic::internal("section index out of range"))?;
    let span = m.file().sub(s.offset.into(), s.size);
    let data = cx.read(span).await?;
    let mut r = Reader::new(&data);
    while !r.at_end() {
        let start = r.pos();
        let Some(symbol) = r.uleb() else {
            return Err(Diagnostic::malformed("truncated ULEB128").at(span.tail(to_u64(start))));
        };
        let at = span.sub(to_u64(start), to_u64(r.pos().saturating_sub(start)));
        let name = match u32::try_from(symbol) {
            Ok(n) => super::symbols::symbol_name(&cx, &m, n)
                .await
                .unwrap_or_else(|_| format!("symbol #{symbol}")),
            Err(_) => format!("symbol #{symbol}"),
        };
        cx.push(
            Node::new(name)
                .span(at)
                .value(crate::formats::util::val::uint(symbol, 32)),
        )
        .await;
    }
    Ok(())
}
