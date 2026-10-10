//! Imports: the import directory (`IMAGE_IMPORT_DESCRIPTOR`s, each with an
//! import lookup table, an import address table and hint/name entries), the
//! delay-load directory (`IMAGE_DELAYLOAD_DESCRIPTOR`), bound imports
//! (`IMAGE_BOUND_IMPORT_DESCRIPTOR`) and the IAT directory.

use super::{
    Directory, LE, MAX_NAME, Pe, PeInfo, name_node, overflow, padding_node, read_name, rva_field,
};
use crate::bytes::{u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Fields, parse, struct_node};
use crate::formats::executable::pe::tables::{DIR_DELAY_IMPORT, DIR_IMPORT};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{Radix, Value};

const ORDINAL_FLAG_32: u64 = 0x8000_0000;
const ORDINAL_FLAG_64: u64 = 0x8000_0000_0000_0000;
/// Descriptor tables longer than this are cut off.
const MAX_MODULES: u32 = 1 << 14;
/// Thunk tables longer than this are cut off.
const MAX_THUNKS: u32 = 1 << 20;

fn ordinal_flag(pe: &PeInfo) -> u64 {
    if pe.wide {
        ORDINAL_FLAG_64
    } else {
        ORDINAL_FLAG_32
    }
}

fn thunk_value(pe: &PeInfo, data: &[u8]) -> u64 {
    if pe.wide {
        u64_le(data, 0)
    } else {
        u32_le(data, 0).map(u64::from)
    }
    .unwrap_or(0)
}

fn word_value(pe: &PeInfo, value: u64) -> Value {
    Value::UInt {
        value,
        bits: if pe.wide { 64 } else { 32 },
        radix: Radix::Hex,
    }
}

// ---------------------------------------------------------------------------
// Counting, for the image summary

/// `(DLLs, functions)` imported through the import directory.
pub(super) async fn count(cx: &Cx, pe: &PeInfo) -> Result<(u64, u64)> {
    let (rva, _) = pe.directory(DIR_IMPORT);
    if rva == 0 {
        return Ok((0, 0));
    }
    let (mut dlls, mut functions) = (0u64, 0u64);
    for i in 0..MAX_MODULES {
        let at = i
            .checked_mul(20)
            .and_then(|o| rva.checked_add(o))
            .ok_or_else(overflow)?;
        let d = cx.read(pe.rva_exact(at, 20)?).await?;
        if d.iter().all(|&b| b == 0) {
            break;
        }
        dlls = dlls.saturating_add(1);
        let lookup = u32_le(&d, 0).unwrap_or(0);
        let first = u32_le(&d, 16).unwrap_or(0);
        let table = if lookup != 0 { lookup } else { first };
        functions = functions.saturating_add(count_thunks(cx, pe, table).await);
    }
    Ok((dlls, functions))
}

/// The number of DLLs in the delay-load directory.
pub(super) async fn count_delay(cx: &Cx, pe: &PeInfo) -> Result<u64> {
    let (rva, _) = pe.directory(DIR_DELAY_IMPORT);
    if rva == 0 {
        return Ok(0);
    }
    let mut n = 0u64;
    for i in 0..MAX_MODULES {
        let at = i
            .checked_mul(32)
            .and_then(|o| rva.checked_add(o))
            .ok_or_else(overflow)?;
        let d = cx.read(pe.rva_exact(at, 32)?).await?;
        if d.iter().all(|&b| b == 0) {
            break;
        }
        n = n.saturating_add(1);
    }
    Ok(n)
}

/// Entries before the terminating zero of the thunk table at `rva`, read in
/// windows.
async fn count_thunks(cx: &Cx, pe: &PeInfo, rva: u32) -> u64 {
    count_thunks_ended(cx, pe, rva).await.0
}

/// Like [`count_thunks`]; also whether the terminating zero was found.
async fn count_thunks_ended(cx: &Cx, pe: &PeInfo, rva: u32) -> (u64, bool) {
    let width = usize::from(pe.wide).saturating_mul(4).saturating_add(4);
    let mut n = 0u64;
    let mut at = rva;
    while n < u64::from(MAX_THUNKS) {
        let Ok(span) = pe.rva_span(at, 4096) else {
            break;
        };
        let Ok(data) = cx.read_avail(span).await else {
            break;
        };
        let mut whole = 0usize;
        for chunk in data.chunks_exact(width) {
            if chunk.iter().all(|&b| b == 0) {
                return (n, true);
            }
            n = n.saturating_add(1);
            whole = whole.saturating_add(width);
        }
        if whole == 0 {
            break;
        }
        let Some(next) = u32::try_from(whole).ok().and_then(|w| at.checked_add(w)) else {
            break;
        };
        at = next;
    }
    (n, false)
}

// ---------------------------------------------------------------------------
// Import directory

#[derive(Clone, Copy, Debug)]
struct ImportDescriptor {
    lookup: u32,
    timestamp: u32,
    name: u32,
    address: u32,
    null: bool,
}

fn import_descriptor(f: &mut Fields<'_>, pe: &Pe) -> Result<ImportDescriptor> {
    let lookup = rva_field(f.u32("OriginalFirstThunk"), pe)
        .desc("RVA of the import lookup table (ILT)")
        .emit()?;
    let timestamp = f
        .u32("TimeDateStamp")
        .hex()
        .desc("0, or 0xffffffff if bound (new style), or the bound DLL's time stamp (old style)")
        .with(|&v, n| match v {
            0 => n.summary("not bound"),
            0xffff_ffff => n.summary("bound, see the bound import directory"),
            _ => n.summary("bound (old style)"),
        })
        .emit()?;
    let forwarder = f
        .u32("ForwarderChain")
        .hex()
        .desc("Index of the first forwarder reference (old-style binding), or -1")
        .emit()?;
    let name = rva_field(f.u32("Name"), pe)
        .desc("RVA of the DLL name")
        .emit()?;
    let address = rva_field(f.u32("FirstThunk"), pe)
        .desc("RVA of the import address table (IAT), overwritten by the loader")
        .emit()?;
    Ok(ImportDescriptor {
        lookup,
        timestamp,
        name,
        address,
        null: lookup | timestamp | forwarder | name | address == 0,
    })
}

pub(super) async fn imports(cx: Cx, (pe, dir): (Pe, Directory)) -> Result<()> {
    let mut rva = dir.rva;
    for _ in 0..MAX_MODULES {
        let span = pe.rva_span(rva, 20)?;
        let descriptor = parse(&cx, span, LE, &pe, import_descriptor).await?;
        if descriptor.null {
            cx.push(
                struct_node("Terminator", span, LE, pe.clone(), import_descriptor)
                    .summary("null descriptor, ends the table"),
            )
            .await;
            return Ok(());
        }
        let node = match read_name(&cx, &pe, descriptor.name).await {
            Ok((name, _)) => Node::new(name),
            Err(e) => Node::new("<unreadable name>").diag(e),
        };
        let table = if descriptor.lookup != 0 {
            descriptor.lookup
        } else {
            descriptor.address
        };
        let n = count_thunks(&cx, &pe, table).await;
        let mut summary = format!("{n} function{}", if n == 1 { "" } else { "s" });
        if descriptor.timestamp != 0 {
            summary.push_str(", bound");
        }
        cx.push(
            node.span(span)
                .summary(summary)
                .lazy(import_module, (pe.clone(), span)),
        )
        .await;
        rva = rva.checked_add(20).ok_or_else(overflow)?;
    }
    cx.diag(Diagnostic::limit(format!(
        "more than {MAX_MODULES} import descriptors"
    )));
    Ok(())
}

async fn import_module(cx: Cx, (pe, descriptor): (Pe, Span)) -> Result<()> {
    cx.emit(struct_node(
        "Import Descriptor",
        descriptor,
        LE,
        pe.clone(),
        import_descriptor,
    ));
    let d = parse(&cx, descriptor, LE, &pe, import_descriptor).await?;
    match read_name(&cx, &pe, d.name).await {
        Ok((name, at)) => cx.emit(name_node("Name", &name, at)),
        Err(e) => cx.diag(e),
    }
    let lookup = if d.lookup != 0 { d.lookup } else { d.address };
    // Descriptor, name, the functions and the end of the table.
    if let (n, true) = count_thunks_ended(&cx, &pe, lookup).await {
        cx.set_count(Count::Exact(n.saturating_add(3)));
    }
    let address = if d.lookup != 0 && d.address != d.lookup {
        Some(d.address)
    } else {
        None
    };
    walk_thunks(&cx, &pe, lookup, address, None, false).await
}

/// Lists the functions of one DLL: the lookup table (`lookup`), with the
/// address table (`address`) slot and hint/name entry of each.
/// `va_based`: the tables hold virtual addresses (old delay-load format).
async fn walk_thunks(
    cx: &Cx,
    pe: &Pe,
    lookup: u32,
    address: Option<u32>,
    va_based: Option<u64>,
    delay: bool,
) -> Result<()> {
    let width: u32 = if pe.wide { 8 } else { 4 };
    let flag = ordinal_flag(pe);
    for index in 0..MAX_THUNKS {
        let offset = index.checked_mul(width).ok_or_else(overflow)?;
        let rva = lookup.checked_add(offset).ok_or_else(overflow)?;
        let span = pe.rva_exact(rva, width.into())?;
        let thunk = thunk_value(pe, &cx.read(span).await?);
        let iat = match address {
            Some(a) => a
                .checked_add(offset)
                .and_then(|r| pe.rva_exact(r, width.into()).ok()),
            None => None,
        };
        if thunk == 0 {
            let node = Node::new("End of table")
                .span(span)
                .value(word_value(pe, 0))
                .desc("A zero entry ends the lookup table");
            cx.push(match iat {
                Some(iat) => node.lazy(terminator, (pe.clone(), span, iat)),
                None => node,
            })
            .await;
            return Ok(());
        }
        let (node, hint) = if thunk & flag != 0 {
            (
                Node::new(format!("Ordinal {}", thunk & 0xffff)).summary("by ordinal"),
                None,
            )
        } else {
            let target = match va_based {
                Some(base) => thunk.checked_sub(base),
                None => Some(thunk & 0x7fff_ffff),
            };
            let hint_rva = target.and_then(|t| u32::try_from(t).ok()).unwrap_or(0);
            match hint_and_name(cx, pe, hint_rva).await {
                Ok(h) => (
                    Node::new(h.name.clone())
                        .summary(format!("hint {}", h.hint))
                        .target(h.span),
                    Some(h),
                ),
                Err(e) => (Node::new("<unreadable>").diag(e), None),
            }
        };
        let node = node.span(span).value(word_value(pe, thunk)).lazy(
            function_parts,
            FunctionParts {
                pe: pe.clone(),
                lookup: span,
                iat,
                hint,
                delay,
            },
        );
        cx.push(node).await;
    }
    cx.diag(Diagnostic::limit(format!(
        "more than {MAX_THUNKS} imports from one DLL"
    )));
    Ok(())
}

#[derive(Clone)]
struct HintName {
    hint: u16,
    name: String,
    /// The whole entry, without padding.
    span: Span,
}

async fn hint_and_name(cx: &Cx, pe: &PeInfo, rva: u32) -> Result<HintName> {
    let span = pe.rva_span(rva, MAX_NAME.saturating_add(2))?;
    let hint = cx.read(span.sub(0, 2)).await?;
    let (name, at) = cx.cstr(span.tail(2)).await?;
    Ok(HintName {
        hint: u16_le(&hint, 0).unwrap_or(0),
        name,
        span: span.sub(0, at.len.saturating_add(2)),
    })
}

#[derive(Clone)]
struct FunctionParts {
    pe: Pe,
    lookup: Span,
    iat: Option<Span>,
    hint: Option<HintName>,
    /// A delay-load table: the address entries point to load thunks.
    delay: bool,
}

async fn function_parts(cx: Cx, p: FunctionParts) -> Result<()> {
    let flag = ordinal_flag(&p.pe);
    let thunk = thunk_value(&p.pe, &cx.read(p.lookup).await?);
    let meaning = if thunk & flag != 0 {
        format!("import by ordinal {}", thunk & 0xffff)
    } else {
        "RVA of the hint/name entry".to_owned()
    };
    cx.emit(
        Node::new("Lookup Entry")
            .span(p.lookup)
            .value(word_value(&p.pe, thunk))
            .summary(meaning),
    );
    if let Some(iat) = p.iat {
        let slot = thunk_value(&p.pe, &cx.read(iat).await?);
        cx.emit(
            Node::new("Address Entry")
                .span(iat)
                .value(word_value(&p.pe, slot))
                .summary(if p.delay {
                    "address of the delay-load thunk, replaced on first call"
                } else if slot == thunk {
                    "same as the lookup entry until the loader binds it"
                } else {
                    "pre-bound address"
                }),
        );
    }
    if let Some(h) = p.hint {
        cx.emit(
            Node::new("Hint")
                .span(h.span.sub(0, 2))
                .value(Value::UInt {
                    value: h.hint.into(),
                    bits: 16,
                    radix: Radix::Dec,
                })
                .desc("Index into the DLL's export name table to try first"),
        );
        cx.emit(name_node("Name", &h.name, h.span.tail(2)));
        // Entries are padded to an even length.
        if h.span.len % 2 == 1 {
            let pad = Span::new(h.span.source, h.span.end(), 1);
            cx.emit(padding_node(
                "Padding",
                pad,
                "Pads the entry to an even length",
            ));
        }
    }
    Ok(())
}

async fn terminator(cx: Cx, (pe, lookup, iat): (Pe, Span, Span)) -> Result<()> {
    cx.emit(
        Node::new("Lookup Entry")
            .span(lookup)
            .value(word_value(&pe, 0)),
    );
    let slot = thunk_value(&pe, &cx.read(iat).await?);
    cx.emit(
        Node::new("Address Entry")
            .span(iat)
            .value(word_value(&pe, slot)),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// IAT directory

/// The import address tables of all DLLs, slot by slot.
pub(super) async fn iat(cx: Cx, (pe, dir): (Pe, Directory)) -> Result<()> {
    let width = pe.word();
    let count = dir.span.len.checked_div(width).unwrap_or(0);
    cx.set_count(Count::Exact(count));
    let flag = ordinal_flag(&pe);
    for i in 0..count {
        let span = dir.span.sub(i.saturating_mul(width), width);
        let value = thunk_value(&pe, &cx.read(span).await?);
        let summary = if value == 0 {
            "end of a DLL's table".to_owned()
        } else if value & flag != 0 {
            format!("ordinal {}", value & 0xffff)
        } else {
            match u32::try_from(value)
                .ok()
                .filter(|&v| u64::from(v) < pe.image_base.max(1u64 << 31))
            {
                Some(rva) => match hint_and_name(&cx, &pe, rva).await {
                    Ok(h) => h.name,
                    Err(_) => "address".to_owned(),
                },
                None => "address".to_owned(),
            }
        };
        cx.push(
            Node::new(format!("#{i}"))
                .span(span)
                .value(word_value(&pe, value))
                .summary(summary),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Delay-load imports

#[derive(Clone, Copy, Debug)]
struct DelayDescriptor {
    attributes: u32,
    name: u32,
    module: u32,
    iat: u32,
    int: u32,
    bound: u32,
    unload: u32,
}

impl DelayDescriptor {
    fn is_null(&self) -> bool {
        self.attributes | self.name | self.module | self.iat | self.int | self.bound | self.unload
            == 0
    }
}

fn delay_descriptor(f: &mut Fields<'_>, pe: &Pe) -> Result<DelayDescriptor> {
    let attributes = f
        .u32("Attributes")
        .hex()
        .desc("Bit 0 set: the fields below are RVAs (otherwise virtual addresses, VC6 style)")
        .with(|&v, n| {
            n.summary(if v & 1 != 0 {
                "RVA-based"
            } else {
                "VA-based (legacy)"
            })
        })
        .emit()?;
    let name = rva_field(f.u32("DllNameRVA"), pe).emit()?;
    let module = rva_field(f.u32("ModuleHandleRVA"), pe)
        .desc("Where the helper stores the HMODULE")
        .emit()?;
    let iat = rva_field(f.u32("ImportAddressTableRVA"), pe)
        .desc("Delay IAT: initially points to the load thunks")
        .emit()?;
    let int = rva_field(f.u32("ImportNameTableRVA"), pe)
        .desc("Delay INT: like an import lookup table")
        .emit()?;
    let bound = rva_field(f.u32("BoundImportAddressTableRVA"), pe).emit()?;
    let unload = rva_field(f.u32("UnloadInformationTableRVA"), pe)
        .desc("Copy of the IAT, restored when the DLL is unloaded")
        .emit()?;
    f.u32("TimeDateStamp")
        .hex()
        .desc("Time stamp of the DLL the image was bound to, or 0")
        .emit()?;
    Ok(DelayDescriptor {
        attributes,
        name,
        module,
        iat,
        int,
        bound,
        unload,
    })
}

impl DelayDescriptor {
    /// Converts a field to an RVA (VA-based descriptors hold addresses).
    fn rva(&self, pe: &PeInfo, value: u32) -> Option<u32> {
        if value == 0 {
            None
        } else if self.attributes & 1 != 0 {
            Some(value)
        } else {
            pe.va_rva(value.into())
        }
    }
}

pub(super) async fn delay_imports(cx: Cx, (pe, dir): (Pe, Directory)) -> Result<()> {
    let mut rva = dir.rva;
    for _ in 0..MAX_MODULES {
        let span = pe.rva_span(rva, 32)?;
        let d = parse(&cx, span, LE, &pe, delay_descriptor).await?;
        if d.is_null() {
            cx.push(
                struct_node("Terminator", span, LE, pe.clone(), delay_descriptor)
                    .summary("null descriptor, ends the table"),
            )
            .await;
            return Ok(());
        }
        let node = match d.rva(&pe, d.name) {
            Some(name_rva) => match read_name(&cx, &pe, name_rva).await {
                Ok((name, _)) => Node::new(name),
                Err(e) => Node::new("<unreadable name>").diag(e),
            },
            None => Node::new("<no name>"),
        };
        let n = match d.rva(&pe, d.int) {
            Some(int) => count_thunks(&cx, &pe, int).await,
            None => 0,
        };
        cx.push(
            node.span(span)
                .summary(format!(
                    "{n} function{}, delay-loaded",
                    if n == 1 { "" } else { "s" }
                ))
                .lazy(delay_module, (pe.clone(), span)),
        )
        .await;
        rva = rva.checked_add(32).ok_or_else(overflow)?;
    }
    Ok(())
}

async fn delay_module(cx: Cx, (pe, descriptor): (Pe, Span)) -> Result<()> {
    cx.emit(struct_node(
        "Delay Import Descriptor",
        descriptor,
        LE,
        pe.clone(),
        delay_descriptor,
    ));
    let d = parse(&cx, descriptor, LE, &pe, delay_descriptor).await?;
    if let Some(rva) = d.rva(&pe, d.name) {
        match read_name(&cx, &pe, rva).await {
            Ok((name, at)) => cx.emit(name_node("Name", &name, at)),
            Err(e) => cx.diag(e),
        }
    }
    if let Some(rva) = d.rva(&pe, d.module)
        && let Ok(span) = pe.rva_exact(rva, pe.word())
    {
        let value = thunk_value(&pe, &cx.read(span).await?);
        cx.emit(
            Node::new("Module Handle")
                .span(span)
                .value(word_value(&pe, value))
                .desc("Filled in with the DLL's HMODULE when it is loaded"),
        );
    }
    for (label, field, desc) in [
        (
            "Bound IAT",
            d.bound,
            "Addresses the image was bound to (optional)",
        ),
        (
            "Unload IAT",
            d.unload,
            "Copy of the delay IAT, restored on unload (optional)",
        ),
    ] {
        if let Some(rva) = d.rva(&pe, field) {
            let n = count_thunks(&cx, &pe, rva).await;
            if let Ok(span) = pe.rva_span(rva, n.saturating_add(1).saturating_mul(pe.word())) {
                cx.emit(
                    Node::new(label)
                        .span(span)
                        .summary(format!("{n} entries"))
                        .desc(desc)
                        .lazy(address_list, (pe.clone(), span)),
                );
            }
        }
    }
    let va_base = if d.attributes & 1 != 0 {
        None
    } else {
        Some(pe.image_base)
    };
    match (d.rva(&pe, d.int), d.rva(&pe, d.iat)) {
        (Some(int), iat) => walk_thunks(&cx, &pe, int, iat, va_base, true).await,
        (None, _) => Ok(()),
    }
}

/// A table of addresses (bound or unload IAT), slot by slot.
async fn address_list(cx: Cx, (pe, span): (Pe, Span)) -> Result<()> {
    let width = pe.word();
    let count = span.len.checked_div(width).unwrap_or(0);
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let slot = span.sub(i.saturating_mul(width), width);
        let value = thunk_value(&pe, &cx.read(slot).await?);
        cx.push(
            Node::new(format!("#{i}"))
                .span(slot)
                .value(word_value(&pe, value)),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Bound imports

fn bound_descriptor(f: &mut Fields<'_>, names: &Span) -> Result<(u16, u16)> {
    f.u32("TimeDateStamp")
        .timestamp()
        .desc("Time stamp of the DLL the imports were bound to")
        .emit()?;
    let base = *names;
    let name = f
        .u16("OffsetModuleName")
        .hex()
        .desc("Offset of the DLL name from the start of the bound import directory")
        .with(|&v, n| n.target(base.tail(v.into()).sub(0, 0)))
        .emit()?;
    let refs = f
        .u16("NumberOfModuleForwarderRefs")
        .desc("Forwarder references that follow this descriptor")
        .emit()?;
    Ok((name, refs))
}

fn forwarder_ref(f: &mut Fields<'_>, names: &Span) -> Result<u16> {
    f.u32("TimeDateStamp").timestamp().emit()?;
    let base = *names;
    let name = f
        .u16("OffsetModuleName")
        .hex()
        .with(|&v, n| n.target(base.tail(v.into()).sub(0, 0)))
        .emit()?;
    f.u16("Reserved").emit()?;
    Ok(name)
}

pub(super) async fn bound(cx: Cx, (_pe, dir): (Pe, Directory)) -> Result<()> {
    let base = dir.span;
    let mut offset = 0u64;
    while offset.saturating_add(8) <= base.len {
        let head = cx.read(base.sub(offset, 8)).await?;
        if head.iter().all(|&b| b == 0) {
            cx.push(
                struct_node(
                    "Terminator",
                    base.sub(offset, 8),
                    LE,
                    base,
                    bound_descriptor,
                )
                .summary("null descriptor, ends the table"),
            )
            .await;
            break;
        }
        let name_at = u16_le(&head, 4).unwrap_or(0);
        let refs = u16_le(&head, 6).unwrap_or(0);
        let len = 8u64.saturating_add(u64::from(refs).saturating_mul(8));
        let span = base.sub(offset, len);
        let node = match cx.cstr(base.tail(name_at.into()).sub(0, MAX_NAME)).await {
            Ok((name, _)) => Node::new(name),
            Err(e) => Node::new("<unreadable name>").diag(e),
        };
        cx.push(
            node.span(span)
                .summary(format!(
                    "{refs} forwarder reference{}",
                    if refs == 1 { "" } else { "s" }
                ))
                .lazy(bound_entry, (base, span)),
        )
        .await;
        offset = offset.saturating_add(len);
    }
    Ok(())
}

async fn bound_entry(cx: Cx, (base, span): (Span, Span)) -> Result<()> {
    let head = span.sub(0, 8);
    cx.emit(struct_node("Descriptor", head, LE, base, bound_descriptor));
    let (name, refs) = parse(&cx, head, LE, &base, bound_descriptor).await?;
    if let Ok((text, at)) = cx.cstr(base.tail(name.into()).sub(0, MAX_NAME)).await {
        cx.emit(name_node("Name", &text, at));
    }
    for i in 0..u64::from(refs) {
        let entry = span.sub(8u64.saturating_add(i.saturating_mul(8)), 8);
        let name = parse(&cx, entry, LE, &base, forwarder_ref).await?;
        let label = match cx.cstr(base.tail(name.into()).sub(0, MAX_NAME)).await {
            Ok((text, _)) => format!("Forwarder: {text}"),
            Err(_) => format!("Forwarder #{i}"),
        };
        cx.push(struct_node(label, entry, LE, base, forwarder_ref))
            .await;
    }
    Ok(())
}
