//! The export directory (`IMAGE_EXPORT_DIRECTORY`): the export address table
//! (RVAs of code or data, or of forwarder strings inside the directory), the
//! name pointer table (sorted RVAs of names) and the parallel ordinal table
//! (indices into the address table).

use super::{Directory, LE, Pe, PeInfo, name_node, read_name, rva_field};
use crate::bytes::{to_u64, to_usize, u16_le, u32_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Fields, parse, struct_node};
use crate::formats::executable::pe::tables::DIR_EXPORT;
use crate::node::{Count, Node};
use crate::value::{Radix, Value};

/// Address tables up to this many entries are read whole to count exports.
const MAX_COUNTED: u32 = 1 << 16;

#[derive(Clone, Copy, Debug)]
pub(super) struct ExportDirectory {
    name: u32,
    base: u32,
    functions: u32,
    names: u32,
    address_of_functions: u32,
    address_of_names: u32,
    address_of_name_ordinals: u32,
}

fn export_directory(f: &mut Fields<'_>, pe: &Pe) -> Result<ExportDirectory> {
    f.u32("Characteristics").hex().desc("Reserved, 0").emit()?;
    f.u32("TimeDateStamp").timestamp().emit()?;
    f.u16("MajorVersion").emit()?;
    f.u16("MinorVersion").emit()?;
    let name = rva_field(f.u32("Name"), pe)
        .desc("RVA of the DLL name")
        .emit()?;
    let base = f
        .u32("Base")
        .desc("Ordinal of the first entry of the address table")
        .emit()?;
    let functions = f
        .u32("NumberOfFunctions")
        .desc("Entries in the export address table (including unused ones)")
        .emit()?;
    let names = f
        .u32("NumberOfNames")
        .desc("Entries in the name pointer and ordinal tables")
        .emit()?;
    let address_of_functions = rva_field(f.u32("AddressOfFunctions"), pe).emit()?;
    let address_of_names = rva_field(f.u32("AddressOfNames"), pe).emit()?;
    let address_of_name_ordinals = rva_field(f.u32("AddressOfNameOrdinals"), pe).emit()?;
    Ok(ExportDirectory {
        name,
        base,
        functions,
        names,
        address_of_functions,
        address_of_names,
        address_of_name_ordinals,
    })
}

/// The number of exports (used address table entries), for the summary.
pub(super) async fn count(cx: &Cx, pe: &PeInfo) -> Result<u64> {
    let (rva, size) = pe.directory(DIR_EXPORT);
    if rva == 0 || size == 0 {
        return Ok(0);
    }
    let head = cx.read(pe.rva_exact(rva, 40)?).await?;
    let functions = u32_le(&head, 20).unwrap_or(0);
    let table = u32_le(&head, 28).unwrap_or(0);
    if functions > MAX_COUNTED {
        return Ok(functions.into());
    }
    let addresses = cx.read(pe.table(table, functions, 4)?).await?;
    let mut used = 0u64;
    for (i, slot) in addresses.as_chunks::<4>().0.iter().enumerate() {
        if i.is_multiple_of(4096) {
            cx.checkpoint().await;
        }
        if slot.iter().any(|&b| b != 0) {
            used = used.saturating_add(1);
        }
    }
    Ok(used)
}

pub(super) async fn exports(cx: Cx, (pe, dir): (Pe, Directory)) -> Result<()> {
    let span = pe.rva_span(dir.rva, 40)?;
    cx.emit(struct_node(
        "Export Directory",
        span,
        LE,
        pe.clone(),
        export_directory,
    ));
    let ed = parse(&cx, span, LE, &pe, export_directory).await?;
    match read_name(&cx, &pe, ed.name).await {
        Ok((name, at)) => {
            cx.annotate(format!("{name}, {} functions", ed.functions));
            cx.emit(name_node("Name", &name, at));
        }
        Err(e) => cx.diag(e),
    }
    cx.emit(
        Node::new("Functions")
            .summary(format!("{} functions, {} by name", ed.functions, ed.names))
            .desc("Exports by name, then those exported by ordinal only")
            .lazy(export_functions, (pe.clone(), dir, ed)),
    );
    match pe.table(ed.address_of_functions, ed.functions, 4) {
        Ok(table) if table.len > 0 => cx.emit(
            Node::new("Export Address Table")
                .span(table)
                .summary(format!("{} entries", ed.functions))
                .lazy(address_table, (pe.clone(), dir, ed)),
        ),
        Ok(_) => {}
        Err(e) => cx.diag(e),
    }
    if ed.names > 0 {
        match pe.table(ed.address_of_names, ed.names, 4) {
            Ok(table) => cx.emit(
                Node::new("Name Pointer Table")
                    .span(table)
                    .summary(format!("{} names", ed.names))
                    .desc("RVAs of the exported names, sorted for binary search")
                    .lazy(name_pointers, (pe.clone(), ed)),
            ),
            Err(e) => cx.diag(e),
        }
        match pe.table(ed.address_of_name_ordinals, ed.names, 2) {
            Ok(table) => cx.emit(
                Node::new("Ordinal Table")
                    .span(table)
                    .summary(format!("{} entries", ed.names))
                    .desc("For each name, its index in the export address table (ordinal − Base)")
                    .lazy(ordinal_table, (pe.clone(), ed)),
            ),
            Err(e) => cx.diag(e),
        }
    }
    Ok(())
}

/// For each address table index, the RVA of its first name (bounded by the
/// tables actually read).
async fn names_by_index(
    cx: &Cx,
    pe: &PeInfo,
    ed: &ExportDirectory,
    slots: usize,
) -> Result<Vec<u32>> {
    let names = cx.read(pe.table(ed.address_of_names, ed.names, 4)?).await?;
    let ordinals = cx
        .read(pe.table(ed.address_of_name_ordinals, ed.names, 2)?)
        .await?;
    let mut out = vec![0u32; slots];
    for i in 0..ordinals.len().checked_div(2).unwrap_or(0) {
        if i.is_multiple_of(4096) {
            cx.checkpoint().await;
        }
        if let (Some(o), Some(name)) = (
            u16_le(&ordinals, i.saturating_mul(2)),
            u32_le(&names, i.saturating_mul(4)),
        ) && let Some(slot) = out.get_mut(usize::from(o))
            && *slot == 0
        {
            *slot = name;
        }
    }
    Ok(out)
}

async fn export_functions(cx: Cx, (pe, dir, ed): (Pe, Directory, ExportDirectory)) -> Result<()> {
    let address_table = pe.table(ed.address_of_functions, ed.functions, 4)?;
    let addresses = cx.read(address_table).await?;
    let names = cx.read(pe.table(ed.address_of_names, ed.names, 4)?).await?;
    let ordinals = cx
        .read(pe.table(ed.address_of_name_ordinals, ed.names, 2)?)
        .await?;

    // Allocation is bounded by bytes actually read, not by declared counts.
    let mut named = vec![false; addresses.len().checked_div(4).unwrap_or(0)];
    for i in 0..ordinals.len().checked_div(2).unwrap_or(0) {
        if i.is_multiple_of(4096) {
            cx.checkpoint().await;
        }
        if let Some(o) = u16_le(&ordinals, i.saturating_mul(2))
            && let Some(slot) = named.get_mut(usize::from(o))
        {
            *slot = true;
        }
    }
    let mut unnamed = Vec::new();
    for (i, &n) in named.iter().enumerate() {
        if i.is_multiple_of(4096) {
            cx.checkpoint().await;
        }
        if !n && u32_le(&addresses, i.saturating_mul(4)).is_some_and(|a| a != 0) {
            unnamed.push(i);
        }
    }
    cx.set_count(Count::Exact(
        u64::from(ed.names).saturating_add(to_u64(unnamed.len())),
    ));

    let exports = Exports {
        pe: &pe,
        dir,
        base: ed.base,
        table: address_table,
        addresses: &addresses,
    };
    for i in 0..to_usize(ed.names.into()) {
        let name_rva = u32_le(&names, i.saturating_mul(4)).unwrap_or(0);
        let index = u16_le(&ordinals, i.saturating_mul(2)).unwrap_or(0);
        let node = match read_name(&cx, &pe, name_rva).await {
            Ok((name, _)) => exports.entry(&cx, index.into(), name).await,
            Err(e) => exports
                .entry(&cx, index.into(), "<unreadable name>".to_owned())
                .await
                .diag(e),
        };
        cx.push(node).await;
    }
    for index in unnamed {
        let ordinal = ed
            .base
            .saturating_add(u32::try_from(index).unwrap_or(u32::MAX));
        let node = exports
            .entry(&cx, index, format!("#{ordinal}"))
            .await
            .desc("Exported by ordinal only (NONAME)");
        cx.push(node).await;
    }
    Ok(())
}

struct Exports<'a> {
    pe: &'a PeInfo,
    dir: Directory,
    base: u32,
    table: crate::span::Span,
    addresses: &'a [u8],
}

impl Exports<'_> {
    async fn entry(&self, cx: &Cx, index: usize, name: String) -> Node {
        let ordinal = self
            .base
            .saturating_add(u32::try_from(index).unwrap_or(u32::MAX));
        let at = index.saturating_mul(4);
        let node = Node::new(name).span(self.table.sub(to_u64(at), 4));
        let Some(address) = u32_le(self.addresses, at) else {
            return node.diag(Diagnostic::malformed(format!(
                "ordinal index {index} is outside the export address table"
            )));
        };
        let node = node.value(Value::UInt {
            value: address.into(),
            bits: 32,
            radix: Radix::Hex,
        });
        if forwarded(&self.dir, address) {
            match read_name(cx, self.pe, address).await {
                Ok((target, at)) => node
                    .summary(format!("ordinal {ordinal}, forwarded to {target}"))
                    .target(at),
                Err(e) => node.diag(e),
            }
        } else {
            let kind = match self.pe.section_of(address) {
                Some(s) if s.characteristics & 0x2000_0000 != 0 => "code",
                Some(_) => "data",
                None => "unmapped",
            };
            let node = node.summary(format!("ordinal {ordinal}, {kind} at {address:#x}"));
            match self.pe.rva_span(address, 0) {
                Ok(at) => node.target(at),
                Err(_) => node,
            }
        }
    }
}

/// An address inside the export directory is a forwarder string.
fn forwarded(dir: &Directory, address: u32) -> bool {
    address.checked_sub(dir.rva).is_some_and(|d| d < dir.size)
}

/// The export address table, slot by slot.
async fn address_table(cx: Cx, (pe, dir, ed): (Pe, Directory, ExportDirectory)) -> Result<()> {
    let table = pe.table(ed.address_of_functions, ed.functions, 4)?;
    let addresses = cx.read(table).await?;
    let slots = addresses.len().checked_div(4).unwrap_or(0);
    let names = names_by_index(&cx, &pe, &ed, slots)
        .await
        .unwrap_or_default();
    cx.set_count(Count::Exact(to_u64(slots)));
    for index in 0..slots {
        let at = index.saturating_mul(4);
        let address = u32_le(&addresses, at).unwrap_or(0);
        let ordinal = ed
            .base
            .saturating_add(u32::try_from(index).unwrap_or(u32::MAX));
        let mut node = Node::new(format!("Ordinal {ordinal}"))
            .span(table.sub(to_u64(at), 4))
            .value(Value::UInt {
                value: address.into(),
                bits: 32,
                radix: Radix::Hex,
            });
        let name = match names.get(index).copied().filter(|&n| n != 0) {
            Some(rva) => read_name(&cx, &pe, rva).await.ok().map(|(n, _)| n),
            None => None,
        };
        if address == 0 {
            node = node.summary("unused");
        } else if forwarded(&dir, address) {
            let label = name.unwrap_or_else(|| "(no name)".to_owned());
            match read_name(&cx, &pe, address).await {
                Ok((target, at)) => {
                    node = node
                        .summary(format!("{label} → {target}"))
                        .target(at)
                        .lazy(forwarder, (target, at));
                }
                Err(e) => node = node.diag(e),
            }
        } else {
            node = node.summary(match name {
                Some(n) => format!("{n}, {}", pe.describe_rva(address)),
                None => format!("by ordinal, {}", pe.describe_rva(address)),
            });
            if let Ok(at) = pe.rva_span(address, 0) {
                node = node.target(at);
            }
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn forwarder(cx: Cx, (target, at): (String, crate::span::Span)) -> Result<()> {
    cx.emit(
        name_node("Forwarder", &target, at)
            .desc("\"DLL.Function\" or \"DLL.#Ordinal\": the loader resolves the export there"),
    );
    Ok(())
}

async fn name_pointers(cx: Cx, (pe, ed): (Pe, ExportDirectory)) -> Result<()> {
    let table = pe.table(ed.address_of_names, ed.names, 4)?;
    let names = cx.read(table).await?;
    let count = names.len().checked_div(4).unwrap_or(0);
    cx.set_count(Count::Exact(to_u64(count)));
    for i in 0..count {
        let at = i.saturating_mul(4);
        let rva = u32_le(&names, at).unwrap_or(0);
        let node = Node::new(format!("#{i}"))
            .span(table.sub(to_u64(at), 4))
            .value(Value::UInt {
                value: rva.into(),
                bits: 32,
                radix: Radix::Hex,
            });
        let node = match read_name(&cx, &pe, rva).await {
            Ok((name, span)) => node
                .summary(name.clone())
                .target(span)
                .lazy(name_string, (name, span)),
            Err(e) => node.diag(e),
        };
        cx.push(node).await;
    }
    Ok(())
}

async fn name_string(cx: Cx, (name, span): (String, crate::span::Span)) -> Result<()> {
    cx.emit(name_node("Name", &name, span));
    Ok(())
}

async fn ordinal_table(cx: Cx, (pe, ed): (Pe, ExportDirectory)) -> Result<()> {
    let table = pe.table(ed.address_of_name_ordinals, ed.names, 2)?;
    let ordinals = cx.read(table).await?;
    let names = cx
        .read(pe.table(ed.address_of_names, ed.names, 4)?)
        .await
        .unwrap_or_default();
    let count = ordinals.len().checked_div(2).unwrap_or(0);
    cx.set_count(Count::Exact(to_u64(count)));
    for i in 0..count {
        let at = i.saturating_mul(2);
        let index = u16_le(&ordinals, at).unwrap_or(0);
        let ordinal = ed.base.saturating_add(index.into());
        let name = match u32_le(&names, i.saturating_mul(4)) {
            Some(rva) => read_name(&cx, &pe, rva).await.ok().map(|(n, _)| n),
            None => None,
        };
        let summary = match name {
            Some(n) => format!("{n} → ordinal {ordinal}"),
            None => format!("ordinal {ordinal}"),
        };
        cx.push(
            Node::new(format!("#{i}"))
                .span(table.sub(to_u64(at), 2))
                .value(Value::UInt {
                    value: index.into(),
                    bits: 16,
                    radix: Radix::Dec,
                })
                .summary(summary),
        )
        .await;
    }
    Ok(())
}
