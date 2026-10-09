//! The debug directory (`IMAGE_DEBUG_DIRECTORY` entries) and the data of
//! the common entry types: CodeView (`RSDS` / `NB10`: the PDB path and its
//! signature), POGO (profile-guided optimization section map), VC_FEATURE
//! (compiler feature counts), REPRO (deterministic-build hash), the
//! extended DLL characteristics, MISC, FPO, PDB checksums and embedded
//! portable PDBs.

use super::tables::*;
use super::{Directory, LE, Pe, padding_node, rva_field};
use crate::bytes::{to_u64, u32_le};
use crate::codec::Codec;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Fields, parse, struct_node};
use crate::formats::content;
use crate::formats::util::binutil::hex_string;
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{Value, lookup};

#[derive(Clone, Copy, Debug)]
struct DebugEntry {
    kind: u32,
    size: u32,
    pointer: u32,
}

fn debug_entry(f: &mut Fields<'_>, pe: &Pe) -> Result<DebugEntry> {
    f.u32("Characteristics").hex().desc("Reserved, 0").emit()?;
    f.u32("TimeDateStamp").timestamp().emit()?;
    f.u16("MajorVersion").emit()?;
    f.u16("MinorVersion").emit()?;
    let kind = f.u32("Type").enumeration(DEBUG_TYPE).emit()?;
    let size = f.u32("SizeOfData").hex().emit()?;
    rva_field(f.u32("AddressOfRawData"), pe)
        .desc("RVA of the data when it is mapped, or 0")
        .emit()?;
    let file = pe.file();
    let pointer = f
        .u32("PointerToRawData")
        .hex()
        .desc("File offset of the data")
        .with(|&p, n| {
            if p == 0 && size == 0 {
                n
            } else {
                n.target(file.sub(p.into(), size.into()))
            }
        })
        .emit()?;
    Ok(DebugEntry {
        kind,
        size,
        pointer,
    })
}

pub(super) async fn directory(cx: Cx, (pe, dir): (Pe, Directory)) -> Result<()> {
    if dir.size % 28 != 0 {
        cx.diag(Diagnostic::warning(format!(
            "size {:#x} is not a multiple of the 28-byte entry size",
            dir.size
        )));
    }
    let count = dir.size.checked_div(28).unwrap_or(0);
    cx.set_count(Count::Exact(count.into()));
    let mut kinds = Vec::new();
    for i in 0..count {
        let span = dir.span.sub(u64::from(i).saturating_mul(28), 28);
        let entry = parse(&cx, span, LE, &pe, debug_entry).await?;
        let label = lookup(DEBUG_TYPE, entry.kind.into())
            .map_or_else(|| format!("Type {}", entry.kind), str::to_owned);
        if kinds.len() < 8 {
            kinds.push(label.clone());
        }
        let data = pe.file().sub(entry.pointer.into(), entry.size.into());
        let summary = match entry_summary(&cx, entry, data).await {
            Some(s) => s,
            None => format!("{:#x} bytes", entry.size),
        };
        cx.push(
            Node::new(label)
                .span(span)
                .summary(summary)
                .lazy(debug_entry_node, (pe.clone(), span)),
        )
        .await;
    }
    cx.annotate(kinds.join(", "));
    Ok(())
}

/// A one-line description of an entry's data (a PDB path, a feature set).
async fn entry_summary(cx: &Cx, entry: DebugEntry, data: Span) -> Option<String> {
    if entry.size == 0 {
        return Some("no data".to_owned());
    }
    match entry.kind {
        DEBUG_TYPE_CODEVIEW => {
            let head = cx.read_avail(data.sub(0, 4)).await.ok()?;
            let skip = match head.as_slice() {
                b"RSDS" => 24,
                b"NB10" => 16,
                _ => return None,
            };
            let (path, _) = cx.cstr(data.tail(skip)).await.ok()?;
            Some(path)
        }
        DEBUG_TYPE_EX_DLLCHARACTERISTICS => {
            let raw = cx.read_avail(data.sub(0, 4)).await.ok()?;
            let v = u32_le(&raw, 0)?;
            let (set, _) = crate::value::decode_flags(EX_DLL_CHARACTERISTICS, v.into());
            Some(if set.is_empty() {
                format!("{v:#x}")
            } else {
                set.join(" | ")
            })
        }
        DEBUG_TYPE_POGO => {
            let raw = cx.read_avail(data.sub(0, 4)).await.ok()?;
            Some(format!(
                "{}, {:#x} bytes",
                pogo_kind(u32_le(&raw, 0)?),
                entry.size
            ))
        }
        _ => None,
    }
}

async fn debug_entry_node(cx: Cx, (pe, span): (Pe, Span)) -> Result<()> {
    let block = cx.block(span).await?;
    let entry = debug_entry(&mut Fields::emitting(&cx, &block, LE), &pe)?;
    if entry.size == 0 {
        return Ok(());
    }
    let data = pe.file().sub(entry.pointer.into(), entry.size.into());
    let input = pe.input;
    let node = match entry.kind {
        DEBUG_TYPE_CODEVIEW => Node::new("CodeView").span(data).lazy(codeview, data),
        DEBUG_TYPE_POGO => Node::new("POGO").span(data).lazy(pogo, data),
        DEBUG_TYPE_VC_FEATURE => struct_node("VC Feature", data, LE, (), vc_feature),
        DEBUG_TYPE_REPRO => Node::new("Repro").span(data).lazy(repro, data),
        DEBUG_TYPE_EX_DLLCHARACTERISTICS => {
            struct_node("Extended DLL Characteristics", data, LE, (), ex_dll)
        }
        DEBUG_TYPE_MISC => Node::new("MISC").span(data).lazy(misc, data),
        DEBUG_TYPE_FPO => Node::new("FPO")
            .span(data)
            .summary(format!("{} records", data.len / 16))
            .lazy(fpo, data),
        DEBUG_TYPE_PDBCHECKSUM => Node::new("PDB Checksum")
            .span(data)
            .lazy(pdb_checksum, data),
        DEBUG_TYPE_EMBEDDED_PDB => Node::new("Embedded Portable PDB")
            .span(data)
            .lazy(embedded_pdb, (input, data)),
        _ => Node::new("Data").span(data),
    };
    cx.emit(node);
    Ok(())
}

async fn codeview(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    let signature = f.ascii("Signature", 4).emit()?;
    match signature.as_str() {
        "RSDS" => {
            f.guid("Guid")
                .desc("Must match the PDB; with Age, keys the symbol server path")
                .emit()?;
            f.u32("Age").emit()?;
        }
        "NB10" => {
            f.u32("Offset").desc("Always 0").emit()?;
            f.u32("Signature")
                .timestamp()
                .desc("Time stamp that must match the PDB")
                .emit()?;
            f.u32("Age").emit()?;
        }
        "MTOC" => {
            f.guid("Uuid")
                .desc("UUID of the Mach-O image this EFI image was converted from")
                .emit()?;
        }
        _ => {
            return Err(Diagnostic::unsupported(format!(
                "CodeView signature {signature:?}"
            )));
        }
    }
    let path = f
        .cstr(if signature == "MTOC" {
            "FileName"
        } else {
            "PdbFileName"
        })
        .emit()?;
    cx.annotate(path);
    if f.pos() < span.len {
        cx.emit(padding_node(
            "Padding",
            span.tail(f.pos()),
            "After the file name",
        ));
    }
    Ok(())
}

fn pogo_kind(signature: u32) -> &'static str {
    match signature {
        0x5047_5500 | 0x0055_4750 => "PGU (profile-guided, optimized)",
        0x5047_4900 | 0x0049_4750 => "PGI (profile-guided, instrumented)",
        0x4c54_4347 | 0x4743_544c => "LTCG",
        _ => "unknown kind",
    }
}

/// `POGO`: a signature, then `(RVA, size, NUL-terminated name padded to 4)`
/// records mapping the image's sections to the linker's contributions.
async fn pogo(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read_avail(span).await?;
    let head = cx.block(span.sub(0, 4)).await?;
    Fields::emitting(&cx, &head, LE)
        .u32("Signature")
        .hex()
        .with(|&v, n| n.summary(pogo_kind(v)))
        .emit()?;
    let mut at = 4usize;
    while at.saturating_add(8) < data.len() {
        cx.checkpoint().await;
        let rva = u32_le(&data, at).unwrap_or(0);
        let size = u32_le(&data, at.saturating_add(4)).unwrap_or(0);
        let rest = data.get(at.saturating_add(8)..).unwrap_or_default();
        let Some(len) = rest.iter().position(|&b| b == 0) else {
            break;
        };
        let name = String::from_utf8_lossy(rest.get(..len).unwrap_or_default()).into_owned();
        let end = at
            .saturating_add(8)
            .saturating_add(len)
            .saturating_add(1)
            .next_multiple_of(4)
            .min(data.len());
        let entry = span.sub(to_u64(at), to_u64(end.saturating_sub(at)));
        cx.push(
            Node::new(name.clone())
                .span(entry)
                .value(Value::Text(name))
                .summary(format!("RVA {rva:#x}, {size:#x} bytes")),
        )
        .await;
        at = end;
    }
    Ok(())
}

fn vc_feature(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("Pre-VC++ 11.00")
        .desc("Objects built by compilers older than VS2012")
        .emit()?;
    f.u32("C/C++")
        .desc("Objects built by VS2012 or later")
        .emit()?;
    f.u32("/GS")
        .desc("Objects built with buffer security checks")
        .emit()?;
    f.u32("/sdl")
        .desc("Objects built with extra security checks")
        .emit()?;
    f.u32("guardN")
        .desc("Objects built with /guard:cf")
        .emit()?;
    Ok(())
}

/// `REPRO`: a length-prefixed hash of the build inputs (empty in older
/// images, where the time stamps are the hash).
async fn repro(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    let len = f.u32("Length").emit()?;
    let hash = f.bytes("Hash", len.into()).emit()?;
    cx.annotate(hex_string(&hash));
    Ok(())
}

fn ex_dll(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("ExDllCharacteristics")
        .flags(EX_DLL_CHARACTERISTICS)
        .emit()?;
    Ok(())
}

/// `IMAGE_DEBUG_MISC`: the name of the DBG file (Windows NT era).
async fn misc(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u32("DataType")
        .enumeration(&[(1, "IMAGE_DEBUG_MISC_EXENAME")])
        .emit()?;
    let len = f.u32("Length").desc("Including this header").emit()?;
    let unicode = f.u8("Unicode").emit()?;
    f.bytes("Reserved", 3).emit()?;
    let text = u64::from(len)
        .saturating_sub(12)
        .min(span.len.saturating_sub(12));
    if unicode != 0 {
        f.utf16("Data", text / 2).emit()?;
    } else {
        f.ascii("Data", text).emit()?;
    }
    Ok(())
}

const FPO_FRAME: crate::value::EnumTable = &[
    (0, "FRAME_FPO"),
    (1, "FRAME_TRAP"),
    (2, "FRAME_TSS"),
    (3, "FRAME_NONFPO"),
];

fn fpo_record(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("ulOffStart")
        .hex()
        .desc("Offset of the function")
        .emit()?;
    f.u32("cbProcSize").hex().emit()?;
    f.u32("cdwLocals").desc("Locals, in dwords").emit()?;
    f.u16("cdwParams").desc("Parameters, in dwords").emit()?;
    let span = f.peek_span(2);
    let bits = f.u16("Attributes").hex().get()?;
    let frame = (bits >> 14) & 3;
    f.node(
        Node::new("Attributes")
            .span(span)
            .value(Value::UInt {
                value: bits.into(),
                bits: 16,
                radix: crate::value::Radix::Hex,
            })
            .summary(format!(
                "prolog {} bytes, {} saved registers{}{}, {}",
                bits & 0xff,
                (bits >> 8) & 7,
                if bits & 0x800 != 0 { ", SEH" } else { "" },
                if bits & 0x1000 != 0 {
                    ", EBP allocated"
                } else {
                    ""
                },
                lookup(FPO_FRAME, frame.into()).unwrap_or("?")
            )),
    );
    Ok(())
}

async fn fpo(cx: Cx, span: Span) -> Result<()> {
    let count = span.len / 16;
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let record = span.sub(i.saturating_mul(16), 16);
        cx.push(struct_node(format!("#{i}"), record, LE, (), fpo_record))
            .await;
    }
    Ok(())
}

/// `PDBCHECKSUM`: a hash algorithm name and the hash of the PDB.
async fn pdb_checksum(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    let algorithm = f.cstr("AlgorithmName").emit()?;
    let rest = f.remaining();
    let hash = f.bytes("Checksum", rest).emit()?;
    cx.annotate(format!("{algorithm} {}", hex_string(&hash)));
    Ok(())
}

/// `EMBEDDED_PORTABLE_PDB`: "MPDB", the uncompressed size, then the
/// portable PDB compressed with raw DEFLATE.
async fn embedded_pdb(cx: Cx, (input, span): (crate::formats::Input, Span)) -> Result<()> {
    let block = cx.block(span.sub(0, 8)).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.ascii("Signature", 4).desc("\"MPDB\"").emit()?;
    let size = f.u32("UncompressedSize").emit()?;
    cx.emit(content(
        "Portable PDB",
        input,
        span.tail(8),
        Codec::Deflate,
        Some(size.into()),
    ));
    Ok(())
}
