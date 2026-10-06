//! DirectX shader containers (`DXBC`): compiled HLSL from `fxc` and `dxc`.
//!
//! A header with a checksum and a table of chunk offsets; chunks hold the
//! input/output signatures, resource definitions, statistics and the
//! bytecode itself — legacy shader model tokens (`SHDR`/`SHEX`) or DXIL,
//! which is LLVM bitcode and is shown as embedded bitcode.

use crate::bytes::{to_u64, u32_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::binutil::{data_node, ellipsize, hex_string, name_or, text};
use crate::formats::{Format, Input, Probe, embedded_as};
use crate::node::Node;
use crate::span::Span;
use crate::value::EnumTable;

const LE: Endian = Endian::Little;

pub static FORMAT: Format = Format {
    name: "dxbc",
    title: "DirectX shader bytecode container",
    extensions: &["cso", "dxbc", "fxc"],
    mime: "application/octet-stream",
    probe: Probe::Custom(|h| h.starts_with(b"DXBC") && u32_le(h.data, 20) == Some(1)),
    dissect: crate::expander!(dissect: Input),
};

const CHUNK: EnumTable = &[
    (u32::from_le_bytes(*b"RDEF") as u64, "resource definitions"),
    (u32::from_le_bytes(*b"ISGN") as u64, "input signature"),
    (u32::from_le_bytes(*b"ISG1") as u64, "input signature"),
    (u32::from_le_bytes(*b"OSGN") as u64, "output signature"),
    (u32::from_le_bytes(*b"OSG1") as u64, "output signature"),
    (
        u32::from_le_bytes(*b"OSG5") as u64,
        "output signature (SM5)",
    ),
    (
        u32::from_le_bytes(*b"PCSG") as u64,
        "patch constant signature",
    ),
    (u32::from_le_bytes(*b"SHDR") as u64, "shader bytecode (SM4)"),
    (u32::from_le_bytes(*b"SHEX") as u64, "shader bytecode (SM5)"),
    (u32::from_le_bytes(*b"STAT") as u64, "statistics"),
    (u32::from_le_bytes(*b"DXIL") as u64, "DXIL (LLVM bitcode)"),
    (u32::from_le_bytes(*b"ILDB") as u64, "DXIL with debug info"),
    (u32::from_le_bytes(*b"ILDN") as u64, "debug name"),
    (u32::from_le_bytes(*b"HASH") as u64, "shader hash"),
    (
        u32::from_le_bytes(*b"PSV0") as u64,
        "pipeline state validation",
    ),
    (u32::from_le_bytes(*b"SFI0") as u64, "feature info"),
    (u32::from_le_bytes(*b"RTS0") as u64, "root signature"),
    (u32::from_le_bytes(*b"SDBG") as u64, "debug info"),
    (u32::from_le_bytes(*b"SPDB") as u64, "PDB debug info"),
    (u32::from_le_bytes(*b"PRIV") as u64, "private data"),
];

const PROGRAM: EnumTable = &[
    (0, "pixel"),
    (1, "vertex"),
    (2, "geometry"),
    (3, "hull"),
    (4, "domain"),
    (5, "compute"),
    (6, "library"),
    (7, "ray generation"),
    (8, "intersection"),
    (9, "any hit"),
    (10, "closest hit"),
    (11, "miss"),
    (12, "callable"),
    (13, "mesh"),
    (14, "amplification"),
];

const SYSTEM_VALUE: EnumTable = &[
    (0, "undefined"),
    (1, "SV_Position"),
    (2, "SV_ClipDistance"),
    (3, "SV_CullDistance"),
    (4, "SV_RenderTargetArrayIndex"),
    (5, "SV_ViewportArrayIndex"),
    (6, "SV_VertexID"),
    (7, "SV_PrimitiveID"),
    (8, "SV_InstanceID"),
    (9, "SV_IsFrontFace"),
    (10, "SV_SampleIndex"),
    (64, "SV_Target"),
    (65, "SV_Depth"),
    (66, "SV_Coverage"),
];

const COMPONENT: EnumTable = &[(0, "unknown"), (1, "uint32"), (2, "int32"), (3, "float32")];

fn fourcc(v: u32) -> String {
    String::from_utf8_lossy(&v.to_le_bytes()).into_owned()
}

/// A version token: program type in the high 16 bits, major/minor nibbles.
fn shader_model(token: u32) -> String {
    format!(
        "{} shader, model {}.{}",
        name_or(PROGRAM, (token >> 16).into(), "program"),
        (token >> 4) & 0xf,
        token & 0xf
    )
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 32)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("magic", 4).emit()?;
    f.bytes("checksum", 16)
        .with(|b, n| n.summary(hex_string(b)))
        .desc("Modified MD5 of the rest of the container")
        .emit()?;
    f.u32("version").emit()?;
    f.u32("size").hex().emit()?;
    let count = f.u32("chunk count").emit()?;
    let offsets = cx
        .read_avail(file.sub(32, u64::from(count.min(1024)).saturating_mul(4)))
        .await?;
    let mut chunks = Vec::new();
    for i in 0..offsets.len() / 4 {
        let off = u64::from(u32_le(&offsets, i.saturating_mul(4)).unwrap_or(0));
        let hdr = cx.read_avail(file.sub(off, 8)).await?;
        let id = u32_le(&hdr, 0).unwrap_or(0);
        let size = u64::from(u32_le(&hdr, 4).unwrap_or(0));
        chunks.push((
            id,
            file.sub(off, size.saturating_add(8)),
            file.sub(off.saturating_add(8), size),
        ));
    }
    let mut summary = vec!["DirectX shader".to_owned()];
    let names: Vec<String> = chunks.iter().map(|(id, ..)| fourcc(*id)).collect();
    for (id, _, data) in &chunks {
        match &id.to_le_bytes() {
            b"SHDR" | b"SHEX" => {
                let v = cx.read_avail(data.sub(0, 4)).await?;
                summary.push(shader_model(u32_le(&v, 0).unwrap_or(0)));
            }
            b"DXIL" | b"ILDB" => {
                let v = cx.read_avail(data.sub(0, 4)).await?;
                summary.push(format!(
                    "{} (DXIL)",
                    shader_model(u32_le(&v, 0).unwrap_or(0))
                ));
            }
            _ => {}
        }
    }
    summary.push(format!("chunks {}", ellipsize(&names.join(" "), 80)));
    cx.annotate(summary.join(", "));
    for (id, span, data) in chunks {
        let what = crate::value::lookup(CHUNK, id.into()).unwrap_or("chunk");
        cx.emit(
            Node::new(fourcc(id))
                .span(span)
                .summary(format!("{what}, {:#x} bytes", data.len))
                .lazy(chunk, (input, id, data)),
        );
    }
    Ok(())
}

async fn chunk(cx: Cx, (input, id, data): (Input, u32, Span)) -> Result<()> {
    match &id.to_le_bytes() {
        b"ISGN" | b"OSGN" | b"PCSG" | b"ISG1" | b"OSG1" => signature(&cx, data, id).await,
        b"SHDR" | b"SHEX" => {
            let block = cx.block(data.sub(0, 8)).await?;
            let mut f = Fields::emitting(&cx, &block, LE);
            f.u32("version")
                .hex()
                .with(|&v, n| n.summary(shader_model(v)))
                .emit()?;
            f.u32("length").desc("In 32-bit tokens").emit()?;
            cx.emit(data_node(
                "Tokens",
                data.tail(8),
                data.len.saturating_sub(8),
            ));
            Ok(())
        }
        b"DXIL" | b"ILDB" => {
            let block = cx.block(data.sub(0, 24)).await?;
            let mut f = Fields::emitting(&cx, &block, LE);
            f.u32("program version")
                .hex()
                .with(|&v, n| n.summary(shader_model(v)))
                .emit()?;
            f.u32("size").desc("In 32-bit words").emit()?;
            f.ascii("magic", 4).emit()?;
            f.u32("DXIL version")
                .hex()
                .with(|&v, n| n.summary(format!("{}.{}", v >> 8, v & 0xff)))
                .emit()?;
            let offset = f
                .u32("bitcode offset")
                .hex()
                .desc("From the DXIL magic")
                .emit()?;
            let size = f.u32("bitcode size").hex().emit()?;
            let bitcode = data.sub(8u64.saturating_add(offset.into()), size.into());
            cx.emit(embedded_as(
                "Bitcode",
                input.nested(bitcode),
                &crate::formats::bitcode::FORMAT,
            ));
            Ok(())
        }
        b"ILDN" => {
            let block = cx.block(data.sub(0, 4)).await?;
            let mut f = Fields::emitting(&cx, &block, LE);
            f.u16("flags").emit()?;
            let len = f.u16("name length").emit()?;
            let name = cx.read_avail(data.sub(4, len.into())).await?;
            cx.emit(
                Node::new("name")
                    .span(data.sub(4, len.into()))
                    .value(text(crate::text::until_nul(&name))),
            );
            Ok(())
        }
        b"HASH" => {
            let block = cx.block(data.sub(0, 20)).await?;
            let mut f = Fields::emitting(&cx, &block, LE);
            f.u32("flags").emit()?;
            f.bytes("digest", 16)
                .with(|b, n| n.summary(hex_string(b)))
                .emit()?;
            Ok(())
        }
        _ => {
            cx.emit(data_node("Data", data, data.len));
            Ok(())
        }
    }
}

async fn signature(cx: &Cx, data: Span, id: u32) -> Result<()> {
    let bytes = cx.read(data.sub(0, 0x10000)).await?;
    let count = u32_le(&bytes, 0).unwrap_or(0);
    cx.emit(
        Node::new("element count")
            .span(data.sub(0, 4))
            .value(crate::formats::binutil::dec(count.into(), 32)),
    );
    let width = if matches!(&id.to_le_bytes(), b"ISG1" | b"OSG1") {
        32usize
    } else {
        24
    };
    let first = 8usize;
    for i in 0..usize::try_from(count).unwrap_or(0).min(256) {
        let at = first.saturating_add(i.saturating_mul(width));
        let off = if width == 32 { 4 } else { 0 };
        let w = |k: usize| {
            u32_le(
                &bytes,
                at.saturating_add(off).saturating_add(k.saturating_mul(4)),
            )
        };
        let (Some(name_off), Some(index), Some(sv), Some(comp), Some(reg)) =
            (w(0), w(1), w(2), w(3), w(4))
        else {
            return Err(Diagnostic::truncated(
                data.sub(to_u64(at), to_u64(width)),
                0,
            ));
        };
        let mask = bytes
            .get(at.saturating_add(off).saturating_add(20))
            .copied()
            .unwrap_or(0);
        let name_start = usize::try_from(name_off).unwrap_or(usize::MAX);
        let name = crate::text::until_nul(bytes.get(name_start..).unwrap_or_default());
        let mask_s: String = ['x', 'y', 'z', 'w']
            .iter()
            .enumerate()
            .filter(|(b, _)| mask >> b & 1 != 0)
            .map(|(_, c)| *c)
            .collect();
        cx.push(
            Node::new(format!("{name}{index}"))
                .span(data.sub(to_u64(at), to_u64(width)))
                .value(text(name_or(SYSTEM_VALUE, sv.into(), "system value")))
                .summary(format!(
                    "register {reg}.{mask_s}, {}",
                    name_or(COMPONENT, comp.into(), "type")
                )),
        )
        .await;
    }
    Ok(())
}
