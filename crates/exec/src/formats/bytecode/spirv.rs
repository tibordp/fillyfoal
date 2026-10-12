//! SPIR-V shader modules (Vulkan, OpenCL, OpenGL): a five-word header and
//! a stream of instructions, each starting with a word holding its length
//! and opcode. Instructions are listed in pages; debug names, entry points,
//! capabilities and extensions are decoded.

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::binutil::{NodeExt, get_at};
use crate::formats::util::fmt::clip;
use crate::formats::util::val::name_or;
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Value};

use super::spirv_tables::{
    ADDRESSING_MODEL, CAPABILITY, EXECUTION_MODEL, MEMORY_MODEL, OPCODE, SOURCE_LANGUAGE,
};

pub static FORMAT: Format = Format {
    name: "spirv",
    title: "SPIR-V shader module",
    extensions: &["spv", "spirv"],
    mime: "application/x-spirv",
    probe: Probe::Magic(&[(0, b"\x03\x02\x23\x07"), (0, b"\x07\x23\x02\x03")]),
    dissect: crate::expander!(dissect: Input),
};

const GENERATOR: EnumTable = &[
    (0, "Khronos"),
    (1, "LunarG"),
    (2, "Valve"),
    (3, "Codeplay"),
    (4, "NVIDIA"),
    (5, "ARM"),
    (6, "Khronos LLVM/SPIR-V Translator"),
    (7, "Khronos SPIR-V Tools Assembler"),
    (8, "Khronos Glslang Reference Front End"),
    (13, "Google Shaderc over Glslang"),
    (14, "Google spiregg"),
    (15, "Google rspirv"),
    (17, "Khronos SPIR-V Tools Linker"),
    (19, "Tellusim Clay Shader Compiler"),
    (22, "Rust GPU"),
    (23, "Embark Studios Rust GPU"),
    (24, "gfx-rs Naga"),
    (27, "Microsoft DXC"),
    (28, "Google Clspv"),
    (30, "Mesa"),
    (35, "Slang"),
];

/// A literal string in words (UTF-8, NUL-terminated, padded to a word).
fn literal(bytes: &[u8]) -> (String, usize) {
    let n = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    let words = n.saturating_add(4) / 4;
    (
        String::from_utf8_lossy(bytes.get(..n).unwrap_or_default()).into_owned(),
        words,
    )
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 4)).await?;
    let endian = if head.as_slice() == b"\x03\x02\x23\x07" {
        Endian::Little
    } else {
        Endian::Big
    };
    let block = cx.block(file.sub(0, 20)).await?;
    let mut f = Fields::emitting(&cx, &block, endian);
    f.u32("Magic").hex().emit()?;
    let version = f
        .u32("Version")
        .hex()
        .with(|&v, n| n.summary(format!("{}.{}", (v >> 16) & 0xff, (v >> 8) & 0xff)))
        .emit()?;
    f.u32("Generator")
        .hex()
        .with(|&v, n| {
            n.summary(format!(
                "{}, version {}",
                name_or(GENERATOR, (v >> 16).into(), "tool"),
                v & 0xffff
            ))
        })
        .emit()?;
    f.u32("Bound").desc("All IDs are below this").emit()?;
    f.u32("Schema").emit()?;

    if file.len > cx.limits().max_read {
        return Err(Diagnostic::limit("module too large").at(file));
    }
    let data = cx.read_avail(file).await?;
    let word = |i: usize| get_at::<u32>(&data, to_u64(i.saturating_mul(4)), endian);
    let words = data.len() / 4;
    // Pre-pass for the summary: entry points, capabilities, source.
    let mut entries = Vec::new();
    let mut caps = Vec::new();
    let mut source = None;
    let mut steps = 0u32;
    let mut i = 5usize;
    while i < words {
        let Some(w) = word(i) else { break };
        let (count, op) = (usize::try_from(w >> 16).unwrap_or(0), w & 0xffff);
        steps = steps.wrapping_add(1);
        if steps.is_multiple_of(4096) {
            cx.checkpoint().await;
        }
        if count == 0 {
            break;
        }
        // The summary is ellipsized: 128 of each is more than it shows.
        match op {
            15 if entries.len() < 128 => {
                let model = word(i.saturating_add(1)).unwrap_or(0);
                let at = i.saturating_add(3).saturating_mul(4);
                let (name, _) = literal(data.get(at..).unwrap_or_default());
                entries.push(format!(
                    "{name} ({})",
                    name_or(EXECUTION_MODEL, model.into(), "model")
                ));
            }
            17 if caps.len() < 128 => caps.push(name_or(
                CAPABILITY,
                word(i.saturating_add(1)).unwrap_or(0).into(),
                "capability",
            )),
            3 => {
                source = Some(format!(
                    "{} {}",
                    name_or(
                        SOURCE_LANGUAGE,
                        word(i.saturating_add(1)).unwrap_or(0).into(),
                        "language"
                    ),
                    word(i.saturating_add(2)).unwrap_or(0)
                ));
            }
            _ => {}
        }
        i = i.saturating_add(count);
    }
    let mut summary = format!(
        "SPIR-V {}.{} module",
        (version >> 16) & 0xff,
        (version >> 8) & 0xff
    );
    if !entries.is_empty() {
        summary.push_str(&format!(
            ", entry points {}",
            clip(&entries.join(", "), 120)
        ));
    }
    if let Some(s) = source {
        summary.push_str(&format!(", from {s}"));
    }
    if !caps.is_empty() {
        summary.push_str(&format!(", capabilities {}", clip(&caps.join(" "), 80)));
    }
    cx.annotate(summary);

    let mut i = 5usize;
    while i < words {
        let Some(w) = word(i) else { break };
        let (count, op) = (usize::try_from(w >> 16).unwrap_or(0), w & 0xffff);
        let span: Span = file.sub(
            to_u64(i.saturating_mul(4)),
            to_u64(count.max(1).saturating_mul(4)),
        );
        if count == 0 {
            cx.push(
                Node::new("<bad instruction>")
                    .span(span)
                    .diag(Diagnostic::malformed("zero word count")),
            )
            .await;
            break;
        }
        let operand = |k: usize| word(i.saturating_add(k)).unwrap_or(0);
        let text_at = |k: usize| {
            let at = i.saturating_add(k).saturating_mul(4);
            let end = i.saturating_add(count).saturating_mul(4).min(data.len());
            literal(data.get(at..end).unwrap_or_default()).0
        };
        let summary = match op {
            3 => format!(
                "{} {}",
                name_or(SOURCE_LANGUAGE, operand(1).into(), "language"),
                operand(2)
            ),
            4 | 10 => text_at(1),
            5 | 7 | 11 => format!("%{} = {:?}", operand(1), text_at(2)),
            6 => format!("%{}.{} = {:?}", operand(1), operand(2), text_at(3)),
            14 => format!(
                "addressing {}, memory {}",
                name_or(ADDRESSING_MODEL, operand(1).into(), "model"),
                name_or(MEMORY_MODEL, operand(2).into(), "model")
            ),
            15 => format!(
                "{} %{} {:?}",
                name_or(EXECUTION_MODEL, operand(1).into(), "model"),
                operand(2),
                text_at(3)
            ),
            17 => name_or(CAPABILITY, operand(1).into(), "capability"),
            330 => text_at(1),
            _ => {
                let ops: Vec<String> = (1..count.min(9)).map(|k| operand(k).to_string()).collect();
                ops.join(" ")
            }
        };
        cx.push(
            Node::new(format!("{:#x}", i.saturating_mul(4)))
                .span(span)
                .value(Value::Enum {
                    raw: op.into(),
                    bits: 16,
                    name: crate::value::lookup(OPCODE, op.into()),
                })
                .maybe_summary(summary),
        )
        .await;
        i = i.saturating_add(count);
    }
    Ok(())
}
