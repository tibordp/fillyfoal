//! Quake III virtual machine bytecode (`.qvm`: game, cgame and ui
//! modules for id Tech 3 engines): header, code (disassembled), data and
//! literal segments.

use crate::bytes::{to_u64, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::binutil::{NodeExt, data_node, text};
use crate::formats::{Format, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;

const LE: Endian = Endian::Little;

pub static FORMAT: Format = Format {
    name: "qvm",
    title: "Quake III VM bytecode",
    extensions: &["qvm"],
    mime: "application/octet-stream",
    probe: Probe::Magic(&[(0, b"\x44\x14\x72\x12"), (0, b"\x45\x14\x72\x12")]),
    dissect: crate::expander!(dissect: Input),
};

/// `(mnemonic, operand bytes)`.
const OPCODES: [(&str, u8); 60] = [
    ("UNDEF", 0),
    ("IGNORE", 0),
    ("BREAK", 0),
    ("ENTER", 4),
    ("LEAVE", 4),
    ("CALL", 0),
    ("PUSH", 0),
    ("POP", 0),
    ("CONST", 4),
    ("LOCAL", 4),
    ("JUMP", 0),
    ("EQ", 4),
    ("NE", 4),
    ("LTI", 4),
    ("LEI", 4),
    ("GTI", 4),
    ("GEI", 4),
    ("LTU", 4),
    ("LEU", 4),
    ("GTU", 4),
    ("GEU", 4),
    ("EQF", 4),
    ("NEF", 4),
    ("LTF", 4),
    ("LEF", 4),
    ("GTF", 4),
    ("GEF", 4),
    ("LOAD1", 0),
    ("LOAD2", 0),
    ("LOAD4", 0),
    ("STORE1", 0),
    ("STORE2", 0),
    ("STORE4", 0),
    ("ARG", 1),
    ("BLOCK_COPY", 4),
    ("SEX8", 0),
    ("SEX16", 0),
    ("NEGI", 0),
    ("ADD", 0),
    ("SUB", 0),
    ("DIVI", 0),
    ("DIVU", 0),
    ("MODI", 0),
    ("MODU", 0),
    ("MULI", 0),
    ("MULU", 0),
    ("BAND", 0),
    ("BOR", 0),
    ("BXOR", 0),
    ("BCOM", 0),
    ("LSH", 0),
    ("RSHI", 0),
    ("RSHU", 0),
    ("NEGF", 0),
    ("ADDF", 0),
    ("SUBF", 0),
    ("DIVF", 0),
    ("MULF", 0),
    ("CVIF", 0),
    ("CVFI", 0),
];

record! {
    struct Header {
        magic: u32 "vmMagic" .hex(),
        instructions: u32 "instructionCount",
        code_offset: u32 "codeOffset" .hex(),
        code_length: u32 "codeLength" .hex(),
        data_offset: u32 "dataOffset" .hex(),
        data_length: u32 "dataLength" .hex(),
        lit_length: u32 "litLength" .hex() .desc("String literals, stored after the data"),
        bss_length: u32 "bssLength" .hex(),
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let hspan = file.sub(0, Header::SIZE);
    cx.emit(Header::node("Header", hspan, LE));
    let h = parse(&cx, hspan, LE, &(), Header::layout).await?;
    if h.magic == 0x1272_1445 {
        let j = cx.read_avail(file.sub(Header::SIZE, 4)).await?;
        cx.emit(
            Node::new("jtrgLength")
                .span(file.sub(Header::SIZE, 4))
                .value(crate::formats::binutil::hex(
                    u32_le(&j, 0).unwrap_or(0).into(),
                    32,
                )),
        );
    }
    cx.annotate(format!(
        "Quake III VM bytecode, {} instructions, {:#x} bytes of data, {:#x} of literals, {:#x} of bss",
        h.instructions, h.data_length, h.lit_length, h.bss_length
    ));
    let code = file.sub(h.code_offset.into(), h.code_length.into());
    cx.emit(
        Node::new("Code")
            .span(code)
            .summary(format!("{} instructions", h.instructions))
            .lazy(disassemble, (code, h.instructions)),
    );
    cx.emit(data_node(
        "Data",
        file.sub(h.data_offset.into(), h.data_length.into()),
        h.data_length.into(),
    ));
    let lit = file.sub(
        u64::from(h.data_offset).saturating_add(h.data_length.into()),
        h.lit_length.into(),
    );
    cx.emit(
        Node::new("Literals")
            .span(lit)
            .lazy(crate::formats::binutil::cstrings, lit),
    );
    Ok(())
}

async fn disassemble(cx: Cx, (code, count): (Span, u32)) -> Result<()> {
    let data = cx.read(code).await?;
    let mut at = 0usize;
    cx.set_count(Count::AtLeast(count.into()));
    for i in 0..count {
        let Some(&op) = data.get(at) else { break };
        let Some(&(name, operand)) = OPCODES.get(usize::from(op)) else {
            cx.push(
                Node::new(format!("{i}"))
                    .span(code.sub(to_u64(at), 1))
                    .diag(Diagnostic::malformed(format!("opcode {op}"))),
            )
            .await;
            break;
        };
        let len = usize::from(operand).saturating_add(1);
        let arg = match operand {
            4 => u32_le(&data, at.saturating_add(1))
                .map(|v| format!("{v:#x}"))
                .unwrap_or_default(),
            1 => data
                .get(at.saturating_add(1))
                .map(u8::to_string)
                .unwrap_or_default(),
            _ => String::new(),
        };
        cx.push(
            Node::new(format!("{i}"))
                .span(code.sub(to_u64(at), to_u64(len)))
                .value(text(name))
                .maybe_summary(arg),
        )
        .await;
        at = at.saturating_add(len);
    }
    Ok(())
}
