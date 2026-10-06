//! Precompiled Lua chunks (`luac` output, `\x1bLua`), versions 5.0 to 5.5.
//!
//! The header records the version, the format and the sizes (and test
//! values) of the C types the chunk was compiled for. It is followed by the
//! main function prototype, whose leading fields (source name, line range,
//! parameters, code size) are decoded for 5.1 to 5.4.

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::binutil::{Reader, dec, text};
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::Value;

pub static FORMAT: Format = Format {
    name: "lua",
    title: "Lua bytecode",
    extensions: &["luac", "out", "lub"],
    mime: "application/x-lua-bytecode",
    probe: Probe::Custom(|h| {
        h.starts_with(b"\x1bLua") && h.data.get(4).is_some_and(|v| (0x50..=0x55).contains(v))
    }),
    dissect: crate::expander!(dissect: Input),
};

const LUAC_DATA: &[u8] = b"\x19\x93\r\n\x1a\n";

#[derive(Clone, Copy, Debug)]
struct Sizes {
    endian: Endian,
    int: u8,
    size_t: u8,
    instruction: u8,
    integer: u8,
}

fn size_field(f: &mut Fields<'_>, name: &'static str) -> Result<u8> {
    f.u8(name).emit()
}

/// Decodes the header; returns the sizes the function prototypes use.
fn header(f: &mut Fields<'_>, version: &u8) -> Result<Sizes> {
    f.bytes("signature", 4).desc("\"\\x1bLua\"").emit()?;
    f.u8("version")
        .hex()
        .with(|&v, n| n.summary(format!("Lua {}.{}", v >> 4, v & 0xf)))
        .emit()?;
    let mut s = Sizes {
        endian: Endian::Little,
        int: 4,
        size_t: 8,
        instruction: 4,
        integer: 8,
    };
    match *version {
        0x50 => {
            s.endian = endian(f.u8("endianness").desc("1: little-endian").emit()?);
            s.int = size_field(f, "sizeof(int)")?;
            s.size_t = size_field(f, "sizeof(size_t)")?;
            s.instruction = size_field(f, "sizeof(Instruction)")?;
            for name in ["SIZE_OP", "SIZE_A", "SIZE_B", "SIZE_C"] {
                f.u8(name).emit()?;
            }
            size_field(f, "sizeof(lua_Number)")?;
            f.f64("test number").emit()?;
        }
        0x51 | 0x52 => {
            f.u8("format").desc("0: official format").emit()?;
            s.endian = endian(f.u8("endianness").desc("1: little-endian").emit()?);
            s.int = size_field(f, "sizeof(int)")?;
            s.size_t = size_field(f, "sizeof(size_t)")?;
            s.instruction = size_field(f, "sizeof(Instruction)")?;
            size_field(f, "sizeof(lua_Number)")?;
            f.u8("integral")
                .desc("1: lua_Number is an integer type")
                .emit()?;
            if *version == 0x52 {
                f.bytes("LUAC_TAIL", 6).emit()?;
            }
        }
        0x53 => {
            f.u8("format").emit()?;
            f.bytes("LUAC_DATA", 6).emit()?;
            s.int = size_field(f, "sizeof(int)")?;
            s.size_t = size_field(f, "sizeof(size_t)")?;
            s.instruction = size_field(f, "sizeof(Instruction)")?;
            s.integer = size_field(f, "sizeof(lua_Integer)")?;
            let number = size_field(f, "sizeof(lua_Number)")?;
            s.endian = test_integer(f, s.integer)?;
            test_number(f, number, s.endian)?;
            f.u8("sizeupvalues").emit()?;
        }
        0x54 => {
            f.u8("format").emit()?;
            f.bytes("LUAC_DATA", 6).emit()?;
            s.instruction = size_field(f, "sizeof(Instruction)")?;
            s.integer = size_field(f, "sizeof(lua_Integer)")?;
            let number = size_field(f, "sizeof(lua_Number)")?;
            s.endian = test_integer(f, s.integer)?;
            test_number(f, number, s.endian)?;
            f.u8("sizeupvalues").emit()?;
        }
        _ => {
            // 5.5: each type's size is followed by a test value.
            f.u8("format").emit()?;
            f.bytes("LUAC_DATA", 6).emit()?;
            s.int = size_field(f, "sizeof(int)")?;
            f.bytes("LUAC_INT (int)", s.int.into()).emit()?;
            s.instruction = size_field(f, "sizeof(Instruction)")?;
            f.bytes("LUAC_INST", s.instruction.into()).emit()?;
            s.integer = size_field(f, "sizeof(lua_Integer)")?;
            s.endian = test_integer(f, s.integer)?;
            let number = size_field(f, "sizeof(lua_Number)")?;
            test_number(f, number, s.endian)?;
            f.u8("sizeupvalues").emit()?;
        }
    }
    Ok(s)
}

fn endian(flag: u8) -> Endian {
    if flag == 0 {
        Endian::Big
    } else {
        Endian::Little
    }
}

/// `LUAC_INT` (0x5678, or -0x5678 in 5.5) in the chunk's byte order, which
/// also reveals that order.
fn test_integer(f: &mut Fields<'_>, size: u8) -> Result<Endian> {
    let span = f.peek_span(size.into());
    let bytes = f.bytes("LUAC_INT", size.into()).get()?;
    let le = i64::from_le_bytes(sign_extend(&bytes, false));
    let be = i64::from_be_bytes(sign_extend(&bytes, true));
    let (endian, value) = if le.unsigned_abs() == 0x5678 {
        (Endian::Little, le)
    } else {
        (Endian::Big, be)
    };
    f.node(
        Node::new("LUAC_INT")
            .span(span)
            .value(Value::Int {
                value,
                bits: size.saturating_mul(8),
            })
            .summary(match endian {
                Endian::Little => "little-endian",
                Endian::Big => "big-endian",
            }),
    );
    Ok(endian)
}

fn sign_extend(bytes: &[u8], big: bool) -> [u8; 8] {
    let negative = if big { bytes.first() } else { bytes.last() }.is_some_and(|b| b & 0x80 != 0);
    let mut out = [if negative { 0xff } else { 0 }; 8];
    let n = bytes.len().min(8);
    if big {
        if let Some(dst) = out.get_mut(8usize.saturating_sub(n)..) {
            dst.copy_from_slice(bytes.get(..n).unwrap_or_default());
        }
    } else if let Some(dst) = out.get_mut(..n) {
        dst.copy_from_slice(bytes.get(..n).unwrap_or_default());
    }
    out
}

fn test_number(f: &mut Fields<'_>, size: u8, endian: Endian) -> Result<()> {
    let span = f.peek_span(size.into());
    let bytes = f.bytes("LUAC_NUM", size.into()).get()?;
    let value = match (size, endian) {
        (8, Endian::Little) => bytes.as_slice().try_into().ok().map(f64::from_le_bytes),
        (8, Endian::Big) => bytes.as_slice().try_into().ok().map(f64::from_be_bytes),
        (4, Endian::Little) => bytes
            .as_slice()
            .try_into()
            .ok()
            .map(|b| f64::from(f32::from_le_bytes(b))),
        (4, Endian::Big) => bytes
            .as_slice()
            .try_into()
            .ok()
            .map(|b| f64::from(f32::from_be_bytes(b))),
        _ => None,
    };
    let node = Node::new("LUAC_NUM").span(span);
    f.node(match value {
        Some(v) => node.value(Value::Float(v)).desc("370.5 (or -370.5 in 5.5)"),
        None => node.value(Value::Bytes(bytes)),
    });
    Ok(())
}

// ---------------------------------------------------------------------------
// Main function

/// What the main function's leading fields decode to.
struct Main {
    nodes: Vec<Node>,
    source: Option<String>,
    instructions: Option<u64>,
}

fn function(data: &[u8], span: Span, version: u8, s: Sizes) -> Main {
    let mut r = Reader::new(data);
    let mut main = Main {
        nodes: Vec::new(),
        source: None,
        instructions: None,
    };
    let at = |start: usize, end: usize| span.sub(to_u64(start), to_u64(end.saturating_sub(start)));
    macro_rules! push {
        ($name:expr, $start:expr, $value:expr) => {{
            let end = r.pos();
            main.nodes
                .push(Node::new($name).span(at($start, end)).value($value));
        }};
    }
    let int = |r: &mut Reader<'_>, size: u8| -> Option<u64> {
        match (size, s.endian) {
            (4, Endian::Little) => r.int::<u32>(Endian::Little).map(u64::from),
            (4, Endian::Big) => r.int::<u32>(Endian::Big).map(u64::from),
            (8, e) => r.int::<u64>(e),
            _ => None,
        }
    };
    // 5.4: MSB-first groups of seven bits; the last byte has the high bit.
    let varint = |r: &mut Reader<'_>| -> Option<u64> {
        let mut v = 0u64;
        for _ in 0..10 {
            let b = r.u8()?;
            v = v.checked_shl(7)? | u64::from(b & 0x7f);
            if b & 0x80 != 0 {
                return Some(v);
            }
        }
        None
    };
    let decoded = (|| -> Option<()> {
        // Source name.
        if matches!(version, 0x51 | 0x53 | 0x54) {
            let start = r.pos();
            let len = match version {
                0x51 => int(&mut r, s.size_t)?,
                0x53 => {
                    let b = r.u8()?;
                    if b == 0xff {
                        int(&mut r, s.size_t)?
                    } else {
                        b.into()
                    }
                }
                _ => varint(&mut r)?,
            };
            let source = if len == 0 {
                String::new()
            } else {
                let n = usize::try_from(len).ok()?;
                // 5.1 counts the NUL; 5.3 and 5.4 store length + 1.
                let bytes = r.bytes(n.checked_sub(if version == 0x51 { 0 } else { 1 })?)?;
                crate::text::until_nul(bytes)
            };
            push!("source", start, text(source.clone()));
            main.source = Some(source);
        }
        for name in ["linedefined", "lastlinedefined"] {
            let start = r.pos();
            let v = if version == 0x54 {
                varint(&mut r)?
            } else {
                int(&mut r, s.int)?
            };
            push!(name, start, dec(v, 32));
        }
        let names: &[&str] = if version == 0x51 {
            &["nups", "numparams", "is_vararg", "maxstacksize"]
        } else {
            &["numparams", "is_vararg", "maxstacksize"]
        };
        for name in names {
            let start = r.pos();
            let v = r.u8()?;
            push!(*name, start, dec(v.into(), 8));
        }
        let start = r.pos();
        let n = if version == 0x54 {
            varint(&mut r)?
        } else {
            int(&mut r, s.int)?
        };
        let code_len = n.checked_mul(s.instruction.into())?;
        r.bytes(usize::try_from(code_len).ok()?)?;
        let end = r.pos();
        main.nodes.push(
            Node::new("code")
                .span(at(start, end))
                .value(dec(n, 32))
                .summary(format!("{n} instructions")),
        );
        main.instructions = Some(n);
        Some(())
    })();
    let rest = span.tail(to_u64(r.pos()));
    let mut node = Node::new("rest of the prototype")
        .span(rest)
        .desc("Constants, upvalues, nested prototypes and debug information");
    if decoded.is_none() {
        node = node.diag(Diagnostic::malformed(
            "truncated or malformed function prototype",
        ));
    }
    main.nodes.push(node);
    main
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 64)).await?;
    let version = head.get(4).copied().unwrap_or(0);
    let block = cx.block(file.sub(0, 64)).await?;
    let mut probe = Fields::new(&block, Endian::Little);
    let sizes = header(&mut probe, &version)?;
    let header_len = probe.pos();
    let hspan = file.sub(0, header_len);
    cx.emit(crate::fields::struct_node(
        "Header",
        hspan,
        Endian::Little,
        version,
        header,
    ));
    if matches!(version, 0x53..=0x55) && head.get(6..12) != Some(LUAC_DATA) {
        cx.diag(Diagnostic::warning(
            "LUAC_DATA does not match (corrupted by a text conversion?)",
        ));
    }
    let body = file.tail(header_len);
    let mut summary = format!("Lua {}.{} bytecode", version >> 4, version & 0xf);
    if matches!(version, 0x51..=0x54) {
        let data = cx.read_avail(body.sub(0, 0x10_0000)).await?;
        let main = function(&data, body, version, sizes);
        if let Some(source) = &main.source
            && !source.is_empty()
        {
            summary.push_str(&format!(", from {}", source.trim_start_matches(['@', '='])));
        }
        if let Some(n) = main.instructions {
            summary.push_str(&format!(", main function of {n} instructions"));
        }
        cx.emit(
            Node::new("Main function")
                .span(body)
                .lazy(emit_nodes, main.nodes),
        );
    } else {
        cx.emit(Node::new("Main function").span(body));
    }
    cx.annotate(summary);
    Ok(())
}

async fn emit_nodes(cx: Cx, nodes: Vec<Node>) -> Result<()> {
    for node in nodes {
        cx.emit(node);
    }
    Ok(())
}
