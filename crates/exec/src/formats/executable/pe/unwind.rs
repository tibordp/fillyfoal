//! Exception data (`.pdata`): function tables for table-based exception
//! handling, by machine.
//!
//! - x64: `RUNTIME_FUNCTION` (begin, end, unwind info RVA) and `UNWIND_INFO`
//!   with its unwind codes, chained entries and handlers (Microsoft "x64
//!   exception handling" documentation; slot counts as in LLVM's
//!   `Win64EH`).
//! - ARM64: `(begin, unwind data)` pairs whose low bits select packed unwind
//!   data or an `.xdata` record (header, epilog scopes, unwind code bytes,
//!   handler) ("ARM64 exception handling" documentation).
//! - ARMv7 (Thumb-2): the same pairs, shown without decoding the unwind data.

use super::tables::{MACHINE_AMD64, MACHINE_ARM64, MACHINE_ARM64EC, MACHINE_ARM64X, MACHINE_ARMNT};
use super::{Directory, LE, Pe, rva_field};
use crate::bytes::{to_u64, u16_le, u32_le};
use crate::cx::Cx;
use crate::error::Result;
use crate::fields::{Fields, struct_node};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{Radix, Value};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Arch {
    X64,
    Arm64,
    Arm,
    /// MIPS, Alpha, PowerPC: 20-byte entries.
    Legacy,
}

fn arch(machine: u16) -> Arch {
    match machine {
        MACHINE_AMD64 => Arch::X64,
        MACHINE_ARM64 | MACHINE_ARM64EC | MACHINE_ARM64X => Arch::Arm64,
        MACHINE_ARMNT | 0x1c0 | 0x1c2 => Arch::Arm,
        _ => Arch::Legacy,
    }
}

fn hex32(v: u32) -> Value {
    Value::UInt {
        value: v.into(),
        bits: 32,
        radix: Radix::Hex,
    }
}

pub(super) async fn exceptions(cx: Cx, (pe, dir): (Pe, Directory)) -> Result<()> {
    let a = arch(pe.machine);
    let entry = match a {
        Arch::X64 => 12u64,
        Arch::Arm64 | Arch::Arm => 8,
        Arch::Legacy => 20,
    };
    let count = dir.span.len.checked_div(entry).unwrap_or(0);
    cx.set_count(Count::Exact(count));
    cx.annotate(format!("{count} functions"));
    for i in 0..count {
        let span = dir.span.sub(i.saturating_mul(entry), entry);
        let data = cx.read(span).await?;
        let begin = u32_le(&data, 0).unwrap_or(0);
        let second = u32_le(&data, 4).unwrap_or(0);
        let node = match a {
            Arch::X64 | Arch::Legacy => Node::new(format!("{begin:#x}..{second:#x}"))
                .summary(format!("{} bytes", second.saturating_sub(begin))),
            Arch::Arm64 | Arch::Arm => {
                let summary = match second & 3 {
                    0 => format!("unwind data at {second:#x}"),
                    1 => format!(
                        "packed, {} bytes",
                        ((second >> 2) & 0x7ff).saturating_mul(if a == Arch::Arm { 2 } else { 4 })
                    ),
                    2 => format!(
                        "packed fragment, {} bytes",
                        ((second >> 2) & 0x7ff).saturating_mul(if a == Arch::Arm { 2 } else { 4 })
                    ),
                    _ => "reserved".to_owned(),
                };
                Node::new(format!("{begin:#x}")).summary(summary)
            }
        };
        let node = match pe.rva_span(begin, 0) {
            Ok(code) => node.target(code),
            Err(_) => node,
        };
        cx.push(node.span(span).lazy(function, (pe.clone(), span)))
            .await;
    }
    Ok(())
}

fn x64_function(f: &mut Fields<'_>, pe: &Pe) -> Result<u32> {
    rva_field(f.u32("BeginAddress"), pe).emit()?;
    rva_field(f.u32("EndAddress"), pe).emit()?;
    rva_field(f.u32("UnwindInfoAddress"), pe)
        .desc("RVA of the UNWIND_INFO (bit 0 set: of another RUNTIME_FUNCTION)")
        .emit()
}

fn legacy_function(f: &mut Fields<'_>, pe: &Pe) -> Result<()> {
    rva_field(f.u32("BeginAddress"), pe).emit()?;
    rva_field(f.u32("EndAddress"), pe).emit()?;
    f.u32("ExceptionHandler").hex().emit()?;
    f.u32("HandlerData").hex().emit()?;
    f.u32("PrologEndAddress").hex().emit()?;
    Ok(())
}

async fn function(cx: Cx, (pe, span): (Pe, Span)) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    match arch(pe.machine) {
        Arch::X64 => {
            let unwind = x64_function(&mut f, &pe)?;
            if unwind & 1 == 0 && unwind != 0 {
                let info = pe.rva_span(unwind, 528)?;
                cx.emit(
                    Node::new("Unwind Info")
                        .span(info.sub(0, 4))
                        .lazy(x64_unwind, (pe.clone(), info)),
                );
            }
        }
        Arch::Legacy => legacy_function(&mut f, &pe)?,
        a @ (Arch::Arm64 | Arch::Arm) => {
            rva_field(f.u32("BeginAddress"), &pe).emit()?;
            let data = f
                .u32("UnwindData")
                .hex()
                .desc("Bits 0-1: 0 = RVA of an .xdata record, 1 = packed, 2 = packed fragment")
                .emit()?;
            match data & 3 {
                0 if data != 0 => {
                    if a == Arch::Arm64 {
                        let xdata = pe.rva_span(data, 4)?;
                        cx.emit(
                            Node::new("Unwind Data (.xdata)")
                                .span(xdata)
                                .lazy(arm64_xdata, (pe.clone(), data)),
                        );
                    } else if let Ok(xdata) = pe.rva_span(data, 4) {
                        cx.emit(Node::new("Unwind Data (.xdata)").target(xdata));
                    }
                }
                1 | 2 if a == Arch::Arm64 => {
                    cx.emit(packed_arm64(span.sub(4, 4), data));
                }
                _ => {}
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// x64

const X64_REGISTERS: [&str; 16] = [
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15",
];

fn reg(n: u16) -> &'static str {
    X64_REGISTERS
        .get(usize::from(n & 15))
        .copied()
        .unwrap_or("?")
}

/// Decodes the unwind code at slot `i`; returns its slot count and text.
fn x64_code(codes: &[u8], i: usize, version: u8, frame: u8) -> (usize, &'static str, String) {
    let slot = |k: usize| u16_le(codes, i.saturating_add(k).saturating_mul(2)).unwrap_or(0);
    let s0 = slot(0);
    let op = (s0 >> 8) & 0xf;
    let info = s0 >> 12;
    let next32 = || u32::from(slot(1)) | (u32::from(slot(2)) << 16);
    match op {
        0 => (1, "PUSH_NONVOL", format!("push {}", reg(info))),
        1 if info == 0 => (
            2,
            "ALLOC_LARGE",
            format!("sub rsp, {:#x}", u32::from(slot(1)).saturating_mul(8)),
        ),
        1 => (3, "ALLOC_LARGE", format!("sub rsp, {:#x}", next32())),
        2 => (
            1,
            "ALLOC_SMALL",
            format!("sub rsp, {:#x}", info.saturating_mul(8).saturating_add(8)),
        ),
        3 => (
            1,
            "SET_FPREG",
            format!(
                "lea {}, [rsp+{:#x}]",
                reg(u16::from(frame & 15)),
                u16::from(frame >> 4).saturating_mul(16)
            ),
        ),
        4 => (
            2,
            "SAVE_NONVOL",
            format!(
                "mov [rsp+{:#x}], {}",
                u32::from(slot(1)).saturating_mul(8),
                reg(info)
            ),
        ),
        5 => (
            3,
            "SAVE_NONVOL_FAR",
            format!("mov [rsp+{:#x}], {}", next32(), reg(info)),
        ),
        6 if version >= 2 => (
            2,
            "EPILOG",
            format!("epilog of {} bytes (flags {info:#x})", s0 & 0xff),
        ),
        6 => (
            2,
            "SAVE_XMM",
            format!(
                "movaps [rsp+{:#x}], xmm{info}",
                u32::from(slot(1)).saturating_mul(8)
            ),
        ),
        7 => (3, "SPARE_CODE", "reserved".to_owned()),
        8 => (
            2,
            "SAVE_XMM128",
            format!(
                "movaps [rsp+{:#x}], xmm{info}",
                u32::from(slot(1)).saturating_mul(16)
            ),
        ),
        9 => (
            3,
            "SAVE_XMM128_FAR",
            format!("movaps [rsp+{:#x}], xmm{info}", next32()),
        ),
        10 => (
            1,
            "PUSH_MACHFRAME",
            if info == 0 {
                "machine frame".to_owned()
            } else {
                "machine frame with error code".to_owned()
            },
        ),
        _ => (1, "UNKNOWN", format!("op {op}")),
    }
}

async fn x64_unwind(cx: Cx, (pe, span): (Pe, Span)) -> Result<()> {
    let data = cx.read_avail(span).await?;
    let first = data.first().copied().unwrap_or(0);
    let version = first & 7;
    let flags = first >> 3;
    let count = usize::from(data.get(2).copied().unwrap_or(0));
    let frame = data.get(3).copied().unwrap_or(0);
    let mut names = Vec::new();
    if flags & 1 != 0 {
        names.push("EHANDLER");
    }
    if flags & 2 != 0 {
        names.push("UHANDLER");
    }
    if flags & 4 != 0 {
        names.push("CHAININFO");
    }
    cx.emit(
        Node::new("Version / Flags")
            .span(span.sub(0, 1))
            .value(Value::UInt {
                value: first.into(),
                bits: 8,
                radix: Radix::Hex,
            })
            .summary(format!(
                "version {version}{}{}",
                if names.is_empty() { "" } else { ", " },
                names.join(" | ")
            )),
    );
    cx.emit(
        Node::new("SizeOfProlog")
            .span(span.sub(1, 1))
            .value(Value::UInt {
                value: data.get(1).copied().unwrap_or(0).into(),
                bits: 8,
                radix: Radix::Dec,
            }),
    );
    cx.emit(
        Node::new("CountOfCodes")
            .span(span.sub(2, 1))
            .value(Value::UInt {
                value: to_u64(count),
                bits: 8,
                radix: Radix::Dec,
            })
            .desc("Unwind code slots (16 bits each)"),
    );
    cx.emit(
        Node::new("FrameRegister / FrameOffset")
            .span(span.sub(3, 1))
            .value(Value::UInt {
                value: frame.into(),
                bits: 8,
                radix: Radix::Hex,
            })
            .summary(if frame & 15 == 0 {
                "no frame pointer".to_owned()
            } else {
                format!(
                    "{} = rsp + {:#x}",
                    reg(u16::from(frame & 15)),
                    u16::from(frame >> 4).saturating_mul(16)
                )
            }),
    );
    let codes = data.get(4..).unwrap_or_default();
    let mut i = 0usize;
    while i < count {
        let (slots, name, text) = x64_code(codes, i, version, frame);
        let offset = codes.get(i.saturating_mul(2)).copied().unwrap_or(0);
        let at = 4u64.saturating_add(to_u64(i).saturating_mul(2));
        let len = to_u64(slots.min(count.saturating_sub(i))).saturating_mul(2);
        cx.push(
            Node::new(format!("{name} @{offset:#x}"))
                .span(span.sub(at, len))
                .value(Value::Text(text))
                .desc("Prolog offset of the instruction after the operation, and what it did"),
        )
        .await;
        i = i.saturating_add(slots);
    }
    // The code array is padded to an even number of slots.
    let mut at = 4u64.saturating_add(to_u64(count).saturating_mul(2));
    if count % 2 == 1 {
        cx.emit(Node::new("Padding").span(span.sub(at, 2)));
        at = at.saturating_add(2);
    }
    if flags & 4 != 0 {
        cx.emit(struct_node(
            "Chained Function",
            span.sub(at, 12),
            LE,
            pe.clone(),
            x64_function,
        ));
    } else if flags & 3 != 0 {
        let block = cx.block(span.sub(at, 4)).await?;
        rva_field(
            Fields::emitting(&cx, &block, LE).u32("ExceptionHandler"),
            &pe,
        )
        .desc("RVA of the language-specific handler; its data follows")
        .emit()?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ARM64

fn packed_arm64(span: Span, d: u32) -> Node {
    let length = ((d >> 2) & 0x7ff).saturating_mul(4);
    let reg_f = (d >> 13) & 7;
    let reg_i = (d >> 16) & 0xf;
    let h = (d >> 20) & 1;
    let cr = (d >> 21) & 3;
    let frame = ((d >> 23) & 0x1ff).saturating_mul(16);
    let cr_text = match cr {
        0 => "unchained, lr saved with the integer registers",
        1 => "unchained, lr saved separately",
        2 => "chained, with pointer authentication",
        _ => "chained (fp/lr saved, fp set)",
    };
    Node::new("Packed Unwind Data")
        .span(span)
        .value(hex32(d))
        .summary(format!(
            "{length} bytes, frame {frame} bytes, {reg_i} integer and {} FP registers saved{}, {cr_text}",
            if reg_f == 0 { 0 } else { reg_f.saturating_add(1) },
            if h == 1 { ", parameters homed" } else { "" }
        ))
        .desc("FunctionLength, RegF, RegI, H, CR and FrameSize packed into one word")
}

/// Decodes one ARM64 unwind code; returns its length in bytes and text.
fn arm64_code(code: &[u8], i: usize) -> (usize, String) {
    let b = |k: usize| u32::from(code.get(i.saturating_add(k)).copied().unwrap_or(0));
    let b0 = b(0);
    let b1 = b(1);
    // Scaled offsets: `z * 8`, `(z + 1) * 8`, register numbers `base + x`.
    let by = |v: u32, scale: u32| v.saturating_mul(scale);
    let pre = |z: u32| z.saturating_add(1).saturating_mul(8);
    let r = |base: u32, x: u32| base.saturating_add(x);
    match b0 {
        0x00..=0x1f => (1, format!("alloc_s: sub sp, #{}", by(b0 & 0x1f, 16))),
        0x20..=0x3f => (
            1,
            format!("save_r19r20_x: stp x19, x20, [sp, #-{}]!", by(b0 & 0x1f, 8)),
        ),
        0x40..=0x7f => (
            1,
            format!("save_fplr: stp fp, lr, [sp, #{}]", by(b0 & 0x3f, 8)),
        ),
        0x80..=0xbf => (
            1,
            format!("save_fplr_x: stp fp, lr, [sp, #-{}]!", pre(b0 & 0x3f)),
        ),
        0xc0..=0xc7 => (
            2,
            format!("alloc_m: sub sp, #{}", by(((b0 & 7) << 8) | b1, 16)),
        ),
        0xc8..=0xcf => {
            let x = ((b0 & 3) << 2) | (b1 >> 6);
            let z = b1 & 0x3f;
            if b0 < 0xcc {
                (
                    2,
                    format!(
                        "save_regp: stp x{}, x{}, [sp, #{}]",
                        r(19, x),
                        r(20, x),
                        by(z, 8)
                    ),
                )
            } else {
                (
                    2,
                    format!(
                        "save_regp_x: stp x{}, x{}, [sp, #-{}]!",
                        r(19, x),
                        r(20, x),
                        pre(z)
                    ),
                )
            }
        }
        0xd0..=0xd3 => {
            let x = ((b0 & 3) << 2) | (b1 >> 6);
            (
                2,
                format!("save_reg: str x{}, [sp, #{}]", r(19, x), by(b1 & 0x3f, 8)),
            )
        }
        0xd4 | 0xd5 => {
            let x = ((b0 & 1) << 3) | (b1 >> 5);
            (
                2,
                format!("save_reg_x: str x{}, [sp, #-{}]!", r(19, x), pre(b1 & 0x1f)),
            )
        }
        0xd6 | 0xd7 => {
            let x = ((b0 & 1) << 2) | (b1 >> 6);
            (
                2,
                format!(
                    "save_lrpair: stp x{}, lr, [sp, #{}]",
                    r(19, by(x, 2)),
                    by(b1 & 0x3f, 8)
                ),
            )
        }
        0xd8..=0xdd => {
            let x = ((b0 & 1) << 2) | (b1 >> 6);
            let z = b1 & 0x3f;
            match b0 {
                0xd8 | 0xd9 => (
                    2,
                    format!(
                        "save_fregp: stp d{}, d{}, [sp, #{}]",
                        r(8, x),
                        r(9, x),
                        by(z, 8)
                    ),
                ),
                0xda | 0xdb => (
                    2,
                    format!(
                        "save_fregp_x: stp d{}, d{}, [sp, #-{}]!",
                        r(8, x),
                        r(9, x),
                        pre(z)
                    ),
                ),
                _ => (
                    2,
                    format!("save_freg: str d{}, [sp, #{}]", r(8, x), by(z, 8)),
                ),
            }
        }
        0xde => (
            2,
            format!(
                "save_freg_x: str d{}, [sp, #-{}]!",
                r(8, b1 >> 5),
                pre(b1 & 0x1f)
            ),
        ),
        0xdf => (2, format!("alloc_z: addvl sp, #-{b1}")),
        0xe0 => (
            4,
            format!(
                "alloc_l: sub sp, #{}",
                by((b1 << 16) | (b(2) << 8) | b(3), 16)
            ),
        ),
        0xe1 => (1, "set_fp: mov fp, sp".to_owned()),
        0xe2 => (2, format!("add_fp: add fp, sp, #{}", by(b1, 8))),
        0xe3 => (1, "nop".to_owned()),
        0xe4 => (1, "end".to_owned()),
        0xe5 => (1, "end_c".to_owned()),
        0xe6 => (1, "save_next".to_owned()),
        0xe7 => (3, "save_any_reg".to_owned()),
        0xe8 => (1, "MSFT_OP_TRAP_FRAME".to_owned()),
        0xe9 => (1, "MSFT_OP_MACHINE_FRAME".to_owned()),
        0xea => (1, "MSFT_OP_CONTEXT".to_owned()),
        0xeb => (1, "MSFT_OP_EC_CONTEXT".to_owned()),
        0xec => (1, "MSFT_OP_CLEAR_UNWOUND_TO_CALL".to_owned()),
        0xfc => (1, "pac_sign_lr".to_owned()),
        _ => (1, format!("reserved {b0:#04x}")),
    }
}

/// An ARM64 `.xdata` record.
async fn arm64_xdata(cx: Cx, (pe, rva): (Pe, u32)) -> Result<()> {
    let head_span = pe.rva_span(rva, 8)?;
    let head = cx.read_avail(head_span).await?;
    let w = u32_le(&head, 0).unwrap_or(0);
    let mut epilogs = (w >> 22) & 0x1f;
    let mut words = (w >> 27) & 0x1f;
    let x = (w >> 20) & 1;
    let e = (w >> 21) & 1;
    cx.emit(
        Node::new("Header")
            .span(head_span.sub(0, 4))
            .value(hex32(w))
            .summary(format!(
                "function {} bytes, version {}{}{}, {epilogs} epilog{}, {words} code words",
                (w & 0x3ffff).saturating_mul(4),
                (w >> 18) & 3,
                if x == 1 { ", exception data" } else { "" },
                if e == 1 { ", single packed epilog" } else { "" },
                if epilogs == 1 { "" } else { "s" },
            ))
            .desc("FunctionLength, Vers, X, E, Epilog Count and Code Words"),
    );
    let mut at = 4u64;
    if epilogs == 0 && words == 0 {
        let ext = u32_le(&head, 4).unwrap_or(0);
        epilogs = ext & 0xffff;
        words = (ext >> 16) & 0xff;
        cx.emit(
            Node::new("Extended Header")
                .span(head_span.sub(4, 4))
                .value(hex32(ext))
                .summary(format!("{epilogs} epilogs, {words} code words")),
        );
        at = 8;
    }
    let scopes = if e == 1 { 0 } else { epilogs };
    let total = u64::from(scopes)
        .saturating_mul(4)
        .saturating_add(u64::from(words).saturating_mul(4))
        .saturating_add(if x == 1 { 4 } else { 0 });
    let body = pe.rva_span(rva, at.saturating_add(total))?;
    let data = cx.read_avail(body).await?;
    for i in 0..u64::from(scopes) {
        let pos = crate::bytes::to_usize(at);
        let s = u32_le(&data, pos).unwrap_or(0);
        cx.push(
            Node::new(format!("Epilog Scope {i}"))
                .span(body.sub(at, 4))
                .value(hex32(s))
                .summary(format!(
                    "starts at +{:#x}, codes from index {}",
                    (s & 0x3ffff).saturating_mul(4),
                    s >> 22
                )),
        )
        .await;
        at = at.saturating_add(4);
    }
    let code_len = u64::from(words).saturating_mul(4);
    let start = crate::bytes::to_usize(at);
    let code = data
        .get(start..start.saturating_add(crate::bytes::to_usize(code_len)))
        .unwrap_or_default();
    let mut i = 0usize;
    while i < code.len() {
        let (len, text) = arm64_code(code, i);
        let len = len.min(code.len().saturating_sub(i));
        cx.push(
            Node::new(format!("Code @{i}"))
                .span(body.sub(at.saturating_add(to_u64(i)), to_u64(len)))
                .value(Value::Text(text)),
        )
        .await;
        i = i.saturating_add(len.max(1));
    }
    at = at.saturating_add(code_len);
    if x == 1 {
        let pos = crate::bytes::to_usize(at);
        let handler = u32_le(&data, pos).unwrap_or(0);
        let mut node = Node::new("Exception Handler")
            .span(body.sub(at, 4))
            .value(hex32(handler))
            .summary(pe.describe_rva(handler))
            .desc("RVA of the language-specific handler; its data follows");
        if let Ok(t) = pe.rva_span(handler, 0) {
            node = node.target(t);
        }
        cx.emit(node);
    }
    Ok(())
}
