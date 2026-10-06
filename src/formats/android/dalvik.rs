//! Dalvik bytecode decoding: mnemonics, instruction formats and operands.

/// What a constant pool index operand refers to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ref {
    String,
    Type,
    Field,
    Method,
    Proto,
    CallSite,
    MethodHandle,
}

/// Instruction formats (the Dalvik names: units, registers, kind).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Form {
    F10x,
    F12x,
    F11n,
    F11x,
    F10t,
    F20t,
    F22x,
    F21t,
    F21s,
    F21h,
    F21hw,
    F21c,
    F23x,
    F22b,
    F22t,
    F22s,
    F22c,
    F32x,
    F30t,
    F31t,
    F31i,
    F31c,
    F35c,
    F3rc,
    F45cc,
    F4rcc,
    F51l,
}

fn op(code: u8) -> (&'static str, Form, Option<Ref>) {
    use Form::*;
    const BINOPS: [&str; 32] = [
        "add-int",
        "sub-int",
        "mul-int",
        "div-int",
        "rem-int",
        "and-int",
        "or-int",
        "xor-int",
        "shl-int",
        "shr-int",
        "ushr-int",
        "add-long",
        "sub-long",
        "mul-long",
        "div-long",
        "rem-long",
        "and-long",
        "or-long",
        "xor-long",
        "shl-long",
        "shr-long",
        "ushr-long",
        "add-float",
        "sub-float",
        "mul-float",
        "div-float",
        "rem-float",
        "add-double",
        "sub-double",
        "mul-double",
        "div-double",
        "rem-double",
    ];
    const BINOPS_2ADDR: [&str; 32] = [
        "add-int/2addr",
        "sub-int/2addr",
        "mul-int/2addr",
        "div-int/2addr",
        "rem-int/2addr",
        "and-int/2addr",
        "or-int/2addr",
        "xor-int/2addr",
        "shl-int/2addr",
        "shr-int/2addr",
        "ushr-int/2addr",
        "add-long/2addr",
        "sub-long/2addr",
        "mul-long/2addr",
        "div-long/2addr",
        "rem-long/2addr",
        "and-long/2addr",
        "or-long/2addr",
        "xor-long/2addr",
        "shl-long/2addr",
        "shr-long/2addr",
        "ushr-long/2addr",
        "add-float/2addr",
        "sub-float/2addr",
        "mul-float/2addr",
        "div-float/2addr",
        "rem-float/2addr",
        "add-double/2addr",
        "sub-double/2addr",
        "mul-double/2addr",
        "div-double/2addr",
        "rem-double/2addr",
    ];
    const UNOPS: [&str; 21] = [
        "neg-int",
        "not-int",
        "neg-long",
        "not-long",
        "neg-float",
        "neg-double",
        "int-to-long",
        "int-to-float",
        "int-to-double",
        "long-to-int",
        "long-to-float",
        "long-to-double",
        "float-to-int",
        "float-to-long",
        "float-to-double",
        "double-to-int",
        "double-to-long",
        "double-to-float",
        "int-to-byte",
        "int-to-char",
        "int-to-short",
    ];
    const ARRAY: [&str; 14] = [
        "aget",
        "aget-wide",
        "aget-object",
        "aget-boolean",
        "aget-byte",
        "aget-char",
        "aget-short",
        "aput",
        "aput-wide",
        "aput-object",
        "aput-boolean",
        "aput-byte",
        "aput-char",
        "aput-short",
    ];
    const INSTANCE: [&str; 14] = [
        "iget",
        "iget-wide",
        "iget-object",
        "iget-boolean",
        "iget-byte",
        "iget-char",
        "iget-short",
        "iput",
        "iput-wide",
        "iput-object",
        "iput-boolean",
        "iput-byte",
        "iput-char",
        "iput-short",
    ];
    const STATIC: [&str; 14] = [
        "sget",
        "sget-wide",
        "sget-object",
        "sget-boolean",
        "sget-byte",
        "sget-char",
        "sget-short",
        "sput",
        "sput-wide",
        "sput-object",
        "sput-boolean",
        "sput-byte",
        "sput-char",
        "sput-short",
    ];
    const INVOKE: [&str; 5] = [
        "invoke-virtual",
        "invoke-super",
        "invoke-direct",
        "invoke-static",
        "invoke-interface",
    ];
    const INVOKE_RANGE: [&str; 5] = [
        "invoke-virtual/range",
        "invoke-super/range",
        "invoke-direct/range",
        "invoke-static/range",
        "invoke-interface/range",
    ];
    const CMP: [&str; 5] = [
        "cmpl-float",
        "cmpg-float",
        "cmpl-double",
        "cmpg-double",
        "cmp-long",
    ];
    const IF: [&str; 6] = ["if-eq", "if-ne", "if-lt", "if-ge", "if-gt", "if-le"];
    const IFZ: [&str; 6] = ["if-eqz", "if-nez", "if-ltz", "if-gez", "if-gtz", "if-lez"];
    const LIT16: [&str; 8] = [
        "add-int/lit16",
        "rsub-int",
        "mul-int/lit16",
        "div-int/lit16",
        "rem-int/lit16",
        "and-int/lit16",
        "or-int/lit16",
        "xor-int/lit16",
    ];
    const LIT8: [&str; 11] = [
        "add-int/lit8",
        "rsub-int/lit8",
        "mul-int/lit8",
        "div-int/lit8",
        "rem-int/lit8",
        "and-int/lit8",
        "or-int/lit8",
        "xor-int/lit8",
        "shl-int/lit8",
        "shr-int/lit8",
        "ushr-int/lit8",
    ];
    let pick = |table: &'static [&'static str], base: u8| {
        table
            .get(usize::from(code.wrapping_sub(base)))
            .copied()
            .unwrap_or("?")
    };
    match code {
        0x00 => ("nop", F10x, None),
        0x01 => ("move", F12x, None),
        0x02 => ("move/from16", F22x, None),
        0x03 => ("move/16", F32x, None),
        0x04 => ("move-wide", F12x, None),
        0x05 => ("move-wide/from16", F22x, None),
        0x06 => ("move-wide/16", F32x, None),
        0x07 => ("move-object", F12x, None),
        0x08 => ("move-object/from16", F22x, None),
        0x09 => ("move-object/16", F32x, None),
        0x0a => ("move-result", F11x, None),
        0x0b => ("move-result-wide", F11x, None),
        0x0c => ("move-result-object", F11x, None),
        0x0d => ("move-exception", F11x, None),
        0x0e => ("return-void", F10x, None),
        0x0f => ("return", F11x, None),
        0x10 => ("return-wide", F11x, None),
        0x11 => ("return-object", F11x, None),
        0x12 => ("const/4", F11n, None),
        0x13 => ("const/16", F21s, None),
        0x14 => ("const", F31i, None),
        0x15 => ("const/high16", F21h, None),
        0x16 => ("const-wide/16", F21s, None),
        0x17 => ("const-wide/32", F31i, None),
        0x18 => ("const-wide", F51l, None),
        0x19 => ("const-wide/high16", F21hw, None),
        0x1a => ("const-string", F21c, Some(Ref::String)),
        0x1b => ("const-string/jumbo", F31c, Some(Ref::String)),
        0x1c => ("const-class", F21c, Some(Ref::Type)),
        0x1d => ("monitor-enter", F11x, None),
        0x1e => ("monitor-exit", F11x, None),
        0x1f => ("check-cast", F21c, Some(Ref::Type)),
        0x20 => ("instance-of", F22c, Some(Ref::Type)),
        0x21 => ("array-length", F12x, None),
        0x22 => ("new-instance", F21c, Some(Ref::Type)),
        0x23 => ("new-array", F22c, Some(Ref::Type)),
        0x24 => ("filled-new-array", F35c, Some(Ref::Type)),
        0x25 => ("filled-new-array/range", F3rc, Some(Ref::Type)),
        0x26 => ("fill-array-data", F31t, None),
        0x27 => ("throw", F11x, None),
        0x28 => ("goto", F10t, None),
        0x29 => ("goto/16", F20t, None),
        0x2a => ("goto/32", F30t, None),
        0x2b => ("packed-switch", F31t, None),
        0x2c => ("sparse-switch", F31t, None),
        0x2d..=0x31 => (pick(&CMP, 0x2d), F23x, None),
        0x32..=0x37 => (pick(&IF, 0x32), F22t, None),
        0x38..=0x3d => (pick(&IFZ, 0x38), F21t, None),
        0x44..=0x51 => (pick(&ARRAY, 0x44), F23x, None),
        0x52..=0x5f => (pick(&INSTANCE, 0x52), F22c, Some(Ref::Field)),
        0x60..=0x6d => (pick(&STATIC, 0x60), F21c, Some(Ref::Field)),
        0x6e..=0x72 => (pick(&INVOKE, 0x6e), F35c, Some(Ref::Method)),
        0x74..=0x78 => (pick(&INVOKE_RANGE, 0x74), F3rc, Some(Ref::Method)),
        0x7b..=0x8f => (pick(&UNOPS, 0x7b), F12x, None),
        0x90..=0xaf => (pick(&BINOPS, 0x90), F23x, None),
        0xb0..=0xcf => (pick(&BINOPS_2ADDR, 0xb0), F12x, None),
        0xd0..=0xd7 => (pick(&LIT16, 0xd0), F22s, None),
        0xd8..=0xe2 => (pick(&LIT8, 0xd8), F22b, None),
        0xfa => ("invoke-polymorphic", F45cc, Some(Ref::Method)),
        0xfb => ("invoke-polymorphic/range", F4rcc, Some(Ref::Method)),
        0xfc => ("invoke-custom", F35c, Some(Ref::CallSite)),
        0xfd => ("invoke-custom/range", F3rc, Some(Ref::CallSite)),
        0xfe => ("const-method-handle", F21c, Some(Ref::MethodHandle)),
        0xff => ("const-method-type", F21c, Some(Ref::Proto)),
        _ => ("unused", F10x, None),
    }
}

/// A decoded instruction.
pub struct Insn {
    pub mnemonic: &'static str,
    /// Registers and literals, rendered.
    pub operands: String,
    /// A constant pool reference, to be resolved by the caller.
    pub reference: Option<(Ref, u32)>,
    /// Length in 16-bit code units.
    pub units: usize,
}

fn i16_of(u: u16) -> i64 {
    i64::from(i16::from_le_bytes(u.to_le_bytes()))
}

fn i32_of(lo: u16, hi: u16) -> i64 {
    i64::from(i32::from_le_bytes(
        (u32::from(lo) | (u32::from(hi) << 16)).to_le_bytes(),
    ))
}

fn target(pc: usize, delta: i64) -> String {
    let t = i64::try_from(pc).unwrap_or(0).saturating_add(delta);
    format!("{t:#06x}")
}

/// Decodes the instruction at `units[pc]`, or a payload pseudo-instruction.
pub fn decode(units: &[u16], pc: usize) -> Option<Insn> {
    let u = |i: usize| units.get(pc.checked_add(i)?).copied();
    let u0 = u(0)?;
    let code = u8::try_from(u0 & 0xff).ok()?;
    let a8 = u0 >> 8;
    let a4 = (u0 >> 8) & 0xf;
    let b4 = u0 >> 12;
    // Payloads live inline, after a nop opcode byte.
    if code == 0 && a8 != 0 {
        let (name, len) = match a8 {
            1 => {
                let size = usize::from(u(1)?);
                (
                    "packed-switch-payload",
                    size.checked_mul(2)?.checked_add(4)?,
                )
            }
            2 => {
                let size = usize::from(u(1)?);
                (
                    "sparse-switch-payload",
                    size.checked_mul(4)?.checked_add(2)?,
                )
            }
            3 => {
                let width = usize::from(u(1)?);
                let size = usize::try_from(u32::from(u(2)?) | (u32::from(u(3)?) << 16)).ok()?;
                let bytes = size.checked_mul(width)?;
                (
                    "fill-array-data-payload",
                    (bytes.checked_add(1)? / 2).checked_add(4)?,
                )
            }
            _ => return None,
        };
        return Some(Insn {
            mnemonic: name,
            operands: format!("{} units", len),
            reference: None,
            units: len,
        });
    }
    let (mnemonic, format, kind) = op(code);
    use Form::*;
    let (operands, reference, units) = match format {
        F10x => (String::new(), None, 1),
        F12x => (format!("v{a4}, v{b4}"), None, 1),
        F11n => {
            let lit = i64::from(i8::from_le_bytes([u8::try_from(b4 << 4).unwrap_or(0)]) >> 4);
            (format!("v{a4}, #{lit}"), None, 1)
        }
        F11x => (format!("v{a8}"), None, 1),
        F10t => {
            let d = i64::from(i8::from_le_bytes([u8::try_from(a8).unwrap_or(0)]));
            (target(pc, d), None, 1)
        }
        F20t => (target(pc, i16_of(u(1)?)), None, 2),
        F22x => (format!("v{a8}, v{}", u(1)?), None, 2),
        F21t => (format!("v{a8}, {}", target(pc, i16_of(u(1)?))), None, 2),
        F21s => (format!("v{a8}, #{}", i16_of(u(1)?)), None, 2),
        F21h => (format!("v{a8}, #{:#x}", u32::from(u(1)?) << 16), None, 2),
        F21hw => (format!("v{a8}, #{:#x}", u64::from(u(1)?) << 48), None, 2),
        F21c => (
            format!("v{a8}"),
            {
                let i = u32::from(u(1)?);
                kind.map(|k| (k, i))
            },
            2,
        ),
        F23x => {
            let b = u(1)?;
            (format!("v{a8}, v{}, v{}", b & 0xff, b >> 8), None, 2)
        }
        F22b => {
            let b = u(1)?;
            let lit = i8::from_le_bytes([u8::try_from(b >> 8).unwrap_or(0)]);
            (format!("v{a8}, v{}, #{lit}", b & 0xff), None, 2)
        }
        F22t => (
            format!("v{a4}, v{b4}, {}", target(pc, i16_of(u(1)?))),
            None,
            2,
        ),
        F22s => (format!("v{a4}, v{b4}, #{}", i16_of(u(1)?)), None, 2),
        F22c => (
            format!("v{a4}, v{b4}"),
            {
                let i = u32::from(u(1)?);
                kind.map(|k| (k, i))
            },
            2,
        ),
        F32x => (format!("v{}, v{}", u(1)?, u(2)?), None, 3),
        F30t => (target(pc, i32_of(u(1)?, u(2)?)), None, 3),
        F31t => (
            format!("v{a8}, {}", target(pc, i32_of(u(1)?, u(2)?))),
            None,
            3,
        ),
        F31i => (format!("v{a8}, #{}", i32_of(u(1)?, u(2)?)), None, 3),
        F31c => (
            format!("v{a8}"),
            {
                let i = u32::from(u(1)?) | (u32::from(u(2)?) << 16);
                kind.map(|k| (k, i))
            },
            3,
        ),
        F35c | F45cc => {
            let count = usize::from(b4);
            let regs = u(2)?;
            let all = [
                regs & 0xf,
                (regs >> 4) & 0xf,
                (regs >> 8) & 0xf,
                regs >> 12,
                a4,
            ];
            let list: Vec<String> = all.iter().take(count).map(|r| format!("v{r}")).collect();
            let units = if format == F45cc { 4 } else { 3 };
            (
                format!("{{{}}}", list.join(", ")),
                {
                    let i = u32::from(u(1)?);
                    kind.map(|k| (k, i))
                },
                units,
            )
        }
        F3rc | F4rcc => {
            let first = u32::from(u(2)?);
            let last = first.saturating_add(u32::from(a8)).saturating_sub(1);
            let units = if format == F4rcc { 4 } else { 3 };
            (
                format!("{{v{first} .. v{last}}}"),
                {
                    let i = u32::from(u(1)?);
                    kind.map(|k| (k, i))
                },
                units,
            )
        }
        F51l => {
            let v = u64::from(u(1)?)
                | (u64::from(u(2)?) << 16)
                | (u64::from(u(3)?) << 32)
                | (u64::from(u(4)?) << 48);
            (
                format!("v{a8}, #{}", i64::from_le_bytes(v.to_le_bytes())),
                None,
                5,
            )
        }
    };
    Some(Insn {
        mnemonic,
        operands,
        reference,
        units,
    })
}
