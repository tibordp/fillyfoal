//! WebAssembly instruction decoding, for listing function bodies.

use super::{heap_type, val_type};
use crate::formats::binutil::Reader;

const NUMERIC: [&str; 128] = [
    "i32.eqz", "i32.eq", "i32.ne", "i32.lt_s", "i32.lt_u", "i32.gt_s", "i32.gt_u", "i32.le_s",
    "i32.le_u", "i32.ge_s", "i32.ge_u", "i64.eqz", "i64.eq", "i64.ne", "i64.lt_s", "i64.lt_u",
    "i64.gt_s", "i64.gt_u", "i64.le_s", "i64.le_u", "i64.ge_s", "i64.ge_u", "f32.eq", "f32.ne",
    "f32.lt", "f32.gt", "f32.le", "f32.ge", "f64.eq", "f64.ne", "f64.lt", "f64.gt", "f64.le",
    "f64.ge", "i32.clz", "i32.ctz", "i32.popcnt", "i32.add", "i32.sub", "i32.mul", "i32.div_s",
    "i32.div_u", "i32.rem_s", "i32.rem_u", "i32.and", "i32.or", "i32.xor", "i32.shl",
    "i32.shr_s", "i32.shr_u", "i32.rotl", "i32.rotr", "i64.clz", "i64.ctz", "i64.popcnt",
    "i64.add", "i64.sub", "i64.mul", "i64.div_s", "i64.div_u", "i64.rem_s", "i64.rem_u",
    "i64.and", "i64.or", "i64.xor", "i64.shl", "i64.shr_s", "i64.shr_u", "i64.rotl", "i64.rotr",
    "f32.abs", "f32.neg", "f32.ceil", "f32.floor", "f32.trunc", "f32.nearest", "f32.sqrt",
    "f32.add", "f32.sub", "f32.mul", "f32.div", "f32.min", "f32.max", "f32.copysign", "f64.abs",
    "f64.neg", "f64.ceil", "f64.floor", "f64.trunc", "f64.nearest", "f64.sqrt", "f64.add",
    "f64.sub", "f64.mul", "f64.div", "f64.min", "f64.max", "f64.copysign", "i32.wrap_i64",
    "i32.trunc_f32_s", "i32.trunc_f32_u", "i32.trunc_f64_s", "i32.trunc_f64_u",
    "i64.extend_i32_s", "i64.extend_i32_u", "i64.trunc_f32_s", "i64.trunc_f32_u",
    "i64.trunc_f64_s", "i64.trunc_f64_u", "f32.convert_i32_s", "f32.convert_i32_u",
    "f32.convert_i64_s", "f32.convert_i64_u", "f32.demote_f64", "f64.convert_i32_s",
    "f64.convert_i32_u", "f64.convert_i64_s", "f64.convert_i64_u", "f64.promote_f32",
    "i32.reinterpret_f32", "i64.reinterpret_f64", "f32.reinterpret_i32", "f64.reinterpret_i64",
    "i32.extend8_s", "i32.extend16_s", "i64.extend8_s", "i64.extend16_s", "i64.extend32_s",
];

const MEMORY: [&str; 23] = [
    "i32.load", "i64.load", "f32.load", "f64.load", "i32.load8_s", "i32.load8_u",
    "i32.load16_s", "i32.load16_u", "i64.load8_s", "i64.load8_u", "i64.load16_s",
    "i64.load16_u", "i64.load32_s", "i64.load32_u", "i32.store", "i64.store", "f32.store",
    "f64.store", "i32.store8", "i32.store16", "i64.store8", "i64.store16", "i64.store32",
];

const MISC: [&str; 18] = [
    "i32.trunc_sat_f32_s", "i32.trunc_sat_f32_u", "i32.trunc_sat_f64_s", "i32.trunc_sat_f64_u",
    "i64.trunc_sat_f32_s", "i64.trunc_sat_f32_u", "i64.trunc_sat_f64_s", "i64.trunc_sat_f64_u",
    "memory.init", "data.drop", "memory.copy", "memory.fill", "table.init", "elem.drop",
    "table.copy", "table.grow", "table.size", "table.fill",
];

const GC: [&str; 31] = [
    "struct.new", "struct.new_default", "struct.get", "struct.get_s", "struct.get_u",
    "struct.set", "array.new", "array.new_default", "array.new_fixed", "array.new_data",
    "array.new_elem", "array.get", "array.get_s", "array.get_u", "array.set", "array.len",
    "array.fill", "array.copy", "array.init_data", "array.init_elem", "ref.test",
    "ref.test null", "ref.cast", "ref.cast null", "br_on_cast", "br_on_cast_fail",
    "any.convert_extern", "extern.convert_any", "ref.i31", "i31.get_s", "i31.get_u",
];

/// How many LEB128 index immediates each GC instruction has (after any
/// heap-type operands, handled separately).
const GC_INDICES: [u8; 31] = [
    1, 1, 2, 2, 2, 2, 1, 1, 2, 2, 2, 1, 1, 1, 1, 0, 1, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

fn memarg(r: &mut Reader<'_>) -> Option<String> {
    let align = r.uleb()?;
    let (memory, align) = if align & 0x40 != 0 {
        (Some(r.uleb()?), align & !0x40)
    } else {
        (None, align)
    };
    let offset = r.uleb()?;
    let mut s = String::new();
    if let Some(m) = memory {
        s.push_str(&format!("memory {m} "));
    }
    if offset != 0 {
        s.push_str(&format!("offset={offset} "));
    }
    s.push_str(&format!("align={}", 1u64.checked_shl(u32::try_from(align).ok()?)?));
    Some(s)
}

fn block_type(r: &mut Reader<'_>) -> Option<String> {
    match r.peek()? {
        0x40 => {
            r.u8();
            Some(String::new())
        }
        0x7f | 0x7e | 0x7d | 0x7c | 0x7b | 0x70 | 0x6f | 0x6e | 0x6d | 0x6c | 0x6b | 0x6a
        | 0x69 | 0x64 | 0x63 => Some(format!("(result {})", val_type(r)?)),
        _ => Some(format!("(type {})", r.sleb()?)),
    }
}

fn indices(r: &mut Reader<'_>, n: u8) -> Option<String> {
    let mut parts = Vec::new();
    for _ in 0..n {
        parts.push(r.uleb()?.to_string());
    }
    Some(parts.join(" "))
}

/// Decodes one instruction: its mnemonic and rendered immediates. `name`
/// gives function names for calls.
pub fn instruction(r: &mut Reader<'_>, name: &dyn Fn(u64) -> Option<String>) -> Option<(String, String)> {
    let op = r.u8()?;
    let call = |r: &mut Reader<'_>| -> Option<String> {
        let f = r.uleb()?;
        Some(match name(f) {
            Some(n) => format!("{f} <{n}>"),
            None => f.to_string(),
        })
    };
    let simple = |s: &str| Some((s.to_owned(), String::new()));
    match op {
        0x00 => simple("unreachable"),
        0x01 => simple("nop"),
        0x02 => Some(("block".to_owned(), block_type(r)?)),
        0x03 => Some(("loop".to_owned(), block_type(r)?)),
        0x04 => Some(("if".to_owned(), block_type(r)?)),
        0x05 => simple("else"),
        0x06 => Some(("try".to_owned(), block_type(r)?)),
        0x07 => Some(("catch".to_owned(), r.uleb()?.to_string())),
        0x08 => Some(("throw".to_owned(), r.uleb()?.to_string())),
        0x09 => Some(("rethrow".to_owned(), r.uleb()?.to_string())),
        0x0a => simple("throw_ref"),
        0x0b => simple("end"),
        0x0c => Some(("br".to_owned(), r.uleb()?.to_string())),
        0x0d => Some(("br_if".to_owned(), r.uleb()?.to_string())),
        0x0e => {
            let n = r.uleb()?;
            let mut labels = Vec::new();
            for _ in 0..n {
                labels.push(r.uleb()?.to_string());
            }
            let default = r.uleb()?;
            let mut s = labels.join(" ");
            if s.len() > 120 {
                s = format!("{n} labels");
            }
            Some(("br_table".to_owned(), format!("{s} default {default}")))
        }
        0x0f => simple("return"),
        0x10 => Some(("call".to_owned(), call(r)?)),
        0x11 => Some((
            "call_indirect".to_owned(),
            format!("type {} table {}", r.uleb()?, r.uleb()?),
        )),
        0x12 => Some(("return_call".to_owned(), call(r)?)),
        0x13 => Some((
            "return_call_indirect".to_owned(),
            format!("type {} table {}", r.uleb()?, r.uleb()?),
        )),
        0x14 => Some(("call_ref".to_owned(), format!("type {}", r.uleb()?))),
        0x15 => Some(("return_call_ref".to_owned(), format!("type {}", r.uleb()?))),
        0x18 => Some(("delegate".to_owned(), r.uleb()?.to_string())),
        0x19 => simple("catch_all"),
        0x1a => simple("drop"),
        0x1b => simple("select"),
        0x1c => {
            let n = r.uleb()?;
            let mut types = Vec::new();
            for _ in 0..n {
                types.push(val_type(r)?);
            }
            Some(("select".to_owned(), types.join(" ")))
        }
        0x1f => {
            let bt = block_type(r)?;
            let n = r.uleb()?;
            let mut catches = Vec::new();
            for _ in 0..n {
                let kind = r.u8()?;
                catches.push(match kind {
                    0 | 1 => format!("catch {} {}", r.uleb()?, r.uleb()?),
                    2 | 3 => format!("catch_all {}", r.uleb()?),
                    _ => return None,
                });
            }
            Some(("try_table".to_owned(), format!("{bt} {}", catches.join(", "))))
        }
        0x20 => Some(("local.get".to_owned(), r.uleb()?.to_string())),
        0x21 => Some(("local.set".to_owned(), r.uleb()?.to_string())),
        0x22 => Some(("local.tee".to_owned(), r.uleb()?.to_string())),
        0x23 => Some(("global.get".to_owned(), r.uleb()?.to_string())),
        0x24 => Some(("global.set".to_owned(), r.uleb()?.to_string())),
        0x25 => Some(("table.get".to_owned(), r.uleb()?.to_string())),
        0x26 => Some(("table.set".to_owned(), r.uleb()?.to_string())),
        0x28..=0x3e => {
            let mnemonic = MEMORY.get(usize::from(op.wrapping_sub(0x28)))?;
            Some(((*mnemonic).to_owned(), memarg(r)?))
        }
        0x3f => Some(("memory.size".to_owned(), r.uleb()?.to_string())),
        0x40 => Some(("memory.grow".to_owned(), r.uleb()?.to_string())),
        0x41 => Some(("i32.const".to_owned(), r.sleb()?.to_string())),
        0x42 => Some(("i64.const".to_owned(), r.sleb()?.to_string())),
        0x43 => Some((
            "f32.const".to_owned(),
            f32::from_le_bytes(r.bytes(4)?.try_into().ok()?).to_string(),
        )),
        0x44 => Some((
            "f64.const".to_owned(),
            f64::from_le_bytes(r.bytes(8)?.try_into().ok()?).to_string(),
        )),
        0x45..=0xc4 => simple(NUMERIC.get(usize::from(op.wrapping_sub(0x45)))?),
        0xd0 => Some(("ref.null".to_owned(), heap_type(r)?)),
        0xd1 => simple("ref.is_null"),
        0xd2 => Some(("ref.func".to_owned(), call(r)?)),
        0xd3 => simple("ref.eq"),
        0xd4 => simple("ref.as_non_null"),
        0xd5 => Some(("br_on_null".to_owned(), r.uleb()?.to_string())),
        0xd6 => Some(("br_on_non_null".to_owned(), r.uleb()?.to_string())),
        0xfb => {
            let sub = r.uleb()?;
            let i = usize::try_from(sub).ok()?;
            let mnemonic = (*GC.get(i)?).to_owned();
            let operands = match sub {
                20..=23 => heap_type(r)?,
                24 | 25 => {
                    let flags = r.u8()?;
                    let label = r.uleb()?;
                    format!("{flags} {label} {} {}", heap_type(r)?, heap_type(r)?)
                }
                _ => indices(r, *GC_INDICES.get(i)?)?,
            };
            Some((mnemonic, operands))
        }
        0xfc => {
            let sub = r.uleb()?;
            let mnemonic = (*MISC.get(usize::try_from(sub).ok()?)?).to_owned();
            let operands = match sub {
                8 | 10 | 12 | 14 => indices(r, 2)?,
                9 | 11 | 13 | 15..=17 => indices(r, 1)?,
                _ => String::new(),
            };
            Some((mnemonic, operands))
        }
        0xfd => {
            let sub = r.uleb()?;
            let operands = match sub {
                0..=11 | 92 | 93 => memarg(r)?,
                12 => format!("v128 {}", crate::formats::binutil::hex_string(r.bytes(16)?)),
                13 => format!("lanes {}", crate::formats::binutil::hex_string(r.bytes(16)?)),
                21..=34 => format!("lane {}", r.u8()?),
                84..=91 => format!("{} lane {}", memarg(r)?, r.u8()?),
                _ => String::new(),
            };
            Some((format!("simd.{sub}"), operands))
        }
        0xfe => {
            let sub = r.uleb()?;
            if sub == 3 {
                r.u8()?;
                return simple("atomic.fence");
            }
            Some((format!("atomic.{sub:#x}"), memarg(r)?))
        }
        _ => None,
    }
}
