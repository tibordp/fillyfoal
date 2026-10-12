//! DWARF expressions (location descriptions, `DW_AT_frame_base`, CFA
//! rules) as text: `DW_OP_fbreg -20, DW_OP_deref`.

use crate::fields::Endian;
use crate::formats::util::binutil::Reader;

use super::tables::{op_name, register_name};
use super::{Arch, uint_of};

/// How many operations an expression shows before it is cut short.
const MAX_OPS: usize = 64;

/// The sizes an expression's operands depend on.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Sizes {
    pub address: u8,
    pub offset: u8,
    pub endian: Endian,
    /// For register names.
    pub arch: Arch,
}

fn fixed(r: &mut Reader<'_>, size: u8, endian: Endian) -> Option<u64> {
    let v = uint_of(r.bytes(usize::from(size))?, size, endian)?;
    Some(v)
}

fn signed(v: u64, size: u8) -> i64 {
    let bits = u32::from(size).saturating_mul(8);
    if bits == 0 || bits >= 64 {
        return i64::from_ne_bytes(v.to_ne_bytes());
    }
    let shift = 64u32.saturating_sub(bits);
    i64::from_ne_bytes((v << shift).to_ne_bytes()) >> shift
}

/// Decodes the expression in `data`.
pub(crate) fn describe(data: &[u8], sizes: Sizes) -> String {
    describe_at(data, sizes, 0)
}

fn describe_at(data: &[u8], sizes: Sizes, depth: u8) -> String {
    let mut r = Reader::new(data);
    let mut out: Vec<String> = Vec::new();
    while !r.at_end() {
        if out.len() >= MAX_OPS {
            out.push("…".to_owned());
            break;
        }
        match op(&mut r, sizes, depth) {
            Some(s) => out.push(s),
            None => {
                out.push("<truncated or unknown operation>".to_owned());
                break;
            }
        }
    }
    out.join(", ")
}

fn op(r: &mut Reader<'_>, sizes: Sizes, depth: u8) -> Option<String> {
    let e = sizes.endian;
    let code = r.u8()?;
    let name = op_name(code);
    // "rbp " before an offset, if the register has a name here.
    let named = |reg: u64| register_name(sizes.arch, reg).map(|n| format!("{n} "));
    let operands = match code {
        0x50..=0x6f => {
            register_name(sizes.arch, u64::from(code.saturating_sub(0x50))).unwrap_or_default()
        }
        0x70..=0x8f => format!(
            "{}{:+}",
            named(u64::from(code.saturating_sub(0x70))).unwrap_or_default(),
            r.sleb()?
        ),
        0x90 => {
            let reg = r.uleb()?;
            register_name(sizes.arch, reg).unwrap_or_else(|| format!("{reg:#x}"))
        }
        0x03 => format!("{:#x}", fixed(r, sizes.address, e)?),
        0x08 => format!("{:#x}", r.u8()?),
        0x09 => format!("{}", signed(fixed(r, 1, e)?, 1)),
        0x0a => format!("{:#x}", fixed(r, 2, e)?),
        0x0b => format!("{}", signed(fixed(r, 2, e)?, 2)),
        0x0c => format!("{:#x}", fixed(r, 4, e)?),
        0x0d => format!("{}", signed(fixed(r, 4, e)?, 4)),
        0x0e => format!("{:#x}", fixed(r, 8, e)?),
        0x0f => format!("{}", signed(fixed(r, 8, e)?, 8)),
        0x10 | 0x23 | 0x93 | 0xa1 | 0xa2 | 0xa8 | 0xa9 | 0xf7 | 0xf9 | 0xfb | 0xfc => {
            format!("{:#x}", r.uleb()?)
        }
        0x11 | 0x91 => format!("{:+}", r.sleb()?),
        0x92 => {
            let reg = r.uleb()?;
            let reg = named(reg).unwrap_or_else(|| format!("{reg} "));
            format!("{reg}{:+}", r.sleb()?)
        }
        0x15 | 0x94 | 0x95 => format!("{:#x}", r.u8()?),
        0x28 | 0x2f => format!("{:+}", signed(fixed(r, 2, e)?, 2)),
        0x98 => format!("{:#x}", fixed(r, 2, e)?),
        0x99 | 0xfa => format!("{:#x}", fixed(r, 4, e)?),
        0x9a | 0xfd => format!("{:#x}", fixed(r, sizes.offset, e)?),
        0x9d => {
            let size = r.uleb()?;
            format!("{size:#x} {:#x}", r.uleb()?)
        }
        0x9e => {
            let len = r.uleb()?;
            let bytes = r.bytes(usize::try_from(len).ok()?)?;
            format!("{len:#x} {}", hex_bytes(bytes))
        }
        0xa0 | 0xf2 => {
            let die = fixed(r, sizes.offset, e)?;
            format!("{die:#x} {:+}", r.sleb()?)
        }
        0xa3 | 0xf3 => {
            let len = r.uleb()?;
            let bytes = r.bytes(usize::try_from(len).ok()?)?;
            if depth < 4 {
                format!("({})", describe_at(bytes, sizes, depth.saturating_add(1)))
            } else {
                format!("({})", hex_bytes(bytes))
            }
        }
        0xa4 | 0xf4 => {
            let ty = r.uleb()?;
            let size = r.u8()?;
            let bytes = r.bytes(usize::from(size))?;
            format!("{ty:#x} {}", hex_bytes(bytes))
        }
        0xa5 | 0xf5 => {
            let reg = r.uleb()?;
            let reg = register_name(sizes.arch, reg).unwrap_or_else(|| reg.to_string());
            format!("{reg} {:#x}", r.uleb()?)
        }
        0xa6 | 0xa7 | 0xf6 => {
            let size = r.u8()?;
            format!("{size:#x} {:#x}", r.uleb()?)
        }
        0x06 | 0x12..=0x14 | 0x16..=0x22 | 0x24..=0x27 | 0x29..=0x2e | 0x30..=0x4f => String::new(),
        0x96..=0x97 | 0x9b | 0x9c | 0x9f | 0xe0 | 0xf0 => String::new(),
        _ => return None,
    };
    Some(if operands.is_empty() {
        name
    } else {
        format!("{name} {operands}")
    })
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len().saturating_mul(2).min(64));
    for b in bytes.iter().take(32) {
        s.push_str(&format!("{b:02x}"));
    }
    if bytes.len() > 32 {
        s.push('…');
    }
    s
}
