//! Helpers shared by the stream decoders: a small table-driven language for
//! fixed record layouts, Excel and Office string forms, and text by code
//! page.

use crate::error::Result;
use crate::fields::{Endian, Fields};
use crate::node::Node;
use crate::value::{EnumTable, FlagTable, Value};

pub const LE: Endian = Endian::Little;

/// One field of a fixed layout (the full vocabulary, not all of it in use).
#[allow(dead_code)]
#[derive(Clone, Copy)]
pub enum K {
    U8,
    U16,
    U32,
    I16,
    I32,
    F64,
    H8,
    H16,
    H32,
    E8(EnumTable),
    E16(EnumTable),
    E32(EnumTable),
    F8(FlagTable),
    F16(FlagTable),
    F32(FlagTable),
    /// A 16-bit boolean.
    Bool16,
    /// An 8-bit boolean.
    Bool8,
    /// An Excel RK number.
    Rk,
    /// A zero-based row (u16), shown one-based.
    Row,
    /// A zero-based row (u32), shown one-based.
    Row32,
    /// A zero-based column (u16), shown as letters.
    Col,
    /// A zero-based column (u8), shown as letters.
    Col8,
    /// A length in twips (u16), shown in points.
    Twips,
    /// A height in twips (u16), shown in points.
    ITwips,
    /// An LCID (u16).
    Lcid,
    /// XLUnicodeString: u16 count, flags byte, characters.
    XlStr,
    /// ShortXLUnicodeString: u8 count, flags byte, characters.
    XlStr8,
    /// BIFF5 byte string: u8 count, bytes in the workbook code page.
    Str8,
    /// BIFF5 byte string with a u16 count.
    Str16,
    Guid,
    /// A FILETIME (u64).
    FileTime,
    /// Reserved or unused bytes.
    Pad(u64),
}

/// A fixed layout: field names and kinds, in order.
pub type Spec = &'static [(&'static str, K)];

/// A layout function over a [`Spec`], for `struct_node` and `parse`.
pub fn layout(f: &mut Fields<'_>, spec: &Spec) -> Result<()> {
    for &(name, kind) in spec.iter() {
        field(f, name, kind)?;
    }
    Ok(())
}

/// Decodes (and emits) one field.
pub fn field(f: &mut Fields<'_>, name: &'static str, kind: K) -> Result<()> {
    match kind {
        K::U8 => {
            f.u8(name).emit()?;
        }
        K::U16 => {
            f.u16(name).emit()?;
        }
        K::U32 => {
            f.u32(name).emit()?;
        }
        K::I16 => {
            f.int::<i16>(name).emit()?;
        }
        K::I32 => {
            f.i32(name).emit()?;
        }
        K::F64 => {
            f.f64(name).emit()?;
        }
        K::H8 => {
            f.u8(name).hex().emit()?;
        }
        K::H16 => {
            f.u16(name).hex().emit()?;
        }
        K::H32 => {
            f.u32(name).hex().emit()?;
        }
        K::E8(t) => {
            f.u8(name).enumeration(t).emit()?;
        }
        K::E16(t) => {
            f.u16(name).enumeration(t).emit()?;
        }
        K::E32(t) => {
            f.u32(name).enumeration(t).emit()?;
        }
        K::F8(t) => {
            f.u8(name).flags(t).emit()?;
        }
        K::F16(t) => {
            f.u16(name).flags(t).emit()?;
        }
        K::F32(t) => {
            f.u32(name).flags(t).emit()?;
        }
        K::Bool16 => {
            f.u16(name)
                .with(|&v, n| n.value(Value::Bool(v != 0)))
                .emit()?;
        }
        K::Bool8 => {
            f.u8(name)
                .with(|&v, n| n.value(Value::Bool(v != 0)))
                .emit()?;
        }
        K::Rk => {
            f.u32(name)
                .with(|&v, n| {
                    n.value(Value::Float(rk(v)))
                        .summary(format!("RK {v:#010x}"))
                })
                .emit()?;
        }
        K::Row => {
            f.u16(name)
                .with(|&v, n| n.summary(format!("row {}", u32::from(v).saturating_add(1))))
                .emit()?;
        }
        K::Row32 => {
            f.u32(name)
                .with(|&v, n| n.summary(format!("row {}", u64::from(v).saturating_add(1))))
                .emit()?;
        }
        K::Col => {
            f.u16(name)
                .with(|&v, n| n.summary(format!("column {}", column_name(v.into()))))
                .emit()?;
        }
        K::Col8 => {
            f.u8(name)
                .with(|&v, n| n.summary(format!("column {}", column_name(v.into()))))
                .emit()?;
        }
        K::Twips => {
            f.u16(name)
                .with(|&v, n| n.summary(points(v.into())))
                .emit()?;
        }
        K::ITwips => {
            f.int::<i16>(name)
                .with(|&v, n| n.summary(points(v.into())))
                .emit()?;
        }
        K::Lcid => {
            f.u16(name)
                .hex()
                .with(|&v, n| n.summary(crate::formats::util::lcid::describe(v.into())))
                .emit()?;
        }
        K::XlStr | K::XlStr8 | K::Str8 | K::Str16 => {
            let at = crate::bytes::to_usize(f.pos());
            let form = match kind {
                K::XlStr => StrForm::Wide16,
                K::XlStr8 => StrForm::Wide8,
                K::Str8 => StrForm::Bytes8,
                _ => StrForm::Bytes16,
            };
            let decoded = xl_string(&f.block().data, at, form);
            match decoded {
                Some((text, used)) => {
                    let used = crate::bytes::to_u64(used);
                    f.node(
                        Node::new(name)
                            .span(f.peek_span(used))
                            .value(Value::Text(text)),
                    );
                    f.skip(used);
                }
                None => {
                    // Truncated: let a bytes field report it.
                    let rest = f.remaining();
                    f.bytes(name, rest.saturating_add(1)).emit()?;
                }
            }
        }
        K::Guid => {
            f.guid(name).emit()?;
        }
        K::FileTime => {
            f.u64(name).filetime().emit()?;
        }
        K::Pad(n) => {
            f.bytes(name, n).emit()?;
        }
    }
    Ok(())
}

/// Twips as points.
pub fn points(twips: i64) -> String {
    format!("{} pt", twips as f64 / 20.0)
}

/// An Excel RK number: a 30-bit integer or the top of an IEEE double,
/// optionally divided by 100.
pub fn rk(raw: u32) -> f64 {
    let v = if raw & 2 != 0 {
        f64::from(raw.cast_signed() >> 2)
    } else {
        f64::from_bits(u64::from(raw & !3) << 32)
    };
    if raw & 1 != 0 { v / 100.0 } else { v }
}

/// Spreadsheet column letters (0 = A, 26 = AA).
pub fn column_name(mut col: u32) -> String {
    let mut out = Vec::new();
    loop {
        out.push(char::from(
            b'A'.saturating_add(u8::try_from(col % 26).unwrap_or(0)),
        ));
        if col < 26 || out.len() >= 8 {
            break;
        }
        col = (col / 26).saturating_sub(1);
    }
    out.iter().rev().collect()
}

/// `B7` for zero-based column 1, row 6.
pub fn cell_name(col: u32, row: u32) -> String {
    format!("{}{}", column_name(col), u64::from(row).saturating_add(1))
}

/// A number for display: integers without a fraction.
pub fn number(v: f64) -> String {
    if v.is_finite() && v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{v:.0}")
    } else {
        format!("{v}")
    }
}

/// How an Excel string is stored.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum StrForm {
    /// BIFF8: u16 count, flags byte.
    Wide16,
    /// BIFF8: u8 count, flags byte.
    Wide8,
    /// BIFF8 without a count (the count was elsewhere): flags byte only.
    Flags(usize),
    /// BIFF5: u8 count, bytes.
    Bytes8,
    /// BIFF5: u16 count, bytes.
    Bytes16,
}

/// Decodes an Excel string at `data[at..]`. Returns the text and the bytes
/// it takes (including rich-text runs and phonetic data, when flagged).
pub fn xl_string(data: &[u8], at: usize, form: StrForm) -> Option<(String, usize)> {
    let (count, mut pos) = match form {
        StrForm::Wide16 | StrForm::Bytes16 => (
            usize::from(crate::bytes::u16_le(data, at)?),
            at.checked_add(2)?,
        ),
        StrForm::Wide8 | StrForm::Bytes8 => (usize::from(*data.get(at)?), at.checked_add(1)?),
        StrForm::Flags(n) => (n, at),
    };
    if matches!(form, StrForm::Bytes8 | StrForm::Bytes16) {
        let end = pos.checked_add(count)?;
        let raw = data.get(pos..end)?;
        return Some((crate::text::latin1(raw), end.saturating_sub(at)));
    }
    let flags = *data.get(pos)?;
    pos = pos.checked_add(1)?;
    let mut runs = 0usize;
    let mut ext = 0usize;
    if flags & 0x08 != 0 {
        runs = usize::from(crate::bytes::u16_le(data, pos)?);
        pos = pos.checked_add(2)?;
    }
    if flags & 0x04 != 0 {
        ext = crate::bytes::to_usize(crate::bytes::u32_le(data, pos)?.into());
        pos = pos.checked_add(4)?;
    }
    let wide = flags & 0x01 != 0;
    let bytes = if wide { count.checked_mul(2)? } else { count };
    let raw = data.get(pos..pos.checked_add(bytes)?)?;
    let text = if wide {
        crate::text::utf16(raw, LE)
    } else {
        crate::text::latin1(raw)
    };
    pos = pos
        .checked_add(bytes)?
        .checked_add(runs.checked_mul(4)?)?
        .checked_add(ext)?;
    if pos > data.len() {
        return None;
    }
    Some((text, pos.saturating_sub(at)))
}

/// Text in a Windows code page (1200 is UTF-16LE, 65001 UTF-8).
pub fn codepage_text(codepage: u16, data: &[u8]) -> String {
    match codepage {
        1200 => crate::text::utf16(data, LE),
        65001 => String::from_utf8_lossy(data).into_owned(),
        10000 => crate::formats::util::datakit::mac_roman(data),
        cp => crate::codec::charset::decode_label(&format!("windows-{cp}"), data)
            .or_else(|| crate::codec::charset::decode_label(&format!("cp{cp}"), data))
            .unwrap_or_else(|| crate::text::latin1(data)),
    }
}

/// `value` with its bits `shift..shift + width`.
pub fn bits(value: u64, shift: u32, width: u32) -> u64 {
    let mask = 1u64
        .checked_shl(width)
        .map_or(u64::MAX, |m| m.saturating_sub(1));
    value.checked_shr(shift).unwrap_or(0) & mask
}

/// A text preview for a summary: at most `max` characters, quoted.
pub fn quoted(s: &str, max: usize) -> String {
    let clipped = crate::formats::util::datakit::clip(s, max);
    format!("{clipped:?}")
}

/// A typed unsigned value.
pub fn uint(value: impl Into<u64>, bits: u8) -> Value {
    crate::formats::util::datakit::uint(value, bits)
}

/// A typed unsigned hexadecimal value.
pub fn hex(value: impl Into<u64>, bits: u8) -> Value {
    crate::formats::util::datakit::hex(value, bits)
}

/// A typed enumerated value.
pub fn enumv(raw: impl Into<u64>, bits: u8, table: EnumTable) -> Value {
    crate::formats::util::datakit::enumv(raw, bits, table)
}

/// A typed flags value.
pub fn flagsv(raw: impl Into<u64>, bits: u8, table: FlagTable) -> Value {
    let raw = raw.into();
    let (set, unknown) = crate::value::decode_flags(table, raw);
    Value::Flags {
        raw,
        bits,
        set,
        unknown,
    }
}
