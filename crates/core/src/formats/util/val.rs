//! Constructors for the [`Value`]s dissectors emit most: the canonical
//! versions of helpers that used to be copied into every family.

use crate::value::{EnumTable, FlagTable, Radix, Value, decode_flags, lookup};

/// An unsigned decimal value.
pub fn uint(value: impl Into<u64>, bits: u8) -> Value {
    Value::UInt {
        value: value.into(),
        bits,
        radix: Radix::Dec,
    }
}

/// An unsigned hexadecimal value.
pub fn hex(value: impl Into<u64>, bits: u8) -> Value {
    Value::UInt {
        value: value.into(),
        bits,
        radix: Radix::Hex,
    }
}

/// An unsigned octal value (Unix modes).
pub fn oct(value: impl Into<u64>, bits: u8) -> Value {
    Value::UInt {
        value: value.into(),
        bits,
        radix: Radix::Oct,
    }
}

/// A size of `n` bytes stored `bits` wide: `1536 bytes (1.5 KiB)`.
pub fn size(n: impl Into<u64>, bits: u8) -> Value {
    Value::size(n.into()).bits(bits)
}

/// A size of `n` blocks of `block` bytes, `n` stored `bits` wide:
/// `8 × 512 bytes (4 KiB)`.
pub fn blocks(n: impl Into<u64>, block: u32, bits: u8) -> Value {
    Value::blocks(n.into(), block).bits(bits)
}

/// A span of `ticks` of `1/per_sec` second.
pub fn duration(ticks: impl Into<i64>, per_sec: u64) -> Value {
    Value::duration(ticks.into(), per_sec)
}

/// A signed value.
pub fn int(value: impl Into<i64>, bits: u8) -> Value {
    Value::Int {
        value: value.into(),
        bits,
    }
}

/// An MS-DOS date and time: a local time, or (when the date is not a
/// calendar date) the fields as stored, as text.
pub fn dos(date: u16, time: u16) -> Value {
    crate::value::Time::dos(date, time).map_or_else(
        || Value::Text(crate::text::dos_datetime(date, time)),
        Value::Timestamp,
    )
}

/// [`dos`] of a date and time packed as `date << 16 | time` (FAT, ARJ,
/// ACE, LHA, RAR 2).
pub fn dos_stamp(stamp: u32) -> Value {
    dos(
        u16::try_from(stamp >> 16).unwrap_or(0),
        u16::try_from(stamp & 0xffff).unwrap_or(0),
    )
}

/// A text value.
pub fn text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

/// An enumerated value, named from `table`.
pub fn enumv(raw: impl Into<u64>, bits: u8, table: EnumTable) -> Value {
    let raw = raw.into();
    Value::Enum {
        raw,
        bits,
        name: lookup(table, raw).map(Into::into),
    }
}

/// A set of flags, named from `table`.
pub fn flagsv(raw: impl Into<u64>, bits: u8, table: FlagTable) -> Value {
    let raw = raw.into();
    let (set, unknown) = decode_flags(table, raw);
    Value::Flags {
        raw,
        bits,
        set,
        unknown,
    }
}

/// The name for `raw` in `table`, or `"{prefix} {raw:#x}"`.
pub fn name_or(table: EnumTable, raw: u64, prefix: &str) -> String {
    lookup(table, raw).map_or_else(|| format!("{prefix} {raw:#x}"), str::to_owned)
}
