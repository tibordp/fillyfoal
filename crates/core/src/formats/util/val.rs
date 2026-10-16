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

/// A signed value.
pub fn int(value: impl Into<i64>, bits: u8) -> Value {
    Value::Int {
        value: value.into(),
        bits,
    }
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
