//! Typed field values: the contract between dissectors and frontends.
//!
//! Values carry interpretation (enum names, decoded flags) next to the raw
//! number. The raw bytes themselves are available through the node's span.

use std::borrow::Cow;
use std::fmt;

/// How an unsigned number is shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Radix {
    Dec,
    Hex,
    /// Octal, `0o…`: Unix permission bits and other octal-natured fields.
    Oct,
    /// Binary, `0b…`: small bit fields where the pattern is the point.
    Bin,
}

/// A field's interpreted value.
///
/// Hosts keep a fallback arm (`_ => render::value(v)`): atoms are added over
/// time, and a host that predates one still shows it as text.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Value {
    Bool(bool),
    UInt {
        value: u64,
        bits: u8,
        radix: Radix,
    },
    Int {
        value: i64,
        bits: u8,
    },
    /// A number with a symbolic name, if known. The name usually comes from
    /// a static table ([`lookup`]); a computed one is `Cow::Owned`.
    Enum {
        raw: u64,
        bits: u8,
        name: Option<Cow<'static, str>>,
    },
    /// A bit set: the names of matched flags, and bits no flag accounts for.
    Flags {
        raw: u64,
        bits: u8,
        set: Vec<&'static str>,
        unknown: u64,
    },
    /// A floating-point number. `bits` is the width the file stores it in
    /// (16, 32, 64 or 80). `value` is exact for every width but 80 (the
    /// nearest `f64`); text renderings use the shortest decimal that reads
    /// back to the stored width (`0.8`, not `0.800000011920929`, for an
    /// `f32`). Construct with [`Value::f32`], [`Value::f64`] and friends.
    Float {
        value: f64,
        bits: u8,
    },
    Timestamp {
        unix_seconds: i64,
    },
    Text(String),
    Bytes(Vec<u8>),
    Guid(Guid),
}

impl Value {
    /// A 64-bit float.
    pub const fn f64(value: f64) -> Value {
        Value::Float { value, bits: 64 }
    }

    /// A 32-bit float, kept exact and rendered in its shortest `f32` form.
    pub fn f32(value: f32) -> Value {
        Value::Float {
            value: f64::from(value),
            bits: 32,
        }
    }

    /// A 16-bit (half-precision) float, already widened to `f64`.
    pub const fn f16(value: f64) -> Value {
        Value::Float { value, bits: 16 }
    }

    /// An 80-bit x87 extended float, as the nearest `f64`.
    pub const fn f80(value: f64) -> Value {
        Value::Float { value, bits: 80 }
    }

    /// An enum value with a computed name (one no static table holds).
    pub fn named(raw: u64, bits: u8, name: impl Into<Cow<'static, str>>) -> Value {
        Value::Enum {
            raw,
            bits,
            name: Some(name.into()),
        }
    }
}

/// `(raw value, name)` pairs.
pub type EnumTable = &'static [(u64, &'static str)];

/// A flag matches when `raw & mask == value`. Single bits have
/// `mask == value`; multi-bit fields (e.g. alignment) use one entry per value.
#[derive(Clone, Copy, Debug)]
pub struct FlagDef {
    pub mask: u64,
    pub value: u64,
    pub name: &'static str,
}

pub type FlagTable = &'static [FlagDef];

pub const fn flag(bit: u64, name: &'static str) -> FlagDef {
    FlagDef {
        mask: bit,
        value: bit,
        name,
    }
}

pub const fn field(mask: u64, value: u64, name: &'static str) -> FlagDef {
    FlagDef { mask, value, name }
}

pub fn lookup(table: EnumTable, raw: u64) -> Option<&'static str> {
    table.iter().find(|(v, _)| *v == raw).map(|(_, n)| *n)
}

/// Returns matched flag names and the bits not covered by any match.
pub fn decode_flags(table: FlagTable, raw: u64) -> (Vec<&'static str>, u64) {
    let mut covered = 0u64;
    let mut set = Vec::new();
    for def in table {
        if def.mask != 0 && def.value != 0 && raw & def.mask == def.value {
            set.push(def.name);
            covered |= def.mask;
        }
    }
    (set, raw & !covered)
}

/// A GUID in its conventional (Microsoft, mixed-endian) field layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl Guid {
    /// The GUID's 16 bytes in Windows' mixed-endian order (the first three
    /// fields little-endian), the inverse of `datakit::guid_le`.
    pub fn to_le_bytes(&self) -> [u8; 16] {
        let [a, b, c, d] = self.data1.to_le_bytes();
        let [e, f] = self.data2.to_le_bytes();
        let [g, h] = self.data3.to_le_bytes();
        let [i, j, k, l, m, n, o, p] = self.data4;
        [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p]
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let d = &self.data4;
        write!(
            f,
            "{{{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}",
            self.data1, self.data2, self.data3, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]
        )
    }
}
