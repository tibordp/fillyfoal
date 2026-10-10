//! Typed field values: the contract between dissectors and frontends.
//!
//! Values carry interpretation (enum names, decoded flags) next to the raw
//! number. The raw bytes themselves are available through the node's span.

use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Radix {
    Dec,
    Hex,
}

#[derive(Clone, Debug, PartialEq)]
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
    /// A number with a symbolic name, if known.
    Enum {
        raw: u64,
        bits: u8,
        name: Option<&'static str>,
    },
    /// A bit set: the names of matched flags, and bits no flag accounts for.
    Flags {
        raw: u64,
        bits: u8,
        set: Vec<&'static str>,
        unknown: u64,
    },
    Float(f64),
    Timestamp {
        unix_seconds: i64,
    },
    Text(String),
    Bytes(Vec<u8>),
    Guid(Guid),
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
