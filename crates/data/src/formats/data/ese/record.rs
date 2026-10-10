//! ESE records: a header (last fixed and variable column IDs, end of the
//! fixed data), fixed columns with a null bitmap, variable columns with an
//! offset array, then tagged columns (an array of column ID and offset
//! pairs, each value optionally led by a header byte of flags: long value,
//! separated, multi-valued, ...). Column types come from the catalog.

use crate::bytes::{u16_le, u32_le, u64_le};
use crate::formats::data::valuetree::decimal_string;
use crate::formats::util::civil::ole_date;
use crate::formats::util::datakit::guid_le;
use crate::value::{EnumTable, FlagTable, Value, flag};

pub const COLUMN_TYPES: EnumTable = &[
    (0, "Nil"),
    (1, "Bit"),
    (2, "UnsignedByte"),
    (3, "Short"),
    (4, "Long"),
    (5, "Currency"),
    (6, "IEEESingle"),
    (7, "IEEEDouble"),
    (8, "DateTime"),
    (9, "Binary"),
    (10, "Text"),
    (11, "LongBinary"),
    (12, "LongText"),
    (13, "SLV"),
    (14, "UnsignedLong"),
    (15, "LongLong"),
    (16, "GUID"),
    (17, "UnsignedShort"),
];

/// Persisted column flags (`FIELDFLAG`).
pub const COLUMN_FLAGS: FlagTable = &[
    flag(0x0001, "NotNull"),
    flag(0x0002, "Version"),
    flag(0x0004, "Autoincrement"),
    flag(0x0008, "Multivalued"),
    flag(0x0010, "Default"),
    flag(0x0020, "EscrowUpdate"),
    flag(0x0040, "Finalize"),
    flag(0x0080, "UserDefinedDefault"),
    flag(0x0100, "TemplateColumnESE98"),
    flag(0x0200, "DeleteOnZero"),
    flag(0x0800, "PrimaryIndexPlaceholder"),
    flag(0x1000, "Compressed"),
    flag(0x2000, "Encrypted"),
];

/// The header byte of a tagged value (`TAGFLD_HEADER`).
pub const TAGGED_FLAGS: FlagTable = &[
    flag(0x01, "LongValue"),
    flag(0x02, "Compressed"),
    flag(0x04, "Separated"),
    flag(0x08, "MultiValues"),
    flag(0x10, "TwoValues"),
    flag(0x20, "Null"),
    flag(0x40, "Encrypted"),
];

/// A column definition, from the catalog.
#[derive(Clone, Debug)]
pub struct ColDef {
    pub id: u32,
    pub name: String,
    pub coltyp: u32,
    pub cbmax: u32,
    pub codepage: u32,
    pub flags: u32,
}

/// Size of a fixed column of type `coltyp`.
pub fn fixed_size(coltyp: u32, cbmax: u32) -> usize {
    match coltyp {
        1 | 2 => 1,
        3 | 17 => 2,
        4 | 6 | 14 => 4,
        5 | 7 | 8 | 15 => 8,
        16 => 16,
        _ => usize::try_from(cbmax).unwrap_or(0),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Fixed,
    Variable,
    Tagged,
}

/// One column's value within a record (offsets relative to the record).
#[derive(Clone, Debug)]
pub struct Val {
    pub id: u32,
    pub kind: Kind,
    pub at: usize,
    pub len: usize,
    pub null: bool,
    /// Tagged values: the header byte, if present (it precedes `at`).
    pub header: Option<u8>,
    pub derived: bool,
}

#[derive(Default, Debug)]
pub struct Decoded {
    pub last_fixed: u8,
    pub last_var: u8,
    pub end_fixed: usize,
    pub values: Vec<Val>,
    /// (offset, length) of the fixed null bitmap, variable offsets and
    /// tagged field array.
    pub nullmap: Option<(usize, usize)>,
    pub var_offsets: Option<(usize, usize)>,
    pub tag_array: Option<(usize, usize)>,
    pub problem: Option<String>,
}

/// Decodes a record of the new record format. `def` gives the definition
/// of a fixed column (needed for its size).
pub fn decode<'a>(rec: &[u8], small: bool, def: impl Fn(u32) -> Option<&'a ColDef>) -> Decoded {
    let mut out = Decoded::default();
    let (Some(&last_fixed), Some(&last_var), Some(end_fixed)) =
        (rec.first(), rec.get(1), u16_le(rec, 2))
    else {
        out.problem = Some("record shorter than its header".into());
        return out;
    };
    out.last_fixed = last_fixed;
    out.last_var = last_var;
    let end_fixed = usize::from(end_fixed);
    out.end_fixed = end_fixed;
    if end_fixed > rec.len() || end_fixed < 4 {
        out.problem = Some(format!("end of fixed data {end_fixed} out of range"));
        return out;
    }
    // Fixed columns, then the null bitmap just before the end of the
    // fixed data.
    let bitmap_len = usize::from(last_fixed).div_ceil(8);
    let bitmap_at = end_fixed.saturating_sub(bitmap_len);
    if last_fixed > 0 {
        out.nullmap = Some((bitmap_at, bitmap_len));
    }
    let mut at = 4usize;
    for id in 1..=u32::from(last_fixed) {
        let Some(d) = def(id) else {
            out.problem = Some(format!("fixed column {id} is not in the catalog"));
            break;
        };
        let size = fixed_size(d.coltyp, d.cbmax);
        let bit = usize::try_from(id.saturating_sub(1)).unwrap_or(0);
        let null = rec
            .get(bitmap_at.saturating_add(bit / 8))
            .is_some_and(|b| b & (1u8 << (bit % 8)) != 0);
        if at.saturating_add(size) > bitmap_at {
            out.problem = Some(format!("fixed column {id} overruns the fixed data"));
            break;
        }
        out.values.push(Val {
            id,
            kind: Kind::Fixed,
            at,
            len: size,
            null,
            header: None,
            derived: false,
        });
        at = at.saturating_add(size);
    }
    // Variable columns: an array of end offsets (bit 15: empty/null).
    let nvar = usize::from(last_var.saturating_sub(127));
    let var_data = end_fixed.saturating_add(nvar.saturating_mul(2));
    if nvar > 0 {
        out.var_offsets = Some((end_fixed, nvar.saturating_mul(2)));
    }
    if var_data > rec.len() {
        out.problem = Some("variable offsets run past the record".into());
        return out;
    }
    let mut prev = 0usize;
    for i in 0..nvar {
        let entry = u16_le(rec, end_fixed.saturating_add(i.saturating_mul(2))).unwrap_or(0);
        let end = usize::from(entry & 0x7fff);
        let null = entry & 0x8000 != 0;
        let start = var_data.saturating_add(prev);
        let stop = var_data.saturating_add(end);
        if stop > rec.len() || end < prev {
            out.problem = Some(format!(
                "variable column {} out of range",
                128usize.saturating_add(i)
            ));
            return out;
        }
        out.values.push(Val {
            id: u32::try_from(i.saturating_add(128)).unwrap_or(u32::MAX),
            kind: Kind::Variable,
            at: start,
            len: stop.saturating_sub(start),
            null,
            header: None,
            derived: false,
        });
        prev = end;
    }
    // Tagged columns.
    let tagged = var_data.saturating_add(prev);
    if tagged.saturating_add(4) > rec.len() {
        return out;
    }
    let mask: u16 = if small { 0x1fff } else { 0x7fff };
    let first = u16_le(rec, tagged.saturating_add(2)).unwrap_or(0) & mask;
    let count = usize::from(first / 4);
    out.tag_array = Some((tagged, count.saturating_mul(4)));
    let area = rec.len().saturating_sub(tagged);
    for i in 0..count {
        let e = tagged.saturating_add(i.saturating_mul(4));
        let (Some(id), Some(raw)) = (u16_le(rec, e), u16_le(rec, e.saturating_add(2))) else {
            out.problem = Some("tagged field array runs past the record".into());
            break;
        };
        let start = usize::from(raw & mask);
        let end = if i.saturating_add(1) < count {
            usize::from(u16_le(rec, e.saturating_add(6)).unwrap_or(0) & mask)
        } else {
            area
        };
        if end < start || end > area {
            out.problem = Some(format!("tagged column {id} out of range"));
            break;
        }
        let extended = !small || raw & 0x4000 != 0;
        let null_small = small && raw & 0x2000 != 0;
        let mut at = tagged.saturating_add(start);
        let mut len = end.saturating_sub(start);
        let mut header = None;
        if extended && len > 0 {
            header = rec.get(at).copied();
            at = at.saturating_add(1);
            len = len.saturating_sub(1);
        }
        let null = null_small || header.is_some_and(|h| h & 0x20 != 0);
        out.values.push(Val {
            id: u32::from(id),
            kind: Kind::Tagged,
            at,
            len,
            null,
            header,
            derived: raw & 0x8000 != 0,
        });
    }
    out
}

/// The values of a multi-valued tagged column: (offset, length, separated)
/// relative to the value.
pub fn multi_values(data: &[u8], header: u8) -> Vec<(usize, usize, bool)> {
    if header & 0x10 != 0 {
        // Two values: the first byte is the size of the first.
        let first = usize::from(data.first().copied().unwrap_or(0));
        let rest = data.len().saturating_sub(first.saturating_add(1));
        return vec![
            (1, first.min(data.len().saturating_sub(1)), false),
            (first.saturating_add(1), rest, false),
        ];
    }
    let first = usize::from(u16_le(data, 0).unwrap_or(0) & 0x7fff);
    let count = first / 2;
    let mut out = Vec::new();
    for i in 0..count {
        let raw = u16_le(data, i.saturating_mul(2)).unwrap_or(0);
        let start = usize::from(raw & 0x7fff);
        let end = if i.saturating_add(1) < count {
            usize::from(u16_le(data, i.saturating_add(1).saturating_mul(2)).unwrap_or(0) & 0x7fff)
        } else {
            data.len()
        };
        if end < start || end > data.len() {
            break;
        }
        out.push((start, end.saturating_sub(start), raw & 0x8000 != 0));
    }
    out
}

/// A column value as a node value (`None` for long or odd values).
pub fn value(def: &ColDef, b: &[u8]) -> Value {
    let le = |n: usize| -> Option<u64> {
        (b.len() == n).then(|| {
            b.iter()
                .rev()
                .fold(0u64, |acc, &x| acc.wrapping_shl(8) | u64::from(x))
        })
    };
    let signed = |n: usize| -> Option<Value> {
        let raw = le(n)?;
        let shift = 64u32.saturating_sub(u32::try_from(n.saturating_mul(8)).unwrap_or(64));
        Some(Value::Int {
            value: (raw.wrapping_shl(shift) as i64).wrapping_shr(shift),
            bits: u8::try_from(n.saturating_mul(8)).unwrap_or(64),
        })
    };
    let unsigned = |n: usize| -> Option<Value> {
        Some(Value::UInt {
            value: le(n)?,
            bits: u8::try_from(n.saturating_mul(8)).unwrap_or(64),
            radix: crate::value::Radix::Dec,
        })
    };
    let v = match def.coltyp {
        1 => b.first().map(|&x| Value::Bool(x != 0)),
        2 => unsigned(1),
        3 => signed(2),
        4 => signed(4),
        // Currency: a 64-bit integer in units of 1/10 000.
        5 => le(8).map(|v| {
            let v = v.cast_signed();
            Value::Text(decimal_string(v < 0, &v.unsigned_abs().to_string(), -4))
        }),
        6 => le(4).map(|v| Value::Float(f64::from(f32::from_bits(v as u32)))),
        7 => le(8).map(|v| Value::Float(f64::from_bits(v))),
        8 => le(8).map(|v| {
            let days = f64::from_bits(v);
            ole_date(days).map_or(Value::Float(days), |unix_seconds| Value::Timestamp {
                unix_seconds,
            })
        }),
        10 | 12 => Some(Value::Text(text(def.codepage, b))),
        14 => unsigned(4),
        15 => signed(8),
        16 if b.len() == 16 => Some(Value::Guid(guid_le(b))),
        17 => unsigned(2),
        _ => None,
    };
    v.unwrap_or_else(|| Value::Bytes(b.get(..64).unwrap_or(b).to_vec()))
}

/// Text in a column's code page (1200: UTF-16LE; otherwise single-byte).
pub fn text(codepage: u32, b: &[u8]) -> String {
    if codepage == 1200 {
        crate::text::utf16_trimmed(b, crate::fields::Endian::Little)
    } else {
        crate::text::latin1(b).trim_end_matches('\0').to_owned()
    }
}

/// A long-value ID stored in a record (32- or 64-bit), and its B-tree key.
pub fn lid(b: &[u8]) -> Option<(u64, Vec<u8>)> {
    match b.len() {
        4 => {
            let v = u32_le(b, 0)?;
            Some((v.into(), v.to_be_bytes().to_vec()))
        }
        8 => {
            let v = u64_le(b, 0)?;
            Some((v, v.to_be_bytes().to_vec()))
        }
        _ => None,
    }
}

/// The columns of MSysObjects, which describe everything else.
pub fn catalog_columns() -> Vec<ColDef> {
    const COLS: &[(u32, &str, u32, u32)] = &[
        (1, "ObjidTable", 4, 4),
        (2, "Type", 3, 2),
        (3, "Id", 4, 4),
        (4, "ColtypOrPgnoFDP", 4, 4),
        (5, "SpaceUsage", 4, 4),
        (6, "Flags", 4, 4),
        (7, "PagesOrLocale", 4, 4),
        (8, "RootFlag", 1, 1),
        (9, "RecordOffset", 3, 2),
        (10, "LCMapFlags", 4, 4),
        (11, "KeyMost", 17, 2),
        (12, "LVChunkMax", 4, 4),
        (13, "PgnoFDPLastSetTime", 8, 8),
        (128, "Name", 10, 255),
        (129, "Stats", 9, 255),
        (130, "TemplateTable", 10, 255),
        (131, "DefaultValue", 9, 255),
        (132, "KeyFldIDs", 9, 255),
        (133, "VarSegMac", 9, 255),
        (134, "ConditionalColumns", 9, 255),
        (135, "TupleLimits", 9, 255),
        (136, "Version", 9, 255),
        (137, "SortID", 9, 255),
        (256, "CallbackData", 11, 0),
        (257, "CallbackDependencies", 11, 0),
        (258, "SeparateLV", 11, 0),
        (259, "SpaceHints", 11, 0),
        (260, "SpaceDeferredLVHints", 11, 0),
        (261, "LocaleName", 11, 0),
    ];
    COLS.iter()
        .map(|&(id, name, coltyp, cbmax)| ColDef {
            id,
            name: name.to_owned(),
            coltyp,
            cbmax,
            codepage: 1252,
            flags: 0,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records() {
        let defs = catalog_columns();
        // Two fixed columns (4 + 2 bytes), bitmap, one variable column
        // ("ab"), one tagged column (header byte + 2 bytes).
        let mut rec = vec![2u8, 128, 11, 0];
        rec.extend_from_slice(&7u32.to_le_bytes());
        rec.extend_from_slice(&1u16.to_le_bytes());
        rec.push(0); // null bitmap
        rec.extend_from_slice(&2u16.to_le_bytes()); // var end offset
        rec.extend_from_slice(b"ab");
        rec.extend_from_slice(&256u16.to_le_bytes());
        rec.extend_from_slice(&(4u16 | 0x4000).to_le_bytes());
        rec.extend_from_slice(&[0x00, 9, 9]);
        let d = decode(&rec, true, |id| defs.iter().find(|c| c.id == id));
        assert_eq!(d.problem, None);
        let ids: Vec<u32> = d.values.iter().map(|v| v.id).collect();
        assert_eq!(ids, [1, 2, 128, 256]);
        assert_eq!(d.values.get(2).map(|v| v.at), Some(13));
        assert_eq!(d.values.get(3).and_then(|v| v.header), Some(0));
        assert_eq!(d.values.get(3).map(|v| v.len), Some(2));
        assert_eq!(
            multi_values(&[2, b'a', 0, b'b', 0], 0x18),
            [(1, 2, false), (3, 2, false)]
        );
    }
}
