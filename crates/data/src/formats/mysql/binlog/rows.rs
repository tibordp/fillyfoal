//! Table map events and the column values of rows events.
//!
//! A table map lists a table's column types, each type's metadata (the
//! length, precision or fractional-second digits the value encoding needs)
//! and the nullable columns; MySQL 8 and MariaDB 10.5 can add optional
//! metadata (`binlog_row_metadata=FULL`: column names, signedness, ENUM and
//! SET strings, the primary key). Rows events refer to it by table ID and
//! store each row as a NULL bitmap over the columns present followed by
//! the non-NULL values in their binary log encodings (`log_event.cc`,
//! `Field::pack` of each type; the temporal types in the MySQL 5.6 encodings
//! that MariaDB also writes by default).

use crate::bytes::{f32_le, f64_le, to_usize};
use crate::formats::util::civil::days_from_civil;
use crate::formats::util::fmt::clip;
use crate::value::{EnumTable, Time, Value};

use crate::formats::mysql::innodb::dict::{decimal, decimal_bytes};

pub const COLUMN_TYPES: EnumTable = &[
    (0, "DECIMAL"),
    (1, "TINY"),
    (2, "SHORT"),
    (3, "LONG"),
    (4, "FLOAT"),
    (5, "DOUBLE"),
    (6, "NULL"),
    (7, "TIMESTAMP"),
    (8, "LONGLONG"),
    (9, "INT24"),
    (10, "DATE"),
    (11, "TIME"),
    (12, "DATETIME"),
    (13, "YEAR"),
    (14, "NEWDATE"),
    (15, "VARCHAR"),
    (16, "BIT"),
    (17, "TIMESTAMP2"),
    (18, "DATETIME2"),
    (19, "TIME2"),
    (20, "TYPED_ARRAY"),
    (242, "VECTOR"),
    (243, "INVALID"),
    (244, "BOOL"),
    (245, "JSON"),
    (246, "NEWDECIMAL"),
    (247, "ENUM"),
    (248, "SET"),
    (249, "TINY_BLOB"),
    (250, "MEDIUM_BLOB"),
    (251, "LONG_BLOB"),
    (252, "BLOB"),
    (253, "VAR_STRING"),
    (254, "STRING"),
    (255, "GEOMETRY"),
];

pub const OPTIONAL_METADATA: EnumTable = &[
    (1, "SIGNEDNESS"),
    (2, "DEFAULT_CHARSET"),
    (3, "COLUMN_CHARSET"),
    (4, "COLUMN_NAME"),
    (5, "SET_STR_VALUE"),
    (6, "ENUM_STR_VALUE"),
    (7, "GEOMETRY_TYPE"),
    (8, "SIMPLE_PRIMARY_KEY"),
    (9, "PRIMARY_KEY_WITH_PREFIX"),
    (10, "ENUM_AND_SET_DEFAULT_CHARSET"),
    (11, "ENUM_AND_SET_COLUMN_CHARSET"),
    (12, "COLUMN_VISIBILITY"),
];

/// Columns read at most from one table map (MySQL allows 4096).
pub const MAX_COLUMNS: u64 = 4096;

/// A length-encoded integer (`net_field_length_ll`) at the start of `b`:
/// its value and size. `0xfb` (NULL) reads as 0.
pub fn lenenc(b: &[u8]) -> Option<(u64, usize)> {
    let first = *b.first()?;
    let take = |n: usize| -> Option<u64> {
        let s = b.get(1..n.checked_add(1)?)?;
        Some(
            s.iter()
                .rev()
                .fold(0u64, |a, &x| a.wrapping_shl(8) | u64::from(x)),
        )
    };
    Some(match first {
        0..=250 => (first.into(), 1),
        251 => (0, 1),
        252 => (take(2)?, 3),
        253 => (take(3)?, 4),
        254 => (take(8)?, 9),
        255 => return None,
    })
}

/// A column of a table map.
#[derive(Clone, Debug, Default)]
pub struct Column {
    pub ty: u8,
    pub meta: u16,
    pub nullable: bool,
    pub name: Option<String>,
    pub unsigned: bool,
    /// ENUM or SET member names (optional metadata).
    pub members: Vec<String>,
}

/// A parsed table map: what rows events need to decode values.
#[derive(Clone, Debug, Default)]
pub struct TableMap {
    pub table_id: u64,
    pub db: String,
    pub table: String,
    pub columns: Vec<Column>,
    /// Where the parts are in the event body: column types, metadata, the
    /// NULL bitmap and the optional metadata (offset and length).
    pub types_at: (usize, usize),
    pub meta_at: (usize, usize),
    pub nulls_at: (usize, usize),
    pub optional_at: (usize, usize),
    /// The count field: offset and size.
    pub count_at: (usize, usize),
}

impl TableMap {
    pub fn qualified(&self) -> String {
        format!("`{}`.`{}`", self.db, self.table)
    }
}

/// Metadata bytes of a column type in the table map.
fn meta_size(ty: u8) -> usize {
    match ty {
        4 | 5 | 17 | 18 | 19 | 242 | 245 | 249..=252 | 255 => 1,
        15 | 16 | 246..=248 | 253 | 254 => 2,
        _ => 0,
    }
}

/// Whether a type counts in the SIGNEDNESS bitmap.
fn numeric(ty: u8) -> bool {
    matches!(ty, 1 | 2 | 3 | 4 | 5 | 8 | 9 | 13 | 246)
}

/// The real type and maximum byte length of a STRING column's metadata
/// (`Field_string::do_save_field_metadata`: lengths above 255 borrow two
/// bits of the type byte).
pub fn string_meta(meta: u16) -> (u8, u64) {
    let hi = (meta >> 8) as u8;
    let lo = u64::from(meta & 0xff);
    if hi & 0x30 != 0x30 {
        let len = lo | (u64::from((hi & 0x30) ^ 0x30) << 4);
        (hi | 0x30, len)
    } else {
        (hi, lo)
    }
}

/// Parses the body of a table map event (after the common header);
/// `post` is the post-header length (8, or 6 in old servers).
pub fn parse_table_map(body: &[u8], post: usize) -> Option<TableMap> {
    let id_len = if post == 6 { 4 } else { 6 };
    let id = body
        .get(..id_len)?
        .iter()
        .rev()
        .fold(0u64, |a, &x| a.wrapping_shl(8) | u64::from(x));
    let mut p = post;
    let db_len = usize::from(*body.get(p)?);
    let db = String::from_utf8_lossy(
        body.get(p.checked_add(1)?..p.checked_add(1)?.checked_add(db_len)?)?,
    )
    .into_owned();
    p = p.checked_add(db_len)?.checked_add(2)?;
    let t_len = usize::from(*body.get(p)?);
    let table = String::from_utf8_lossy(
        body.get(p.checked_add(1)?..p.checked_add(1)?.checked_add(t_len)?)?,
    )
    .into_owned();
    p = p.checked_add(t_len)?.checked_add(2)?;
    let (count, n) = lenenc(body.get(p..)?)?;
    let count_at = (p, n);
    if count > MAX_COLUMNS {
        return None;
    }
    let count = to_usize(count);
    p = p.checked_add(n)?;
    let types = body.get(p..p.checked_add(count)?)?;
    let types_at = (p, count);
    p = p.checked_add(count)?;
    let (meta_len, n) = lenenc(body.get(p..)?)?;
    p = p.checked_add(n)?;
    let meta_len = to_usize(meta_len);
    let meta = body.get(p..p.checked_add(meta_len)?)?;
    let meta_at = (p, meta_len);
    p = p.checked_add(meta_len)?;
    let null_len = count.div_ceil(8);
    let nulls = body.get(p..p.checked_add(null_len)?)?;
    let nulls_at = (p, null_len);
    p = p.checked_add(null_len)?;
    let mut columns = Vec::with_capacity(count);
    let mut m = 0usize;
    for (i, &ty) in types.iter().enumerate() {
        let size = meta_size(ty);
        let b = meta.get(m..m.checked_add(size)?)?;
        let value = match (ty, b) {
            (_, [x]) => u16::from(*x),
            // NEWDECIMAL (precision, scale), STRING/ENUM/SET (real type,
            // length) are stored high byte first; VARCHAR and BIT low first.
            (246..=248 | 254, [a, b]) => (u16::from(*a) << 8) | u16::from(*b),
            (_, [a, b]) => u16::from(*a) | (u16::from(*b) << 8),
            _ => 0,
        };
        m = m.checked_add(size)?;
        columns.push(Column {
            ty,
            meta: value,
            nullable: nulls.get(i / 8).is_some_and(|&x| x & (1 << (i % 8)) != 0),
            ..Column::default()
        });
    }
    let optional_at = (p, body.len().saturating_sub(p));
    apply_optional(&mut columns, body.get(p..).unwrap_or_default());
    Some(TableMap {
        table_id: id,
        db,
        table,
        columns,
        types_at,
        meta_at,
        nulls_at,
        optional_at,
        count_at,
    })
}

/// The optional metadata fields (type, length, value), as offsets into `b`.
pub fn optional_fields(b: &[u8]) -> Vec<(u8, usize, usize, usize)> {
    let mut out = Vec::new();
    let mut p = 0usize;
    while let Some(&t) = b.get(p) {
        let Some((len, n)) = b.get(p.saturating_add(1)..).and_then(lenenc) else {
            break;
        };
        let value = p.saturating_add(1).saturating_add(n);
        let end = value.saturating_add(to_usize(len));
        if end > b.len() {
            break;
        }
        out.push((t, p, value, end));
        p = end;
    }
    out
}

/// Length-encoded strings filling `b`.
pub fn lenenc_strings(b: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut p = 0usize;
    while p < b.len() {
        let Some((len, n)) = b.get(p..).and_then(lenenc) else {
            break;
        };
        let start = p.saturating_add(n);
        let end = start.saturating_add(to_usize(len));
        let Some(s) = b.get(start..end) else {
            break;
        };
        out.push(String::from_utf8_lossy(s).into_owned());
        p = end;
    }
    out
}

fn apply_optional(columns: &mut [Column], b: &[u8]) {
    for (t, _, value, end) in optional_fields(b) {
        let v = b.get(value..end).unwrap_or_default();
        match t {
            1 => {
                let mut k = 0usize;
                for c in columns.iter_mut().filter(|c| numeric(c.ty)) {
                    c.unsigned = v.get(k / 8).is_some_and(|&x| x & (0x80 >> (k % 8)) != 0);
                    k = k.saturating_add(1);
                }
            }
            4 => {
                for (c, name) in columns.iter_mut().zip(lenenc_strings(v)) {
                    c.name = Some(name);
                }
            }
            5 | 6 => {
                // Per SET (5) or ENUM (6) column: a count, then the strings.
                let want = if t == 5 { 248 } else { 247 };
                let mut p = 0usize;
                for c in columns.iter_mut() {
                    let real = if c.ty == 254 {
                        string_meta(c.meta).0
                    } else {
                        c.ty
                    };
                    if real != want {
                        continue;
                    }
                    let Some((count, n)) = v.get(p..).and_then(lenenc) else {
                        break;
                    };
                    p = p.saturating_add(n);
                    for _ in 0..count.min(MAX_COLUMNS) {
                        let Some((len, n)) = v.get(p..).and_then(lenenc) else {
                            break;
                        };
                        let start = p.saturating_add(n);
                        let end = start.saturating_add(to_usize(len));
                        let s = v.get(start..end).unwrap_or_default();
                        c.members.push(String::from_utf8_lossy(s).into_owned());
                        p = end;
                    }
                }
            }
            _ => {}
        }
    }
}

/// A type's SQL-ish description from its metadata.
pub fn describe(c: &Column) -> String {
    let fsp = |m: u16| {
        if m > 0 {
            format!("({m})")
        } else {
            String::new()
        }
    };
    match c.ty {
        1 => "TINYINT".to_owned(),
        2 => "SMALLINT".to_owned(),
        9 => "MEDIUMINT".to_owned(),
        3 => "INT".to_owned(),
        8 => "BIGINT".to_owned(),
        4 => "FLOAT".to_owned(),
        5 => "DOUBLE".to_owned(),
        246 => format!("DECIMAL({},{})", c.meta >> 8, c.meta & 0xff),
        13 => "YEAR".to_owned(),
        10 | 14 => "DATE".to_owned(),
        7 => "TIMESTAMP (old)".to_owned(),
        12 => "DATETIME (old)".to_owned(),
        11 => "TIME (old)".to_owned(),
        17 => format!("TIMESTAMP{}", fsp(c.meta)),
        18 => format!("DATETIME{}", fsp(c.meta)),
        19 => format!("TIME{}", fsp(c.meta)),
        15 | 253 => format!("VARCHAR, {} bytes at most", c.meta),
        254 => match string_meta(c.meta) {
            (247, n) => format!("ENUM ({n}-byte index)"),
            (248, n) => format!("SET ({n}-byte bitmap)"),
            (_, n) => format!("CHAR, {n} bytes at most"),
        },
        247 => "ENUM".to_owned(),
        248 => "SET".to_owned(),
        16 => format!(
            "BIT({})",
            u32::from(c.meta >> 8)
                .saturating_mul(8)
                .saturating_add(u32::from(c.meta & 0xff))
        ),
        245 => "JSON".to_owned(),
        255 => "GEOMETRY".to_owned(),
        242 => "VECTOR".to_owned(),
        249..=252 => format!("BLOB/TEXT ({}-byte length)", c.meta),
        6 => "NULL".to_owned(),
        t => crate::value::lookup(COLUMN_TYPES, t.into())
            .map_or_else(|| format!("type {t}"), str::to_owned),
    }
}

fn le(b: &[u8]) -> u64 {
    b.iter()
        .rev()
        .fold(0u64, |a, &x| a.wrapping_shl(8) | u64::from(x))
}

fn be(b: &[u8]) -> u64 {
    b.iter()
        .fold(0u64, |a, &x| a.wrapping_shl(8) | u64::from(x))
}

/// The byte length of a value of column `c` at the start of `b` (`None`:
/// an encoding this decoder does not know, or `b` too short).
pub fn value_len(c: &Column, b: &[u8]) -> Option<usize> {
    let frac = |m: u16| usize::from(m).saturating_add(1) / 2;
    let prefixed = |n: usize| -> Option<usize> {
        let len = to_usize(le(b.get(..n)?));
        n.checked_add(len)
    };
    Some(match c.ty {
        1 | 13 => 1,
        2 => 2,
        9 | 10 | 14 | 11 => 3,
        3 | 4 | 7 => 4,
        8 | 5 | 12 => 8,
        6 => 0,
        17 => 4usize.saturating_add(frac(c.meta)),
        18 => 5usize.saturating_add(frac(c.meta)),
        19 => 3usize.saturating_add(frac(c.meta)),
        246 => to_usize(decimal_bytes((c.meta >> 8).into(), (c.meta & 0xff).into())),
        16 => usize::from(c.meta >> 8).saturating_add(usize::from(c.meta & 0xff > 0)),
        15 | 253 => prefixed(if c.meta < 256 { 1 } else { 2 })?,
        254 => match string_meta(c.meta) {
            (247 | 248, n) => to_usize(n),
            (_, n) => prefixed(if n < 256 { 1 } else { 2 })?,
        },
        247 | 248 => usize::from(c.meta & 0xff),
        242 | 245 | 249..=252 | 255 => {
            let n = usize::from(c.meta);
            if !(1..=4).contains(&n) {
                return None;
            }
            prefixed(n)?
        }
        _ => return None,
    })
}

/// The string payload of a length-prefixed value.
fn payload(b: &[u8], prefix: usize) -> &[u8] {
    b.get(prefix..).unwrap_or_default()
}

fn int_value(c: &Column, b: &[u8]) -> (Value, String) {
    let raw = le(b);
    let bits = u32::try_from(b.len().saturating_mul(8))
        .unwrap_or(64)
        .clamp(8, 64);
    let bits8 = u8::try_from(bits).unwrap_or(64);
    if c.unsigned {
        return (crate::formats::util::val::uint(raw, bits8), raw.to_string());
    }
    let shift = 64u32.saturating_sub(bits);
    let v = (raw.wrapping_shl(shift) as i64).wrapping_shr(shift);
    (
        Value::Int {
            value: v,
            bits: bits8,
        },
        v.to_string(),
    )
}

fn text_value(b: &[u8]) -> (Value, String) {
    let s = String::from_utf8_lossy(b).into_owned();
    let short = format!("'{}'", clip(&s, 40));
    (Value::Text(clip(&s, 4000)), short)
}

fn bytes_value(b: &[u8]) -> (Value, String) {
    let hex: String = b.iter().take(32).map(|x| format!("{x:02x}")).collect();
    let more = if b.len() > 32 { "…" } else { "" };
    (
        Value::Bytes(b.iter().take(256).copied().collect()),
        format!("0x{hex}{more}"),
    )
}

/// Fractional seconds of `fsp` digits from `n` stored bytes (big-endian).
fn fraction(b: &[u8], fsp: u16) -> String {
    if fsp == 0 || b.is_empty() {
        return String::new();
    }
    let v = be(b);
    let digits = b.len().saturating_mul(2);
    let s = format!("{v:0digits$}");
    format!(".{}", s.get(..usize::from(fsp)).unwrap_or(&s))
}

/// A TIME2 value: `[-]hh:mm:ss[.frac]` (`my_time_packed_from_binary`).
fn time2(b: &[u8], fsp: u16) -> Option<String> {
    let int_part = i64::try_from(be(b.get(..3)?))
        .ok()?
        .saturating_sub(0x80_0000);
    let frac_bytes = b.get(3..).unwrap_or_default();
    let packed: i64 = match fsp {
        1 | 2 => {
            let mut i = int_part;
            let mut f = i64::from(*frac_bytes.first()?);
            if i < 0 && f != 0 {
                i = i.saturating_add(1);
                f = f.saturating_sub(0x100);
            }
            i.saturating_mul(1 << 24)
                .saturating_add(f.saturating_mul(10_000))
        }
        3 | 4 => {
            let mut i = int_part;
            let mut f = i64::try_from(be(frac_bytes.get(..2)?)).ok()?;
            if i < 0 && f != 0 {
                i = i.saturating_add(1);
                f = f.saturating_sub(0x1_0000);
            }
            i.saturating_mul(1 << 24)
                .saturating_add(f.saturating_mul(100))
        }
        5 | 6 => i64::try_from(be(b.get(..6)?))
            .ok()?
            .saturating_sub(0x8000_0000_0000),
        _ => int_part.saturating_mul(1 << 24),
    };
    let negative = packed < 0;
    let packed = packed.unsigned_abs();
    let hms = packed >> 24;
    let micros = packed & 0xff_ffff;
    let mut s = format!(
        "{}{:02}:{:02}:{:02}",
        if negative { "-" } else { "" },
        (hms >> 12) & 0x3ff,
        (hms >> 6) & 0x3f,
        hms & 0x3f
    );
    if fsp > 0 {
        let digits = format!("{micros:06}");
        s.push('.');
        s.push_str(digits.get(..usize::from(fsp.min(6))).unwrap_or(&digits));
    }
    Some(s)
}

/// `t` with the fraction `fraction` gives (`.678901`), to its digits.
pub(crate) fn with_fraction(t: Time, fraction: &str) -> Time {
    let digits = fraction.trim_start_matches('.');
    if digits.is_empty() {
        return t;
    }
    let padded = format!("{digits:0<9}");
    let nanos = padded.get(..9).and_then(|d| d.parse().ok()).unwrap_or(0);
    t.frac(nanos, u8::try_from(digits.len()).unwrap_or(9))
}

/// A DATE or DATETIME as the wall clock it is (MySQL records no zone
/// with it); `None` for zero and other non-calendar dates.
pub(crate) fn wall_time(ymd: (u64, u64, u64), hms: Option<(u64, u64, u64)>) -> Option<Time> {
    let n = |v: u64| i64::try_from(v).ok();
    let days = days_from_civil(n(ymd.0)?, n(ymd.1)?, n(ymd.2)?)?;
    let Some((h, m, s)) = hms else {
        return Some(Time::local(days.saturating_mul(86_400)).day());
    };
    if h > 23 || m > 59 || s > 59 {
        return None;
    }
    let secs = n(h
        .saturating_mul(3600)
        .saturating_add(m.saturating_mul(60))
        .saturating_add(s))?;
    Some(Time::local(
        days.saturating_mul(86_400).saturating_add(secs),
    ))
}

/// `text` as a time value when `t` is one, else as text.
pub(crate) fn time_or_text(t: Option<Time>, text: String) -> (Value, String) {
    match t {
        Some(t) => (Value::Timestamp(t), text),
        None => (Value::Text(text.clone()), text),
    }
}

/// A DATETIME2 value as a local time (`my_datetime_packed_from_binary`).
fn datetime2_time(b: &[u8], fsp: u16) -> Option<Time> {
    let v = be(b.get(..5)?).checked_sub(0x80_0000_0000)?;
    let ymd = v >> 17;
    let ym = ymd >> 5;
    let hms = v & 0x1_ffff;
    let t = wall_time(
        (ym / 13, ym % 13, ymd & 31),
        Some((hms >> 12, (hms >> 6) & 63, hms & 63)),
    )?;
    Some(with_fraction(
        t,
        &fraction(b.get(5..).unwrap_or_default(), fsp),
    ))
}

/// A DATETIME2 value (`my_datetime_packed_from_binary`).
fn datetime2(b: &[u8], fsp: u16) -> Option<String> {
    let v = be(b.get(..5)?).checked_sub(0x80_0000_0000)?;
    let ymd = v >> 17;
    let ym = ymd >> 5;
    let hms = v & 0x1_ffff;
    Some(format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}{}",
        ym / 13,
        ym % 13,
        ymd & 31,
        hms >> 12,
        (hms >> 6) & 63,
        hms & 63,
        fraction(b.get(5..).unwrap_or_default(), fsp)
    ))
}

/// The value of column `c` from its encoded bytes `b` (exactly
/// [`value_len`] long): the node value and a short form for summaries.
pub fn value(c: &Column, b: &[u8]) -> (Value, String) {
    let shown = |s: String| (Value::Text(s.clone()), s);
    match c.ty {
        1 | 2 | 9 | 3 | 8 => int_value(c, b),
        4 => {
            let v = f32_le(b, 0).unwrap_or(0.0);
            (Value::f32(v), v.to_string())
        }
        5 => {
            let v = f64_le(b, 0).unwrap_or(0.0);
            (Value::f64(v), v.to_string())
        }
        246 => shown(
            decimal(b, (c.meta >> 8).into(), (c.meta & 0xff).into())
                .unwrap_or_else(|| "?".to_owned()),
        ),
        13 => {
            let v = le(b);
            let y = if v == 0 { 0 } else { v.saturating_add(1900) };
            (crate::formats::util::val::uint(y, 16), y.to_string())
        }
        10 | 14 => {
            let v = le(b);
            let ymd = (v >> 9, (v >> 5) & 15, v & 31);
            time_or_text(
                wall_time(ymd, None),
                format!("{:04}-{:02}-{:02}", ymd.0, ymd.1, ymd.2),
            )
        }
        7 => {
            let secs = le(b);
            (
                Value::utc(i64::try_from(secs).unwrap_or(0)),
                secs.to_string(),
            )
        }
        12 => {
            let v = le(b);
            let (date, time) = (v / 1_000_000, v % 1_000_000);
            let ymd = (date / 10000, (date / 100) % 100, date % 100);
            let hms = (time / 10000, (time / 100) % 100, time % 100);
            time_or_text(
                wall_time(ymd, Some(hms)),
                format!(
                    "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
                    ymd.0, ymd.1, ymd.2, hms.0, hms.1, hms.2
                ),
            )
        }
        11 => {
            let v = le(b);
            shown(format!(
                "{:02}:{:02}:{:02}",
                v / 10000,
                (v / 100) % 100,
                v % 100
            ))
        }
        17 => {
            let secs = be(b.get(..4).unwrap_or_default());
            let frac = fraction(b.get(4..).unwrap_or_default(), c.meta);
            let t = with_fraction(Time::utc(i64::try_from(secs).unwrap_or(0)), &frac);
            (Value::Timestamp(t), t.text_full())
        }
        18 => time_or_text(
            datetime2_time(b, c.meta),
            datetime2(b, c.meta).unwrap_or_else(|| "?".to_owned()),
        ),
        19 => shown(time2(b, c.meta).unwrap_or_else(|| "?".to_owned())),
        16 => {
            let bits = (u32::from(c.meta >> 8) * 8).saturating_add(u32::from(c.meta & 0xff));
            let v = be(b);
            let s = format!("b'{v:0width$b}'", width = to_usize(bits.into()));
            (crate::formats::util::val::hex(v, 64), s)
        }
        15 | 253 => text_value(payload(b, if c.meta < 256 { 1 } else { 2 })),
        254 => match string_meta(c.meta) {
            (247, _) => enum_value(c, le(b)),
            (248, _) => set_value(c, le(b)),
            (_, n) => text_value(payload(b, if n < 256 { 1 } else { 2 })),
        },
        247 => enum_value(c, le(b)),
        248 => set_value(c, le(b)),
        249..=252 => {
            let data = payload(b, usize::from(c.meta));
            let printable = std::str::from_utf8(data).is_ok_and(|s| {
                s.chars()
                    .all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
            });
            if printable {
                text_value(data)
            } else {
                bytes_value(data)
            }
        }
        245 => {
            let data = payload(b, usize::from(c.meta));
            match json(data) {
                Some(text) => {
                    let short = clip(&text, 60);
                    (Value::Text(text), short)
                }
                None => {
                    let (v, _) = bytes_value(data);
                    (v, format!("binary JSON, {} bytes", data.len()))
                }
            }
        }
        _ => bytes_value(payload(b, usize::from(c.meta).min(4))),
    }
}

/// Characters of JSON text built at most, and values visited.
const JSON_TEXT: usize = 4000;
const JSON_VALUES: u32 = 4096;

/// MySQL's binary JSON (`json_binary.cc`) as JSON text; `None` if it does
/// not decode. Bounded: a long document is cut with "…".
pub fn json(b: &[u8]) -> Option<String> {
    let (&ty, rest) = b.split_first()?;
    let mut out = String::new();
    let mut budget = JSON_VALUES;
    json_value(ty, rest, &mut out, &mut budget, 0)?;
    Some(out)
}

/// A variable-length string length: 7 bits per byte, low bits first.
fn json_varlen(b: &[u8]) -> Option<(usize, usize)> {
    let mut v = 0usize;
    for i in 0..5usize {
        let x = *b.get(i)?;
        v |= usize::from(x & 0x7f).checked_shl(u32::try_from(i.checked_mul(7)?).ok()?)?;
        if x & 0x80 == 0 {
            return Some((v, i.checked_add(1)?));
        }
    }
    None
}

fn json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Appends the value of type `ty` whose data starts `b` (for containers,
/// `b` is the container: offsets are relative to it).
fn json_value(ty: u8, b: &[u8], out: &mut String, budget: &mut u32, depth: usize) -> Option<()> {
    *budget = budget.checked_sub(1)?;
    if out.len() > JSON_TEXT || depth > 64 {
        out.push('…');
        return Some(());
    }
    let int = |n: usize| -> Option<u64> { b.get(..n).map(le) };
    match ty {
        0x00..=0x03 => {
            let large = ty & 1 == 1;
            let object = ty < 2;
            let w = if large { 4 } else { 2 };
            let count = to_usize(int(w)?);
            let key_entry = if object { w.checked_add(2)? } else { 0 };
            let value_entry = 1usize.checked_add(w)?;
            let keys_at = w.checked_mul(2)?;
            let values_at = keys_at.checked_add(count.checked_mul(key_entry)?)?;
            out.push(if object { '{' } else { '[' });
            for i in 0..count {
                if out.len() > JSON_TEXT {
                    out.push('…');
                    break;
                }
                if i > 0 {
                    out.push_str(", ");
                }
                if object {
                    let k = keys_at.checked_add(i.checked_mul(key_entry)?)?;
                    let off = to_usize(le(b.get(k..k.checked_add(w)?)?));
                    let len = to_usize(le(
                        b.get(k.checked_add(w)?..k.checked_add(w)?.checked_add(2)?)?
                    ));
                    let key = b.get(off..off.checked_add(len)?)?;
                    json_string(&String::from_utf8_lossy(key), out);
                    out.push_str(": ");
                }
                let v = values_at.checked_add(i.checked_mul(value_entry)?)?;
                let vty = *b.get(v)?;
                let field = b.get(v.checked_add(1)?..v.checked_add(value_entry)?)?;
                let inlined = matches!(vty, 0x04..=0x06) || (large && matches!(vty, 0x07 | 0x08));
                if inlined {
                    json_value(vty, field, out, budget, depth.checked_add(1)?)?;
                } else {
                    let off = to_usize(le(field));
                    json_value(vty, b.get(off..)?, out, budget, depth.checked_add(1)?)?;
                }
            }
            out.push(if object { '}' } else { ']' });
        }
        0x04 => out.push_str(match *b.first()? {
            0 => "null",
            1 => "true",
            2 => "false",
            _ => return None,
        }),
        0x05 => out.push_str(&(int(2)? as u16 as i16).to_string()),
        0x06 => out.push_str(&int(2)?.to_string()),
        0x07 => out.push_str(&(int(4)? as u32 as i32).to_string()),
        0x08 => out.push_str(&int(4)?.to_string()),
        0x09 => out.push_str(&(int(8)? as i64).to_string()),
        0x0a => out.push_str(&int(8)?.to_string()),
        0x0b => out.push_str(&f64_le(b, 0)?.to_string()),
        0x0c => {
            let (len, n) = json_varlen(b)?;
            let s = b.get(n..n.checked_add(len)?)?;
            json_string(&String::from_utf8_lossy(s), out);
        }
        0x0f => {
            let field_type = *b.first()?;
            let (len, n) = json_varlen(b.get(1..)?)?;
            out.push_str(&format!(
                "\"<opaque {}, {len} bytes>\"",
                crate::value::lookup(COLUMN_TYPES, field_type.into()).unwrap_or("?")
            ));
            let _ = n;
        }
        _ => return None,
    }
    Some(())
}

fn enum_value(c: &Column, index: u64) -> (Value, String) {
    let name = index
        .checked_sub(1)
        .and_then(|i| c.members.get(to_usize(i)));
    match name {
        Some(n) => (Value::Text(n.clone()), format!("'{n}'")),
        None if index == 0 => (Value::Text(String::new()), "'' (invalid)".to_owned()),
        None => (
            crate::formats::util::val::uint(index, 16),
            format!("member {index}"),
        ),
    }
}

fn set_value(c: &Column, bits: u64) -> (Value, String) {
    if c.members.is_empty() {
        return (
            crate::formats::util::val::hex(bits, 64),
            format!("{bits:#b}"),
        );
    }
    let names: Vec<&str> = c
        .members
        .iter()
        .enumerate()
        .filter(|(i, _)| u32::try_from(*i).is_ok_and(|i| i < 64 && bits & (1u64 << i) != 0))
        .map(|(_, n)| n.as_str())
        .collect();
    let s = names.join(",");
    (Value::Text(s.clone()), format!("'{s}'"))
}

/// One decoded value of a row image.
pub struct Cell {
    /// Column index in the table.
    pub column: usize,
    /// Offset and length of the encoded value (`None`: NULL).
    pub at: Option<(usize, usize)>,
    /// A JSON column of a partial update's after image: diffs.
    pub partial: bool,
}

/// Decodes one row image starting at `p` of `b`: the NULL bitmap over the
/// columns `present` marks, then the values. Returns the cells and where
/// the image ends, or the offset at which decoding failed.
pub fn image(
    b: &[u8],
    p: usize,
    columns: &[Column],
    present: &[u8],
) -> Result<(Vec<Cell>, usize), usize> {
    image_with(b, p, columns, present, &[])
}

/// The header of a partial update rows event's after image
/// (`binlog_row_value_options=PARTIAL_JSON`): the value options (a
/// packed integer, bit 0 `PARTIAL_JSON_UPDATES`) and, with that bit, a
/// bitmap with a bit for each JSON column of the table, set where the
/// column holds a list of JSON diffs instead of a whole document. Returns
/// where the header ends, the options and the partial columns' indexes.
/// From memory of MySQL's `Rows_log_event`; checked against files MySQL
/// 8.0 writes.
pub fn partial_header(b: &[u8], p: usize, columns: &[Column]) -> Option<(usize, u64, Vec<usize>)> {
    let (options, n) = lenenc(b.get(p..)?)?;
    let mut at = p.checked_add(n)?;
    let mut partial = Vec::new();
    if options & 1 != 0 {
        let json: Vec<usize> = (0..columns.len())
            .filter(|&i| columns.get(i).is_some_and(|c| c.ty == 245))
            .collect();
        let len = json.len().div_ceil(8);
        let bits = b.get(at..at.checked_add(len)?)?;
        for (k, &i) in json.iter().enumerate() {
            if bits.get(k / 8).is_some_and(|&x| x & (1 << (k % 8)) != 0) {
                partial.push(i);
            }
        }
        at = at.checked_add(len)?;
    }
    Some((at, options, partial))
}

/// JSON diff operations (`enum_json_diff_operation`).
const JSON_DIFF_OPS: [&str; 3] = ["REPLACE", "INSERT", "REMOVE"];

/// A partial JSON value: its diffs (operation, path, then the binary
/// JSON value unless the operation is REMOVE) as text, one per line.
/// `None` if they do not decode.
pub fn json_diffs(b: &[u8]) -> Option<String> {
    let mut p = 0usize;
    let mut lines = Vec::new();
    while p < b.len() {
        if lines.len() >= 256 {
            lines.push("…".to_owned());
            break;
        }
        let op = *b.get(p)?;
        let name = JSON_DIFF_OPS.get(usize::from(op))?;
        p = p.checked_add(1)?;
        let (len, n) = lenenc(b.get(p..)?)?;
        let start = p.checked_add(n)?;
        let end = start.checked_add(to_usize(len))?;
        let path = String::from_utf8_lossy(b.get(start..end)?).into_owned();
        p = end;
        if op == 2 {
            lines.push(format!("{name} {path}"));
            continue;
        }
        let (len, n) = lenenc(b.get(p..)?)?;
        let start = p.checked_add(n)?;
        let end = start.checked_add(to_usize(len))?;
        let value = json(b.get(start..end)?).unwrap_or_else(|| "?".to_owned());
        lines.push(format!("{name} {path} = {}", clip(&value, 200)));
        p = end;
    }
    Some(lines.join("\n"))
}

/// A JSON column's value in a partial after image: its diffs.
pub fn partial_value(c: &Column, b: &[u8]) -> (Value, String) {
    let data = payload(b, usize::from(c.meta));
    match json_diffs(data) {
        Some(text) => {
            let short = clip(&text.replace('\n', "; "), 60);
            (Value::Text(text), short)
        }
        None => {
            let (v, _) = bytes_value(data);
            (v, format!("JSON diffs, {} bytes", data.len()))
        }
    }
}

/// [`image`], with the JSON columns in `partial` holding diffs.
pub fn image_with(
    b: &[u8],
    p: usize,
    columns: &[Column],
    present: &[u8],
    partial: &[usize],
) -> Result<(Vec<Cell>, usize), usize> {
    let used: Vec<usize> = (0..columns.len())
        .filter(|&i| present.get(i / 8).is_some_and(|&x| x & (1 << (i % 8)) != 0))
        .collect();
    let null_len = used.len().div_ceil(8);
    let nulls = b.get(p..p.saturating_add(null_len)).ok_or(p)?;
    let mut at = p.saturating_add(null_len);
    let mut cells = Vec::with_capacity(used.len());
    for (k, &i) in used.iter().enumerate() {
        let is_null = nulls.get(k / 8).is_some_and(|&x| x & (1 << (k % 8)) != 0);
        if is_null {
            cells.push(Cell {
                column: i,
                at: None,
                partial: false,
            });
            continue;
        }
        let col = columns.get(i).ok_or(at)?;
        let n = value_len(col, b.get(at..).unwrap_or_default()).ok_or(at)?;
        if at.saturating_add(n) > b.len() {
            return Err(at);
        }
        cells.push(Cell {
            column: i,
            at: Some((at, n)),
            partial: partial.contains(&i),
        });
        at = at.saturating_add(n);
    }
    Ok((cells, at))
}

/// The number of set bits among the first `n` of a bitmap.
pub fn bits_set(bitmap: &[u8], n: u64) -> u64 {
    (0..n)
        .filter(|&i| {
            bitmap
                .get(to_usize(i / 8))
                .is_some_and(|&x| x & (1 << (i % 8)) != 0)
        })
        .count()
        .try_into()
        .unwrap_or(0)
}

/// Bytes of a bitmap over `n` columns.
pub fn bitmap_len(n: u64) -> u64 {
    n.div_ceil(8)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn temporal() {
        // 12:34:56.789 as TIME(3): int part 0x80c8b8 (12<<12 | 34<<6 | 56
        // plus the offset), fraction 789 * 10 = 7890 in two bytes.
        let int = 0x80_0000u64 + ((12 << 12) | (34 << 6) | 56);
        let mut b = int.to_be_bytes()[5..].to_vec();
        b.extend_from_slice(&7890u16.to_be_bytes());
        assert_eq!(time2(&b, 3).unwrap(), "12:34:56.789");
        assert_eq!(lenenc(&[0xfc, 0x34, 0x12]), Some((0x1234, 3)));
        assert_eq!(string_meta(0xfe10), (254, 16));
        assert_eq!(string_meta(0xee10), (254, 0x110));
    }
}
