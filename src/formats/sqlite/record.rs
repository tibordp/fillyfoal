//! Varints, the record format, and column names from `CREATE` statements.

use crate::bytes::{to_u64, to_usize};
use crate::fields::Endian;

/// Text encodings (header offset 56).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    Utf8,
    Utf16Le,
    Utf16Be,
}

impl Encoding {
    pub fn from_header(raw: u32) -> Self {
        match raw {
            2 => Encoding::Utf16Le,
            3 => Encoding::Utf16Be,
            _ => Encoding::Utf8,
        }
    }

    pub fn decode(self, data: &[u8]) -> String {
        match self {
            Encoding::Utf8 => String::from_utf8_lossy(data).into_owned(),
            Encoding::Utf16Le => crate::text::utf16(data, Endian::Little),
            Encoding::Utf16Be => crate::text::utf16(data, Endian::Big),
        }
    }
}

/// A SQLite varint at `at`: its value and length (1 to 9 bytes).
pub fn varint(data: &[u8], at: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for i in 0..9usize {
        let &b = data.get(at.checked_add(i)?)?;
        if i == 8 {
            return Some((value << 8 | u64::from(b), 9));
        }
        value = value << 7 | u64::from(b & 0x7f);
        if b & 0x80 == 0 {
            return Some((value, i.saturating_add(1)));
        }
    }
    None
}

/// Bytes a value of serial type `serial` occupies.
pub fn serial_len(serial: u64) -> u64 {
    match serial {
        0 | 8 | 9 | 10 | 11 => 0,
        1 => 1,
        2 => 2,
        3 => 3,
        4 => 4,
        5 => 6,
        6 | 7 => 8,
        n => n.saturating_sub(12) / 2,
    }
}

pub fn serial_name(serial: u64) -> String {
    match serial {
        0 => "NULL".to_owned(),
        1..=6 => format!("{}-byte integer", serial_len(serial)),
        7 => "float".to_owned(),
        8 => "integer 0".to_owned(),
        9 => "integer 1".to_owned(),
        10 | 11 => "reserved".to_owned(),
        n if n % 2 == 0 => format!("blob ({} bytes)", serial_len(n)),
        n => format!("text ({} bytes)", serial_len(n)),
    }
}

/// One column of a record: its serial type and where its value is,
/// relative to the start of the payload.
#[derive(Clone, Copy, Debug)]
pub struct Field {
    pub serial: u64,
    /// Where the serial type varint is, and its length.
    pub type_at: u64,
    pub type_len: u64,
    pub offset: u64,
    pub len: u64,
}

/// A record header decoded from the start of a payload: its size and the
/// fields it describes. Fields whose types lie beyond `data` are omitted.
pub fn header(data: &[u8]) -> Option<(u64, Vec<Field>)> {
    let (size, n) = varint(data, 0)?;
    let mut at = n;
    let end = to_usize(size);
    let mut offset = size;
    let mut fields = Vec::new();
    while at < end {
        let Some((serial, n)) = varint(data, at) else {
            break;
        };
        let len = serial_len(serial);
        fields.push(Field {
            serial,
            type_at: to_u64(at),
            type_len: to_u64(n),
            offset,
            len,
        });
        offset = offset.saturating_add(len);
        at = at.saturating_add(n);
    }
    Some((size, fields))
}

/// A decoded value.
#[derive(Clone, Debug, PartialEq)]
pub enum Val {
    Null,
    Int(i64),
    Float(f64),
    Text(String),
    Blob(Vec<u8>),
}

/// Decodes a value from its bytes (`data` may be a prefix for text and
/// blobs; integers and floats need all their bytes).
pub fn decode(serial: u64, data: &[u8], encoding: Encoding) -> Option<Val> {
    Some(match serial {
        0 | 10 | 11 => Val::Null,
        8 => Val::Int(0),
        9 => Val::Int(1),
        1..=6 => {
            let n = to_usize(serial_len(serial));
            let bytes = data.get(..n)?;
            let negative = bytes.first().is_some_and(|&b| b & 0x80 != 0);
            let mut buf = if negative { [0xff; 8] } else { [0; 8] };
            for (slot, &b) in buf.iter_mut().skip(8usize.saturating_sub(n)).zip(bytes) {
                *slot = b;
            }
            Val::Int(i64::from_be_bytes(buf))
        }
        7 => Val::Float(f64::from_be_bytes(crate::bytes::array(data, 0)?)),
        n if n % 2 == 0 => Val::Blob(data.to_vec()),
        _ => Val::Text(encoding.decode(data)),
    })
}

/// A short SQL-literal rendering for summaries.
pub fn short(val: &Val, complete: bool) -> String {
    const MAX: usize = 40;
    match val {
        Val::Null => "NULL".to_owned(),
        Val::Int(v) => v.to_string(),
        Val::Float(v) => format!("{v:?}"),
        Val::Text(s) => {
            let cut: String = s.chars().take(MAX).collect();
            let more = !complete || cut.len() < s.len();
            format!("'{cut}{}'", if more { "…" } else { "" })
        }
        Val::Blob(b) => {
            let hex: String = b.iter().take(8).map(|x| format!("{x:02x}")).collect();
            let more = !complete || b.len() > 8;
            format!("x'{hex}{}'", if more { "…" } else { "" })
        }
    }
}

/// A column of a table or index, as declared.
#[derive(Clone, Debug)]
pub struct Column {
    pub name: String,
    /// `INTEGER PRIMARY KEY`: stored as NULL, the value is the rowid.
    pub rowid_alias: bool,
}

/// Column names from `CREATE TABLE t (a INTEGER PRIMARY KEY, b, ...)` or
/// `CREATE INDEX i ON t (a, b)`. Table constraints are skipped. Returns
/// nothing for statements it cannot follow (e.g. `CREATE TABLE ... AS`).
pub fn columns(sql: &str) -> Vec<Column> {
    let Some(open) = sql.find('(') else {
        return Vec::new();
    };
    let body = sql.get(open.saturating_add(1)..).unwrap_or_default();
    let mut out = Vec::new();
    for def in split_top_level(body) {
        let def = def.trim();
        let (name, rest) = first_token(def);
        let upper = name.to_ascii_uppercase();
        if name.is_empty()
            || matches!(
                upper.as_str(),
                "CONSTRAINT" | "PRIMARY" | "UNIQUE" | "CHECK" | "FOREIGN"
            )
        {
            continue;
        }
        let rest: Vec<String> = rest
            .split_whitespace()
            .map(str::to_ascii_uppercase)
            .collect();
        let rowid_alias = rest.first().is_some_and(|t| t == "INTEGER")
            && rest.get(1).is_some_and(|t| t == "PRIMARY")
            && rest.get(2).is_some_and(|t| t == "KEY")
            && !rest.iter().any(|t| t == "DESC");
        out.push(Column { name, rowid_alias });
    }
    out
}

/// Splits the parenthesised list at top-level commas, stopping at the
/// closing parenthesis. Quotes are respected.
fn split_top_level(body: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut depth = 0u32;
    let mut quote: Option<char> = None;
    for c in body.chars() {
        if let Some(q) = quote {
            current.push(c);
            if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '\'' | '"' | '`' => {
                quote = Some(c);
                current.push(c);
            }
            '[' => {
                quote = Some(']');
                current.push(c);
            }
            '(' => {
                depth = depth.saturating_add(1);
                current.push(c);
            }
            ')' if depth == 0 => {
                parts.push(current);
                return parts;
            }
            ')' => {
                depth = depth.saturating_sub(1);
                current.push(c);
            }
            ',' if depth == 0 => parts.push(std::mem::take(&mut current)),
            _ => current.push(c),
        }
    }
    parts.push(current);
    parts
}

/// The first identifier of a column definition (unquoted) and the rest.
fn first_token(def: &str) -> (String, &str) {
    let mut chars = def.char_indices();
    let Some((_, first)) = chars.next() else {
        return (String::new(), "");
    };
    let close = match first {
        '"' => Some('"'),
        '`' => Some('`'),
        '[' => Some(']'),
        '\'' => Some('\''),
        _ => None,
    };
    if let Some(close) = close {
        let inner = def.get(1..).unwrap_or_default();
        let end = inner.find(close).unwrap_or(inner.len());
        let name = inner.get(..end).unwrap_or_default().to_owned();
        let rest = inner.get(end.saturating_add(1)..).unwrap_or_default();
        return (name, rest);
    }
    let end = def
        .find(|c: char| c.is_whitespace() || c == '(')
        .unwrap_or(def.len());
    (
        def.get(..end).unwrap_or_default().to_owned(),
        def.get(end..).unwrap_or_default(),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn varints_and_columns() {
        assert_eq!(varint(&[0x05], 0), Some((5, 1)));
        assert_eq!(varint(&[0x81, 0x00], 0), Some((128, 2)));
        assert_eq!(varint(&[0xff; 9], 0), Some((u64::MAX, 9)));
        let cols = columns(
            "CREATE TABLE \"t x\" (id INTEGER PRIMARY KEY, [name] TEXT NOT NULL, v REAL DEFAULT (1+2), PRIMARY KEY (name))",
        );
        let names: Vec<_> = cols.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["id", "name", "v"]);
        assert!(cols[0].rowid_alias && !cols[1].rowid_alias);
        let idx = columns("CREATE INDEX i ON t(a, b DESC)");
        assert_eq!(idx.len(), 2);
        assert_eq!(decode(1, &[0xff], Encoding::Utf8), Some(Val::Int(-1)));
        assert_eq!(decode(5, &[0, 0, 0, 1, 0, 0], Encoding::Utf8), Some(Val::Int(65536)));
    }
}
