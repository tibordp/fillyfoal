//! Varints, the record format, and column names from `CREATE` statements.

use std::collections::{BTreeMap, BTreeSet};

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

/// Type affinity of a column, from its declared type (the rules of section
/// 3.1 of "Datatypes In SQLite").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Affinity {
    Integer,
    Text,
    Blob,
    Real,
    Numeric,
}

impl Affinity {
    pub fn of(decl: &str) -> Affinity {
        let t = decl.to_ascii_uppercase();
        if t.contains("INT") {
            Affinity::Integer
        } else if t.contains("CHAR") || t.contains("CLOB") || t.contains("TEXT") {
            Affinity::Text
        } else if t.contains("BLOB") || t.trim().is_empty() {
            Affinity::Blob
        } else if t.contains("REAL") || t.contains("FLOA") || t.contains("DOUB") {
            Affinity::Real
        } else {
            Affinity::Numeric
        }
    }
}

/// A column of a record, as declared.
#[derive(Clone, Debug)]
pub struct Column {
    pub name: String,
    /// The declared type as written (possibly empty).
    pub decl: String,
    pub affinity: Affinity,
    /// `INTEGER PRIMARY KEY`: stored as NULL, the value is the rowid.
    pub rowid_alias: bool,
    /// The value is itself a record (`sqlite_stat4.sample`).
    pub record: bool,
}

impl Column {
    pub fn named(name: impl Into<String>) -> Column {
        Column {
            name: name.into(),
            decl: String::new(),
            affinity: Affinity::Blob,
            rowid_alias: false,
            record: false,
        }
    }
}

/// Columns kept per table (SQLite's default `SQLITE_MAX_COLUMN`).
const MAX_COLUMNS: usize = 2000;

/// What a `CREATE TABLE` statement says about how rows are stored.
#[derive(Clone, Debug, Default)]
pub struct Table {
    /// Stored columns in declaration order (virtual generated columns are
    /// computed when read and are left out).
    pub columns: Vec<Column>,
    pub without_rowid: bool,
    /// Primary-key column names, in key order.
    pub primary_key: Vec<String>,
    /// Constraints that get an automatic index, in the order SQLite numbers
    /// them (`sqlite_autoindex_<table>_<N>`): the constraint and its columns.
    pub auto_indexes: Vec<(&'static str, Vec<String>)>,
}

impl Table {
    /// Column positions by lower-case name.
    fn positions(&self) -> BTreeMap<String, usize> {
        self.columns
            .iter()
            .enumerate()
            .map(|(i, c)| (c.name.to_ascii_lowercase(), i))
            .collect()
    }

    fn lookup(&self, positions: &BTreeMap<String, usize>, name: &str) -> Option<Column> {
        let &i = positions.get(&name.to_ascii_lowercase())?;
        self.columns.get(i).cloned()
    }

    /// Columns in the order a row's record stores them: for a WITHOUT ROWID
    /// table, the primary key first, then the other columns.
    pub fn record_columns(&self) -> Vec<Column> {
        if !self.without_rowid {
            return self.columns.clone();
        }
        let positions = self.positions();
        let keys: BTreeSet<String> = self
            .primary_key
            .iter()
            .map(|k| k.to_ascii_lowercase())
            .collect();
        let mut out: Vec<Column> = self
            .primary_key
            .iter()
            .map(|k| {
                self.lookup(&positions, k)
                    .unwrap_or_else(|| Column::named(k.clone()))
            })
            .collect();
        out.extend(
            self.columns
                .iter()
                .filter(|c| !keys.contains(&c.name.to_ascii_lowercase()))
                .cloned(),
        );
        out
    }

    /// The columns of an index entry: the indexed columns, then the rowid
    /// or, for a WITHOUT ROWID table, the rest of the primary key.
    pub fn index_columns(&self, indexed: &[String]) -> Vec<Column> {
        let positions = self.positions();
        let mut out: Vec<Column> = indexed
            .iter()
            .map(|n| match self.lookup(&positions, n) {
                Some(mut c) => {
                    c.rowid_alias = false;
                    c
                }
                None => Column::named(n.clone()),
            })
            .collect();
        if self.without_rowid {
            let have: BTreeSet<String> = indexed.iter().map(|n| n.to_ascii_lowercase()).collect();
            for k in &self.primary_key {
                if !have.contains(&k.to_ascii_lowercase()) {
                    out.push(
                        self.lookup(&positions, k)
                            .unwrap_or_else(|| Column::named(k.clone())),
                    );
                }
            }
        } else {
            let mut rowid = Column::named("rowid");
            rowid.affinity = Affinity::Integer;
            out.push(rowid);
        }
        out
    }
}

/// Words that end a column's declared type and start its constraints.
const CONSTRAINT_WORDS: [&str; 11] = [
    "CONSTRAINT",
    "PRIMARY",
    "NOT",
    "NULL",
    "UNIQUE",
    "CHECK",
    "DEFAULT",
    "COLLATE",
    "REFERENCES",
    "GENERATED",
    "AS",
];

/// Parses `CREATE TABLE t (a INTEGER PRIMARY KEY, b TEXT, ..., UNIQUE (b))
/// WITHOUT ROWID`. Returns no columns for statements it cannot follow
/// (`CREATE TABLE ... AS SELECT`).
pub fn table(sql: &str) -> Table {
    let sql = strip_comments(sql);
    let mut t = Table::default();
    let Some(open) = sql.find('(') else {
        return t;
    };
    if words_top(sql.get(..open).unwrap_or_default())
        .iter()
        .any(|w| w == "AS")
    {
        return t;
    }
    let (defs, tail) = split_top_level(sql.get(open.saturating_add(1)..).unwrap_or_default());
    let tail = words_top(tail);
    t.without_rowid = tail
        .windows(2)
        .any(|w| matches!(w, [a, b] if a == "WITHOUT" && b == "ROWID"));
    let mut table_pk = false;
    let mut autos: Vec<(&'static str, Vec<String>)> = Vec::new();
    for def in &defs {
        let def = def.trim();
        let (name, rest) = first_token(def);
        if name.is_empty() {
            continue;
        }
        let words = words_top(def);
        let lead = words.first().map(String::as_str).unwrap_or_default();
        let quoted = def.starts_with(['"', '`', '[', '\'']);
        if !quoted
            && matches!(
                lead,
                "CONSTRAINT" | "PRIMARY" | "UNIQUE" | "CHECK" | "FOREIGN"
            )
        {
            let kind = words
                .iter()
                .find(|w| matches!(w.as_str(), "PRIMARY" | "UNIQUE" | "CHECK" | "FOREIGN"));
            let columns = || {
                let inner = def.find('(').and_then(|i| def.get(i.saturating_add(1)..));
                split_top_level(inner.unwrap_or_default())
                    .0
                    .iter()
                    .map(|c| first_token(c.trim()).0)
                    .filter(|c| !c.is_empty())
                    .collect::<Vec<_>>()
            };
            match kind.map(String::as_str) {
                Some("PRIMARY") => {
                    t.primary_key = columns();
                    table_pk = true;
                    autos.push(("PRIMARY KEY", t.primary_key.clone()));
                }
                Some("UNIQUE") => autos.push(("UNIQUE", columns())),
                _ => {}
            }
            continue;
        }
        let (decl, constraints) = split_type(rest);
        let cw = words_top(constraints);
        let pk_at = cw
            .windows(2)
            .position(|w| matches!(w, [a, b] if a == "PRIMARY" && b == "KEY"));
        let desc = pk_at
            .and_then(|i| cw.get(i.saturating_add(2)))
            .is_some_and(|w| w == "DESC");
        let alias = pk_at.is_some() && decl.eq_ignore_ascii_case("INTEGER") && !desc;
        if pk_at.is_some() {
            t.primary_key = vec![name.clone()];
            if !alias || t.without_rowid {
                autos.push(("PRIMARY KEY", vec![name.clone()]));
            }
        }
        if cw.iter().any(|w| w == "UNIQUE") {
            autos.push(("UNIQUE", vec![name.clone()]));
        }
        let generated = cw.iter().any(|w| w == "AS" || w == "GENERATED");
        if generated && !cw.iter().any(|w| w == "STORED") {
            continue;
        }
        if t.columns.len() < MAX_COLUMNS {
            t.columns.push(Column {
                name,
                affinity: Affinity::of(&decl),
                decl,
                rowid_alias: alias && !t.without_rowid,
                record: false,
            });
        }
    }
    // `PRIMARY KEY (id)` on a single INTEGER column of a rowid table makes
    // it the rowid, like the column constraint does.
    if table_pk
        && !t.without_rowid
        && let [key] = t.primary_key.as_slice()
    {
        let key = key.to_ascii_lowercase();
        if let Some(c) = t
            .columns
            .iter_mut()
            .find(|c| c.name.to_ascii_lowercase() == key && c.decl.eq_ignore_ascii_case("INTEGER"))
        {
            c.rowid_alias = true;
            autos.retain(|(kind, _)| *kind != "PRIMARY KEY");
        }
    }
    // A constraint over the same columns as an earlier one shares its index.
    let mut seen = BTreeSet::new();
    for (kind, columns) in autos {
        let key: Vec<String> = columns.iter().map(|c| c.to_ascii_lowercase()).collect();
        if seen.insert(key) {
            t.auto_indexes.push((kind, columns));
        }
    }
    t
}

/// The indexed columns (or expressions) of `CREATE INDEX i ON t (a, b
/// DESC, lower(c))`, without sort order or collation.
pub fn indexed(sql: &str) -> Vec<String> {
    let sql = strip_comments(sql);
    let Some(open) = sql.find('(') else {
        return Vec::new();
    };
    let (defs, _) = split_top_level(sql.get(open.saturating_add(1)..).unwrap_or_default());
    defs.iter()
        .take(MAX_COLUMNS)
        .map(|def| {
            let def = def.trim();
            let (name, rest) = first_token(def);
            let plain = !rest.trim_start().starts_with('(')
                && words_top(rest)
                    .first()
                    .is_none_or(|w| matches!(w.as_str(), "ASC" | "DESC" | "COLLATE"));
            if plain {
                name
            } else {
                def.split_whitespace().collect::<Vec<_>>().join(" ")
            }
        })
        .collect()
}

/// `sql` with `--` and `/* */` comments replaced by spaces (quotes are
/// respected).
fn strip_comments(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    let mut chars = sql.chars().peekable();
    let mut quote: Option<char> = None;
    while let Some(c) = chars.next() {
        if let Some(q) = quote {
            out.push(c);
            if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '\'' | '"' | '`' => {
                quote = Some(c);
                out.push(c);
            }
            '[' => {
                quote = Some(']');
                out.push(c);
            }
            '-' if chars.peek() == Some(&'-') => {
                for c in chars.by_ref() {
                    if c == '\n' {
                        break;
                    }
                }
                out.push(' ');
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                let mut star = false;
                for c in chars.by_ref() {
                    if star && c == '/' {
                        break;
                    }
                    star = c == '*';
                }
                out.push(' ');
            }
            _ => out.push(c),
        }
    }
    out
}

/// The upper-cased keywords and bare identifiers of `s` outside
/// parentheses and quotes.
fn words_top(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut word = String::new();
    let mut depth = 0u32;
    let mut quote: Option<char> = None;
    for c in s.chars() {
        if let Some(q) = quote {
            if c == q {
                quote = None;
            }
            continue;
        }
        if depth == 0 && (c.is_ascii_alphanumeric() || c == '_') {
            word.push(c.to_ascii_uppercase());
            continue;
        }
        if !word.is_empty() {
            out.push(std::mem::take(&mut word));
        }
        match c {
            '\'' | '"' | '`' => quote = Some(c),
            '[' => quote = Some(']'),
            '(' => depth = depth.saturating_add(1),
            ')' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    if !word.is_empty() {
        out.push(word);
    }
    out
}

/// Splits what follows a column name into its declared type (`VARCHAR(80)`,
/// `DECIMAL(10, 2)`, possibly empty) and its constraints.
fn split_type(rest: &str) -> (String, &str) {
    let mut depth = 0u32;
    let mut quote: Option<char> = None;
    let mut boundary = true;
    for (i, c) in rest.char_indices() {
        if let Some(q) = quote {
            if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '\'' | '"' | '`' => {
                quote = Some(c);
                boundary = false;
            }
            '[' => {
                quote = Some(']');
                boundary = false;
            }
            '(' => {
                depth = depth.saturating_add(1);
                boundary = false;
            }
            ')' => depth = depth.saturating_sub(1),
            c if c.is_whitespace() => boundary = depth == 0,
            _ => {
                if boundary && depth == 0 {
                    let tail = rest.get(i..).unwrap_or_default();
                    let head: String = tail
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .map(|c| c.to_ascii_uppercase())
                        .collect();
                    if CONSTRAINT_WORDS.contains(&head.as_str()) {
                        return (rest.get(..i).unwrap_or_default().trim().to_owned(), tail);
                    }
                }
                boundary = false;
            }
        }
    }
    (rest.trim().to_owned(), "")
}

/// Splits the parenthesised list at top-level commas, stopping at the
/// closing parenthesis; returns the parts and what follows the list. Quotes
/// are respected.
fn split_top_level(body: &str) -> (Vec<String>, &str) {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut depth = 0u32;
    let mut quote: Option<char> = None;
    for (i, c) in body.char_indices() {
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
                return (parts, body.get(i.saturating_add(1)..).unwrap_or_default());
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
    (parts, "")
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
        let t = table(
            "CREATE TABLE \"t x\" (id INTEGER PRIMARY KEY, [name] VARCHAR(10) NOT NULL, -- a, comment\n v DECIMAL(10, 2) DEFAULT (CAST(1 AS REAL)), g AS (v * 2), UNIQUE (name))",
        );
        let names: Vec<_> = t.columns.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["id", "name", "v"]);
        assert!(t.columns[0].rowid_alias && !t.columns[1].rowid_alias);
        assert_eq!(t.columns[1].decl, "VARCHAR(10)");
        assert_eq!(t.columns[1].affinity, Affinity::Text);
        assert_eq!(t.columns[2].affinity, Affinity::Numeric);
        assert_eq!(t.auto_indexes.len(), 1);
        let w = table("CREATE TABLE w (a, b UNIQUE, c REAL, PRIMARY KEY (c, a)) WITHOUT ROWID");
        assert!(w.without_rowid);
        let order: Vec<_> = w.record_columns().into_iter().map(|c| c.name).collect();
        assert_eq!(order, ["c", "a", "b"]);
        assert_eq!(w.auto_indexes.len(), 2);
        let entry: Vec<_> = w
            .index_columns(&["b".to_owned()])
            .into_iter()
            .map(|c| c.name)
            .collect();
        assert_eq!(entry, ["b", "c", "a"]);
        let r = table("CREATE TABLE r (x text unique, y primary key, z, unique(z, x), unique(x))");
        assert_eq!(r.auto_indexes.len(), 3);
        let q = table("CREATE TABLE q (id INTEGER, v, PRIMARY KEY (id))");
        assert!(q.columns[0].rowid_alias && q.auto_indexes.is_empty());
        assert!(
            table("CREATE TABLE s AS SELECT (1) AS a")
                .columns
                .is_empty()
        );
        assert_eq!(
            indexed("CREATE INDEX i ON t(a, b DESC, lower(c) COLLATE nocase)"),
            ["a", "b", "lower(c) COLLATE nocase"]
        );
        assert_eq!(decode(1, &[0xff], Encoding::Utf8), Some(Val::Int(-1)));
        assert_eq!(
            decode(5, &[0, 0, 0, 1, 0, 0], Encoding::Utf8),
            Some(Val::Int(65536))
        );
    }
}
