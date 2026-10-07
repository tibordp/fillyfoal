//! Statistics package data files: SPSS system files (`.sav`, `.zsav`) and
//! portable files (`.por`), SAS data sets (`.sas7bdat`) and transport files
//! (`.xpt`), and Stata `.dta`.
//!
//! Each shows its dataset metadata, its variables (name, label, type,
//! width, display format, value labels), its value label sets and its rows
//! as a paged collection of records, decoded per variable type, with
//! missing values named the way the package names them.
//!
//! The helpers here are shared: a decoded [`Cell`], how it reads in a row
//! summary and as a node, dates, and text in a dataset's encoding.

pub mod por;
pub mod sas;
pub mod spss;
pub mod stata;
pub mod xport;

use std::sync::Arc;

use crate::formats::util::arcutil::emit_nodes;
use crate::node::Node;
use crate::span::Span;
use crate::value::Value;

/// How many variables a row's summary lists before eliding the rest.
const SUMMARY_VARS: usize = 12;
/// How many characters of a string cell a row summary shows.
const SUMMARY_TEXT: usize = 40;

/// One decoded value of a row.
#[derive(Clone, Debug)]
pub enum Cell {
    Number(f64),
    Int(i64),
    Text(String),
    /// A date (`time == false`) or date and time, in Unix seconds.
    Date {
        unix_seconds: i64,
        time: bool,
    },
    /// A missing value: `name` is how the package writes it (`.`, `.a`,
    /// `sysmis`); `raw` is the stored number, when it is one.
    Missing {
        name: String,
        raw: Option<f64>,
    },
}

impl Cell {
    /// The cell as it reads in a row summary.
    pub fn display(&self) -> String {
        match self {
            Cell::Number(v) => number(*v),
            Cell::Int(v) => v.to_string(),
            Cell::Text(s) => format!("{:?}", clip(s, SUMMARY_TEXT)),
            Cell::Date { unix_seconds, time } => date_string(*unix_seconds, *time),
            Cell::Missing { name, .. } => name.clone(),
        }
    }

    fn value(&self) -> Value {
        match self {
            Cell::Number(v) => Value::Float(*v),
            Cell::Int(v) => Value::Int {
                value: *v,
                bits: 64,
            },
            Cell::Text(s) => Value::Text(s.clone()),
            Cell::Date { unix_seconds, .. } => Value::Timestamp {
                unix_seconds: *unix_seconds,
            },
            Cell::Missing { raw: Some(v), .. } => Value::Float(*v),
            Cell::Missing { name, raw: None } => Value::Text(name.clone()),
        }
    }

    /// The number, for value-label lookups.
    pub fn as_number(&self) -> Option<f64> {
        match self {
            Cell::Number(v) => Some(*v),
            Cell::Int(v) => Some(*v as f64),
            Cell::Missing { raw, .. } => *raw,
            _ => None,
        }
    }
}

/// A number the way people write it: integers without a fraction.
pub fn number(v: f64) -> String {
    if v.is_finite() && v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        format!("{v}")
    }
}

fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_owned()
    } else {
        let mut out: String = s.chars().take(max).collect();
        out.push('…');
        out
    }
}

/// One decoded value of a row, ready to be shown.
pub struct Item {
    pub name: String,
    pub cell: Cell,
    /// The value label that applies, if any.
    pub label: Option<String>,
    pub span: Span,
}

/// A row node: a summary listing the first variables, expanding to one
/// node per variable.
pub fn row_node(name: String, span: Span, items: Vec<Item>) -> Node {
    let mut parts = Vec::new();
    for item in items.iter().take(SUMMARY_VARS) {
        let mut s = format!("{}={}", item.name, item.cell.display());
        if let Some(label) = &item.label {
            s.push_str(&format!(" ({label})"));
        }
        parts.push(s);
    }
    if items.len() > SUMMARY_VARS {
        parts.push("…".to_owned());
    }
    let nodes: Vec<Node> = items
        .into_iter()
        .map(|item| {
            let mut node = Node::new(item.name)
                .span(item.span)
                .value(item.cell.value());
            let mut summary = Vec::new();
            match &item.cell {
                Cell::Missing { name, raw: Some(_) } => summary.push(format!("missing ({name})")),
                Cell::Missing { .. } => summary.push("missing".to_owned()),
                Cell::Date { .. } => summary.push(item.cell.display()),
                _ => {}
            }
            if let Some(label) = item.label {
                summary.push(label);
            }
            if !summary.is_empty() {
                node = node.summary(summary.join(", "));
            }
            node
        })
        .collect();
    Node::new(name)
        .span(span)
        .summary(parts.join(", "))
        .lazy(emit_nodes, Arc::new(nodes))
}

/// `(year, month, day)` of a day count since 1970-01-01 (Howard Hinnant's
/// `civil_from_days`).
pub fn civil(days: i64) -> (i64, i64, i64) {
    let z = days
        .clamp(-1_000_000_000, 1_000_000_000)
        .saturating_add(719_468);
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = doe
        .saturating_sub(doe / 1460)
        .saturating_add(doe / 36_524)
        .saturating_sub(doe / 146_096)
        / 365;
    let doy = doe.saturating_sub(
        yoe.saturating_mul(365)
            .saturating_add(yoe / 4)
            .saturating_sub(yoe / 100),
    );
    let mp = doy.saturating_mul(5).saturating_add(2) / 153;
    let day = doy
        .saturating_sub(mp.saturating_mul(153).saturating_add(2) / 5)
        .saturating_add(1);
    let month = if mp < 10 {
        mp.saturating_add(3)
    } else {
        mp.saturating_sub(9)
    };
    let year = yoe
        .saturating_add(era.saturating_mul(400))
        .saturating_add(i64::from(month <= 2));
    (year, month, day)
}

/// `1980-01-15`, or `1980-01-15 10:30:00` with the time.
pub fn date_string(unix_seconds: i64, time: bool) -> String {
    let (y, m, d) = civil(unix_seconds.div_euclid(86_400));
    if time {
        let rem = unix_seconds.rem_euclid(86_400);
        format!(
            "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}",
            rem / 3600,
            rem % 3600 / 60,
            rem % 60
        )
    } else {
        format!("{y:04}-{m:02}-{d:02}")
    }
}

/// A date cell from `value` units since an epoch `epoch` seconds after
/// (or before) 1970, `unit` seconds each. Values outside any plausible
/// calendar stay numbers.
pub fn date_cell(value: f64, unit: f64, epoch: i64, time: bool) -> Cell {
    let seconds = value * unit;
    if !seconds.is_finite() || seconds.abs() > 1e13 {
        return Cell::Number(value);
    }
    Cell::Date {
        unix_seconds: (seconds.floor() as i64).saturating_add(epoch),
        time,
    }
}

/// Text in a dataset's encoding (a WHATWG label), or UTF-8 when it is
/// valid, else Latin-1.
pub fn decode_text(encoding: Option<&str>, bytes: &[u8]) -> String {
    if let Some(label) = encoding
        && let Some(s) = crate::codec::charset::decode_label(label, bytes)
    {
        return s;
    }
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_owned(),
        Err(_) => crate::text::latin1(bytes),
    }
}

/// Bytes with trailing blanks and NULs removed.
pub fn trim_end(bytes: &[u8]) -> &[u8] {
    let end = bytes
        .iter()
        .rposition(|&b| b != b' ' && b != 0)
        .map_or(0, |p| p.saturating_add(1));
    bytes.get(..end).unwrap_or_default()
}

/// Bytes up to the first NUL.
pub fn until_nul(bytes: &[u8]) -> &[u8] {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    bytes.get(..end).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(date_string(0, false), "1970-01-01");
        assert_eq!(date_string(-315_619_200, true), "1960-01-01 00:00:00");
        assert_eq!(date_string(1_709_164_800, false), "2024-02-29");
        assert_eq!(date_string(-12_219_292_800, false), "1582-10-15");
        assert_eq!(number(12.0), "12");
        assert_eq!(number(12.5), "12.5");
    }
}
