//! Plain-text rendering, for the example CLI, tests and debugging.
//!
//! Frontends are expected to do their own presentation; this is one
//! reasonable default.

use std::fmt::Write;

use crate::node::{Count, Node};
use crate::session::{ChildState, NodeId, Session};
use crate::value::{Radix, Value};

pub fn value(v: &Value) -> String {
    match v {
        Value::Bool(b) => b.to_string(),
        Value::UInt { value, radix, .. } => uint(*value, *radix),
        Value::Int { value, .. } => value.to_string(),
        Value::Enum { raw, name, .. } => match name {
            Some(name) => format!("{name} ({raw:#x})"),
            None => format!("{raw:#x} (unknown)"),
        },
        Value::Flags {
            raw, set, unknown, ..
        } => {
            let mut parts: Vec<String> = set.iter().map(|s| (*s).to_owned()).collect();
            if *unknown != 0 {
                parts.push(format!("{unknown:#x}"));
            }
            format!("{raw:#x} [{}]", parts.join(" | "))
        }
        Value::Float { value, bits } => float(*value, *bits),
        Value::Timestamp { unix_seconds } => timestamp(*unix_seconds),
        Value::Text(s) => format!("{s:?}"),
        Value::Bytes(b) => bytes(b),
        Value::Guid(g) => g.to_string(),
    }
}

fn bytes(b: &[u8]) -> String {
    const MAX: usize = 16;
    let mut out = String::new();
    for (i, byte) in b.iter().take(MAX).enumerate() {
        if i > 0 {
            out.push(' ');
        }
        let _ = write!(out, "{byte:02x}");
    }
    if b.len() > MAX {
        out.push_str(" …");
    }
    let ascii: String = b
        .iter()
        .take(MAX)
        .map(|&c| {
            if c.is_ascii_graphic() || c == b' ' {
                char::from(c)
            } else {
                '.'
            }
        })
        .collect();
    let _ = write!(out, "  |{ascii}|");
    out
}

/// Formats seconds since the epoch as `YYYY-MM-DD hh:mm:ss UTC`.
fn timestamp(unix_seconds: i64) -> String {
    let (year, month, day) = crate::formats::util::civil::civil(unix_seconds.div_euclid(86_400));
    let rem = unix_seconds.rem_euclid(86_400);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// One line describing a node: `name: value — summary [span] → target`.
pub fn line(node: &Node) -> String {
    let mut out = node.name.to_string();
    if let Some(v) = &node.value {
        let _ = write!(out, ": {}", value(v));
    }
    if let Some(summary) = &node.summary {
        let _ = write!(out, " — {summary}");
    }
    if let Some(span) = node.span {
        let _ = write!(out, "  [{span}]");
    }
    if let Some(target) = node.target {
        let _ = write!(out, " → {target}");
    }
    out
}

/// Renders the materialised part of the tree under `root`.
pub fn tree<C: crate::formats::Catalog>(session: &Session<C>, root: NodeId) -> String {
    let mut out = String::new();
    render(session, root, 0, &mut out);
    out
}

fn render<C: crate::formats::Catalog>(
    session: &Session<C>,
    id: NodeId,
    depth: usize,
    out: &mut String,
) {
    let Some(node) = session.node(id) else {
        return;
    };
    let Some(children) = session.children(id) else {
        return;
    };
    let indent = "  ".repeat(depth);
    let marker = match children.state {
        ChildState::Leaf => "  ",
        ChildState::NotRequested => "▸ ",
        _ => "▾ ",
    };
    let _ = writeln!(out, "{indent}{marker}{}", line(node));
    for d in &node.diagnostics {
        let _ = writeln!(out, "{indent}    ! {d}");
    }
    for &child in children.ids {
        render(session, child, depth.saturating_add(1), out);
    }
    let inner = "  ".repeat(depth.saturating_add(1));
    match children.state {
        ChildState::More => {
            let total = match children.count {
                Count::Exact(n) => format!(" of {n}"),
                Count::AtLeast(n) => format!(" of at least {n}"),
                Count::Unknown => String::new(),
            };
            let _ = writeln!(out, "{inner}  … ({} shown{total})", children.ids.len());
        }
        ChildState::Running(wait) => {
            let _ = writeln!(out, "{inner}  … (in progress: {wait:?})");
        }
        _ => {}
    }
    if let Some(error) = children.error {
        let _ = writeln!(out, "{inner}  ! {error}");
    }
}

/// An unsigned number in `radix`: `123`, `0x7b`, `0o173` or `0b1111011`.
pub fn uint(value: u64, radix: Radix) -> String {
    match radix {
        Radix::Dec => value.to_string(),
        Radix::Hex => format!("{value:#x}"),
        Radix::Oct => format!("{value:#o}"),
        Radix::Bin => format!("{value:#b}"),
    }
}

/// A float stored `bits` wide, in the shortest decimal that reads back to
/// the same value at that width (so an `f32` 0.8 prints `0.8`), switching
/// to exponent notation for very large or very small magnitudes, which `{}`
/// would spell out with hundreds of digits.
pub fn float(value: f64, bits: u8) -> String {
    let a = value.abs();
    let exp = a != 0.0 && a.is_finite() && !(1e-6..1e21).contains(&a);
    match bits {
        // `as` rounds to nearest; it is exact for a value read as an f32.
        32 => {
            let f = value as f32;
            if exp {
                format!("{f:e}")
            } else {
                format!("{f}")
            }
        }
        16 => half(value, exp),
        _ if exp => format!("{value:e}"),
        _ => format!("{value}"),
    }
}

/// The shortest decimal that rounds to `value` as a half-precision float.
fn half(value: f64, exp: bool) -> String {
    if value.is_finite() && value != 0.0 {
        for digits in 0..5 {
            let s = format!("{value:.digits$e}");
            if s.parse::<f64>().ok().map(to_half) == Some(value) {
                // Re-print the parsed value in the usual style.
                let shortest: f64 = s.parse().unwrap_or(value);
                return if exp {
                    format!("{shortest:e}")
                } else {
                    format!("{shortest}")
                };
            }
        }
    }
    if exp {
        format!("{value:e}")
    } else {
        format!("{value}")
    }
}

/// `x` rounded to the nearest half-precision value (ties to even), as `f64`.
fn to_half(x: f64) -> f64 {
    let a = x.abs();
    let rounded = if !a.is_finite() || a >= 65520.0 {
        f64::INFINITY
    } else if a < 2f64.powi(-14) {
        // Subnormal: multiples of 2^-24.
        (a * 2f64.powi(24)).round_ties_even() * 2f64.powi(-24)
    } else {
        // Normal: 10 fraction bits below the leading one. The exponent of a
        // normal f64 is its biased field less 1023.
        let field = (a.to_bits() >> 52) & 0x7ff;
        let e = i32::try_from(field).unwrap_or(1023).saturating_sub(1023);
        let scale = 2f64.powi(e.saturating_sub(10));
        (a / scale).round_ties_even() * scale
    };
    rounded.copysign(x)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::util::floats::f16;

    #[test]
    fn floats_print_shortest_at_their_stored_width() {
        assert_eq!(value(&Value::f32(0.8)), "0.8");
        assert_eq!(value(&Value::f32(1.83)), "1.83");
        assert_eq!(value(&Value::f32(9.96921e36)), "9.96921e36");
        assert_eq!(value(&Value::f32(f32::NAN)), "NaN");
        assert_eq!(value(&Value::f64(f64::from(0.8f32))), "0.800000011920929");
        assert_eq!(value(&Value::f64(0.1)), "0.1");
        assert_eq!(value(&Value::f64(1e300)), "1e300");
        assert_eq!(value(&Value::f80(44100.0)), "44100");
        // binary16: 0x2e66 is the half nearest 0.1, 0x3c00 is 1.
        assert_eq!(value(&Value::f16(f16(0x2e66))), "0.1");
        assert_eq!(value(&Value::f16(f16(0x3c00))), "1");
        assert_eq!(value(&Value::f16(f16(0x7bff))), "65500");
        assert_eq!(value(&Value::f16(f16(0x0001))), "6e-8");
        assert_eq!(value(&Value::f16(f16(0xc000))), "-2");
        assert_eq!(value(&Value::f16(f16(0x7c00))), "inf");
    }

    #[test]
    fn unsigned_numbers_print_in_their_radix() {
        let v = |radix| Value::UInt {
            value: 0o100644,
            bits: 32,
            radix,
        };
        assert_eq!(value(&v(Radix::Dec)), "33188");
        assert_eq!(value(&v(Radix::Hex)), "0x81a4");
        assert_eq!(value(&v(Radix::Oct)), "0o100644");
        assert_eq!(value(&v(Radix::Bin)), "0b1000000110100100");
    }

    #[test]
    fn enum_names_may_be_computed() {
        assert_eq!(
            value(&Value::named(7, 8, format!("type {}", 7))),
            "type 7 (0x7)"
        );
        let table: crate::value::EnumTable = &[(1, "one")];
        assert_eq!(
            value(&crate::formats::util::val::enumv(1u8, 8, table)),
            "one (0x1)"
        );
    }

    #[test]
    fn value_stays_small() {
        assert!(std::mem::size_of::<Value>() <= 48);
    }
}
