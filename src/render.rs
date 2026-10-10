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
        Value::UInt {
            value,
            radix: Radix::Hex,
            ..
        } => format!("{value:#x}"),
        Value::UInt { value, .. } => value.to_string(),
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
        Value::Float(f) => float(*f),
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
#[allow(clippy::arithmetic_side_effects)] // i128 cannot overflow for i64 input
fn timestamp(unix_seconds: i64) -> String {
    let secs = i128::from(unix_seconds);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i128::from(month <= 2);
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

/// A float as Rust prints it (shortest round-trip form), switching to
/// exponent notation for very large or very small magnitudes, which `{}`
/// would spell out with hundreds of digits.
fn float(f: f64) -> String {
    let a = f.abs();
    if a != 0.0 && a.is_finite() && !(1e-6..1e21).contains(&a) {
        format!("{f:e}")
    } else {
        format!("{f}")
    }
}
