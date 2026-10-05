//! Text-based formats.
//!
//! Everything here is built on a small shared toolkit:
//!
//! - [`scan`]: windowed byte access and line iteration over a region, so
//!   that no dissector ever reads a whole (possibly huge) text file at once;
//! - [`piece`]: in-memory slices that carry their spans, so tokens found in
//!   a line keep exact provenance;
//! - [`encoding`]: byte order marks, encoding sniffing, and transcoding of
//!   UTF-16/32 into a derived UTF-8 source for the structured parsers;
//! - [`decode`]: base64, quoted-printable, hex and uuencoding into derived
//!   sources, with the decoded content dissected in turn;
//! - [`probe`]: helpers for cheap, conservative probes.
//!
//! Formats register in the `text` section of [`crate::formats::FORMATS`],
//! which is probed last; the generic [`plain::FORMAT`] comes last of all.

use std::borrow::Cow;

use crate::node::Node;
use crate::span::Span;
use crate::value::Value;

pub mod decode;
pub mod encoding;
pub mod piece;
pub mod probe;
pub mod scan;

// pub mod csv;
// pub mod diff;
// pub mod ini;
// pub mod json;
// pub mod markdown;
// pub mod mime;
// pub mod misc;
// pub mod pem;
pub mod plain;
// pub mod playlist;
// pub mod plist;
// pub mod postscript;
// pub mod rtf;
// pub mod ssh;
// pub mod subtitles;
// pub mod toml;
// pub mod vcard;
// pub mod xml;
// pub mod yaml;

/// The most text a single value holds; longer text is cut (the node's span
/// still covers all of it).
pub const VALUE_CAP: usize = 4096;

/// A leaf holding `text`, capped at [`VALUE_CAP`] characters.
pub fn text_node(name: impl Into<Cow<'static, str>>, span: Span, text: &str) -> Node {
    let (value, cut) = decode::cap(text, VALUE_CAP);
    let node = Node::new(name).span(span).value(Value::Text(value));
    if cut {
        node.summary(format!("{} characters, truncated", text.chars().count()))
    } else {
        node
    }
}

/// An integer or floating-point value parsed from text, if it is one.
pub fn number(text: &str) -> Option<Value> {
    let t = text.trim();
    if t.is_empty() {
        return None;
    }
    if let Ok(v) = t.parse::<i64>() {
        return Some(Value::Int { value: v, bits: 64 });
    }
    if let Ok(v) = t.parse::<u64>() {
        return Some(Value::UInt {
            value: v,
            bits: 64,
            radix: crate::value::Radix::Dec,
        });
    }
    let numeric = t
        .bytes()
        .all(|b| b.is_ascii_digit() || matches!(b, b'.' | b'e' | b'E' | b'+' | b'-'));
    if numeric && t.bytes().any(|b| b.is_ascii_digit()) {
        return t.parse::<f64>().ok().map(Value::Float);
    }
    None
}

/// `n` with thousands separators, for summaries.
pub fn count(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len().saturating_add(digits.len() / 3));
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len().saturating_sub(i)) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// `"1 line"` / `"3 lines"`.
pub fn plural(n: u64, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{} {many}", count(n))
    }
}
