//! Text-based formats.
//!
//! Everything here is built on a small shared toolkit:
//!
//! - [`scan`]: windowed byte access and line iteration over a region, so
//!   that no dissector ever reads a whole (possibly huge) text file at once;
//! - [`piece`]: in-memory slices that carry their spans, so tokens found in
//!   a line keep exact provenance;
//! - [`encoding`]: byte order marks, encoding sniffing, declared encodings
//!   (XML declarations, `<meta charset>`, coding comments), and transcoding
//!   of UTF-16/32 and declared legacy code pages into a derived UTF-8 source
//!   for the structured parsers;
//! - [`decode`]: base64, quoted-printable, hex, percent-encoding and
//!   uu/xxencoding into derived sources, with the decoded content dissected
//!   in turn (yEnc lives in [`yenc`]);
//! - [`probe`]: helpers for cheap, conservative probes.
//!
//! Formats register in the `text` section of `crate::formats::FORMATS`,
//! which is probed last; the generic [`plain::FORMAT`] comes last of all.

use std::borrow::Cow;

use crate::node::Node;
use crate::span::Span;
use crate::value::{Res, Time, Value, Zone};

pub mod decode;
pub mod encoding;
pub mod piece;
pub mod probe;
pub mod scan;

pub mod bibtex;
pub mod checksums;
pub mod csv;
pub mod diff;
pub mod dockerfile;
pub mod dot;
pub mod html;
pub mod ini;
pub mod json;
pub mod klc;
pub mod ldif;
pub mod markdown;
pub mod mime;
pub mod obj;
pub mod pem;
pub mod plain;
pub mod playlist;
pub mod plist;
pub mod po;
pub mod postscript;
pub mod rtf;
pub mod sln;
pub mod ssh;
pub mod stanza;
pub mod subtitles;
pub mod toml;
pub mod uuencode;
pub mod vcard;
pub mod xml;
pub mod yaml;
pub mod yenc;

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
        return t.parse::<f64>().ok().map(Value::f64);
    }
    None
}

/// `n` with thousands separators, for summaries.
pub fn count(n: u64) -> String {
    crate::formats::util::fmt::grouped(n)
}

/// Parses an ISO 8601 / RFC 3339 date or date-time (`2024-01-31`,
/// `2024-01-31T12:00:00Z`, `2024-01-31 12:00:00.5+01:00`) or the basic form
/// used by iCalendar (`20240131T120000Z`) into Unix seconds. Times without a
/// zone are read as if UTC.
pub fn parse_datetime(text: &str) -> Option<i64> {
    parse_time(text).map(|t| t.secs)
}

/// [`parse_datetime`] as the text records it: a date alone is
/// [`Res::Day`](crate::value::Res), a clock without seconds a minute, a
/// fraction is kept (to nine digits); `Z` is UTC, `+hh:mm` an offset, and a
/// time with no zone is a local (floating) time.
pub fn parse_time(text: &str) -> Option<Time> {
    let t = text.trim();
    let digits = |s: &str| -> Option<i64> {
        (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .then(|| s.parse().ok())
            .flatten()
    };
    let (date, time) = match t.find(['T', 't', ' ']) {
        Some(i) => (t.get(..i)?, t.get(i.saturating_add(1)..)?),
        None => (t, ""),
    };
    let (y, m, d) = if date.len() == 8 && !date.contains('-') {
        (
            digits(date.get(..4)?)?,
            digits(date.get(4..6)?)?,
            digits(date.get(6..8)?)?,
        )
    } else {
        let mut parts = date.split('-');
        let y = digits(parts.next()?)?;
        let m = parts.next().map_or(Some(1), digits)?;
        let d = parts.next().map_or(Some(1), digits)?;
        (y, m, d)
    };
    if !(0..=9999).contains(&y) || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    // Split off the zone: `Z`, `+hh:mm`, `-hhmm`.
    let (clock, zone) = match time.find(['Z', 'z', '+', '-']) {
        Some(i) => {
            let zone = time.get(i..)?;
            let z: String = zone.chars().filter(char::is_ascii_digit).collect();
            let hours = z.get(..2).and_then(digits).unwrap_or(0);
            let minutes = z.get(2..4).and_then(digits).unwrap_or(0);
            if hours > 23 || minutes > 59 {
                return None;
            }
            let east = i16::try_from(hours.saturating_mul(60).saturating_add(minutes)).ok()?;
            let zone = if zone.starts_with(['Z', 'z']) {
                Zone::Utc
            } else if zone.starts_with('-') {
                Zone::Offset(east.saturating_neg())
            } else {
                Zone::Offset(east)
            };
            (time.get(..i)?, zone)
        }
        None => (time, Zone::Local),
    };
    let (clock, frac) = match clock.split_once('.') {
        Some((c, f)) => (c, Some(f)),
        None => (clock, None),
    };
    let (h, min, s, res) = if clock.is_empty() {
        (0, 0, 0, Res::Day)
    } else if !clock.contains(':') {
        let part = |a: usize, b: usize| clock.get(a..b).map_or(Some(0), digits);
        let res = if clock.len() <= 4 {
            Res::Minute
        } else {
            Res::Second
        };
        (part(0, 2)?, part(2, 4)?, part(4, 6)?, res)
    } else {
        let mut parts = clock.split(':');
        let h = digits(parts.next()?)?;
        let min = parts.next().map_or(Some(0), digits)?;
        let (s, res) = match parts.next() {
            Some(p) => (digits(p)?, Res::Second),
            None => (0, Res::Minute),
        };
        (h, min, s, res)
    };
    if h > 24 || min > 59 || s > 60 {
        return None;
    }
    let u32_of = |v: i64| u32::try_from(v).ok();
    let wall = crate::formats::util::civil::civil_to_unix(
        y,
        u32_of(m)?,
        u32_of(d)?,
        u32_of(h)?,
        u32_of(min)?,
        u32_of(s)?,
    );
    let mut out = match zone {
        Zone::Offset(minutes) => Time::offset_wall(wall, minutes),
        Zone::Utc => Time::utc(wall),
        _ => Time::local(wall),
    };
    out.res = res;
    if let Some(f) = frac.filter(|f| !f.is_empty() && f.bytes().all(|b| b.is_ascii_digit())) {
        let kept = f.get(..9).unwrap_or(f);
        let width = u32::try_from(kept.len()).unwrap_or(9);
        let nanos = u32::try_from(digits(kept)?)
            .ok()?
            .saturating_mul(10u32.checked_pow(9u32.saturating_sub(width)).unwrap_or(1));
        out = out.frac(nanos, u8::try_from(width).unwrap_or(9));
    }
    Some(out)
}

/// `"1 line"` / `"3 lines"`, with thousands separators.
pub fn plural(n: u64, one: &str, many: &str) -> String {
    crate::formats::util::fmt::grouped_count(n, one, many)
}
