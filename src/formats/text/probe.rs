//! Helpers for cheap, conservative text probes over a [`Head`].

use std::borrow::Cow;

use crate::formats::Head;

use super::encoding;

/// The head as ASCII-compatible text (BOM removed, UTF-16/32 transcoded).
pub fn head<'a>(h: &'a Head<'_>) -> Cow<'a, [u8]> {
    encoding::probe_text(h.data)
}

/// Whether the head looks like text in any supported encoding.
pub fn is_text(h: &Head<'_>) -> bool {
    encoding::classify(h.data).is_some()
}

/// `data` without leading ASCII whitespace.
pub fn trim_start(data: &[u8]) -> &[u8] {
    let n = data.iter().take_while(|b| b.is_ascii_whitespace()).count();
    data.get(n..).unwrap_or_default()
}

pub fn trim(data: &[u8]) -> &[u8] {
    let data = trim_start(data);
    let n = data
        .iter()
        .rev()
        .take_while(|b| b.is_ascii_whitespace())
        .count();
    data.get(..data.len().saturating_sub(n)).unwrap_or_default()
}

/// Lines of `data` (split at `\n`, without a trailing `\r`).
pub fn lines(data: &[u8]) -> impl Iterator<Item = &[u8]> {
    data.split(|&b| b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
}

/// Non-blank lines that do not start (after indentation) with any of
/// `comments`.
pub fn significant<'a>(
    data: &'a [u8],
    comments: &'a [&'a [u8]],
) -> impl Iterator<Item = &'a [u8]> {
    lines(data).filter(move |l| {
        let t = trim_start(l);
        !t.is_empty() && !comments.iter().any(|c| t.starts_with(c))
    })
}

pub fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

pub fn contains(hay: &[u8], needle: &[u8]) -> bool {
    find(hay, needle).is_some()
}

pub fn find_nocase(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    hay.windows(needle.len())
        .position(|w| w.eq_ignore_ascii_case(needle))
}

pub fn starts_with_nocase(hay: &[u8], prefix: &[u8]) -> bool {
    hay.get(..prefix.len())
        .is_some_and(|p| p.eq_ignore_ascii_case(prefix))
}

/// Whether the head covers the whole input (so its last line is complete).
pub fn complete(h: &Head<'_>) -> bool {
    crate::bytes::to_u64(h.data.len()) >= h.len
}
