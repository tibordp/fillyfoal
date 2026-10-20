//! Bare base64 files: nothing but base64 (standard or URL-safe alphabet),
//! on one line or wrapped at a fixed width (`base64`, `openssl base64`), as
//! saved from a mail part, an API response or a clipboard.
//!
//! The decoded data is dissected in turn, decoded on demand. When every
//! line but the last has the same length, a multiple of four characters,
//! the decoded size follows from the file's length and where its last line
//! starts, and any line can start a decoder: reads far into the data
//! decode from the nearest such point rather than from the start.

use crate::bytes::{to_u64, to_usize};
use crate::codec::Codec;
use crate::cx::{Cx, Seed};
use crate::error::Result;
use crate::formats::util::fmt::size;
use crate::formats::{Format, HEAD_LEN, Head, Input, Probe, TAIL_LEN, dissect_or_data};
use crate::node::Node;

use super::plural;

pub static FORMAT: Format = Format {
    name: "base64",
    title: "Base64-encoded data",
    extensions: &["b64", "base64"],
    mime: "application/base64",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

/// The fewest characters a file needs to be taken for base64.
const MIN_CHARS: u64 = 16;
/// The narrowest wrapped line accepted.
const MIN_LINE: u64 = 16;
/// Decoded bytes between seeds, at least, and the most seeds made.
const SEED_STRIDE: u64 = 256 * 1024;
const MAX_SEEDS: u64 = 4096;

/// How a well-formed file is laid out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Geometry {
    /// Characters per full line, or 0 if the data is a single line.
    line: u64,
    /// Bytes ending each full line: 1 (LF) or 2 (CRLF).
    newline: u64,
    /// Full lines, each `line` characters and a newline.
    lines: u64,
    /// Characters on the last line.
    last: u64,
    /// The size of the decoded data.
    decoded: u64,
}

fn is_alphabet(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'-' | b'_')
}

/// Whether `data` holds only base64 characters and line breaks, with
/// padding only at the very end, and one alphabet (standard or URL-safe).
fn clean(data: &[u8]) -> bool {
    let mut padded = false;
    let (mut standard, mut url) = (false, false);
    for &b in data {
        match b {
            b'\r' | b'\n' => {}
            b'=' => padded = true,
            _ if padded => return false,
            b'+' | b'/' => standard = true,
            b'-' | b'_' => url = true,
            _ if is_alphabet(b) => {}
            _ => return false,
        }
    }
    !(standard && url)
}

/// The line breaks at the end of `data`.
fn trailing_breaks(data: &[u8]) -> u64 {
    to_u64(
        data.iter()
            .rev()
            .take_while(|&&b| b == b'\r' || b == b'\n')
            .count(),
    )
}

/// Works out the layout from the first and last bytes of a file of `len`
/// bytes (`head` is the whole file if it is short): `None` unless every
/// line but the last has the same length, a multiple of four.
fn geometry(head: &[u8], tail: &[u8], len: u64) -> Option<Geometry> {
    let whole = to_u64(head.len()) >= len;
    let tail = if whole { head } else { tail };
    if !clean(head) || !clean(tail) {
        return None;
    }
    // Where the data ends, before any final line break.
    let end = len.checked_sub(trailing_breaks(tail))?;
    let tail_at = len.saturating_sub(to_u64(tail.len()));
    let first_break = head.iter().position(|&b| b == b'\n');
    let (line, newline) = match first_break {
        Some(p) if to_u64(p) < end => {
            let crlf = p > 0 && head.get(p.saturating_sub(1)) == Some(&b'\r');
            let newline = if crlf { 2u64 } else { 1 };
            (to_u64(p).saturating_sub(newline.saturating_sub(1)), newline)
        }
        // One line: no break before the end.
        _ => (0, 0),
    };
    if line == 0 {
        // No break before the end, near the end either.
        let body = tail.get(..tail.len().saturating_sub(to_usize(trailing_breaks(tail))))?;
        if body.contains(&b'\n') {
            return None;
        }
        let chars = end;
        return Some(Geometry {
            line: 0,
            newline: 0,
            lines: 0,
            last: chars,
            decoded: decoded_len(chars, tail)?,
        });
    }
    if line < MIN_LINE || line % 4 != 0 {
        return None;
    }
    let stride = line.saturating_add(newline);
    let br: &[u8] = if newline == 2 { b"\r\n" } else { b"\n" };
    // Every full line in the head has the same length and line break.
    let mut at = 0u64;
    while at.saturating_add(stride) <= to_u64(head.len()) && at.saturating_add(stride) <= end {
        let l = head.get(to_usize(at)..to_usize(at.saturating_add(stride)))?;
        let (chars, rest) = l.split_at_checked(to_usize(line))?;
        if rest != br || chars.iter().any(|&b| b == b'\r' || b == b'\n') {
            return None;
        }
        at = at.saturating_add(stride);
    }
    // The last line starts after the last break before the end, at a
    // whole number of full lines.
    let in_tail = to_usize(end.saturating_sub(tail_at));
    let last_break = tail.get(..in_tail)?.iter().rposition(|&b| b == b'\n')?;
    let start = tail_at.saturating_add(to_u64(last_break)).saturating_add(1);
    if !start.is_multiple_of(stride) {
        return None;
    }
    let last = end.saturating_sub(start);
    if last == 0 || last > line {
        return None;
    }
    let lines = start.checked_div(stride)?;
    let chars = lines.saturating_mul(line).saturating_add(last);
    Some(Geometry {
        line,
        newline,
        lines,
        last,
        decoded: decoded_len(chars, tail)?,
    })
}

/// The bytes `chars` base64 characters decode to, given the padding at the
/// end of `tail`.
fn decoded_len(chars: u64, tail: &[u8]) -> Option<u64> {
    let body = tail.get(..tail.len().saturating_sub(to_usize(trailing_breaks(tail))))?;
    let padding = to_u64(body.iter().rev().take_while(|&&b| b == b'=').count());
    if padding > 2 {
        return None;
    }
    let data = chars.checked_sub(padding)?;
    let extra = match data % 4 {
        0 => 0,
        2 => 1,
        3 => 2,
        _ => return None,
    };
    (data / 4).checked_mul(3)?.checked_add(extra)
}

/// The fewest characters an unpadded single line needs: shorter ones are
/// as likely tokens or identifiers (`MotionPhoto_Data`).
const MIN_BARE_LINE: u64 = 32;

fn probe(h: &Head<'_>) -> bool {
    if h.len_known && h.len < MIN_CHARS {
        return false;
    }
    // With an unknown length (content decoded on demand), the head alone:
    // taken as the whole data, cut at its last line break.
    let (layout, end) = if h.len_known {
        (geometry(h.data, h.tail, h.len), h.tail)
    } else {
        let cut = h
            .data
            .iter()
            .rposition(|&b| b == b'\n')
            .map_or(h.data, |p| h.data.get(..=p).unwrap_or(h.data));
        (geometry(cut, cut, to_u64(cut.len())), cut)
    };
    let Some(g) = layout else {
        return false;
    };
    let chars = g.lines.saturating_mul(g.line).saturating_add(g.last);
    let padded = end.iter().rev().find(|b| !b.is_ascii_whitespace()) == Some(&b'=');
    if chars < MIN_CHARS || (g.line == 0 && !padded && chars < MIN_BARE_LINE) {
        return false;
    }
    // Base64 of almost anything mixes cases and digits; words, hex strings
    // and identifiers mostly do not.
    let has = |f: fn(&u8) -> bool| h.data.iter().any(f);
    has(u8::is_ascii_uppercase) && has(u8::is_ascii_lowercase) && has(u8::is_ascii_digit)
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let span = input.span;
    // Without a known length (and a cheap end), decoded from the start
    // with the size found at the end.
    let g = if cx.len_known(span.source) && cx.tail_is_cheap(span.source) {
        let head = cx.read_avail(span.sub(0, HEAD_LEN)).await?;
        let tail = cx
            .read_avail(span.tail(span.len.saturating_sub(TAIL_LEN)))
            .await?;
        geometry(&head, &tail, span.len)
    } else {
        None
    };
    match g {
        Some(g) if g.line > 0 => cx.annotate(format!(
            "{} of {} characters, {} decoded",
            plural(g.lines.saturating_add(1), "line", "lines"),
            g.line,
            size(g.decoded)
        )),
        Some(g) => cx.annotate(format!("one line, {} decoded", size(g.decoded))),
        None => cx.annotate("decoded from the start"),
    }
    cx.emit(Node::new("Decoded").span(span).lazy(decoded, (input, g)));
    Ok(())
}

/// The decoded data, dissected: of a known size and seeded at line starts
/// when the layout is regular, otherwise decoded from the start with its
/// size found at the end.
async fn decoded(cx: Cx, (input, g): (Input, Option<Geometry>)) -> Result<()> {
    let span = input.span;
    let data = match g {
        Some(g) => {
            let seeds = seeds(&g);
            cx.annotate(format!("{}, decoded on demand", size(g.decoded)));
            cx.decode_lazy_seeded(span, &Codec::Base64, g.decoded, seeds)?
        }
        None => cx.decode_lazy_unsized(span, &Codec::Base64)?,
    };
    dissect_or_data(cx, input.nested(data)).await
}

/// Points decoding can start at: line starts (or, on one line, every four
/// characters), at least [`SEED_STRIDE`] decoded bytes apart.
fn seeds(g: &Geometry) -> Vec<Seed> {
    // One unit: a full line, or a group of four characters.
    let (unit_in, unit_out, units) = if g.line > 0 {
        (
            g.line.saturating_add(g.newline),
            (g.line >> 2).saturating_mul(3),
            g.lines,
        )
    } else {
        (4, 3, g.last / 4)
    };
    if unit_out == 0 {
        return Vec::new();
    }
    let per_seed = SEED_STRIDE
        .div_ceil(unit_out)
        .max(units.div_ceil(MAX_SEEDS))
        .max(1);
    let mut out = Vec::new();
    let mut k = per_seed;
    while k < units {
        if let Some(decoder) = Codec::Base64.decoder() {
            out.push(Seed {
                out_pos: k.saturating_mul(unit_out),
                in_pos: k.saturating_mul(unit_in),
                decoder,
            });
        }
        k = k.saturating_add(per_seed);
    }
    out
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    fn g(data: &[u8]) -> Option<Geometry> {
        geometry(data, data, to_u64(data.len()))
    }

    #[test]
    fn wrapped_lines_give_the_decoded_size() {
        // 100 bytes: 136 characters (two padding), wrapped at 64.
        let mut text = Vec::new();
        let chars: Vec<u8> = (0..134).map(|i| b"QUJDabc1"[i % 8]).collect();
        for (i, c) in chars.iter().enumerate() {
            text.push(*c);
            if i % 64 == 63 {
                text.push(b'\n');
            }
        }
        text.extend(b"==\n");
        let geo = g(&text).unwrap();
        assert_eq!((geo.line, geo.lines, geo.last), (64, 2, 8));
        assert_eq!(geo.decoded, 100);
    }

    #[test]
    fn crlf_and_unpadded_single_lines() {
        let text = b"SGVsbG8sIFdvcmxkIQ\r\n";
        let geo = g(text).unwrap();
        assert_eq!((geo.line, geo.last, geo.decoded), (0, 18, 13));
        let wrapped = b"QUJDREVGR0hJSktMTU5PUA==\r\nQUI=\r\n";
        assert!(g(wrapped).is_none(), "first line is not a multiple of 4");
        let wrapped = b"QUJDREVGR0hJSktMTU5PUFFSU1RV\r\nQUI=\r\n";
        let geo = g(wrapped).unwrap();
        assert_eq!((geo.line, geo.newline, geo.lines, geo.last), (28, 2, 1, 4));
    }

    #[test]
    fn ragged_lines_and_strangers_are_refused() {
        assert!(g(b"QUJDREVGR0hJSktMTU5P\nQUJDREVGR0hJSktM\nQUJD\n").is_none());
        assert!(g(b"QUJD=REVG").is_none());
        assert!(g(b"QUJD REVG").is_none());
        assert!(g(b"ab+c-_de").is_none());
    }
}
