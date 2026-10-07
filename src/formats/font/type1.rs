//! The decrypted part of an Adobe Type 1 font: the private dictionary,
//! subroutines and charstrings (decrypted with the fixed `eexec` and
//! charstring keys).

use crate::bytes::to_u64;
use crate::codec::Codec;
use crate::codec::filters::type1_decrypt;
use crate::cx::Cx;
use crate::error::Result;
use crate::formats::Input;
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::Value;

/// A lazy node decrypting the `eexec` portion in `encrypted` (hex text in
/// PFA files, binary in PFB segments).
pub fn private_node(input: Input, encrypted: Span, hex: bool) -> Node {
    Node::new("Private dictionary")
        .span(encrypted)
        .desc("The eexec-encrypted part, decrypted with the fixed key 55665")
        .lazy(expand_private, (input, encrypted, hex))
}

fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n')
}

/// The position after `needle` in `data` (from `from`).
fn find(data: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    data.get(from..)?
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p.saturating_add(from).saturating_add(needle.len()))
}

/// The integer after `key` (e.g. `/lenIV 4`).
fn int_after(data: &[u8], key: &[u8]) -> Option<i64> {
    let at = find(data, key, 0)?;
    let rest = data.get(at..)?;
    let text: String = rest
        .iter()
        .skip_while(|&&b| is_space(b))
        .take_while(|&&b| b.is_ascii_digit() || b == b'-')
        .map(|&b| char::from(b))
        .collect();
    text.parse().ok()
}

/// Expands into the decrypted private dictionary (for nodes that already
/// describe the encrypted span).
pub async fn expand_private(cx: Cx, (input, encrypted, hex): (Input, Span, bool)) -> Result<()> {
    let decoded = crate::codec::decode_span(&cx, encrypted, &Codec::Eexec { hex }, None).await?;
    let data = crate::codec::read_all(&cx, decoded.span).await?;
    let len_iv = int_after(&data, b"/lenIV")
        .and_then(|n| usize::try_from(n).ok())
        .unwrap_or(4);
    // Cleartext entries of the private dictionary (before the binary parts).
    let head_end = find(&data, b"/Subrs", 0)
        .or_else(|| find(&data, b"/CharStrings", 0))
        .unwrap_or(data.len().min(4096));
    let head = String::from_utf8_lossy(data.get(..head_end).unwrap_or_default()).into_owned();
    for line in head.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix('/') {
            let (key, value) = rest.split_once(' ').unwrap_or((rest, ""));
            let value = value
                .trim()
                .trim_end_matches(" def")
                .trim_end_matches(" ND")
                .trim_end_matches(" |-")
                .trim();
            if !value.is_empty() && value.len() < 120 && !key.is_empty() {
                cx.emit(Node::new(key.to_owned()).value(Value::Text(value.to_owned())));
            }
        }
    }
    if let Some(n) = int_after(&data, b"/Subrs") {
        cx.emit(Node::new("Subrs").value(Value::Int { value: n, bits: 32 }));
    }
    if let Some(at) = find(&data, b"/CharStrings", 0) {
        let count = int_after(&data, b"/CharStrings").unwrap_or(0);
        cx.emit(
            Node::new("CharStrings")
                .span(decoded.span.tail(to_u64(at)))
                .summary(format!("{count} glyphs"))
                .lazy(charstrings, (decoded.span, at, len_iv)),
        );
    }
    cx.emit(
        Node::new("Decrypted program")
            .span(decoded.span)
            .summary(format!("{} bytes", decoded.span.len)),
    );
    let _ = input;
    cx.annotate(format!("{} bytes decrypted", decoded.span.len));
    Ok(())
}

/// `/name len RD <len bytes> ND` entries after `/CharStrings`.
async fn charstrings(cx: Cx, (program, start, len_iv): (Span, usize, usize)) -> Result<()> {
    let data = crate::codec::read_all(&cx, program).await?;
    let mut pos = find(&data, b"begin", start).unwrap_or(start);
    let mut n = 0u64;
    loop {
        cx.checkpoint().await;
        while data.get(pos).is_some_and(|&b| is_space(b)) {
            pos = pos.saturating_add(1);
        }
        if data.get(pos) != Some(&b'/') {
            break;
        }
        let name_start = pos.saturating_add(1);
        let name_end = data
            .get(name_start..)
            .and_then(|r| r.iter().position(|&b| is_space(b)))
            .map_or(data.len(), |p| p.saturating_add(name_start));
        let name = String::from_utf8_lossy(data.get(name_start..name_end).unwrap_or_default())
            .into_owned();
        let rest = data.get(name_end..).unwrap_or_default();
        let digits: Vec<u8> = rest
            .iter()
            .copied()
            .skip_while(|&b| is_space(b))
            .take_while(u8::is_ascii_digit)
            .collect();
        let Ok(len) = String::from_utf8_lossy(&digits).parse::<usize>() else {
            break;
        };
        // Skip the length, one space, the RD token and one space.
        let after_len = name_end
            .saturating_add(rest.iter().take_while(|&&b| is_space(b)).count())
            .saturating_add(digits.len());
        let token_start = after_len.saturating_add(1);
        let token_end = data
            .get(token_start..)
            .and_then(|r| r.iter().position(|&b| is_space(b)))
            .map_or(data.len(), |p| p.saturating_add(token_start));
        let body = token_end.saturating_add(1);
        let Some(bytes) = data.get(body..body.saturating_add(len)) else {
            break;
        };
        let decrypted = type1_decrypt(bytes, 4330, len_iv);
        cx.push(
            Node::new(name)
                .span(program.sub(to_u64(body), to_u64(len)))
                .summary(format!("{} bytes of Type 1 charstring", decrypted.len()))
                .value(Value::Bytes(decrypted.into_iter().take(32).collect())),
        )
        .await;
        n = n.saturating_add(1);
        // Skip the ND / |- token.
        pos = body.saturating_add(len);
        while data.get(pos).is_some_and(|&b| is_space(b)) {
            pos = pos.saturating_add(1);
        }
        while data.get(pos).is_some_and(|&b| !is_space(b) && b != b'/') {
            pos = pos.saturating_add(1);
        }
    }
    cx.set_count(Count::Exact(n));
    Ok(())
}
