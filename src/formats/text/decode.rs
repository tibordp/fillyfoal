//! Transfer encodings found inside text: base64, quoted-printable, hex,
//! uuencoding. Each decoder is tolerant and reports where it stopped.

use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::Input;
use crate::node::Node;
use crate::span::{Origin, Span};

/// The result of decoding: bytes, and the first problem, if any.
pub struct Decoded {
    pub bytes: Vec<u8>,
    pub error: Option<String>,
}

fn base64_value(b: u8) -> Option<u32> {
    match b {
        b'A'..=b'Z' => Some(u32::from(b.saturating_sub(b'A'))),
        b'a'..=b'z' => Some(u32::from(b.saturating_sub(b'a')).saturating_add(26)),
        b'0'..=b'9' => Some(u32::from(b.saturating_sub(b'0')).saturating_add(52)),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}

/// Base64 (standard or URL-safe alphabet), ignoring whitespace. Stops at
/// padding or at the first invalid character.
pub fn base64(data: &[u8]) -> Decoded {
    let mut bytes = Vec::with_capacity((data.len() / 4).saturating_mul(3));
    let mut acc = 0u32;
    let mut bits = 0u32;
    let mut error = None;
    for (i, &b) in data.iter().enumerate() {
        if b.is_ascii_whitespace() {
            continue;
        }
        if b == b'=' {
            break;
        }
        let Some(v) = base64_value(b) else {
            error = Some(format!(
                "invalid base64 character {:?} at {i}",
                char::from(b)
            ));
            break;
        };
        acc = (acc << 6 | v) & 0x00ff_ffff;
        bits = bits.saturating_add(6);
        if bits >= 8 {
            bits = bits.saturating_sub(8);
            bytes.push(((acc >> bits) & 0xff) as u8);
        }
    }
    Decoded { bytes, error }
}

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b.saturating_sub(b'0')),
        b'a'..=b'f' => Some(b.saturating_sub(b'a').saturating_add(10)),
        b'A'..=b'F' => Some(b.saturating_sub(b'A').saturating_add(10)),
        _ => None,
    }
}

/// Hex digit pairs, ignoring whitespace and (optionally) commas.
pub fn hex(data: &[u8]) -> Decoded {
    let mut bytes = Vec::with_capacity(data.len() / 2);
    let mut high: Option<u8> = None;
    let mut error = None;
    for (i, &b) in data.iter().enumerate() {
        if b.is_ascii_whitespace() || b == b',' || b == b'\\' {
            continue;
        }
        let Some(v) = hex_value(b) else {
            error = Some(format!("invalid hex digit {:?} at {i}", char::from(b)));
            break;
        };
        match high.take() {
            Some(h) => bytes.push(h << 4 | v),
            None => high = Some(v),
        }
    }
    if high.is_some() && error.is_none() {
        error = Some("odd number of hex digits".to_owned());
    }
    Decoded { bytes, error }
}

/// Quoted-printable (RFC 2045): `=XX` escapes and `=` soft line breaks.
pub fn quoted_printable(data: &[u8]) -> Decoded {
    let mut bytes = Vec::with_capacity(data.len());
    let mut i = 0usize;
    while let Some(&b) = data.get(i) {
        i = i.saturating_add(1);
        if b != b'=' {
            bytes.push(b);
            continue;
        }
        match (data.get(i).copied(), data.get(i.saturating_add(1)).copied()) {
            (Some(b'\r'), Some(b'\n')) => i = i.saturating_add(2),
            (Some(b'\n'), _) => i = i.saturating_add(1),
            (Some(h), Some(l)) => match (hex_value(h), hex_value(l)) {
                (Some(h), Some(l)) => {
                    bytes.push(h << 4 | l);
                    i = i.saturating_add(2);
                }
                _ => bytes.push(b'='),
            },
            _ => bytes.push(b'='),
        }
    }
    Decoded { bytes, error: None }
}

/// One line of uuencoded data (the first character encodes the length).
pub fn uu_line(line: &[u8], out: &mut Vec<u8>) -> bool {
    let dec = |b: u8| b.wrapping_sub(0x20) & 0x3f;
    let Some(&first) = line.first() else {
        return false;
    };
    let len = usize::from(dec(first));
    let body = line.get(1..).unwrap_or_default();
    let mut produced = 0usize;
    for group in body.chunks(4) {
        let c = |i: usize| group.get(i).map_or(0, |&b| dec(b));
        let triple = [
            c(0) << 2 | c(1) >> 4,
            (c(1) & 0x0f) << 4 | c(2) >> 2,
            (c(2) & 0x03) << 6 | c(3),
        ];
        for b in triple {
            if produced < len {
                out.push(b);
                produced = produced.saturating_add(1);
            }
        }
    }
    produced == len
}

/// Decodes `span` with `decode` into a derived source (reusing it if it was
/// decoded before), returning its span and any decoding problem.
pub async fn derive(
    cx: &Cx,
    span: Span,
    transform: &'static str,
    decode: impl Fn(&[u8]) -> Decoded,
) -> Result<(Span, Option<Diagnostic>)> {
    let origin = Origin {
        parent: span,
        transform,
    };
    if let Some(found) = cx.derived(origin) {
        return Ok((found.span, found.error));
    }
    let data = crate::codec::read_all(cx, span).await?;
    let decoded = decode(&data);
    let error = decoded
        .error
        .map(|e| Diagnostic::malformed(format!("{transform}: {e}")).at(span));
    let consumed = crate::bytes::to_u64(data.len());
    let out = cx.add_derived(origin, decoded.bytes, consumed, error.clone())?;
    Ok((out.span, error))
}

/// A node for content transfer-encoded in `span`: decoded on expansion into
/// a derived source, then identified and dissected (or shown as data).
pub fn decoded_node(
    name: impl Into<std::borrow::Cow<'static, str>>,
    input: Input,
    span: Span,
    transform: Transform,
) -> Node {
    Node::new(name)
        .span(span)
        .lazy(expand_decoded, (input, span, transform))
}

/// The transfer encodings [`decoded_node`] understands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transform {
    Base64,
    QuotedPrintable,
    Hex,
    Identity,
}

impl Transform {
    pub fn name(self) -> &'static str {
        match self {
            Transform::Base64 => "base64",
            Transform::QuotedPrintable => "quoted-printable",
            Transform::Hex => "hex",
            Transform::Identity => "identity",
        }
    }

    pub fn decode(self, data: &[u8]) -> Decoded {
        match self {
            Transform::Base64 => base64(data),
            Transform::QuotedPrintable => quoted_printable(data),
            Transform::Hex => hex(data),
            Transform::Identity => Decoded {
                bytes: data.to_vec(),
                error: None,
            },
        }
    }
}

/// Decodes `span` with `transform` into a derived source.
pub async fn derive_with(
    cx: &Cx,
    span: Span,
    transform: Transform,
) -> Result<(Span, Option<Diagnostic>)> {
    if transform == Transform::Identity {
        return Ok((span, None));
    }
    derive(cx, span, transform.name(), |d| transform.decode(d)).await
}

async fn expand_decoded(cx: Cx, (input, span, transform): (Input, Span, Transform)) -> Result<()> {
    let (decoded, error) = derive_with(&cx, span, transform).await?;
    if let Some(e) = error {
        cx.diag(e);
    }
    if transform != Transform::Identity {
        cx.annotate(format!("{:#x} bytes decoded", decoded.len));
    }
    crate::formats::dissect_or_data(cx, input.nested(decoded)).await
}

/// Value-sized text: the first `max` characters, and whether any were cut.
pub fn cap(text: &str, max: usize) -> (String, bool) {
    match text.char_indices().nth(max) {
        Some((i, _)) => (text.get(..i).unwrap_or_default().to_owned(), true),
        None => (text.to_owned(), false),
    }
}

/// A one-line preview of `text` for summaries.
pub fn preview(text: &str, max: usize) -> String {
    let one_line: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let trimmed = one_line.trim();
    match cap(trimmed, max) {
        (s, true) => format!("{s}…"),
        (s, false) => s,
    }
}
