//! Character encodings: byte order marks, sniffing, decoding, and
//! transcoding wide encodings into UTF-8 for the structured dissectors.

use std::borrow::Cow;

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::Result;
use crate::formats::Input;
use crate::node::Node;
use crate::span::{Origin, Span};
use crate::value::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Encoding {
    Utf8,
    /// 8-bit text that is not UTF-8: decoded as Windows-1252, the usual
    /// superset of ISO 8859-1.
    Windows1252,
    Utf16Le,
    Utf16Be,
    Utf32Le,
    Utf32Be,
}

impl Encoding {
    pub fn name(self) -> &'static str {
        match self {
            Encoding::Utf8 => "UTF-8",
            Encoding::Windows1252 => "Windows-1252",
            Encoding::Utf16Le => "UTF-16LE",
            Encoding::Utf16Be => "UTF-16BE",
            Encoding::Utf32Le => "UTF-32LE",
            Encoding::Utf32Be => "UTF-32BE",
        }
    }

    /// Bytes per code unit.
    pub fn unit(self) -> u64 {
        match self {
            Encoding::Utf8 | Encoding::Windows1252 => 1,
            Encoding::Utf16Le | Encoding::Utf16Be => 2,
            Encoding::Utf32Le | Encoding::Utf32Be => 4,
        }
    }

    /// Whether ASCII characters are single bytes (so byte-oriented parsers
    /// work directly on the source).
    pub fn ascii_compatible(self) -> bool {
        self.unit() == 1
    }

    /// The code unit at the start of `bytes`.
    pub fn code_unit(self, bytes: &[u8]) -> Option<u32> {
        use crate::bytes::{u16_be, u16_le, u32_be, u32_le};
        match self {
            Encoding::Utf8 | Encoding::Windows1252 => bytes.first().map(|&b| u32::from(b)),
            Encoding::Utf16Le => u16_le(bytes, 0).map(u32::from),
            Encoding::Utf16Be => u16_be(bytes, 0).map(u32::from),
            Encoding::Utf32Le => u32_le(bytes, 0),
            Encoding::Utf32Be => u32_be(bytes, 0),
        }
    }

    pub fn decode(self, bytes: &[u8]) -> String {
        match self {
            Encoding::Utf8 => decode_8bit(bytes),
            Encoding::Windows1252 => windows_1252(bytes),
            Encoding::Utf16Le => crate::text::utf16(bytes, crate::fields::Endian::Little),
            Encoding::Utf16Be => crate::text::utf16(bytes, crate::fields::Endian::Big),
            Encoding::Utf32Le | Encoding::Utf32Be => bytes
                .as_chunks::<4>()
                .0
                .iter()
                .map(|&b| {
                    let v = if self == Encoding::Utf32Le {
                        u32::from_le_bytes(b)
                    } else {
                        u32::from_be_bytes(b)
                    };
                    char::from_u32(v).unwrap_or(char::REPLACEMENT_CHARACTER)
                })
                .collect(),
        }
    }
}

/// The encoding announced by a byte order mark, and the mark's length.
pub fn bom(data: &[u8]) -> Option<(Encoding, u64)> {
    if data.starts_with(b"\xef\xbb\xbf") {
        Some((Encoding::Utf8, 3))
    } else if data.starts_with(b"\xff\xfe\0\0") {
        Some((Encoding::Utf32Le, 4))
    } else if data.starts_with(b"\0\0\xfe\xff") {
        Some((Encoding::Utf32Be, 4))
    } else if data.starts_with(b"\xff\xfe") {
        Some((Encoding::Utf16Le, 2))
    } else if data.starts_with(b"\xfe\xff") {
        Some((Encoding::Utf16Be, 2))
    } else {
        None
    }
}

/// UTF-16 without a byte order mark, recognised by mostly-ASCII text having
/// a zero byte in every other position.
pub fn sniff_utf16(data: &[u8]) -> Option<Encoding> {
    let sample = data.get(..data.len().min(512)).unwrap_or_default();
    let pairs = sample.as_chunks::<2>().0;
    if pairs.len() < 4 {
        return None;
    }
    let zero_hi = pairs.iter().filter(|p| p[1] == 0 && p[0] != 0).count();
    let zero_lo = pairs.iter().filter(|p| p[0] == 0 && p[1] != 0).count();
    let n = pairs.len();
    let mostly = |k: usize| k.saturating_mul(10) >= n.saturating_mul(9);
    let encoding = if mostly(zero_hi) {
        Encoding::Utf16Le
    } else if mostly(zero_lo) {
        Encoding::Utf16Be
    } else {
        return None;
    };
    let text = encoding.decode(sample);
    plausible_chars(&text).then_some(encoding)
}

fn plausible_chars(text: &str) -> bool {
    let control = text
        .chars()
        .filter(|&c| c.is_control() && !matches!(c, '\t' | '\n' | '\r' | '\x0c'))
        .count();
    control.saturating_mul(100) <= text.chars().count()
}

/// The encoding of text-like data, or `None` if it looks binary.
pub fn classify(data: &[u8]) -> Option<Encoding> {
    if let Some((encoding, len)) = bom(data) {
        let rest = data.get(to_usize(len)..).unwrap_or_default();
        return (rest.is_empty() || plausible_chars(&encoding.decode(rest))).then_some(encoding);
    }
    if let Some(encoding) = sniff_utf16(data) {
        return Some(encoding);
    }
    if crate::text::looks_like_text(data) {
        return Some(Encoding::Utf8);
    }
    // 8-bit legacy text: no NULs, few control characters, mostly ASCII.
    if data.is_empty() || data.contains(&0) {
        return None;
    }
    let control = data
        .iter()
        .filter(|&&b| (b < 0x20 && !matches!(b, b'\t' | b'\n' | b'\r' | 0x0c)) || b == 0x7f)
        .count();
    let high = data.iter().filter(|&&b| b >= 0x80).count();
    (control.saturating_mul(100) <= data.len() && high.saturating_mul(4) <= data.len())
        .then_some(Encoding::Windows1252)
}

/// Bytes as UTF-8 when valid, otherwise as Windows-1252 (so legacy text
/// keeps its accented letters instead of turning into replacement marks).
pub fn decode_8bit(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_owned(),
        // A character cut off at the end (a capped read) is still UTF-8.
        Err(e) if e.error_len().is_none() => {
            String::from_utf8_lossy(bytes.get(..e.valid_up_to()).unwrap_or_default()).into_owned()
        }
        Err(_) => windows_1252(bytes),
    }
}

/// Windows code page 1252.
pub fn windows_1252(bytes: &[u8]) -> String {
    const C1: [char; 32] = [
        '€', '\u{81}', '‚', 'ƒ', '„', '…', '†', '‡', 'ˆ', '‰', 'Š', '‹', 'Œ', '\u{8d}', 'Ž',
        '\u{8f}', '\u{90}', '‘', '’', '“', '”', '•', '–', '—', '˜', '™', 'š', '›', 'œ', '\u{9d}',
        'ž', 'Ÿ',
    ];
    bytes
        .iter()
        .map(|&b| match b {
            0x80..=0x9f => C1
                .get(usize::from(b & 0x1f))
                .copied()
                .unwrap_or(char::REPLACEMENT_CHARACTER),
            _ => char::from(b),
        })
        .collect()
}

/// A text input made ready for byte-oriented (ASCII-compatible) parsing.
#[derive(Clone, Copy, Debug)]
pub struct Prepared {
    /// The text after any byte order mark, in UTF-8 or another
    /// ASCII-compatible encoding. For UTF-16/32 input this is a derived,
    /// transcoded source.
    pub span: Span,
    pub encoding: Encoding,
    pub bom: Option<Span>,
}

impl Prepared {
    /// The prepared text as an input (for embedding).
    pub fn input(&self, input: Input) -> Input {
        if self.span.source == input.span.source {
            Input {
                span: self.span,
                ..input
            }
        } else {
            input.nested(self.span)
        }
    }

    /// A short note for annotations, e.g. `" (UTF-16LE)"`, empty for UTF-8.
    pub fn note(&self) -> String {
        match self.encoding {
            Encoding::Utf8 => String::new(),
            e => format!(" ({})", e.name()),
        }
    }
}

/// Detects the encoding of `input`, emits a node for its byte order mark,
/// and transcodes UTF-16/32 text into a derived UTF-8 source.
pub async fn prepare(cx: &Cx, input: Input) -> Result<Prepared> {
    let span = input.span;
    let head = cx.read_avail(span.sub(0, 512)).await?;
    let (encoding, bom_len) = match bom(&head) {
        Some(found) => found,
        None => match sniff_utf16(&head) {
            Some(e) => (e, 0),
            None => (Encoding::Utf8, 0),
        },
    };
    let bom = (bom_len > 0).then(|| span.sub(0, bom_len));
    if let Some(b) = bom {
        cx.emit(
            Node::new("Byte order mark")
                .span(b)
                .value(Value::Text(encoding.name().to_owned())),
        );
    }
    let body = span.tail(bom_len);
    if encoding.ascii_compatible() {
        return Ok(Prepared {
            span: body,
            encoding,
            bom,
        });
    }
    let transform = match encoding {
        Encoding::Utf16Le => "utf-16le",
        Encoding::Utf16Be => "utf-16be",
        Encoding::Utf32Le => "utf-32le",
        _ => "utf-32be",
    };
    let origin = Origin {
        parent: body,
        transform,
    };
    let decoded = match cx.derived(origin) {
        Some(found) => found,
        None => {
            let data = crate::codec::read_all(cx, body).await?;
            let text = encoding.decode(&data);
            let consumed = to_u64(data.len());
            cx.add_derived(origin, text.into_bytes(), consumed, None)?
        }
    };
    Ok(Prepared {
        span: decoded.span,
        encoding,
        bom,
    })
}

/// The head of a probe as UTF-8-compatible bytes: without a byte order
/// mark, and transcoded if it is UTF-16/32.
pub fn probe_text<'a>(data: &'a [u8]) -> Cow<'a, [u8]> {
    match bom(data) {
        Some((Encoding::Utf8, n)) => Cow::Borrowed(data.get(to_usize(n)..).unwrap_or_default()),
        Some((e, n)) => Cow::Owned(
            e.decode(data.get(to_usize(n)..).unwrap_or_default())
                .into_bytes(),
        ),
        None => match sniff_utf16(data) {
            Some(e) => Cow::Owned(e.decode(data).into_bytes()),
            None => Cow::Borrowed(data),
        },
    }
}
