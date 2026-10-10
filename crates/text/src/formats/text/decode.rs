//! Transfer encodings found inside text: base64, quoted-printable, hex,
//! percent-encoding, uu- and xxencoding, and `data:` URLs. Each decoder is
//! tolerant and reports where it stopped.
//!
//! The decoders are the codec crate's ([`filters::Base64`],
//! [`filters::QuotedPrintable`], [`filters::UuLines`], [`filters::YEnc`]):
//! spans are decoded with [`derive_codec`] into evictable derived sources
//! (decoded again on demand), and in-memory buffers with [`base64`] and
//! [`quoted_printable`].

use crate::codec::Codec;
use crate::codec::charset::Label;
use crate::codec::filters::{self, ByteFilter};
use crate::cx::Cx;
use crate::error::{DiagKind, Diagnostic, Result};
use crate::formats::Input;
use crate::node::Node;
use crate::span::{Origin, Span};
use crate::text::hex_digit;

use super::encoding::Encoding;

pub use crate::codec::filters::{XX_ALPHABET, xx_value};
pub use crate::formats::util::fmt::preview;

/// The result of decoding: bytes, and the first problem, if any.
pub struct Decoded {
    pub bytes: Vec<u8>,
    pub error: Option<String>,
}

/// A decoder that works through an in-memory buffer a bounded step at a
/// time, so that a large body can be decoded between checkpoints.
trait Step: Send {
    /// Decodes about `limit` more input bytes of `data` (always the same
    /// buffer); returns whether the decoder is done.
    fn step(&mut self, data: &[u8], limit: usize) -> bool;
    fn finish(self) -> Decoded;
}

/// Runs `s` over all of `data` at once.
fn run<S: Step>(mut s: S, data: &[u8]) -> Decoded {
    while !s.step(data, usize::MAX) {}
    s.finish()
}

/// Input bytes a stepped decoder works through between checkpoints.
const STEP: usize = 64 * 1024;

/// A codec's [`ByteFilter`] over an in-memory buffer: it stops at the
/// first error (keeping what was decoded before it) and remembers where.
struct Filtered<F> {
    filter: F,
    pos: usize,
    bytes: Vec<u8>,
    error: Option<String>,
    /// The offset of the byte the filter failed on.
    bad: Option<usize>,
}

impl<F: ByteFilter> Filtered<F> {
    fn new(filter: F, capacity: usize) -> Self {
        Filtered {
            filter,
            pos: 0,
            bytes: Vec::with_capacity(capacity),
            error: None,
            bad: None,
        }
    }
}

impl<F: ByteFilter + Send> Step for Filtered<F> {
    fn step(&mut self, data: &[u8], limit: usize) -> bool {
        let end = self.pos.saturating_add(limit).min(data.len());
        while self.pos < end {
            let i = self.pos;
            let Some(&b) = data.get(i) else { break };
            self.pos = i.saturating_add(1);
            match self.filter.byte(b, &mut self.bytes) {
                Ok(true) => {}
                Ok(false) => {
                    // The end-of-data marker: the rest is ignored.
                    self.pos = data.len();
                }
                Err(e) => {
                    self.error = Some(e.message);
                    self.bad = Some(i);
                    return true;
                }
            }
        }
        self.pos >= data.len()
    }

    fn finish(mut self) -> Decoded {
        if self.error.is_none() {
            if let Err(e) = self.filter.finish(&mut self.bytes) {
                self.error = Some(e.message);
            } else if let Some(w) = self.filter.warning() {
                self.error = Some(w.message);
            }
        }
        Decoded {
            bytes: self.bytes,
            error: self.error,
        }
    }
}

fn base64_filter(len: usize) -> Filtered<filters::Base64> {
    Filtered::new(filters::Base64::default(), (len / 4).saturating_mul(3))
}

/// Base64 (standard or URL-safe alphabet), ignoring whitespace. Stops at
/// padding or at the first invalid character (see [`filters::Base64`]).
pub fn base64(data: &[u8]) -> Decoded {
    run(base64_filter(data.len()), data)
}

/// Like [`base64`], in bounded steps with checkpoints in between, failing
/// with the offset of the first invalid character.
pub async fn base64_strict(cx: &Cx, data: &[u8]) -> std::result::Result<Vec<u8>, usize> {
    let mut s = base64_filter(data.len());
    while !s.step(data, STEP) {
        cx.checkpoint().await;
    }
    match s.bad {
        Some(at) => Err(at),
        None => Ok(s.bytes),
    }
}

struct Hex {
    pos: usize,
    high: Option<u8>,
    bytes: Vec<u8>,
    error: Option<String>,
}

impl Hex {
    fn new(len: usize) -> Self {
        Hex {
            pos: 0,
            high: None,
            bytes: Vec::with_capacity(len / 2),
            error: None,
        }
    }
}

impl Step for Hex {
    fn step(&mut self, data: &[u8], limit: usize) -> bool {
        let end = self.pos.saturating_add(limit).min(data.len());
        while self.pos < end {
            let i = self.pos;
            let Some(&b) = data.get(i) else { break };
            self.pos = i.saturating_add(1);
            if b.is_ascii_whitespace() || b == b',' || b == b'\\' {
                continue;
            }
            let Some(v) = hex_digit(b) else {
                self.error = Some(format!("invalid hex digit {:?} at {i}", char::from(b)));
                return true;
            };
            match self.high.take() {
                Some(h) => self.bytes.push(h << 4 | v),
                None => self.high = Some(v),
            }
        }
        self.pos >= data.len()
    }

    fn finish(mut self) -> Decoded {
        if self.high.is_some() && self.error.is_none() {
            self.error = Some("odd number of hex digits".to_owned());
        }
        Decoded {
            bytes: self.bytes,
            error: self.error,
        }
    }
}

/// Hex digit pairs, ignoring whitespace, commas and backslashes.
pub fn hex(data: &[u8]) -> Decoded {
    run(Hex::new(data.len()), data)
}

/// Quoted-printable (RFC 2045): `=XX` escapes and `=` soft line breaks (see
/// [`filters::QuotedPrintable`]).
pub fn quoted_printable(data: &[u8]) -> Decoded {
    run(
        Filtered::new(filters::QuotedPrintable::default(), data.len()),
        data,
    )
}

/// Decodes `span` with `decode` into a derived source (reusing it if it was
/// decoded before), returning its span and any decoding problem. The
/// source stays in memory for the session; decoders that exist as a
/// [`Codec`] go through [`derive_codec`] instead.
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
    store(cx, origin, &data, decoded)
}

/// Keeps `decoded` (from `data`) as the derived source for `origin`.
fn store(
    cx: &Cx,
    origin: Origin,
    data: &[u8],
    decoded: Decoded,
) -> Result<(Span, Option<Diagnostic>)> {
    let transform = origin.transform;
    let error = decoded
        .error
        .map(|e| Diagnostic::malformed(format!("{transform}: {e}")).at(origin.parent));
    let consumed = crate::bytes::to_u64(data.len());
    let out = cx.add_derived(origin, decoded.bytes, consumed, error.clone())?;
    Ok((out.span, error))
}

/// Decodes `span` with `codec` into a derived source (once; the source is
/// evictable and decoded again when needed), returning its span and the
/// first decoding problem, prefixed with the codec's name. Data that fails
/// before its first decoded byte gives an empty source and the problem.
pub async fn derive_codec(
    cx: &Cx,
    span: Span,
    codec: &Codec,
) -> Result<(Span, Option<Diagnostic>)> {
    let name = codec.name();
    let named = |e: Diagnostic| Diagnostic {
        message: format!("{name}: {}", e.message),
        ..e.at(span)
    };
    match crate::codec::decode_span(cx, span, codec, None).await {
        Ok(d) => Ok((d.span, d.error.map(named))),
        Err(e) if e.kind == DiagKind::Malformed => {
            let origin = Origin {
                parent: span,
                transform: name,
            };
            let error = named(e);
            let out = cx.add_derived(origin, Vec::new(), span.len, Some(error.clone()))?;
            Ok((out.span, Some(error)))
        }
        Err(e) => Err(e),
    }
}

/// A node for content transfer-encoded in `span`: decoded on expansion into
/// a derived source, then identified and dissected (or shown as data).
pub fn decoded_node(
    name: impl Into<std::borrow::Cow<'static, str>>,
    input: Input,
    span: Span,
    transform: Transform,
) -> Node {
    decoded_text_node(name, input, span, transform, None)
}

/// Like [`decoded_node`], for text in the declared `charset` (MIME
/// `charset=`): a single-byte code page is transcoded into UTF-8 after the
/// transfer encoding is undone, unless the text is valid UTF-8 anyway.
pub fn decoded_text_node(
    name: impl Into<std::borrow::Cow<'static, str>>,
    input: Input,
    span: Span,
    transform: Transform,
    charset: Option<Label>,
) -> Node {
    Node::new(name)
        .span(span)
        .lazy(expand_decoded, (input, span, transform, charset))
}

/// A node for a `data:` URL whose raw text (as stored at `span`, without
/// escapes of the surrounding syntax) is `url`: it shows the URL and, on
/// expansion, the decoded payload. `None` if `url` is not a `data:` URL.
pub fn data_url_node(
    name: impl Into<std::borrow::Cow<'static, str>>,
    input: Input,
    span: Span,
    url: &str,
) -> Option<Node> {
    let parsed = crate::text::url::data_url(url)?;
    let payload = span.sub(crate::bytes::to_u64(parsed.payload), u64::MAX);
    let transform = if parsed.base64 {
        Transform::Base64
    } else {
        Transform::Percent
    };
    let media = if parsed.media_type.is_empty() {
        "text/plain"
    } else {
        parsed.media_type.as_str()
    };
    let (shown, _) = cap(url, 120);
    Some(
        decoded_node(name, input, payload, transform)
            .span(span)
            .value(crate::value::Value::Text(if shown.len() < url.len() {
                format!("{shown}…")
            } else {
                shown
            }))
            .summary(format!(
                "{media}, data URL{}",
                if parsed.base64 { " (base64)" } else { "" }
            )),
    )
}

/// The transfer encodings [`decoded_node`] understands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transform {
    Base64,
    QuotedPrintable,
    Hex,
    /// `%XX` escapes (URLs, `data:` URLs without `;base64`).
    Percent,
    Identity,
}

impl Transform {
    pub fn name(self) -> &'static str {
        match self {
            Transform::Base64 => "base64",
            Transform::QuotedPrintable => "quoted-printable",
            Transform::Hex => "hex",
            Transform::Percent => "percent-decoding",
            Transform::Identity => "identity",
        }
    }

    pub fn decode(self, data: &[u8]) -> Decoded {
        match self {
            Transform::Base64 => base64(data),
            Transform::QuotedPrintable => quoted_printable(data),
            Transform::Hex => hex(data),
            Transform::Percent => Decoded {
                bytes: crate::text::url::percent_decode_bytes(data),
                error: None,
            },
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
    let name = transform.name();
    match transform {
        Transform::Identity => Ok((span, None)),
        Transform::Base64 => derive_codec(cx, span, &Codec::Base64).await,
        Transform::QuotedPrintable => derive_codec(cx, span, &Codec::QuotedPrintable).await,
        Transform::Hex => {
            let origin = Origin {
                parent: span,
                transform: name,
            };
            if let Some(found) = cx.derived(origin) {
                return Ok((found.span, found.error));
            }
            let data = crate::codec::read_all(cx, span).await?;
            let mut s = Hex::new(data.len());
            while !s.step(&data, STEP) {
                cx.checkpoint().await;
            }
            store(cx, origin, &data, s.finish())
        }
        Transform::Percent => derive(cx, span, name, |d| transform.decode(d)).await,
    }
}

async fn expand_decoded(
    cx: Cx,
    (input, span, transform, charset): (Input, Span, Transform, Option<Label>),
) -> Result<()> {
    let (mut decoded, error) = derive_with(&cx, span, transform).await?;
    if let Some(e) = error {
        cx.diag(e);
    }
    if transform != Transform::Identity {
        cx.annotate(format!("{:#x} bytes decoded", decoded.len));
    }
    if let Some(label @ Label::Single(_)) = charset {
        let head = cx
            .read_avail(decoded.sub(0, crate::formats::HEAD_LEN))
            .await?;
        if let Some(c) = super::encoding::declared_charset_label(&head, label) {
            let origin = Origin {
                parent: decoded,
                transform: c.transform(),
            };
            decoded = match cx.derived(origin) {
                Some(found) => found.span,
                None => {
                    let data = crate::codec::read_all(&cx, decoded).await?;
                    let text = super::encoding::decode_stepped(&cx, Encoding::Single(c), &data)
                        .await
                        .into_bytes();
                    let consumed = crate::bytes::to_u64(data.len());
                    cx.add_derived(origin, text, consumed, None)?.span
                }
            };
            cx.annotate(format!(
                "{:#x} bytes of text from {}",
                decoded.len,
                c.name()
            ));
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_decoders() {
        let b = base64(b"SGVs\r\nbG8=trailing");
        assert_eq!((b.bytes.as_slice(), b.error), (&b"Hello"[..], None));
        let b = base64(b"QUJD*");
        assert_eq!(b.bytes, b"ABC");
        assert_eq!(
            b.error.as_deref(),
            Some("invalid base64 character '*' at 4")
        );
        let q = quoted_printable(b"a=3Db=\r\nc=");
        assert_eq!((q.bytes.as_slice(), q.error), (&b"a=bc="[..], None));
        let h = hex(b"de ad,be\\ef 0");
        assert_eq!(h.bytes, [0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(h.error.as_deref(), Some("odd number of hex digits"));
        assert_eq!(preview("  a\n\tb ", 10), "a b");
    }
}
