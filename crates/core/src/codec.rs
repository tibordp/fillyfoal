//! The codecs (see [`fillyfoal_codec::codec`]), plus decoding through a
//! [`Cx`]: into derived sources, charging the work budget as it goes.

pub use fillyfoal_codec::codec::*;

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::span::{Origin, Span};
use fillyfoal_codec::codec::pipeline::Status;

/// Bytes decoded per step between budget checkpoints.
const STEP: usize = 64 * 1024;

/// Decodes `span` with `codec` into a derived source (memoized). `expected`
/// is the decoded size, if the container records it.
pub async fn decode_span(
    cx: &Cx,
    span: Span,
    codec: &Codec,
    expected: Option<u64>,
) -> Result<Decoded> {
    let origin = Origin {
        parent: span,
        transform: codec.name(),
    };
    if let Some(found) = cx.derived(origin) {
        return Ok(found);
    }
    let input = read_all(cx, span).await?;
    let Some(mut decoder) = codec.decoder() else {
        let len = to_u64(input.len());
        return cx.add_derived(origin, input, len, None);
    };
    let limit = to_usize(cx.limits().max_derived);
    let mut out = Vec::with_capacity(to_usize(expected.unwrap_or(0).min(1 << 24)));
    let mut error = None;
    loop {
        match decoder.decode(&input, true, &mut out, STEP, limit) {
            Ok(Status::Done) => break,
            Ok(Status::More) => cx.checkpoint().await,
            Ok(Status::NeedInput) => {
                error = Some(
                    Diagnostic::malformed(format!("{} stream ended early", codec.name())).at(span),
                );
                break;
            }
            Err(e) => {
                error = Some(if e.span.is_some() { e } else { e.at(span) });
                break;
            }
        }
    }
    if error.is_none() {
        error = decoder.warning(&out).map(|w| w.at(span));
    }
    if let (Some(expected), None) = (expected, &error)
        && expected != to_u64(out.len())
    {
        error = Some(Diagnostic::warning(format!(
            "decoded {:#x} bytes, expected {expected:#x}",
            out.len()
        )));
    }
    if out.is_empty()
        && let Some(e) = error
    {
        return Err(e);
    }
    let consumed = to_u64(decoder.consumed());
    cx.add_decoded(origin, out, consumed, error, codec)
}

/// Reads `span` fully into memory, in pieces no larger than the read limit.
pub async fn read_all(cx: &Cx, span: Span) -> Result<Vec<u8>> {
    let limits = cx.limits();
    if span.len > limits.max_derived {
        return Err(Diagnostic::limit(format!(
            "{:#x} compressed bytes exceed the {:#x}-byte limit",
            span.len, limits.max_derived
        ))
        .at(span));
    }
    let piece = limits.max_read.clamp(1, 1 << 20);
    let mut out = Vec::with_capacity(to_usize(span.len));
    let mut pos = 0u64;
    while pos < span.len {
        let data = cx.read(span.sub(pos, piece)).await?;
        if data.is_empty() {
            break;
        }
        pos = pos.saturating_add(to_u64(data.len()));
        out.extend_from_slice(&data);
    }
    Ok(out)
}

/// [`decode_span`] for raw DEFLATE or zlib-wrapped data.
pub async fn inflate_span(
    cx: &Cx,
    span: Span,
    zlib: bool,
    expected: Option<u64>,
) -> Result<Decoded> {
    let codec = if zlib { Codec::Zlib } else { Codec::Deflate };
    decode_span(cx, span, &codec, expected).await
}

pub mod crypto {
    //! Ciphers, hashes and key derivations (see
    //! [`fillyfoal_codec::codec::crypto`]), plus running a key derivation
    //! under the work budget.

    pub use fillyfoal_codec::codec::crypto::*;

    use crate::cx::Cx;

    /// Runs `kdf` to completion in chunks of [`CHUNK`] units, charging the work
    /// budget one unit per unit of work (a checkpoint charges one), so the poll
    /// yields between chunks once its budget is spent.
    pub async fn run(cx: &Cx, kdf: &mut impl Stepped) {
        while !kdf.done() {
            let used = kdf.advance(CHUNK);
            for _ in 0..used {
                cx.checkpoint().await;
            }
        }
    }
}
