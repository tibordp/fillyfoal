//! Format identification and embedding, and the helpers dissectors share.
//!
//! Every format is a [`Format`]: a name, a probe that recognises it from the
//! first and last bytes of the input, and an entry point. A session
//! identifies content with the [`Registry`] of its [`Catalog`]; the
//! `fillyfoal` crate's `formats::FORMATS` lists every format, in the
//! category crates that hold the dissectors.

use std::borrow::Cow;

use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::node::{Expansion, Node};
use crate::session::Interpretation;
use crate::span::Span;

// Modules, grouped by theme; each family's `mod.rs` summarises what it
// holds. Keep each group sorted.

// -- shared helpers --
pub mod util;

/// How many leading bytes probes see. Large enough for magic numbers deep in
/// a file, such as ISO 9660's volume descriptor at 0x8001 and the btrfs and
/// UFS2 superblocks at 64 KiB.
pub const HEAD_LEN: u64 = 0x10800;
/// How many trailing bytes probes see.
pub const TAIL_LEN: u64 = 0x400;

/// The region a format dissector works on, plus how deeply it is embedded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Input {
    pub span: Span,
    pub nesting: u32,
    /// The region this input is embedded in (itself, for the root).
    pub outer: Span,
}

impl Input {
    pub fn root(span: Span) -> Self {
        Input {
            span,
            nesting: 0,
            outer: span,
        }
    }

    /// An input embedded in this one.
    pub fn nested(&self, span: Span) -> Self {
        Input {
            span,
            nesting: self.nesting.saturating_add(1),
            outer: self.span,
        }
    }
}

/// What a probe sees of an input.
pub struct Head<'a> {
    /// The first [`HEAD_LEN`] bytes (fewer if the input is shorter).
    pub data: &'a [u8],
    /// The last [`TAIL_LEN`] bytes (may overlap `data`).
    pub tail: &'a [u8],
    /// Length of the whole input. When `len_known` is false this is only an
    /// upper bound (content decoded on demand whose size nothing records; see
    /// `Cx::decode_lazy_unsized`): a declared size that "fits" proves nothing
    /// then, and a probe must not accept on that evidence alone.
    pub len: u64,
    pub len_known: bool,
}

impl Head<'_> {
    /// Whether `magic` occurs at `offset`.
    pub fn at(&self, offset: usize, magic: &[u8]) -> bool {
        offset
            .checked_add(magic.len())
            .and_then(|end| self.data.get(offset..end))
            .is_some_and(|b| b == magic)
    }

    pub fn starts_with(&self, magic: &[u8]) -> bool {
        self.data.starts_with(magic)
    }
}

pub enum Probe {
    /// Any of these `(offset, bytes)` pairs matches.
    Magic(&'static [(usize, &'static [u8])]),
    Custom(fn(&Head<'_>) -> bool),
    /// No reliable signature: never identified by content, only chosen by
    /// hand (`by_extension`, [`crate::Session::open_as`]) or embedded by
    /// a dissector that knows what it holds.
    Never,
}

impl Probe {
    fn matches(&self, head: &Head<'_>) -> bool {
        match self {
            Probe::Magic(list) => list.iter().any(|(offset, magic)| head.at(*offset, magic)),
            Probe::Custom(f) => f(head),
            Probe::Never => false,
        }
    }
}

/// A registered file format.
pub struct Format {
    /// Short identifier, e.g. `"png"`.
    pub name: &'static str,
    /// Human-readable name, e.g. `"Portable Network Graphics"`.
    pub title: &'static str,
    pub extensions: &'static [&'static str],
    pub mime: &'static str,
    pub probe: Probe,
    pub dissect: fn(Cx, Input) -> Expansion,
}

impl std::fmt::Debug for Format {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Format").field(&self.name).finish()
    }
}

/// The formats a session knows: all of them in probing order, and those
/// that stream (see `STREAMING`).
pub struct Registry {
    pub formats: &'static [&'static Format],
    pub streaming: &'static [&'static Format],
}

impl Registry {
    pub fn by_name(&self, name: &str) -> Option<&'static Format> {
        self.formats.iter().copied().find(|f| f.name == name)
    }

    /// The formats that list `extension` (without the dot, any case), in
    /// probe order: candidates for a file whose content was not recognised,
    /// or for an "inspect as" menu. Identification itself never uses
    /// extensions.
    pub fn by_extension(&self, extension: &str) -> Vec<&'static Format> {
        let ext = extension.trim_start_matches('.');
        self.formats
            .iter()
            .copied()
            .filter(|f| f.extensions.iter().any(|e| e.eq_ignore_ascii_case(ext)))
            .collect()
    }

    /// Picks the first format whose probe matches.
    pub fn identify(&self, head: &Head<'_>) -> Option<&'static Format> {
        self.formats.iter().copied().find(|f| f.probe.matches(head))
    }

    /// Whether `format` dissects unsized streams from the front.
    pub fn streams(&self, format: &Format) -> bool {
        self.streaming.iter().any(|f| std::ptr::eq(*f, format))
    }
}

/// Names the registry a [`crate::session::Session`] uses.
pub trait Catalog: 'static {
    const REGISTRY: &'static Registry;
}

/// A top-level node that identifies and dissects `span` when expanded.
pub fn root(name: impl Into<Cow<'static, str>>, span: Span) -> Node {
    Node::new(name).span(span).lazy(dissect, Input::root(span))
}

/// A node for embedded content, identified and dissected on expansion.
pub fn embedded(name: impl Into<Cow<'static, str>>, input: Input) -> Node {
    Node::new(name).span(input.span).lazy(dissect, input)
}

/// A node for embedded content of a known format.
pub fn embedded_as(
    name: impl Into<Cow<'static, str>>,
    input: Input,
    format: &'static Format,
) -> Node {
    Node::new(name)
        .span(input.span)
        .lazy(dissect_as, (input, format))
}

/// A node for embedded content of the format registered as `format`, for
/// a dissector that cannot name the format's static (it lives in a crate
/// that depends on the dissector's). Content of a format this session does
/// not register is identified as usual.
pub fn embedded_named(
    name: impl Into<Cow<'static, str>>,
    input: Input,
    format: &'static str,
) -> Node {
    Node::new(name)
        .span(input.span)
        .lazy(dissect_named, (input, format))
}

fn check_nesting(cx: &Cx, input: &Input) -> Result<()> {
    let max = cx.limits().max_nesting;
    if input.nesting > max {
        return Err(
            Diagnostic::limit(format!("embedded objects nested deeper than {max}")).at(input.span),
        );
    }
    Ok(())
}

/// Reads what probes need: the head and the tail of the input.
pub async fn head(cx: &Cx, span: Span) -> Result<(Vec<u8>, Vec<u8>)> {
    let max = cx.limits().max_read;
    let data = cx.read_avail(span.sub(0, HEAD_LEN.min(max))).await?;
    // Reading the tail of a lazily decoded stream would decode all of it,
    // unless its decoder has already reached the end (an unsized stream
    // decoded to find its length, see `dissect_unsized`).
    let tail = if span.len > HEAD_LEN && !cx.tail_is_cheap(span.source) {
        Vec::new()
    } else if span.len > HEAD_LEN {
        cx.read_avail(span.tail(span.len.saturating_sub(TAIL_LEN.min(max))))
            .await?
    } else {
        data.clone()
    };
    Ok((data, tail))
}

/// Settles the format of `input`: `given` if the caller knows it, else by
/// identification. A format the host forced on the node (see
/// [`crate::Session::reinterpret`]) overrides both, but only at the node's
/// own detection step; content nested inside it is identified as usual.
/// The second value is whether `input` had no bytes to identify.
async fn settle(
    cx: &Cx,
    input: &Input,
    given: Option<&'static Format>,
) -> Result<(Option<&'static Format>, bool)> {
    check_nesting(cx, input)?;
    let claim = cx.claim_detection();
    if let Some(Some(format)) = claim {
        cx.interpreted(Interpretation {
            format: Some(format),
            forced: true,
        });
        return Ok((Some(format), false));
    }
    let (format, empty) = match given {
        Some(format) => (Some(format), false),
        None => {
            let (data, tail) = head(cx, input.span).await?;
            let probe = Head {
                data: &data,
                tail: &tail,
                len: input.span.len,
                len_known: cx.len_known(input.span.source),
            };
            (cx.registry().identify(&probe), data.is_empty())
        }
    };
    if claim.is_some() {
        cx.interpreted(Interpretation {
            format,
            forced: false,
        });
    }
    Ok((format, empty))
}

/// Identifies the format of `input` and dissects it.
pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    match settle(&cx, &input, None).await? {
        (Some(format), _) => (format.dissect)(cx, input).await,
        (None, true) => Err(Diagnostic::note("empty").at(input.span)),
        (None, false) => Err(Diagnostic::unsupported("unrecognized format").at(input.span)),
    }
}

/// Dissects content decoded on demand whose length nothing records (see
/// `Cx::decode_lazy_unsized`; `input.span`'s length is an upper bound). A
/// format in `STREAMING` dissects it at once; any other first has the
/// stream decoded to its end, in budgeted steps, and sees the real length.
/// Unrecognized content stays a data leaf of unknown length (nothing needs
/// its length; hosts check `Session::source_len_known`).
pub async fn dissect_unsized(cx: Cx, input: Input) -> Result<()> {
    let span = input.span;
    let format = match cx.forced_format() {
        Some(format) => Some(format),
        None if cx.len_known(span.source) => None,
        None => {
            let (data, tail) = head(&cx, span).await?;
            cx.registry().identify(&Head {
                data: &data,
                tail: &tail,
                len: span.len,
                len_known: false,
            })
        }
    };
    if format.is_some_and(|f| !cx.registry().streams(f)) && !cx.len_known(span.source) {
        // Decoding up to the provisional end finds the real one.
        let last = span.sub(span.len.saturating_sub(1), 1);
        if let Err(e) = cx.read_avail(last).await {
            cx.diag(e);
        }
    }
    // Once the length is known (also when identification read a short
    // stream to its end), the content gets it.
    let input = if cx.len_known(span.source) {
        let len = cx
            .source_len(span.source)
            .saturating_sub(span.offset)
            .min(span.len);
        let known = Span::new(span.source, span.offset, len);
        Input {
            span: known,
            outer: if input.outer == span {
                known
            } else {
                input.outer
            },
            ..input
        }
    } else {
        input
    };
    dissect_or_data(cx, input).await
}

/// Dissects `input`, or, if its format is not recognised, shows it as a
/// plain data leaf so its bytes stay reachable (e.g. decompressed content).
pub async fn dissect_or_data(cx: Cx, input: Input) -> Result<()> {
    match settle(&cx, &input, None).await? {
        (Some(format), _) => (format.dissect)(cx, input).await,
        (None, _) => {
            cx.emit(Node::new("Data").span(input.span));
            Ok(())
        }
    }
}

/// Members larger than this are decompressed lazily rather than up front.
const LAZY_THRESHOLD: u64 = 1024 * 1024;
/// Encoded streams of unrecorded decoded size above this many bytes are
/// decoded on demand (their output could be any size up to the codec's
/// maximum ratio).
const UNSIZED_LAZY_THRESHOLD: u64 = 64 * 1024;

pub use crate::codec::Codec;

/// A node for content stored in `span` with `codec`. Nothing is read or
/// decompressed until it is expanded; then the content is decoded into a
/// derived source and dissected in place.
pub fn content(
    name: impl Into<Cow<'static, str>>,
    input: Input,
    span: Span,
    codec: Codec,
    expected: Option<u64>,
) -> Node {
    Node::new(name)
        .span(span)
        .lazy(expand_content, (input, span, codec, expected))
}

/// Expands a content node in place: what [`content`] does on expansion, for
/// expanders that work out the decoded size themselves first.
/// A node for content whose decoded size is not recorded, but which a
/// container gives a hint of (gzip's ISIZE: one member's size, modulo
/// 2^32): a large hint, or a large encoded span, decodes on demand with the
/// size found at the end; otherwise the content is decoded eagerly, which
/// finds its exact size. The hint is never taken as the length.
pub fn content_hinted(
    name: impl Into<Cow<'static, str>>,
    input: Input,
    span: Span,
    codec: Codec,
    hint: u64,
) -> Node {
    Node::new(name)
        .span(span)
        .lazy(expand_content_hinted, (input, span, codec, hint))
}

async fn expand_content_hinted(
    cx: Cx,
    (input, span, codec, hint): (Input, Span, Codec, u64),
) -> Result<()> {
    if hint > LAZY_THRESHOLD && span.len <= UNSIZED_LAZY_THRESHOLD {
        let decoded = cx.decode_lazy_unsized(span, &codec)?;
        cx.annotate("size unknown, decoded on demand");
        return dissect_unsized(cx, input.nested(decoded)).await;
    }
    expand_content(cx, (input, span, codec, None)).await
}

/// Whether [`expand_content`] decodes `span`, recorded to decode to
/// `expected` bytes with `codec`, on demand: a large size, not beyond the
/// codec's maximum ratio. Containers that record points the stream can be
/// decoded from check this before collecting them for
/// [`expand_content_seeded`].
pub fn decodes_lazily(span: Span, codec: &Codec, expected: u64) -> bool {
    !matches!(codec, Codec::Stored)
        && expected > LAZY_THRESHOLD
        && expected <= span.len.saturating_mul(codec.max_ratio())
}

/// [`expand_content`] for content that [`decodes_lazily`], with the points
/// its container records it can be decoded from (see
/// [`Cx::decode_lazy_seeded`]): a read anywhere decodes from the nearest
/// one, the first time too.
pub async fn expand_content_seeded(
    cx: Cx,
    (input, span, codec, len): (Input, Span, Codec, u64),
    seeds: Vec<crate::cx::Seed>,
) -> Result<()> {
    let decoded = cx.decode_lazy_seeded(span, &codec, len, seeds)?;
    cx.annotate(format!("{len:#x} bytes, decoded on demand"));
    dissect_or_data(cx, input.nested(decoded)).await
}

pub async fn expand_content(
    cx: Cx,
    (input, span, codec, expected): (Input, Span, Codec, Option<u64>),
) -> Result<()> {
    let inner = match codec {
        Codec::Stored => input.nested(span),
        // Large members are decoded lazily: listing the first entries of a
        // multi-gigabyte tarball only decodes what those entries need. A
        // claimed size beyond the codec's maximum ratio is bogus and gets the
        // eager path (which reports the real size).
        codec if expected.is_some_and(|e| decodes_lazily(span, &codec, e)) => {
            let len = expected.unwrap_or(0);
            let decoded = cx.decode_lazy(span, &codec, len)?;
            cx.annotate(format!("{len:#x} bytes, decoded on demand"));
            input.nested(decoded)
        }
        // Nothing records the decoded size: rather than decode the whole
        // stream before its first bytes can be dissected, decode on demand
        // with a provisional length (see `Cx::decode_lazy_unsized`). Small
        // streams are decoded eagerly, which reports their exact size.
        codec if expected.is_none() && span.len > UNSIZED_LAZY_THRESHOLD => {
            let decoded = cx.decode_lazy_unsized(span, &codec)?;
            cx.annotate("size unknown, decoded on demand");
            return dissect_unsized(cx, input.nested(decoded)).await;
        }
        codec => {
            let decoded = crate::codec::decode_span(&cx, span, &codec, expected).await?;
            cx.annotate(format!("{:#x} bytes {}", decoded.span.len, codec.verb()));
            if let Some(e) = decoded.error {
                cx.diag(e);
            } else if decoded.consumed < span.len {
                cx.diag(Diagnostic::note(format!(
                    "{:#x} bytes follow the encoded stream",
                    span.len.saturating_sub(decoded.consumed)
                )));
            }
            input.nested(decoded.span)
        }
    };
    dissect_or_data(cx, inner).await
}

async fn dissect_as(cx: Cx, (input, given): (Input, &'static Format)) -> Result<()> {
    match settle(&cx, &input, Some(given)).await? {
        (Some(format), _) => (format.dissect)(cx, input).await,
        (None, _) => Err(Diagnostic::internal(format!(
            "format {} was not settled",
            given.name
        ))),
    }
}

async fn dissect_named(cx: Cx, (input, name): (Input, &'static str)) -> Result<()> {
    match cx.registry().by_name(name) {
        Some(format) => dissect_as(cx, (input, format)).await,
        None => dissect(cx, input).await,
    }
}
