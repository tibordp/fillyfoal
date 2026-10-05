//! Format identification and the dissectors themselves.
//!
//! Every format is a [`Format`] entry in [`FORMATS`]: a name, a probe that
//! recognises it from the first and last bytes of the input, and an entry
//! point. Adding a format means adding a module and one line to the registry.

use std::borrow::Cow;

use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::node::{Expansion, Node};
use crate::span::Span;

// Modules, grouped by family. Keep each group sorted; parallel branches
// touch different groups, so they merge cleanly.

// -- archives & compression --
pub mod gzip;
pub mod zip;
// -- end archives --

// -- executables & code --
pub mod pe;
// -- end executables --

// -- images --
pub mod png;
// -- end images --

// -- audio & video --
// -- end audio & video --

// -- documents & data --
// -- end documents --

// -- disk images & filesystems --
// -- end disk images --

// -- text --
pub mod text;
// -- end text --

/// How many leading bytes probes see. Large enough for magic numbers deep in
/// a file, such as ISO 9660's volume descriptor at 0x8001.
pub const HEAD_LEN: u64 = 0x9000;
/// How many trailing bytes probes see.
pub const TAIL_LEN: u64 = 0x400;

/// The region a format dissector works on, plus how deeply it is embedded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Input {
    pub span: Span,
    pub nesting: u32,
}

impl Input {
    pub fn root(span: Span) -> Self {
        Input { span, nesting: 0 }
    }

    /// An input embedded in this one.
    pub fn nested(&self, span: Span) -> Self {
        Input {
            span,
            nesting: self.nesting.saturating_add(1),
        }
    }
}

/// What a probe sees of an input.
pub struct Head<'a> {
    /// The first [`HEAD_LEN`] bytes (fewer if the input is shorter).
    pub data: &'a [u8],
    /// The last [`TAIL_LEN`] bytes (may overlap `data`).
    pub tail: &'a [u8],
    /// Length of the whole input.
    pub len: u64,
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
}

impl Probe {
    fn matches(&self, head: &Head<'_>) -> bool {
        match self {
            Probe::Magic(list) => list.iter().any(|(offset, magic)| head.at(*offset, magic)),
            Probe::Custom(f) => f(head),
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

/// All formats, in probing order: specific before generic.
pub static FORMATS: &[&Format] = &[
    // -- executables & code --
    &pe::FORMAT,
    // -- end executables --

    // -- images --
    &png::FORMAT,
    &png::MNG,
    &png::JNG,
    // -- end images --

    // -- audio & video --
    // -- end audio & video --

    // -- documents & data --
    // -- end documents --

    // -- disk images & filesystems --
    // -- end disk images --

    // -- archives & compression --
    &gzip::FORMAT,
    // ZIP-based formats before plain ZIP.
    &zip::EPUB,
    &zip::ODT,
    &zip::ODS,
    &zip::ODP,
    &zip::ODG,
    &zip::DOCX,
    &zip::XLSX,
    &zip::PPTX,
    &zip::VSDX,
    &zip::XPS,
    &zip::APK,
    &zip::XPI,
    &zip::NUPKG,
    &zip::VSIX,
    &zip::WHL,
    &zip::IPA,
    &zip::KMZ,
    &zip::THREE_MF,
    &zip::SKETCH,
    &zip::USDZ,
    &zip::JAR,
    &zip::FORMAT,
    // -- end archives --

    // -- text (generic probes, keep last) --
    // Binary formats found inside text armor.
    &text::ssh::PRIVATE,
    &text::ssh::BLOB,
    // Armor and keys.
    &text::pem::PGP,
    &text::pem::SSH2,
    &text::pem::FORMAT,
    &text::ssh::KEYS,
    // Messages (header blocks look like YAML; keep them before it).
    &text::mime::MBOX,
    &text::mime::MHTML,
    &text::mime::EML,
    // Markup: specific XML vocabularies, then HTML, then generic XML.
    &text::plist::FORMAT,
    &text::xml::XHTML,
    &text::xml::SVG,
    &text::xml::RSS,
    &text::xml::ATOM,
    &text::xml::GPX,
    &text::xml::KML,
    &text::xml::POM,
    &text::xml::XAML,
    &text::xml::MATHML,
    &text::xml::XSLT,
    &text::xml::XSD,
    &text::xml::MSBUILD,
    &text::xml::COLLADA,
    &text::xml::TTML,
    &text::xml::DASH,
    &text::xml::XLIFF,
    &text::xml::OPF,
    &text::xml::OSM,
    &text::xml::XSPF,
    &text::xml::TEI,
    &text::xml::DOCBOOK,
    &text::xml::ANDROID_MANIFEST,
    &text::xml::WSDL,
    &text::xml::SOAP,
    &text::xml::SITEMAP,
    &text::xml::DRAWIO,
    &text::html::FORMAT,
    &text::xml::FORMAT,
    // JSON and its vocabularies.
    &text::json::IPYNB,
    &text::json::GEOJSON,
    &text::json::HAR,
    &text::json::NDJSON,
    &text::json::FORMAT,
    // TOML before INI: its values are typed, INI's are not.
    &text::toml::FORMAT,
    // INI family: specific first.
    &text::ini::REG,
    &text::ini::DESKTOP,
    &text::ini::URL,
    &text::ini::SYSTEMD,
    &text::ini::INF,
    &text::ini::ASS,
    &text::ini::FORMAT,
    &text::yaml::FORMAT,
    &text::plain::SCRIPT,
    // Weak, statistical probes.
    &text::csv::TSV,
    &text::csv::CSV,
    // Plain text matches anything textual: keep it last.
    &text::plain::FORMAT,
    // -- end text --
];

pub fn by_name(name: &str) -> Option<&'static Format> {
    FORMATS.iter().copied().find(|f| f.name == name)
}

/// Picks the first format whose probe matches.
pub fn identify(head: &Head<'_>) -> Option<&'static Format> {
    FORMATS.iter().copied().find(|f| f.probe.matches(head))
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
        .lazy(dissect_as, (input, format.name))
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
    let tail = if span.len > HEAD_LEN {
        cx.read_avail(span.tail(span.len.saturating_sub(TAIL_LEN.min(max))))
            .await?
    } else {
        data.clone()
    };
    Ok((data, tail))
}

/// Identifies the format of `input` and dissects it.
pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    check_nesting(&cx, &input)?;
    let (data, tail) = head(&cx, input.span).await?;
    let probe = Head {
        data: &data,
        tail: &tail,
        len: input.span.len,
    };
    match identify(&probe) {
        Some(format) => (format.dissect)(cx, input).await,
        None if data.is_empty() => Err(Diagnostic::note("empty").at(input.span)),
        None => Err(Diagnostic::unsupported("unrecognized format").at(input.span)),
    }
}

/// Dissects `input`, or, if its format is not recognised, shows it as a
/// plain data leaf so its bytes stay reachable (e.g. decompressed content).
pub async fn dissect_or_data(cx: Cx, input: Input) -> Result<()> {
    check_nesting(&cx, &input)?;
    let (data, tail) = head(&cx, input.span).await?;
    let probe = Head {
        data: &data,
        tail: &tail,
        len: input.span.len,
    };
    match identify(&probe) {
        Some(format) => (format.dissect)(cx, input).await,
        None => {
            cx.emit(Node::new("Data").span(input.span));
            Ok(())
        }
    }
}

/// How compressed content is encoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Codec {
    Stored,
    Deflate,
    Zlib,
}

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

async fn expand_content(
    cx: Cx,
    (input, span, codec, expected): (Input, Span, Codec, Option<u64>),
) -> Result<()> {
    let inner = match codec {
        Codec::Stored => input.nested(span),
        Codec::Deflate | Codec::Zlib => {
            let decoded =
                crate::codec::inflate_span(&cx, span, codec == Codec::Zlib, expected).await?;
            cx.annotate(format!("{:#x} bytes decompressed", decoded.span.len));
            if let Some(e) = decoded.error {
                cx.diag(e);
            } else if decoded.consumed < span.len {
                cx.diag(Diagnostic::note(format!(
                    "{:#x} bytes follow the compressed stream",
                    span.len.saturating_sub(decoded.consumed)
                )));
            }
            input.nested(decoded.span)
        }
    };
    dissect_or_data(cx, inner).await
}

async fn dissect_as(cx: Cx, (input, name): (Input, &'static str)) -> Result<()> {
    check_nesting(&cx, &input)?;
    let format =
        by_name(name).ok_or_else(|| Diagnostic::internal(format!("unknown format {name}")))?;
    (format.dissect)(cx, input).await
}
