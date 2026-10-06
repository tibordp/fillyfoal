//! XML, the many vocabularies built on it (SVG, XHTML, RSS, Atom, GPX, KML,
//! Maven POM, XAML, ...), and the markup machinery HTML shares.
//!
//! A tolerant streaming lexer turns the text into markup tokens. Elements
//! are lazy nodes: expanding one walks its own content only, skipping over
//! child elements (which become lazy nodes in turn). Attributes are shown as
//! `@name` children, text as `#text`, and elements holding only text carry
//! it as their value. Namespace prefixes are resolved along the way.
//!
//! The root element's extent is found from the end of the input when the
//! document is large, so the top level appears without scanning everything.

use std::sync::Arc;

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::error::{DiagKind, Diagnostic, Result};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::Value;

use super::decode::preview;
use super::encoding::prepare;
use super::piece::Piece;
use super::probe;
use super::scan::{Owned, Scanner};
use super::{VALUE_CAP, plural, text_node};

// ---------------------------------------------------------------------------
// Formats

/// What variant probes see: the root element's name and start tag.
pub struct Root {
    pub name: Vec<u8>,
    pub tag: Vec<u8>,
    /// Whether the document starts with an XML declaration.
    pub declared: bool,
}

impl Root {
    pub fn local(&self) -> &[u8] {
        match self.name.iter().rposition(|&b| b == b':') {
            Some(i) => self.name.get(i.saturating_add(1)..).unwrap_or_default(),
            None => &self.name,
        }
    }

    pub fn is(&self, name: &[u8]) -> bool {
        self.name == name
    }

    /// Whether the start tag mentions `text` (e.g. a namespace URI).
    pub fn mentions(&self, text: &[u8]) -> bool {
        probe::contains(&self.tag, text)
    }
}

/// Finds the root element of a document in a probe's head: skips the XML
/// declaration, comments, processing instructions and the DOCTYPE.
pub fn root(h: &Head<'_>) -> Option<Root> {
    let head = probe::head(h);
    let data = probe::trim_start(&head);
    let declared = data.starts_with(b"<?xml");
    let mut rest = data;
    loop {
        rest = probe::trim_start(rest);
        if !rest.starts_with(b"<") {
            return None;
        }
        let skip = if rest.starts_with(b"<?") {
            probe::find(rest, b"?>").map(|i| i.saturating_add(2))
        } else if rest.starts_with(b"<!--") {
            probe::find(rest, b"-->").map(|i| i.saturating_add(3))
        } else if rest.starts_with(b"<!") {
            doctype_end(rest)
        } else {
            let body = rest.get(1..).unwrap_or_default();
            let n = body.iter().take_while(|&&b| is_name(b)).count();
            if n == 0 || !body.first().is_some_and(|&b| is_name_start(b)) {
                return None;
            }
            let end = body
                .iter()
                .position(|&b| b == b'>')
                .unwrap_or(body.len().min(4096));
            return Some(Root {
                name: body.get(..n).unwrap_or_default().to_vec(),
                tag: body.get(..end).unwrap_or_default().to_vec(),
                declared,
            });
        };
        rest = rest.get(skip?..).unwrap_or_default();
    }
}

/// The end of `<!DOCTYPE ... [ ... ]>` in `data`, honouring quotes and the
/// internal subset.
fn doctype_end(data: &[u8]) -> Option<usize> {
    let mut quote = None;
    let mut depth = 0u32;
    for (i, &b) in data.iter().enumerate() {
        match (quote, b) {
            (Some(q), _) if b == q => quote = None,
            (Some(_), _) => {}
            (None, b'"' | b'\'') => quote = Some(b),
            (None, b'[') => depth = depth.saturating_add(1),
            (None, b']') => depth = depth.saturating_sub(1),
            (None, b'>') if depth == 0 => return Some(i.saturating_add(1)),
            _ => {}
        }
    }
    None
}

fn probe_xml(h: &Head<'_>) -> bool {
    let Some(root) = root(h) else {
        return false;
    };
    // Plain HTML is not XML unless it says so.
    (root.declared || !root.name.eq_ignore_ascii_case(b"html")) && probe::is_text(h)
}

pub static FORMAT: Format = Format {
    name: "xml",
    title: "XML document",
    extensions: &["xml", "xsl", "rdf", "xul", "resx", "config", "manifest", "nuspec", "wxs"],
    mime: "application/xml",
    probe: Probe::Custom(probe_xml),
    dissect: crate::expander!(dissect: Input),
};

/// An XML vocabulary recognised by its root element.
pub struct Variant {
    pub title: &'static str,
    /// Extra detail for the annotation, from the root and the head.
    pub detail: fn(&Root, &[u8]) -> Option<String>,
}

macro_rules! xml_variant {
    ($id:ident, $info:ident, $f:ident, $name:literal, $title:literal, [$($ext:literal),*],
     $mime:literal, $probe:expr, $detail:expr) => {
        pub static $id: Format = Format {
            name: $name,
            title: $title,
            extensions: &[$($ext),*],
            mime: $mime,
            probe: Probe::Custom(|h| probe_xml(h) && root(h).is_some_and($probe)),
            dissect: crate::expander!($f: Input),
        };
        static $info: Variant = Variant { title: $title, detail: $detail };
        async fn $f(cx: Cx, input: Input) -> Result<()> {
            dissect_variant(cx, input, &$info).await
        }
    };
}

fn no_detail(_: &Root, _: &[u8]) -> Option<String> {
    None
}

xml_variant!(SVG, SVG_INFO, dissect_svg, "svg", "Scalable Vector Graphics", ["svg"],
    "image/svg+xml", |r| r.local() == b"svg", svg_detail);
xml_variant!(XHTML, XHTML_INFO, dissect_xhtml, "xhtml", "XHTML document", ["xhtml", "xht"],
    "application/xhtml+xml",
    |r| r.local().eq_ignore_ascii_case(b"html") && (r.declared || r.mentions(b"http://www.w3.org/1999/xhtml")),
    |_, head| first_text(head, b"title"));
xml_variant!(RSS, RSS_INFO, dissect_rss, "rss", "RSS feed", ["rss"],
    "application/rss+xml",
    |r| r.is(b"rss") || (r.local() == b"RDF" && r.mentions(b"purl.org/rss")),
    |_, head| first_text(head, b"title"));
xml_variant!(ATOM, ATOM_INFO, dissect_atom, "atom", "Atom feed", ["atom"],
    "application/atom+xml",
    |r| r.local() == b"feed" && r.mentions(b"http://www.w3.org/2005/Atom"),
    |_, head| first_text(head, b"title"));
xml_variant!(GPX, GPX_INFO, dissect_gpx, "gpx", "GPS Exchange Format", ["gpx"],
    "application/gpx+xml", |r| r.local() == b"gpx",
    |r, _| attr(r, b"creator").map(|c| format!("created by {c}")));
xml_variant!(KML, KML_INFO, dissect_kml, "kml", "Keyhole Markup Language", ["kml"],
    "application/vnd.google-earth.kml+xml", |r| r.local() == b"kml",
    |_, head| first_text(head, b"name"));
xml_variant!(POM, POM_INFO, dissect_pom, "maven-pom", "Maven project (POM)", ["pom"],
    "application/xml",
    |r| r.is(b"project") && r.mentions(b"maven.apache.org/POM"),
    |_, head| first_text(head, b"artifactId"));
xml_variant!(XAML, XAML_INFO, dissect_xaml, "xaml", "XAML markup", ["xaml", "axaml"],
    "application/xaml+xml",
    |r| r.mentions(b"schemas.microsoft.com/winfx/2006/xaml") || r.mentions(b"github.com/avaloniaui")
        || r.mentions(b"schemas.microsoft.com/dotnet/2021/maui"),
    no_detail);
xml_variant!(MATHML, MATHML_INFO, dissect_mathml, "mathml", "MathML", ["mml", "mathml"],
    "application/mathml+xml", |r| r.local() == b"math", no_detail);
xml_variant!(XSLT, XSLT_INFO, dissect_xslt, "xslt", "XSLT stylesheet", ["xsl", "xslt"],
    "application/xslt+xml",
    |r| matches!(r.local(), b"stylesheet" | b"transform") && r.mentions(b"http://www.w3.org/1999/XSL/Transform"),
    |r, _| attr(r, b"version").map(|v| format!("version {v}")));
xml_variant!(XSD, XSD_INFO, dissect_xsd, "xsd", "XML Schema", ["xsd"],
    "application/xml",
    |r| r.local() == b"schema" && r.mentions(b"http://www.w3.org/2001/XMLSchema"),
    |r, _| attr(r, b"targetNamespace"));
xml_variant!(MSBUILD, MSBUILD_INFO, dissect_msbuild, "msbuild", "MSBuild project",
    ["csproj", "vbproj", "fsproj", "vcxproj", "props", "targets", "proj"],
    "application/xml",
    |r| r.is(b"Project") && (r.mentions(b"Sdk=") || r.mentions(b"schemas.microsoft.com/developer/msbuild")),
    |r, _| attr(r, b"Sdk"));
xml_variant!(COLLADA, COLLADA_INFO, dissect_collada, "collada", "COLLADA 3D asset", ["dae"],
    "model/vnd.collada+xml", |r| r.is(b"COLLADA"),
    |r, _| attr(r, b"version").map(|v| format!("version {v}")));
xml_variant!(TTML, TTML_INFO, dissect_ttml, "ttml", "Timed Text Markup Language", ["ttml", "dfxp"],
    "application/ttml+xml", |r| r.local() == b"tt" && r.mentions(b"/ttml"), no_detail);
xml_variant!(DASH, DASH_INFO, dissect_dash, "dash-mpd", "MPEG-DASH manifest", ["mpd"],
    "application/dash+xml", |r| r.local() == b"MPD",
    |r, _| attr(r, b"type").map(|t| format!("{t} presentation")));
xml_variant!(XLIFF, XLIFF_INFO, dissect_xliff, "xliff", "XLIFF localisation", ["xlf", "xliff"],
    "application/xliff+xml", |r| r.local() == b"xliff",
    |r, _| attr(r, b"version").map(|v| format!("version {v}")));
xml_variant!(OPF, OPF_INFO, dissect_opf, "opf", "EPUB package document", ["opf"],
    "application/oebps-package+xml",
    |r| r.local() == b"package" && r.mentions(b"http://www.idpf.org/2007/opf"),
    |_, head| first_text(head, b"dc:title"));
xml_variant!(OSM, OSM_INFO, dissect_osm, "osm", "OpenStreetMap data", ["osm"],
    "application/vnd.openstreetmap.data+xml", |r| r.is(b"osm"),
    |r, _| attr(r, b"generator"));
xml_variant!(XSPF, XSPF_INFO, dissect_xspf, "xspf", "XML Shareable Playlist", ["xspf"],
    "application/xspf+xml",
    |r| r.local() == b"playlist" && r.mentions(b"http://xspf.org/ns/0/"),
    |_, head| first_text(head, b"title"));
xml_variant!(TEI, TEI_INFO, dissect_tei, "tei", "TEI document", ["tei"],
    "application/tei+xml", |r| r.local() == b"TEI" || r.local() == b"teiCorpus",
    |_, head| first_text(head, b"title"));
xml_variant!(DOCBOOK, DOCBOOK_INFO, dissect_docbook, "docbook", "DocBook document", ["dbk", "docbook"],
    "application/docbook+xml", |r| r.mentions(b"http://docbook.org/ns/docbook"),
    |_, head| first_text(head, b"title"));
xml_variant!(ANDROID_MANIFEST, ANDROID_MANIFEST_INFO, dissect_android_manifest, "android-manifest",
    "Android manifest (text)", [], "application/xml",
    |r| r.is(b"manifest") && r.mentions(b"schemas.android.com/apk/res/android"),
    |r, _| attr(r, b"package"));
xml_variant!(WSDL, WSDL_INFO, dissect_wsdl, "wsdl", "WSDL service description", ["wsdl"],
    "application/wsdl+xml",
    |r| matches!(r.local(), b"definitions" | b"description") && r.mentions(b"wsdl"),
    |r, _| attr(r, b"name"));
xml_variant!(SOAP, SOAP_INFO, dissect_soap, "soap", "SOAP message", [], "application/soap+xml",
    |r| r.local() == b"Envelope" && r.mentions(b"soap"), no_detail);
xml_variant!(SITEMAP, SITEMAP_INFO, dissect_sitemap, "sitemap", "Sitemap", [], "application/xml",
    |r| matches!(r.local(), b"urlset" | b"sitemapindex") && r.mentions(b"sitemaps.org"), no_detail);
xml_variant!(DRAWIO, DRAWIO_INFO, dissect_drawio, "drawio", "draw.io diagram", ["drawio"],
    "application/vnd.jgraph.mxfile", |r| r.is(b"mxfile") || r.is(b"mxGraphModel"),
    |r, _| attr(r, b"host"));
xml_variant!(OPML, OPML_INFO, dissect_opml, "opml", "OPML outline", ["opml"],
    "text/x-opml", |r| r.is(b"opml"), |_, head| first_text(head, b"title"));
xml_variant!(FB2, FB2_INFO, dissect_fb2, "fb2", "FictionBook e-book", ["fb2"],
    "application/x-fictionbook+xml", |r| r.is(b"FictionBook"),
    |_, head| first_text(head, b"book-title"));
xml_variant!(GRAPHML, GRAPHML_INFO, dissect_graphml, "graphml", "GraphML graph", ["graphml"],
    "application/graphml+xml", |r| r.local() == b"graphml", no_detail);
xml_variant!(SMIL, SMIL_INFO, dissect_smil, "smil", "SMIL presentation", ["smil", "smi", "wpl"],
    "application/smil+xml", |r| r.local() == b"smil", |_, head| first_text(head, b"title"));
xml_variant!(NZB, NZB_INFO, dissect_nzb, "nzb", "NZB Usenet index", ["nzb"],
    "application/x-nzb", |r| r.local() == b"nzb", no_detail);
xml_variant!(JUNIT, JUNIT_INFO, dissect_junit, "junit-xml", "JUnit test report", [],
    "application/xml", |r| matches!(r.local(), b"testsuites" | b"testsuite"),
    |r, _| match (attr(r, b"tests"), attr(r, b"failures")) {
        (Some(t), Some(f)) => Some(format!("{t} tests, {f} failures")),
        (t, _) => t.map(|t| format!("{t} tests")),
    });
xml_variant!(MUSICXML, MUSICXML_INFO, dissect_musicxml, "musicxml", "MusicXML score", ["musicxml"],
    "application/vnd.recordare.musicxml+xml",
    |r| matches!(r.local(), b"score-partwise" | b"score-timewise"),
    |_, head| first_text(head, b"work-title").or_else(|| first_text(head, b"movement-title")));
xml_variant!(X3D, X3D_INFO, dissect_x3d, "x3d", "X3D scene", ["x3d"],
    "model/x3d+xml", |r| r.is(b"X3D"), |r, _| attr(r, b"profile"));
xml_variant!(WIX, WIX_INFO, dissect_wix, "wix", "WiX installer source", ["wxs", "wxi", "wxl"],
    "application/xml", |r| r.is(b"Wix"), no_detail);
xml_variant!(NUSPEC, NUSPEC_INFO, dissect_nuspec, "nuspec", "NuGet package manifest", ["nuspec"],
    "application/xml", |r| r.local() == b"package" && r.mentions(b"nuspec.xsd"),
    |_, head| first_text(head, b"id"));
xml_variant!(XIB, XIB_INFO, dissect_xib, "interface-builder", "Interface Builder document",
    ["xib", "storyboard"], "application/xml",
    |r| r.is(b"document") && r.mentions(b"com.apple.InterfaceBuilder"), |r, _| attr(r, b"type"));
xml_variant!(GLADE, GLADE_INFO, dissect_glade, "gtkbuilder", "GtkBuilder UI definition", ["ui", "glade"],
    "application/x-gtk-builder", |r| r.is(b"interface"), no_detail);
xml_variant!(FLAT_ODF, FLAT_ODF_INFO, dissect_flat_odf, "flat-odf", "Flat OpenDocument",
    ["fodt", "fods", "fodp", "fodg"], "application/vnd.oasis.opendocument.text-flat-xml",
    |r| r.is(b"office:document"), |r, _| attr(r, b"office:mimetype"));
xml_variant!(VSTEMPLATE, VSTEMPLATE_INFO, dissect_vsixmanifest, "vsix-manifest", "VSIX extension manifest",
    ["vsixmanifest"], "application/xml", |r| r.local() == b"PackageManifest", no_detail);

/// The value of attribute `name` in the root's start tag.
fn attr(root: &Root, name: &[u8]) -> Option<String> {
    let span = Span::new(crate::span::SourceId(0), 0, 0);
    let mut full = b"<".to_vec();
    full.extend_from_slice(&root.tag);
    let tag = Piece::new(&full, span);
    attributes(tag)
        .into_iter()
        .find(|a| a.name.bytes() == name)
        .and_then(|a| a.value)
        .map(|v| decode_entities(&v.text(), false))
}

/// The text of the first `<tag>` in `head`, for annotations.
pub fn first_text(head: &[u8], tag: &[u8]) -> Option<String> {
    let mut open = b"<".to_vec();
    open.extend_from_slice(tag);
    let mut at = 0usize;
    loop {
        let rest = head.get(at..)?;
        let i = probe::find(rest, &open)?;
        let after = rest.get(i.saturating_add(open.len())..)?;
        if matches!(after.first(), Some(b'>' | b' ' | b'\t' | b'\r' | b'\n')) {
            let gt = after.iter().position(|&b| b == b'>')?;
            let body = after.get(gt.saturating_add(1)..)?;
            let end = body.iter().position(|&b| b == b'<')?;
            let mut text = body.get(..end).unwrap_or_default();
            if let Some(cdata) = body.strip_prefix(b"<![CDATA[") {
                text = cdata.get(..probe::find(cdata, b"]]>")?).unwrap_or_default();
            }
            let text = decode_entities(&super::encoding::decode_8bit(text), false);
            let text = preview(&text, 80);
            return (!text.is_empty()).then_some(text);
        }
        at = at.saturating_add(i).saturating_add(1);
    }
}

fn svg_detail(root: &Root, _: &[u8]) -> Option<String> {
    match (attr(root, b"width"), attr(root, b"height"), attr(root, b"viewBox")) {
        (Some(w), Some(h), _) => Some(format!("{w}×{h}")),
        (_, _, Some(v)) => Some(format!("viewBox {v}")),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Lexer

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Mode {
    Xml,
    Html,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `<?xml ...?>`
    Decl,
    /// `<?target ...?>`
    Pi,
    Comment,
    Cdata,
    Doctype,
    /// Any other `<!...>`.
    Bang,
    Start,
    End,
    Text,
    Eof,
}

#[derive(Clone, Copy, Debug)]
pub struct Tok {
    pub kind: Kind,
    pub start: u64,
    pub end: u64,
    /// The tag name (or processing instruction target).
    pub name_start: u64,
    pub name_end: u64,
    /// `<.../>`
    pub empty: bool,
    /// Whether the markup was properly terminated.
    pub closed: bool,
}

pub fn is_name_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_' || b == b':' || b >= 0x80
}

pub fn is_name(b: u8) -> bool {
    is_name_start(b) || b.is_ascii_digit() || b == b'-' || b == b'.'
}

/// HTML elements whose content is raw text up to their end tag.
const RAW_TEXT: &[&[u8]] = &[
    b"script", b"style", b"textarea", b"title", b"xmp", b"noembed", b"noframes", b"iframe",
];

/// HTML elements that never have content.
pub const VOID: &[&[u8]] = &[
    b"area", b"base", b"br", b"col", b"embed", b"hr", b"img", b"input", b"link", b"meta",
    b"param", b"source", b"track", b"wbr", b"keygen", b"basefont", b"frame",
];

pub struct Lexer<'a> {
    pub scan: Scanner<'a>,
    pub pos: u64,
    mode: Mode,
    /// In HTML, the raw-text element whose content comes next.
    raw: Option<Vec<u8>>,
}

impl<'a> Lexer<'a> {
    pub fn new(cx: &'a Cx, region: Span, mode: Mode) -> Self {
        Lexer {
            scan: Scanner::new(cx, region),
            pos: 0,
            mode,
            raw: None,
        }
    }

    pub fn seek(&mut self, pos: u64) {
        self.pos = pos;
        self.raw = None;
    }

    pub fn span(&self, t: &Tok) -> Span {
        self.scan.span(t.start, t.end)
    }

    fn tok(kind: Kind, start: u64, end: u64, closed: bool) -> Tok {
        Tok {
            kind,
            start,
            end,
            name_start: start,
            name_end: start,
            empty: false,
            closed,
        }
    }

    /// The tag name of `t` (lowercased in HTML).
    pub async fn name(&mut self, t: &Tok) -> Result<Vec<u8>> {
        let mut name = self.scan.bytes(t.name_start, t.name_end, 256).await?;
        if self.mode == Mode::Html {
            name.make_ascii_lowercase();
        }
        Ok(name)
    }

    /// The bytes of `t` (at most `cap`).
    pub async fn owned(&mut self, t: &Tok, cap: usize) -> Result<Owned> {
        self.scan.owned(t.start, t.end, cap).await
    }

    pub async fn next(&mut self) -> Result<Tok> {
        let start = self.pos;
        if let Some(raw) = self.raw.take() {
            let mut close = b"</".to_vec();
            close.extend_from_slice(&raw);
            let end = self
                .scan
                .find_seq_nocase(start, &close)
                .await?
                .unwrap_or(self.scan.len());
            if end > start {
                self.pos = end;
                return Ok(Self::tok(Kind::Text, start, end, true));
            }
        }
        let tok = match self.scan.byte(start).await? {
            None => Self::tok(Kind::Eof, start, start, true),
            Some(b'<') => self.markup(start).await?,
            Some(_) => self.text(start).await?,
        };
        self.pos = tok.end.max(start.saturating_add(1)).min(self.scan.len().max(start));
        if tok.kind == Kind::Eof {
            self.pos = start;
        }
        Ok(tok)
    }

    async fn text(&mut self, start: u64) -> Result<Tok> {
        let end = self
            .scan
            .find(start.saturating_add(1), |b| b == b'<')
            .await?
            .unwrap_or(self.scan.len());
        Ok(Self::tok(Kind::Text, start, end, true))
    }

    /// Skips to just past `terminator`, or to the end.
    async fn until(&mut self, from: u64, terminator: &[u8]) -> Result<(u64, bool)> {
        Ok(match self.scan.find_seq(from, terminator).await? {
            Some(at) => (at.saturating_add(to_u64(terminator.len())), true),
            None => (self.scan.len(), false),
        })
    }

    async fn markup(&mut self, start: u64) -> Result<Tok> {
        let at = |n: u64| start.saturating_add(n);
        match self.scan.byte(at(1)).await? {
            Some(b'?') => {
                let name_end = self
                    .scan
                    .find(at(2), |b| !is_name(b))
                    .await?
                    .unwrap_or(self.scan.len());
                let terminator: &[u8] = if self.mode == Mode::Html { b">" } else { b"?>" };
                let (end, closed) = self.until(at(2), terminator).await?;
                let target = self.scan.bytes(at(2), name_end, 8).await?;
                let kind = if target.eq_ignore_ascii_case(b"xml") {
                    Kind::Decl
                } else {
                    Kind::Pi
                };
                Ok(Tok {
                    name_start: at(2),
                    name_end,
                    ..Self::tok(kind, start, end, closed)
                })
            }
            Some(b'!') => {
                if self.scan.matches(at(2), b"--").await? {
                    let (end, closed) = self.until(at(4), b"-->").await?;
                    Ok(Self::tok(Kind::Comment, start, end, closed))
                } else if self.scan.matches(at(2), b"[CDATA[").await? {
                    let (end, closed) = self.until(at(9), b"]]>").await?;
                    Ok(Self::tok(Kind::Cdata, start, end, closed))
                } else if self.scan.matches_nocase(at(2), b"DOCTYPE").await? {
                    let (end, closed) = self.doctype(at(9)).await?;
                    Ok(Self::tok(Kind::Doctype, start, end, closed))
                } else {
                    let (end, closed) = self.until(at(2), b">").await?;
                    Ok(Self::tok(Kind::Bang, start, end, closed))
                }
            }
            Some(b'/') => {
                let name_end = self
                    .scan
                    .find(at(2), |b| !is_name(b))
                    .await?
                    .unwrap_or(self.scan.len());
                let (end, closed) = self.until(name_end, b">").await?;
                Ok(Tok {
                    name_start: at(2),
                    name_end,
                    ..Self::tok(Kind::End, start, end, closed)
                })
            }
            Some(b) if is_name_start(b) => self.start_tag(start).await,
            _ => self.text(start).await,
        }
    }

    async fn doctype(&mut self, from: u64) -> Result<(u64, bool)> {
        let mut quote = None;
        let mut depth = 0u32;
        let mut pos = from;
        while let Some(b) = self.scan.byte(pos).await? {
            pos = pos.saturating_add(1);
            match (quote, b) {
                (Some(q), _) if b == q => quote = None,
                (Some(_), _) => {}
                (None, b'"' | b'\'') => quote = Some(b),
                (None, b'[') => depth = depth.saturating_add(1),
                (None, b']') => depth = depth.saturating_sub(1),
                (None, b'>') if depth == 0 => return Ok((pos, true)),
                _ => {}
            }
        }
        Ok((pos, false))
    }

    async fn start_tag(&mut self, start: u64) -> Result<Tok> {
        let name_start = start.saturating_add(1);
        let name_end = self
            .scan
            .find(name_start, |b| !is_name(b))
            .await?
            .unwrap_or(self.scan.len());
        let mut pos = name_end;
        let mut quote = None;
        let mut last = 0u8;
        let (end, closed) = loop {
            let Some(b) = self.scan.byte(pos).await? else {
                break (pos, false);
            };
            match (quote, b) {
                (Some(q), _) if b == q => quote = None,
                (Some(_), _) => {}
                (None, b'"' | b'\'') => quote = Some(b),
                (None, b'>') => break (pos.saturating_add(1), true),
                // A new tag starts: this one was never closed.
                (None, b'<') => break (pos, false),
                _ => {}
            }
            if !b.is_ascii_whitespace() {
                last = b;
            }
            pos = pos.saturating_add(1);
        };
        let empty = closed && last == b'/';
        let tok = Tok {
            kind: Kind::Start,
            start,
            end,
            name_start,
            name_end,
            empty,
            closed,
        };
        if self.mode == Mode::Html && !empty {
            let name = self.name(&tok).await?;
            if RAW_TEXT.contains(&name.as_slice()) {
                self.raw = Some(name);
            }
        }
        Ok(tok)
    }
}

// ---------------------------------------------------------------------------
// Attributes and entities

pub struct Attr<'a> {
    pub name: Piece<'a>,
    /// The value without quotes, if there is one.
    pub value: Option<Piece<'a>>,
    /// The whole attribute (`name="value"`).
    pub whole: Piece<'a>,
}

/// The attributes of a start tag (`tag` starts at `<`).
pub fn attributes(tag: Piece<'_>) -> Vec<Attr<'_>> {
    let name_len = tag.from(1).bytes().iter().take_while(|&&b| is_name(b)).count();
    let mut rest = tag.from(name_len.saturating_add(1));
    let mut out = Vec::new();
    loop {
        rest = rest.trim_start();
        while rest.first() == Some(b'/') {
            rest = rest.from(1).trim_start();
        }
        match rest.first() {
            None | Some(b'>') => break,
            _ => {}
        }
        let n = rest
            .find_by(|b| b.is_ascii_whitespace() || matches!(b, b'=' | b'>' | b'/'))
            .unwrap_or(rest.len())
            .max(1);
        let name = rest.to(n);
        let mut after = rest.from(n).trim_start();
        let mut value = None;
        if after.first() == Some(b'=') {
            after = after.from(1).trim_start();
            match after.first() {
                Some(q @ (b'"' | b'\'')) => {
                    let body = after.from(1);
                    let end = body.find(q).unwrap_or(body.len());
                    value = Some(body.to(end));
                    after = body.from(end.saturating_add(1));
                }
                _ => {
                    let end = after
                        .find_by(|b| b.is_ascii_whitespace() || b == b'>')
                        .unwrap_or(after.len());
                    value = Some(after.to(end));
                    after = after.from(end);
                }
            }
        }
        out.push(Attr {
            name,
            value,
            whole: rest.before(&after),
        });
        rest = after;
    }
    out
}

/// Named character references understood in HTML (beyond XML's five).
const HTML_ENTITIES: &[(&str, char)] = &[
    ("nbsp", '\u{a0}'),
    ("copy", '©'),
    ("reg", '®'),
    ("trade", '™'),
    ("mdash", '—'),
    ("ndash", '–'),
    ("hellip", '…'),
    ("laquo", '«'),
    ("raquo", '»'),
    ("ldquo", '“'),
    ("rdquo", '”'),
    ("lsquo", '‘'),
    ("rsquo", '’'),
    ("bull", '•'),
    ("middot", '·'),
    ("deg", '°'),
    ("euro", '€'),
    ("pound", '£'),
    ("yen", '¥'),
    ("cent", '¢'),
    ("sect", '§'),
    ("para", '¶'),
    ("times", '×'),
    ("divide", '÷'),
    ("plusmn", '±'),
    ("eacute", 'é'),
    ("egrave", 'è'),
    ("aacute", 'á'),
    ("agrave", 'à'),
    ("ouml", 'ö'),
    ("uuml", 'ü'),
    ("auml", 'ä'),
    ("szlig", 'ß'),
    ("ccedil", 'ç'),
    ("ntilde", 'ñ'),
    ("larr", '←'),
    ("rarr", '→'),
    ("uarr", '↑'),
    ("darr", '↓'),
    ("shy", '\u{ad}'),
    ("zwj", '\u{200d}'),
    ("zwnj", '\u{200c}'),
];

/// Replaces character and entity references.
pub fn decode_entities(text: &str, html: bool) -> String {
    if !text.contains('&') {
        return text.to_owned();
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find('&') {
        out.push_str(rest.get(..i).unwrap_or_default());
        let after = rest.get(i.saturating_add(1)..).unwrap_or_default();
        let end = after
            .char_indices()
            .take(32)
            .find(|&(_, c)| c == ';')
            .map(|(j, _)| j);
        let decoded = end.and_then(|j| {
            let name = after.get(..j)?;
            let c = if let Some(num) = name.strip_prefix('#') {
                let code = match num.strip_prefix(['x', 'X']) {
                    Some(hex) => u32::from_str_radix(hex, 16).ok()?,
                    None => num.parse::<u32>().ok()?,
                };
                char::from_u32(code)?
            } else {
                match name {
                    "lt" => '<',
                    "gt" => '>',
                    "amp" => '&',
                    "quot" => '"',
                    "apos" => '\'',
                    _ if html => HTML_ENTITIES.iter().find(|(n, _)| *n == name)?.1,
                    _ => return None,
                }
            };
            Some((c, j))
        });
        match decoded {
            Some((c, j)) => {
                out.push(c);
                rest = after.get(j.saturating_add(1)..).unwrap_or_default();
            }
            None => {
                out.push('&');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

// ---------------------------------------------------------------------------
// Element extents

/// How an element's content ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Closure {
    /// By its end tag.
    Explicit,
    /// By something HTML lets close it (a sibling, a parent's end tag).
    Implicit,
    /// By the end of the input.
    Unclosed,
}

/// What skipping over an element found.
#[derive(Clone, Copy, Debug)]
pub struct Extent {
    pub end: u64,
    pub closure: Closure,
    /// Child elements.
    pub elements: u64,
    /// Child nodes other than whitespace (elements, text, comments, ...).
    pub nodes: u64,
    /// The only child, if it is text (or CDATA): its token.
    pub text: Option<Tok>,
}

/// Whether, in HTML, a start tag `new` implicitly closes an open `open`.
fn html_closes(open: &[u8], new: &[u8]) -> bool {
    const BLOCK: &[&[u8]] = &[
        b"p", b"div", b"ul", b"ol", b"dl", b"table", b"h1", b"h2", b"h3", b"h4", b"h5", b"h6",
        b"pre", b"blockquote", b"form", b"hr", b"section", b"article", b"header", b"footer",
        b"nav", b"aside", b"main", b"figure", b"fieldset", b"address", b"details", b"menu",
    ];
    match open {
        b"p" => BLOCK.contains(&new),
        b"li" => new == b"li",
        b"dt" | b"dd" => matches!(new, b"dt" | b"dd"),
        b"option" => matches!(new, b"option" | b"optgroup"),
        b"td" | b"th" => matches!(new, b"td" | b"th" | b"tr" | b"tbody" | b"thead" | b"tfoot"),
        b"tr" => matches!(new, b"tr" | b"tbody" | b"thead" | b"tfoot"),
        b"thead" | b"tbody" | b"tfoot" => matches!(new, b"tbody" | b"thead" | b"tfoot"),
        b"head" => new == b"body",
        _ => false,
    }
}

/// The deepest open element tracked by name; deeper ones are only counted.
const MAX_STACK: usize = 512;

/// Skips the content of the element whose start tag `open` was just read.
///
/// `ancestors` are the names of the open elements around it: an end tag
/// for one of them closes this element too; other unmatched end tags are
/// ignored.
pub async fn skip_element(
    lex: &mut Lexer<'_>,
    open: &Tok,
    ancestors: &[Vec<u8>],
) -> Result<Extent> {
    let mut ext = Extent {
        end: open.end,
        closure: Closure::Explicit,
        elements: 0,
        nodes: 0,
        text: None,
    };
    let html = lex.mode == Mode::Html;
    let name = lex.name(open).await?;
    if open.empty || !open.closed || (html && VOID.contains(&name.as_slice())) {
        if !open.closed {
            ext.closure = Closure::Unclosed;
        }
        return Ok(ext);
    }
    let mut stack: Vec<Vec<u8>> = vec![name];
    let mut untracked = 0u64;
    let mut only_text: Option<Tok> = None;
    loop {
        lex.scan.tick().await;
        let t = lex.next().await?;
        let top = stack.len() == 1 && untracked == 0;
        match t.kind {
            Kind::Eof => {
                ext.end = t.start;
                ext.closure = if html {
                    Closure::Implicit
                } else {
                    Closure::Unclosed
                };
                break;
            }
            Kind::Start => {
                let child = lex.name(&t).await?;
                if html {
                    while untracked == 0
                        && stack.last().is_some_and(|open| html_closes(open, &child))
                    {
                        stack.pop();
                    }
                    if stack.is_empty() {
                        lex.seek(t.start);
                        ext.end = t.start;
                        ext.closure = Closure::Implicit;
                        break;
                    }
                }
                let top = stack.len() == 1 && untracked == 0;
                if top {
                    ext.elements = ext.elements.saturating_add(1);
                    ext.nodes = ext.nodes.saturating_add(1);
                }
                let void = html && VOID.contains(&child.as_slice());
                if !t.empty && t.closed && !void {
                    if stack.len() < MAX_STACK {
                        stack.push(child);
                    } else {
                        untracked = untracked.saturating_add(1);
                    }
                }
            }
            Kind::End => {
                if untracked > 0 {
                    untracked = untracked.saturating_sub(1);
                    continue;
                }
                let child = lex.name(&t).await?;
                if let Some(i) = stack.iter().rposition(|n| *n == child) {
                    stack.truncate(i);
                    if stack.is_empty() {
                        ext.end = t.end;
                        break;
                    }
                } else if ancestors.contains(&child) {
                    // An end tag for an ancestor closes us too.
                    lex.seek(t.start);
                    ext.end = t.start;
                    ext.closure = Closure::Implicit;
                    break;
                }
            }
            Kind::Text => {
                if top && !is_blank(lex, &t).await? {
                    ext.nodes = ext.nodes.saturating_add(1);
                    only_text = Some(t);
                }
            }
            Kind::Cdata if top => {
                ext.nodes = ext.nodes.saturating_add(1);
                only_text = Some(t);
            }
            _ if top => ext.nodes = ext.nodes.saturating_add(1),
            _ => {}
        }
    }
    if ext.elements == 0 && ext.nodes == 1 {
        ext.text = only_text;
    }
    Ok(ext)
}

async fn is_blank(lex: &mut Lexer<'_>, t: &Tok) -> Result<bool> {
    Ok(lex
        .scan
        .find(t.start, |b| !b.is_ascii_whitespace())
        .await?
        .is_none_or(|p| p >= t.end))
}

/// The text of a text or CDATA token, entities decoded (capped).
pub async fn token_text(lex: &mut Lexer<'_>, t: &Tok) -> Result<String> {
    let cap = VALUE_CAP.saturating_mul(4);
    let owned = lex.owned(t, cap).await?;
    let p = owned.piece();
    Ok(match t.kind {
        Kind::Cdata => {
            let inner = p.from(9);
            let inner = inner.strip_suffix(b"]]>").unwrap_or(inner);
            inner.text()
        }
        Kind::Comment => {
            let inner = p.from(4);
            inner.strip_suffix(b"-->").unwrap_or(inner).text()
        }
        _ => decode_entities(&p.text(), lex.mode == Mode::Html),
    })
}

// ---------------------------------------------------------------------------
// Element nodes

type Bindings = Arc<Vec<(String, String)>>;

/// The state of a lazy element node.
#[derive(Clone)]
pub struct Elem {
    pub input: Input,
    /// From `<` of the start tag to the end of the element.
    pub span: Span,
    pub mode: Mode,
    /// Namespace prefixes in scope (outside this element).
    pub ns: Bindings,
    /// Names of the enclosing elements.
    pub ancestors: Ancestors,
}

pub type Ancestors = Arc<Vec<Vec<u8>>>;

/// Namespace declarations in `attrs`, added to `ns`.
fn bind(ns: &Bindings, attrs: &[Attr<'_>]) -> Bindings {
    let mut added = Vec::new();
    for a in attrs {
        let name = a.name.bytes();
        let prefix = if name == b"xmlns" {
            Some(String::new())
        } else {
            name.strip_prefix(b"xmlns:")
                .map(|p| String::from_utf8_lossy(p).into_owned())
        };
        if let Some(prefix) = prefix {
            added.push((prefix, a.value.map(|v| v.text()).unwrap_or_default()));
        }
    }
    if added.is_empty() {
        return Arc::clone(ns);
    }
    let mut all: Vec<(String, String)> = ns.iter().cloned().collect();
    all.extend(added);
    Arc::new(all)
}

fn resolve<'b>(ns: &'b Bindings, name: &[u8]) -> Option<&'b str> {
    let prefix = match name.iter().position(|&b| b == b':') {
        Some(i) => name.get(..i).unwrap_or_default(),
        None => b"",
    };
    ns.iter()
        .rev()
        .find(|(p, _)| p.as_bytes() == prefix)
        .map(|(_, uri)| uri.as_str())
        .filter(|uri| !uri.is_empty())
}

/// Builds the node for an element whose start tag is `open` and whose
/// extent is `ext`.
async fn element_node(
    lex: &mut Lexer<'_>,
    open: &Tok,
    ext: &Extent,
    input: Input,
    ns: &Bindings,
    ancestors: &Ancestors,
) -> Result<Node> {
    let tag = lex.owned(open, 4096).await?;
    let piece = tag.piece();
    let attrs = attributes(piece);
    let raw_name = lex.scan.bytes(open.name_start, open.name_end, 256).await?;
    let name = String::from_utf8_lossy(&raw_name).into_owned();
    let span = lex.scan.span(open.start, ext.end);
    let scope = bind(ns, &attrs);
    let mut node = Node::new(name).span(span);
    if let Some(uri) = resolve(&scope, &raw_name) {
        node = node.desc(format!("namespace {uri}"));
    }
    // Namespace declarations are noise in a summary (they are children).
    let shown: Vec<&Attr<'_>> = attrs
        .iter()
        .filter(|a| !a.name.starts_with(b"xmlns"))
        .collect();
    let mut summary: Vec<String> = shown.iter().take(6).map(|a| a.whole.text()).collect();
    if shown.len() > 6 {
        summary.push("…".to_owned());
    }
    let mut summary = preview(&summary.join(" "), 100);
    if ext.elements > 0 {
        let count = plural(ext.elements, "element", "elements");
        summary = if summary.is_empty() {
            count
        } else {
            format!("{summary} ({count})")
        };
    }
    if let Some(t) = ext.text {
        let text = token_text(lex, &t).await?;
        let (value, _) = super::decode::cap(text.trim(), VALUE_CAP);
        node = node.value(Value::Text(value));
    }
    if !summary.is_empty() {
        node = node.summary(summary);
    }
    match ext.closure {
        Closure::Unclosed => node = node.diag(Diagnostic::new(DiagKind::Truncated, "element not closed")),
        Closure::Implicit if lex.mode == Mode::Xml => {
            node = node.diag(Diagnostic::malformed("end tag missing"));
        }
        _ => {}
    }
    if attrs.is_empty() && (ext.nodes == 0 || ext.text.is_some()) {
        return Ok(node);
    }
    Ok(node.lazy(
        crate::expander!(self::element: Elem),
        Elem {
            input,
            span,
            mode: lex.mode,
            ns: Arc::clone(ns),
            ancestors: Arc::clone(ancestors),
        },
    ))
}

/// Expands an element: attributes, then content.
pub async fn element(cx: Cx, e: Elem) -> Result<()> {
    let mut lex = Lexer::new(&cx, e.span, e.mode);
    let open = lex.next().await?;
    if open.kind != Kind::Start {
        return Err(Diagnostic::malformed("expected a start tag").at(lex.span(&open)));
    }
    let own_name = lex.name(&open).await?;
    let tag = lex.owned(&open, 1 << 20).await?;
    let attrs = attributes(tag.piece());
    for a in &attrs {
        let mut node = Node::new(format!("@{}", a.name.text())).span(a.whole.span());
        if let Some(v) = a.value {
            let text = decode_entities(&v.text(), e.mode == Mode::Html);
            node = text_node(format!("@{}", a.name.text()), v.span(), &text);
        }
        cx.push(node).await;
    }
    let ns = bind(&e.ns, &attrs);
    if open.empty || (e.mode == Mode::Html && VOID.contains(&own_name.as_slice())) {
        return Ok(());
    }
    let mut inner: Vec<Vec<u8>> = e.ancestors.iter().take(MAX_STACK).cloned().collect();
    inner.push(own_name.clone());
    content(&cx, &mut lex, e.input, &ns, Some(&own_name), &Arc::new(inner)).await
}

/// Pushes the nodes of element content (or of the document top level when
/// `own` is `None`) until the matching end tag or the end of the region.
async fn content(
    cx: &Cx,
    lex: &mut Lexer<'_>,
    input: Input,
    ns: &Bindings,
    own: Option<&[u8]>,
    ancestors: &Ancestors,
) -> Result<()> {
    loop {
        let t = lex.next().await?;
        let span = lex.span(&t);
        let node = match t.kind {
            // An unclosed element is flagged on its node.
            Kind::Eof => return Ok(()),
            Kind::End => {
                let name = lex.name(&t).await?;
                if Some(name.as_slice()) == own {
                    return Ok(());
                }
                Node::new("Stray end tag")
                    .span(span)
                    .value(Value::Text(String::from_utf8_lossy(&name).into_owned()))
                    .diag(Diagnostic::malformed("end tag without a matching start tag"))
            }
            Kind::Start => {
                let ext = skip_element(lex, &t, ancestors).await?;
                element_node(lex, &t, &ext, input, ns, ancestors).await?
            }
            Kind::Text => {
                if is_blank(lex, &t).await? {
                    continue;
                }
                text_node("#text", span, token_text(lex, &t).await?.trim())
            }
            Kind::Cdata => text_node("#cdata", span, &token_text(lex, &t).await?),
            Kind::Comment => text_node("#comment", span, token_text(lex, &t).await?.trim()),
            Kind::Decl => Node::new("XML declaration")
                .span(span)
                .lazy(declaration, (span, lex.mode)),
            Kind::Pi => {
                let target = lex.name(&t).await?;
                let owned = lex.owned(&t, VALUE_CAP).await?;
                let data = owned.piece().from(target.len().saturating_add(2));
                let data = data.strip_suffix(b"?>").unwrap_or(data).trim();
                text_node(
                    format!("?{}", String::from_utf8_lossy(&target)),
                    span,
                    &data.text(),
                )
            }
            Kind::Doctype => doctype_node(lex, &t).await?,
            Kind::Bang => text_node("<!…>", span, &lex.owned(&t, VALUE_CAP).await?.piece().text()),
        };
        let node = if t.closed {
            node
        } else {
            node.diag(Diagnostic::new(DiagKind::Truncated, "markup not terminated"))
        };
        cx.push(node).await;
    }
}

async fn declaration(cx: Cx, (span, mode): (Span, Mode)) -> Result<()> {
    let owned = Scanner::new(&cx, span).owned(0, span.len, 1024).await?;
    let p = owned.piece();
    // `<?xml version=...?>` parses like a start tag.
    let inner = p.from(1);
    let inner = inner.strip_suffix(b"?>").unwrap_or(inner);
    for a in attributes(inner) {
        if let Some(v) = a.value {
            let name = match a.name.bytes() {
                b"version" => "Version".to_owned(),
                b"encoding" => "Encoding".to_owned(),
                b"standalone" => "Standalone".to_owned(),
                other => String::from_utf8_lossy(other).into_owned(),
            };
            cx.emit(text_node(name, v.span(), &decode_entities(&v.text(), mode == Mode::Html)));
        }
    }
    Ok(())
}

async fn doctype_node(lex: &mut Lexer<'_>, t: &Tok) -> Result<Node> {
    let owned = lex.owned(t, 64 * 1024).await?;
    let p = owned.piece();
    let body = p.from(9).trim_start();
    let (name, rest) = body.split_word();
    let name = name.trim_end_matches(|b| b == b'>' || b == b'[');
    let mut node = Node::new("DOCTYPE")
        .span(lex.span(t))
        .value(Value::Text(name.text()));
    let ids: Vec<String> = rest
        .split(b'"')
        .skip(1)
        .step_by(2)
        .map(|s| s.text())
        .collect();
    if !ids.is_empty() {
        node = node.summary(ids.join(" "));
    }
    if let Some(i) = p.find(b'[') {
        let subset = p.from(i);
        let subset = subset.to(subset.rfind(b']').map_or(subset.len(), |j| j.saturating_add(1)));
        node = node.lazy(internal_subset, subset.span());
    }
    Ok(node)
}

/// Declarations of a DOCTYPE's internal subset.
async fn internal_subset(cx: Cx, span: Span) -> Result<()> {
    let mut lex = Lexer::new(&cx, span, Mode::Xml);
    lex.seek(1);
    loop {
        let t = lex.next().await?;
        match t.kind {
            Kind::Eof => return Ok(()),
            Kind::Text => {}
            _ => {
                let text = lex.owned(&t, VALUE_CAP).await?.piece().text();
                let kind = text
                    .trim_start_matches("<!")
                    .split_whitespace()
                    .next()
                    .unwrap_or("declaration")
                    .to_owned();
                cx.push(text_node(kind, lex.span(&t), &text)).await;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Documents

/// Below this size the root element's end is found by scanning; above it,
/// from the end of the input.
const SCAN_LIMIT: u64 = 1 << 20;

/// Finds where the root element ends: by scanning small documents, from the
/// tail of large ones (its end tag is normally the last markup).
async fn root_extent(lex: &mut Lexer<'_>, open: &Tok) -> Result<Extent> {
    let total = lex.scan.len();
    if total <= SCAN_LIMIT || open.empty {
        return skip_element(lex, open, &[]).await;
    }
    let name = lex.name(open).await?;
    let window = 64 * 1024u64;
    let from = total.saturating_sub(window).max(open.end);
    let tail = lex.scan.bytes(from, total, 1 << 16).await?;
    let mut close = b"</".to_vec();
    close.extend_from_slice(&name);
    let found = tail
        .windows(close.len())
        .enumerate()
        .rev()
        .filter(|(_, w)| {
            if lex.mode == Mode::Html {
                w.eq_ignore_ascii_case(&close)
            } else {
                *w == close.as_slice()
            }
        })
        .find_map(|(i, _)| {
            let after = tail.get(i.saturating_add(close.len())..)?;
            let gt = after.iter().position(|&b| !b.is_ascii_whitespace())?;
            (after.get(gt) == Some(&b'>')).then(|| i.saturating_add(close.len()).saturating_add(gt).saturating_add(1))
        });
    let unknown = Extent {
        end: total,
        closure: if lex.mode == Mode::Html {
            Closure::Implicit
        } else {
            Closure::Unclosed
        },
        elements: 0,
        nodes: 1,
        text: None,
    };
    Ok(match found {
        Some(end) => Extent {
            end: from.saturating_add(to_u64(end)),
            closure: Closure::Explicit,
            ..unknown
        },
        None => unknown,
    })
}

/// Dissects a markup document: prolog, root element(s), epilog.
pub async fn document(cx: &Cx, input: Input, mode: Mode) -> Result<()> {
    let prepared = prepare(cx, input).await?;
    let input = prepared.input(input);
    let mut lex = Lexer::new(cx, prepared.span, mode);
    let ns: Bindings = Arc::new(vec![
        ("xml".to_owned(), "http://www.w3.org/XML/1998/namespace".to_owned()),
    ]);
    let mut roots = 0u32;
    loop {
        let t = lex.next().await?;
        if t.kind != Kind::Start {
            if t.kind == Kind::Eof {
                break;
            }
            // Everything else at the top level: reuse the content walker for
            // one token.
            lex.seek(t.start);
            top_level_token(cx, &mut lex, input, &ns).await?;
            continue;
        }
        roots = roots.saturating_add(1);
        let ext = root_extent(&mut lex, &t).await?;
        let mut node = element_node(&mut lex, &t, &ext, input, &ns, &Arc::default()).await?;
        if roots == 2 && mode == Mode::Xml {
            node = node.diag(Diagnostic::malformed("more than one root element"));
        }
        cx.push(node).await;
        lex.seek(ext.end.max(t.end));
    }
    if roots == 0 {
        cx.diag(Diagnostic::malformed("no root element"));
    }
    Ok(())
}

/// Pushes the node for the single (non-element) token at the lexer.
async fn top_level_token(cx: &Cx, lex: &mut Lexer<'_>, input: Input, ns: &Bindings) -> Result<()> {
    let start = lex.pos;
    let t = lex.next().await?;
    // Limit the content walker to this token.
    let region = lex.scan.span(start, t.end);
    let mut one = Lexer::new(cx, region, lex.mode);
    if t.kind == Kind::Text && !is_blank(lex, &t).await? && lex.mode == Mode::Xml {
        cx.diag(Diagnostic::malformed("text outside the root element").at(lex.span(&t)));
    }
    content(cx, &mut one, input, ns, None, &Arc::default()).await
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let head = cx.read_avail(input.span.sub(0, 4096)).await?;
    let h = Head {
        data: &head,
        tail: &[],
        len: input.span.len,
    };
    let summary = match root(&h) {
        Some(r) => format!("XML document, root <{}>", String::from_utf8_lossy(&r.name)),
        None => "XML document".to_owned(),
    };
    cx.annotate(summary);
    document(&cx, input, Mode::Xml).await
}

async fn dissect_variant(cx: Cx, input: Input, variant: &'static Variant) -> Result<()> {
    let head = cx
        .read_avail(input.span.sub(0, crate::formats::HEAD_LEN))
        .await?;
    let h = Head {
        data: &head,
        tail: &[],
        len: input.span.len,
    };
    let text = probe::head(&h);
    let detail = root(&h).and_then(|r| (variant.detail)(&r, &text));
    cx.annotate(match detail {
        Some(d) => format!("{}: {d}", variant.title),
        None => variant.title.to_owned(),
    });
    document(&cx, input, Mode::Xml).await
}
