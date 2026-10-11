//! Files of RFC 822-style header stanzas that are not mail: Debian control
//! data (deb822: `debian/control`, `.dsc`, `Packages`, `Release`), JAR
//! manifests (`META-INF/MANIFEST.MF`, signature files) and Python core
//! metadata (`PKG-INFO`, `METADATA`).
//!
//! Each is a sequence of `Name: value` fields with continuation lines, in
//! stanzas separated by blank lines, and every value is a string. They
//! differ in how a value continues: a manifest line is cut at 72 bytes and
//! continues after exactly one space (joined with nothing, so a class path
//! is not split), while deb822 and core metadata continue after any
//! whitespace on a new line (deb822 marks an empty line with ` .`). Core
//! metadata has one header stanza; the rest of the file is the long
//! description.

use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;

use super::decode::preview;
use super::encoding::prepare;
use super::scan::{LineBuf, Lines};
use super::{VALUE_CAP, probe, text_node};

pub static DEB822: Format = Format {
    name: "deb822",
    title: "Debian control data",
    extensions: &["dsc", "changes", "sources"],
    mime: "text/x-debian-control",
    probe: Probe::Custom(probe_deb822),
    dissect: crate::expander!(dissect_deb822: Input),
};

pub static MANIFEST: Format = Format {
    name: "jar-manifest",
    title: "JAR manifest",
    extensions: &["mf", "sf"],
    mime: "text/x-java-manifest",
    probe: Probe::Custom(probe_manifest),
    dissect: crate::expander!(dissect_manifest: Input),
};

pub static METADATA: Format = Format {
    name: "python-metadata",
    title: "Python package metadata",
    extensions: &[],
    mime: "text/x-python-metadata",
    probe: Probe::Custom(probe_metadata),
    dissect: crate::expander!(dissect_metadata: Input),
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Deb822,
    Manifest,
    Metadata,
}

// ---------------------------------------------------------------------------
// Probes

/// The name of a `Name: value` line (no leading space; `A-Za-z0-9-_.`).
fn field_name(line: &[u8]) -> Option<&[u8]> {
    let colon = line.iter().position(|&b| b == b':')?;
    let name = line.get(..colon)?;
    (!name.is_empty()
        && name.len() <= 64
        && name.first().is_some_and(u8::is_ascii_alphabetic)
        && name
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')))
    .then_some(name)
}

fn starts_with_field(h: &Head<'_>, names: &[&[u8]]) -> bool {
    let head = probe::head(h);
    let first = probe::lines(&head).next().unwrap_or_default();
    field_name(first).is_some_and(|n| names.iter().any(|k| n.eq_ignore_ascii_case(k)))
        && first.get(
            first
                .iter()
                .position(|&b| b == b':')
                .unwrap_or(0)
                .saturating_add(1),
        ) == Some(&b' ')
        && probe::is_text(h)
}

fn probe_manifest(h: &Head<'_>) -> bool {
    starts_with_field(h, &[b"Manifest-Version", b"Signature-Version"])
}

fn probe_metadata(h: &Head<'_>) -> bool {
    starts_with_field(h, &[b"Metadata-Version"])
        && probe::lines(&probe::head(h))
            .take(20)
            .any(|l| l.starts_with(b"Name: "))
}

/// Fields that open a deb822 stanza.
const DEB_FIRST: &[&[u8]] = &[
    b"Source",
    b"Package",
    b"Format",
    b"Origin",
    b"Types",
    b"Upstream-Name",
];

/// Fields typical of deb822 files.
const DEB_KNOWN: &[&[u8]] = &[
    b"Source",
    b"Package",
    b"Binary",
    b"Version",
    b"Architecture",
    b"Maintainer",
    b"Uploaders",
    b"Section",
    b"Priority",
    b"Standards-Version",
    b"Build-Depends",
    b"Build-Depends-Indep",
    b"Depends",
    b"Pre-Depends",
    b"Recommends",
    b"Suggests",
    b"Conflicts",
    b"Breaks",
    b"Replaces",
    b"Provides",
    b"Description",
    b"Homepage",
    b"Vcs-Git",
    b"Vcs-Browser",
    b"Rules-Requires-Root",
    b"Installed-Size",
    b"Multi-Arch",
    b"Essential",
    b"Files",
    b"Checksums-Sha1",
    b"Checksums-Sha256",
    b"Suite",
    b"Codename",
    b"Components",
    b"URIs",
    b"Signed-By",
    b"Upstream-Contact",
    b"Copyright",
    b"License",
    b"Format",
];

fn probe_deb822(h: &Head<'_>) -> bool {
    let head = probe::head(h);
    let complete = probe::complete(h);
    let mut lines: Vec<&[u8]> = probe::lines(&head).take(200).collect();
    // The last line of a cut head may be partial.
    if !complete {
        lines.pop();
    }
    // A clearsigned `.dsc`/`.changes`.
    let mut rest = lines.as_slice();
    if rest
        .first()
        .is_some_and(|l| l.starts_with(b"-----BEGIN PGP SIGNED MESSAGE-----"))
    {
        let body = rest.iter().position(|l| l.is_empty()).unwrap_or(rest.len());
        rest = rest.get(body.saturating_add(1)..).unwrap_or_default();
    }
    let Some(first) = rest.first().and_then(|l| field_name(l)) else {
        return false;
    };
    if !DEB_FIRST.iter().any(|k| first.eq_ignore_ascii_case(k)) {
        return false;
    }
    let mut known = 0usize;
    let mut fields = 0usize;
    for &line in rest {
        if line.starts_with(b"-----BEGIN PGP SIGNATURE-----") {
            break;
        }
        if line.is_empty() || matches!(line.first(), Some(b' ' | b'\t' | b'#')) {
            continue;
        }
        // Every other line is a field with a space after its colon (or
        // nothing: `Files:` then continuation lines).
        let Some(name) = field_name(line) else {
            return false;
        };
        if !matches!(
            line.get(name.len().saturating_add(1)),
            None | Some(b' ' | b'\t' | b'\r')
        ) {
            return false;
        }
        fields = fields.saturating_add(1);
        if DEB_KNOWN.iter().any(|k| name.eq_ignore_ascii_case(k)) {
            known = known.saturating_add(1);
        }
    }
    fields >= 3 && known.saturating_mul(2) >= fields && probe::is_text(h)
}

// ---------------------------------------------------------------------------
// Fields

/// A field being read: name, value so far and the span of its lines.
struct Field {
    name: String,
    value: String,
    span: Span,
}

/// Value text kept per field: well past what a value shows.
const FIELD_CAP: usize = VALUE_CAP * 4;

impl Field {
    fn start(line: &LineBuf) -> Option<Field> {
        let p = line.piece();
        let (name, value) = p.split_once(b':')?;
        let name = name.trim();
        (!name.is_empty()).then(|| Field {
            name: name.text(),
            value: value.trim().text(),
            span: line.span,
        })
    }

    /// Adds a continuation line.
    fn extend(&mut self, line: &LineBuf, kind: Kind) {
        self.span = Span::new(
            self.span.source,
            self.span.offset,
            line.span.end().saturating_sub(self.span.offset),
        );
        if self.value.len() >= FIELD_CAP {
            return;
        }
        let p = line.piece();
        match kind {
            // Exactly one space, then the bytes go on.
            Kind::Manifest => self.value.push_str(&p.from(1).text()),
            Kind::Deb822 => {
                let t = p.trim();
                if !self.value.is_empty() {
                    self.value.push('\n');
                }
                if t.bytes() != b"." {
                    self.value.push_str(&t.text());
                }
            }
            Kind::Metadata => {
                let t = p.trim_start();
                let t = t.strip_prefix(b"|").unwrap_or(t);
                self.value.push('\n');
                self.value.push_str(&t.trim_end().text());
            }
        }
    }

    fn node(&self) -> Node {
        text_node(self.name.clone(), self.span, &self.value)
    }
}

fn continues(line: &LineBuf) -> bool {
    matches!(line.bytes.first(), Some(b' ' | b'\t'))
}

fn comment(line: &LineBuf, kind: Kind) -> bool {
    kind == Kind::Deb822 && line.bytes.first() == Some(&b'#')
}

/// A stanza's span and its first field (for naming it).
struct Stanza {
    span: Span,
    first: Option<Field>,
    /// The `Name` field of a manifest section.
    name: Option<String>,
}

/// Reads the next stanza (skipping blank lines before it): its extent and
/// first field only, so a huge stanza costs no memory here.
async fn next_stanza(lines: &mut Lines<'_>, kind: Kind) -> Result<Option<Stanza>> {
    let mut start: Option<Span> = None;
    let mut end = 0u64;
    let mut first: Option<Field> = None;
    let mut name: Option<Field> = None;
    let mut current: Option<u8> = None; // 1: first field, 2: name field
    loop {
        let Some(line) = lines.peek().await? else {
            break;
        };
        if line.is_blank() {
            lines.next().await?;
            if start.is_some() {
                break;
            }
            continue;
        }
        if kind == Kind::Deb822 && line.bytes.starts_with(b"-----BEGIN PGP SIGNATURE-----") {
            // The signature block is not a stanza: leave it to the caller.
            if start.is_some() {
                break;
            }
            return Ok(None);
        }
        lines.next().await?;
        start.get_or_insert(line.span);
        end = line.full.end();
        if comment(&line, kind) {
            continue;
        }
        if continues(&line) {
            match current {
                Some(1) => {
                    if let Some(f) = first.as_mut() {
                        f.extend(&line, kind);
                    }
                }
                Some(2) => {
                    if let Some(f) = name.as_mut() {
                        f.extend(&line, kind);
                    }
                }
                _ => {}
            }
            continue;
        }
        current = None;
        let Some(field) = Field::start(&line) else {
            continue;
        };
        if first.is_none() {
            first = Some(field);
            current = Some(1);
        } else if name.is_none() && field.name.eq_ignore_ascii_case("Name") {
            name = Some(field);
            current = Some(2);
        }
    }
    Ok(start.map(|s| Stanza {
        span: Span::new(s.source, s.offset, end.saturating_sub(s.offset)),
        name: name.map(|f| f.value).or_else(|| {
            first
                .as_ref()
                .filter(|f| f.name.eq_ignore_ascii_case("Name"))
                .map(|f| f.value.clone())
        }),
        first,
    }))
}

#[derive(Clone, Copy, Debug)]
struct Section {
    span: Span,
    kind: Kind,
}

/// The fields of a stanza, streamed (one field held at a time).
async fn fields(cx: Cx, s: Section) -> Result<()> {
    let mut lines = Lines::new(&cx, s.span);
    let mut current: Option<Field> = None;
    let mut count = 0u64;
    while let Some(line) = lines.next().await? {
        if line.is_blank() || comment(&line, s.kind) {
            continue;
        }
        if continues(&line) {
            match current.as_mut() {
                Some(f) => f.extend(&line, s.kind),
                None => {
                    cx.push(
                        text_node("(continuation)", line.span, &line.text())
                            .diag(Diagnostic::malformed("continuation line before any field")),
                    )
                    .await;
                }
            }
            continue;
        }
        if let Some(f) = current.take() {
            count = count.saturating_add(1);
            cx.push(f.node()).await;
        }
        match Field::start(&line) {
            Some(f) => current = Some(f),
            None => {
                cx.push(
                    text_node("(line)", line.span, &line.text())
                        .diag(Diagnostic::malformed("not a `Name: value` field")),
                )
                .await;
            }
        }
    }
    if let Some(f) = current.take() {
        count = count.saturating_add(1);
        cx.push(f.node()).await;
    }
    cx.set_count(Count::Exact(count));
    Ok(())
}

fn section_node(name: String, span: Span, kind: Kind, summary: String) -> Node {
    Node::new(name)
        .span(span)
        .summary(summary)
        .lazy(crate::expander!(fields: Section), Section { span, kind })
}

/// Walks the stanzas of `span`, pushing a lazy node for each (with resume
/// marks if `marks`).
async fn stanzas(cx: &Cx, span: Span, kind: Kind, marks: bool) -> Result<()> {
    let mut lines = Lines::new(cx, span);
    // Resume marks: (byte position, lines so far, stanzas so far).
    let resumed = if marks {
        cx.resume::<(u64, u64, u64)>()
    } else {
        None
    };
    let (pos, number, mut index) = resumed.unwrap_or((0, 0, 0));
    lines.seek(pos, number);
    loop {
        if marks {
            let at = (lines.pos(), lines.number(), index);
            cx.mark(move || at);
        }
        let Some(s) = next_stanza(&mut lines, kind).await? else {
            break;
        };
        index = index.saturating_add(1);
        lines.progress();
        let first = s.first.as_ref();
        let summary = first.map_or_else(String::new, |f| {
            format!("{}: {}", f.name, preview(&f.value, 60))
        });
        let name = match kind {
            Kind::Manifest if index == 1 => "Main attributes".to_owned(),
            Kind::Manifest => s.name.clone().unwrap_or_else(|| format!("Section {index}")),
            _ => first.map_or_else(
                || format!("Stanza {index}"),
                |f| format!("{} {}", f.name, preview(&f.value, 40)),
            ),
        };
        cx.push(section_node(name, s.span, kind, summary)).await;
    }
    // A clearsigned file's signature.
    if kind == Kind::Deb822 && lines.pos() < span.len {
        let rest = span.tail(lines.pos());
        cx.push(
            Node::new("PGP signature")
                .span(rest)
                .lazy(crate::expander!(signature: Span), rest),
        )
        .await;
    }
    Ok(())
}

/// The armored signature after a clearsigned stanza list.
async fn signature(cx: Cx, span: Span) -> Result<()> {
    let mut lines = Lines::new(&cx, span);
    let mut n = 0u64;
    while let Some(line) = lines.next().await? {
        n = n.saturating_add(1);
        cx.push(text_node(format!("Line {n}"), line.span, &line.text()))
            .await;
    }
    Ok(())
}

/// The first `Name: value` of the head (for the annotation).
async fn head_field(cx: &Cx, span: Span, name: &str) -> Result<Option<String>> {
    let head = cx.read_avail(span.sub(0, 16 * 1024)).await?;
    let text = super::encoding::probe_text(&head);
    Ok(probe::lines(&text)
        .take_while(|l| !probe::trim(l).is_empty())
        .find_map(|l| {
            let (k, v) = l.split_at(l.iter().position(|&b| b == b':')?);
            k.eq_ignore_ascii_case(name.as_bytes()).then(|| {
                String::from_utf8_lossy(probe::trim(v.get(1..).unwrap_or_default())).into_owned()
            })
        }))
}

// ---------------------------------------------------------------------------
// Entry points

pub async fn dissect_deb822(cx: Cx, input: Input) -> Result<()> {
    let prepared = prepare(&cx, input).await?;
    let mut span = prepared.span;
    let mut summary = String::from("Debian control data");
    let mut clearsigned = false;
    let head = cx.read_avail(span.sub(0, 64)).await?;
    if head.starts_with(b"-----BEGIN PGP SIGNED MESSAGE-----") {
        // The armor header (`Hash: ...`) up to the first blank line.
        let mut lines = Lines::new(&cx, span);
        let mut end = 0u64;
        while let Some(line) = lines.next().await? {
            end = line.next;
            if line.is_blank() {
                break;
            }
        }
        cx.emit(Node::new("PGP armor header").span(span.sub(0, end)));
        span = span.tail(end);
        summary.push_str(" (clearsigned)");
        clearsigned = true;
    }
    let first = head_field(&cx, span, "Source").await?;
    let first = match first {
        Some(f) => Some(format!("source {f}")),
        None => head_field(&cx, span, "Package")
            .await?
            .map(|f| format!("package {f}")),
    };
    if let Some(f) = first {
        summary = format!("{summary}: {}", preview(&f, 60));
    }

    cx.annotate(summary);
    // Resume marks need every child pushed by the walk: not with the armor
    // header emitted first.
    stanzas(&cx, span, Kind::Deb822, !clearsigned).await?;
    Ok(())
}

pub async fn dissect_manifest(cx: Cx, input: Input) -> Result<()> {
    let prepared = prepare(&cx, input).await?;
    let span = prepared.span;
    let version = match head_field(&cx, span, "Manifest-Version").await? {
        Some(v) => Some(v),
        None => head_field(&cx, span, "Signature-Version").await?,
    };
    let main = head_field(&cx, span, "Main-Class").await?;
    let mut summary = String::from("JAR manifest");
    if let Some(v) = version {
        summary = format!("{summary} {}", preview(&v, 20));
    }
    if let Some(m) = main {
        summary = format!("{summary}, main class {}", preview(&m, 60));
    }
    cx.annotate(summary);
    stanzas(&cx, span, Kind::Manifest, true).await?;
    Ok(())
}

pub async fn dissect_metadata(cx: Cx, input: Input) -> Result<()> {
    let prepared = prepare(&cx, input).await?;
    let span = prepared.span;
    let name = head_field(&cx, span, "Name").await?;
    let version = head_field(&cx, span, "Version").await?;
    let mut summary = String::from("Python package metadata");
    match (name, version) {
        (Some(n), Some(v)) => {
            summary = format!("{summary}: {} {}", preview(&n, 60), preview(&v, 30))
        }
        (Some(n), None) => summary = format!("{summary}: {}", preview(&n, 60)),
        _ => {}
    }
    cx.annotate(summary);
    // The header stanza, then the description body.
    let mut lines = Lines::new(&cx, span);
    let mut current: Option<Field> = None;
    let mut body = span.len;
    while let Some(line) = lines.next().await? {
        if line.is_blank() {
            body = line.next;
            break;
        }
        if continues(&line) {
            if let Some(f) = current.as_mut() {
                f.extend(&line, Kind::Metadata);
            }
            continue;
        }
        if let Some(f) = current.take() {
            cx.push(f.node()).await;
        }
        current = Field::start(&line);
    }
    if let Some(f) = current.take() {
        cx.push(f.node()).await;
    }
    if body < span.len {
        let rest = span.tail(body);
        let text = cx
            .read_avail(rest.sub(0, crate::bytes::to_u64(FIELD_CAP)))
            .await?;
        cx.push(
            text_node("Description", rest, &super::encoding::decode_8bit(&text))
                .summary(format!("{:#x} bytes", rest.len)),
        )
        .await;
    }
    Ok(())
}
