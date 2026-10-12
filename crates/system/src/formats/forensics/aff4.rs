//! AFF4 forensic images (the AFF4 Standard v1.0/1.1, as written by
//! aff4imager, pyaff4, Evimetry and others).
//!
//! An AFF4 volume is a ZIP64 archive whose comment (and
//! `container.description` member) names the volume URN. `information.turtle`
//! describes the objects in RDF: an `aff4:Image` (`DiskImage`, `FileImage`,
//! ...) has a `dataStream`, usually an `aff4:Map` whose `map` member lists
//! ranges (28 bytes each) over the targets named in its `idx` member; a
//! target is usually an `aff4:ImageStream`, whose data is in bevies
//! (`<stream>/00000000`, ...) of compressed chunks indexed by
//! `<stream>/00000000.index` (offset and length, 12 bytes each). Logical
//! images store small files as plain ZIP members. Members are named by their
//! URN, relative to the volume's, with the `aff4://` of others escaped.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::error::{Diagnostic, Result};
use crate::formats::archive::zip::{self, Member};
use crate::formats::disk::PieceList;
use crate::formats::util::datakit::{clip, size, text, uint};
use crate::formats::util::fmt::plural;
use crate::formats::{Codec, Head, Input, Probe, content, dissect_or_data, embedded_as};
use crate::node::{Count, Node};
use crate::span::{Origin, Span};

fn aff4_probe(h: &Head<'_>) -> bool {
    if !h.starts_with(b"PK\x03\x04") {
        return false;
    }
    // The first member is often the volume's description or metadata.
    let first = u16_le(h.data, 26).and_then(|n| h.data.get(30..30usize.saturating_add(n.into())));
    if matches!(
        first,
        Some(b"container.description" | b"information.turtle")
    ) {
        return true;
    }
    // The archive comment is the volume URN.
    let tail = h.tail;
    (0..tail.len().saturating_sub(21)).rev().any(|i| {
        tail.get(i..i.saturating_add(4)) == Some(b"PK\x05\x06")
            && u16_le(tail, i.saturating_add(20))
                .is_some_and(|n| i.saturating_add(22).saturating_add(n.into()) == tail.len())
            && tail
                .get(i.saturating_add(22)..)
                .is_some_and(|c| c.starts_with(b"aff4://"))
    })
}

declare_format!(pub FORMAT = "aff4", "AFF4 forensic image", ["aff4"], "application/x-aff4",
    Probe::Custom(aff4_probe), aff4);

/// At most this much of `information.turtle` is read.
const MAX_TURTLE: u64 = 8 << 20;
/// At most this many members of a map's `idx` or a stream's bevies.
const MAX_BEVIES: u64 = 1 << 20;

// ---------------------------------------------------------------------------
// Turtle (enough for AFF4 metadata)

#[derive(Clone, Debug, PartialEq)]
enum Obj {
    Iri(String),
    Literal(String, Option<String>),
    Blank,
}

impl Obj {
    fn as_str(&self) -> &str {
        match self {
            Obj::Iri(s) | Obj::Literal(s, _) => s,
            Obj::Blank => "",
        }
    }
}

const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";

/// A Turtle statement reader: prefixes, IRIs, prefixed names, literals
/// (with datatype or language), `a`, `;`, `,`, blank node property lists
/// and collections (skipped). Bounded by its input.
struct Turtle<'a> {
    src: &'a [u8],
    at: usize,
    prefixes: BTreeMap<String, String>,
}

#[derive(Debug, PartialEq)]
enum Tok {
    Iri(String),
    Name(String),
    Lit(String),
    Punct(u8),
    Word(String),
}

impl<'a> Turtle<'a> {
    fn new(src: &'a [u8]) -> Self {
        Turtle {
            src,
            at: 0,
            prefixes: BTreeMap::new(),
        }
    }

    fn peek_byte(&self) -> Option<u8> {
        self.src.get(self.at).copied()
    }

    fn skip_space(&mut self) {
        while let Some(b) = self.peek_byte() {
            if b == b'#' {
                while let Some(c) = self.peek_byte() {
                    self.at = self.at.saturating_add(1);
                    if c == b'\n' {
                        break;
                    }
                }
            } else if b.is_ascii_whitespace() {
                self.at = self.at.saturating_add(1);
            } else {
                break;
            }
        }
    }

    fn take_while(&mut self, f: impl Fn(u8) -> bool) -> String {
        let start = self.at;
        while self.peek_byte().is_some_and(&f) {
            self.at = self.at.saturating_add(1);
        }
        String::from_utf8_lossy(self.src.get(start..self.at).unwrap_or_default()).into_owned()
    }

    fn string(&mut self, quote: u8) -> String {
        let long = self.src.get(self.at..self.at.saturating_add(3)) == Some(&[quote; 3][..]);
        self.at = self.at.saturating_add(if long { 3 } else { 1 });
        let mut out = Vec::new();
        while let Some(b) = self.peek_byte() {
            if b == quote
                && (!long
                    || self.src.get(self.at..self.at.saturating_add(3)) == Some(&[quote; 3][..]))
            {
                self.at = self.at.saturating_add(if long { 3 } else { 1 });
                break;
            }
            self.at = self.at.saturating_add(1);
            if b == b'\\' {
                let e = self.peek_byte().unwrap_or(b'\\');
                self.at = self.at.saturating_add(1);
                out.push(match e {
                    b'n' => b'\n',
                    b't' => b'\t',
                    b'r' => b'\r',
                    other => other,
                });
            } else {
                out.push(b);
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    fn token(&mut self) -> Option<Tok> {
        self.skip_space();
        let b = self.peek_byte()?;
        Some(match b {
            b'<' => {
                self.at = self.at.saturating_add(1);
                let iri = self.take_while(|c| c != b'>' && c != b'\n');
                self.at = self.at.saturating_add(1);
                Tok::Iri(iri)
            }
            b'"' | b'\'' => Tok::Lit(self.string(b)),
            b'.' | b';' | b',' | b'[' | b']' | b'(' | b')' => {
                self.at = self.at.saturating_add(1);
                Tok::Punct(b)
            }
            b'^' => {
                self.at = self.at.saturating_add(2);
                Tok::Punct(b'^')
            }
            _ => {
                let w = self.take_while(|c| {
                    !c.is_ascii_whitespace()
                        && !matches!(c, b'<' | b'"' | b';' | b',' | b'[' | b']' | b'(' | b')')
                        && c != b'^'
                });
                // A statement's final `.` sticks to a name or number.
                let w = match w.strip_suffix('.') {
                    Some(stem) if !stem.is_empty() && !stem.ends_with(':') => {
                        self.at = self.at.saturating_sub(1);
                        stem.to_owned()
                    }
                    _ => w,
                };
                if w.is_empty() {
                    // Not a token start we know: skip the byte.
                    self.at = self.at.saturating_add(1);
                    Tok::Word(String::new())
                } else if w.contains(':') && !w.starts_with('@') {
                    Tok::Name(w)
                } else {
                    Tok::Word(w)
                }
            }
        })
    }

    fn expand(&self, name: &str) -> String {
        match name.split_once(':') {
            Some((p, local)) => match self.prefixes.get(p) {
                Some(ns) => format!("{ns}{local}"),
                None => name.to_owned(),
            },
            None => name.to_owned(),
        }
    }

    fn term(&mut self, tok: Tok) -> Option<Obj> {
        Some(match tok {
            Tok::Iri(s) => Obj::Iri(s),
            Tok::Name(n) => Obj::Iri(self.expand(&n)),
            Tok::Word(w) if w == "a" => Obj::Iri(RDF_TYPE.to_owned()),
            Tok::Word(w) => Obj::Literal(w, None),
            Tok::Lit(s) => {
                let save = self.at;
                let datatype = match self.token() {
                    Some(Tok::Punct(b'^')) => match self.token() {
                        Some(Tok::Iri(t)) => Some(t),
                        Some(Tok::Name(n)) => Some(self.expand(&n)),
                        _ => None,
                    },
                    Some(Tok::Word(w)) if w.starts_with('@') => None,
                    _ => {
                        self.at = save;
                        None
                    }
                };
                Obj::Literal(s, datatype)
            }
            Tok::Punct(b'[') | Tok::Punct(b'(') => {
                // A blank node or collection: skipped to its close.
                let mut depth = 1u32;
                while depth > 0 {
                    match self.token()? {
                        Tok::Punct(b'[') | Tok::Punct(b'(') => depth = depth.saturating_add(1),
                        Tok::Punct(b']') | Tok::Punct(b')') => depth = depth.saturating_sub(1),
                        _ => {}
                    }
                }
                Obj::Blank
            }
            Tok::Punct(_) => return None,
        })
    }

    /// The next statement's triples (empty for a directive); `None` at the
    /// end.
    fn statement(&mut self) -> Option<Vec<(String, String, Obj)>> {
        let first = self.token()?;
        if let Tok::Word(w) = &first
            && (w == "@prefix" || w.eq_ignore_ascii_case("prefix"))
        {
            let sparql = !w.starts_with('@');
            if let (Some(Tok::Name(p)), Some(Tok::Iri(ns))) = (self.token(), self.token()) {
                self.prefixes.insert(p.trim_end_matches(':').to_owned(), ns);
            }
            if !sparql {
                self.token();
            }
            return Some(Vec::new());
        }
        if let Tok::Word(w) = &first
            && (w == "@base" || w.eq_ignore_ascii_case("base"))
        {
            self.token();
            if w.starts_with('@') {
                self.token();
            }
            return Some(Vec::new());
        }
        let mut out = Vec::new();
        let Some(subject) = self.term(first) else {
            return Some(out);
        };
        let subject = subject.as_str().to_owned();
        'predicates: while let Some(tok) = self.token() {
            if tok == Tok::Punct(b'.') {
                break;
            }
            if tok == Tok::Punct(b';') {
                continue;
            }
            let Some(predicate) = self.term(tok) else {
                break;
            };
            let predicate = predicate.as_str().to_owned();
            loop {
                let Some(tok) = self.token() else {
                    break 'predicates;
                };
                let Some(object) = self.term(tok) else {
                    break 'predicates;
                };
                out.push((subject.clone(), predicate.clone(), object));
                match self.token() {
                    Some(Tok::Punct(b',')) => continue,
                    Some(Tok::Punct(b';')) => continue 'predicates,
                    _ => break 'predicates,
                }
            }
        }
        Some(out)
    }
}

/// The local name of an IRI (after `#` or the last `/`).
fn local(iri: &str) -> &str {
    iri.rsplit(['#', '/']).next().unwrap_or(iri)
}

// ---------------------------------------------------------------------------
// The volume

/// What the dissector learnt from the ZIP directory and the metadata.
struct Volume {
    input: Input,
    urn: String,
    members: Vec<Member>,
    /// Member index by the URN it stores.
    by_urn: BTreeMap<String, usize>,
    /// Statements by subject, in file order.
    subjects: BTreeMap<String, Vec<(String, Obj)>>,
}

impl Volume {
    fn props(&self, urn: &str) -> &[(String, Obj)] {
        self.subjects.get(urn).map_or(&[], Vec::as_slice)
    }

    /// The first object of `urn`'s predicate with local name `name`.
    fn prop(&self, urn: &str, name: &str) -> Option<&Obj> {
        self.props(urn)
            .iter()
            .find(|(p, _)| local(p) == name)
            .map(|(_, o)| o)
    }

    fn number(&self, urn: &str, name: &str) -> Option<u64> {
        self.prop(urn, name)
            .and_then(|o| o.as_str().trim().parse().ok())
    }

    fn types(&self, urn: &str) -> impl Iterator<Item = &str> {
        self.props(urn)
            .iter()
            .filter(|(p, _)| p == RDF_TYPE || local(p) == "type")
            .map(|(_, o)| local(o.as_str()))
    }

    fn is(&self, urn: &str, kind: &str) -> bool {
        self.types(urn).any(|t| t == kind)
    }

    fn member(&self, urn: &str) -> Option<&Member> {
        self.by_urn.get(urn).and_then(|&i| self.members.get(i))
    }

    /// A member's content: its data, decoded lazily if compressed.
    async fn content(&self, cx: &Cx, m: &Member) -> Result<Span> {
        let data = zip::member_data(cx, self.input.span, m).await?;
        match m.codec() {
            Some(Codec::Stored) => Ok(data),
            Some(codec) => cx.decode_lazy(data, &codec, m.uncompressed),
            None => Err(Diagnostic::unsupported(format!(
                "ZIP member {} (method {})",
                m.name, m.method
            ))
            .at(data)),
        }
    }

    async fn content_of(&self, cx: &Cx, urn: &str) -> Result<Option<Span>> {
        match self.member(urn) {
            Some(m) => Ok(Some(self.content(cx, m).await?)),
            None => Ok(None),
        }
    }

    /// A short label for an object: its file name, or its URN.
    fn label(&self, urn: &str) -> String {
        for name in ["originalFileName", "pathName"] {
            if let Some(o) = self.prop(urn, name) {
                return o.as_str().to_owned();
            }
        }
        urn.to_owned()
    }

    fn kinds(&self, urn: &str) -> String {
        let mut kinds: Vec<&str> = self.types(urn).collect();
        kinds.dedup();
        kinds.join(", ")
    }
}

/// The URN a member stores: escapes removed, relative names under the
/// volume URN.
fn member_urn(volume: &str, name: &str) -> String {
    let name = crate::text::url::percent_decode(name);
    if name.starts_with("aff4:") {
        name
    } else {
        format!("{volume}/{name}")
    }
}

async fn read_text(cx: &Cx, span: Span, max: u64) -> Result<String> {
    let raw = cx.read_avail(span.sub(0, max)).await?;
    Ok(String::from_utf8_lossy(&raw).into_owned())
}

async fn aff4(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let Some((directory, members)) = zip::members(&cx, file).await? else {
        return Err(Diagnostic::malformed("no ZIP end record").at(file.sub(0, 4)));
    };
    let mut volume = Volume {
        input,
        urn: String::new(),
        members,
        by_urn: BTreeMap::new(),
        subjects: BTreeMap::new(),
    };
    let named = |n: &str| volume.members.iter().position(|m| m.name == n);
    let (description, turtle, version) = (
        named("container.description"),
        named("information.turtle"),
        named("version.txt"),
    );
    if let Some(m) = description.and_then(|i| volume.members.get(i)) {
        let span = volume.content(&cx, m).await?;
        volume.urn = read_text(&cx, span, 1024).await?.trim().to_owned();
    }
    if volume.urn.is_empty() {
        // The archive comment.
        let tail = cx
            .read_avail(file.sub(directory.end().saturating_sub(file.offset), 0x400))
            .await?;
        if let Some(at) = tail.windows(7).position(|w| w == b"aff4://") {
            let urn = tail.get(at..).unwrap_or_default();
            let end = urn.iter().position(|&b| b <= b' ').unwrap_or(urn.len());
            volume.urn = String::from_utf8_lossy(urn.get(..end).unwrap_or_default()).into_owned();
        }
    }
    for (i, m) in volume.members.iter().enumerate() {
        if i.is_multiple_of(1024) {
            cx.checkpoint().await;
        }
        volume.by_urn.insert(member_urn(&volume.urn, &m.name), i);
    }
    let mut tool = String::new();
    if let Some(m) = version.and_then(|i| volume.members.get(i)) {
        let span = volume.content(&cx, m).await?;
        let txt = read_text(&cx, span, 1024).await?;
        let get = |k: &str| {
            txt.lines()
                .find_map(|l| l.strip_prefix(k)?.strip_prefix('='))
                .unwrap_or_default()
                .trim()
                .to_owned()
        };
        tool = format!("{} {}.{}", get("tool"), get("major"), get("minor"));
    }
    let mut turtle_node = None;
    if let Some(m) = turtle.and_then(|i| volume.members.get(i)) {
        let span = volume.content(&cx, m).await?;
        turtle_node = Some(
            content(
                "Metadata (information.turtle)",
                input,
                span,
                Codec::Stored,
                Some(span.len),
            )
            .summary(size(span.len)),
        );
        if span.len > MAX_TURTLE {
            cx.diag(Diagnostic::limit(format!(
                "only the first {} of the metadata are read",
                size(MAX_TURTLE)
            )));
        }
        let raw = cx.read_avail(span.sub(0, MAX_TURTLE)).await?;
        let mut parser = Turtle::new(&raw);
        let mut n = 0u32;
        while let Some(triples) = parser.statement() {
            n = n.saturating_add(1);
            if n.is_multiple_of(64) {
                cx.charge(64).await;
            }
            for (s, p, o) in triples {
                volume.subjects.entry(s).or_default().push((p, o));
            }
        }
    } else {
        cx.diag(Diagnostic::malformed("no information.turtle member"));
    }
    let volume = Arc::new(volume);

    // Images first, then the streams they are made of.
    let images: Vec<String> = volume
        .subjects
        .keys()
        .filter(|s| volume.is(s, "Image"))
        .cloned()
        .collect();
    let streams: Vec<String> = volume
        .subjects
        .keys()
        .filter(|s| volume.is(s, "Map") || volume.is(s, "ImageStream"))
        .cloned()
        .collect();
    let mut summary = Vec::new();
    for urn in images.iter().take(3) {
        let kind = volume
            .types(urn)
            .find(|t| *t != "Image")
            .unwrap_or("Image")
            .to_owned();
        match volume.number(urn, "size") {
            Some(n) => summary.push(format!("{kind} {}", size(n))),
            None => summary.push(kind),
        }
    }
    cx.emit(
        Node::new("Images")
            .summary(format!("{}", images.len()))
            .lazy(list_objects, (volume.clone(), Arc::new(images.clone()))),
    );
    cx.emit(
        Node::new("Streams")
            .summary(format!("{}", streams.len()))
            .lazy(list_objects, (volume.clone(), Arc::new(streams))),
    );
    if let Some(node) = turtle_node {
        cx.emit(node);
    }
    cx.emit(embedded_as(
        "ZIP container",
        input.nested(file),
        &zip::FORMAT,
    ));
    let mut label = String::from("AFF4 volume");
    if !tool.trim().is_empty() {
        label.push_str(&format!(" ({})", tool.trim()));
    }
    label.push_str(&format!(
        ", {} image{}",
        images.len(),
        if images.len() == 1 { "" } else { "s" }
    ));
    if !summary.is_empty() {
        label.push_str(&format!(": {}", clip(&summary.join(", "), 100)));
    }
    cx.annotate(label);
    Ok(())
}

async fn list_objects(cx: Cx, (volume, urns): (Arc<Volume>, Arc<Vec<String>>)) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(urns.len())));
    for urn in urns.iter() {
        let mut parts = vec![volume.kinds(urn)];
        if volume.is(urn, "ImageStream")
            && let Some(c) = volume.prop(urn, "compressionMethod")
        {
            parts.push(compression_name(c.as_str()).to_owned());
        }
        if let Some(n) = volume.number(urn, "size") {
            parts.push(size(n));
        }
        cx.push(
            Node::new(volume.label(urn))
                .summary(parts.join(", "))
                .lazy(object, (volume.clone(), urn.clone())),
        )
        .await;
    }
    Ok(())
}

/// An object: its properties, its parts and its data.
async fn object(cx: Cx, (volume, urn): (Arc<Volume>, String)) -> Result<()> {
    if volume.label(&urn) != urn {
        cx.emit(Node::new("URN").value(text(urn.clone())));
    }
    for (p, o) in volume.props(&urn) {
        let value = match o {
            Obj::Literal(s, t)
                if t.as_deref()
                    .is_none_or(|t| matches!(local(t), "long" | "int" | "integer"))
                    && let Ok(n) = s.parse::<u64>() =>
            {
                uint(n, 64)
            }
            Obj::Literal(s, Some(t)) if local(t) != "string" => {
                text(clip(&format!("{s} ({})", local(t)), 200))
            }
            other => text(clip(other.as_str(), 200)),
        };
        cx.emit(Node::new(local(p).to_owned()).value(value));
    }
    if volume.is(&urn, "Map") {
        for (part, name) in [("map", "Map entries"), ("idx", "Targets")] {
            let member = format!("{urn}/{part}");
            if let Some(m) = volume.member(&member) {
                let span = volume.content(&cx, m).await?;
                cx.emit(
                    Node::new(name)
                        .span(span)
                        .summary(size(span.len))
                        .lazy(map_part, (volume.clone(), urn.clone(), part == "map")),
                );
            }
        }
    }
    if volume.is(&urn, "ImageStream") {
        cx.emit(Node::new("Bevies").lazy(bevies, (volume.clone(), urn.clone())));
    }
    cx.emit(Node::new("Data").lazy(data, (volume, urn)));
    Ok(())
}

async fn data(cx: Cx, (volume, urn): (Arc<Volume>, String)) -> Result<()> {
    let span = open(&cx, &volume, &urn).await?;
    dissect_or_data(cx, volume.input.nested(span)).await
}

/// The targets listed in a map's `idx` member.
async fn targets(cx: &Cx, volume: &Volume, urn: &str) -> Result<Vec<String>> {
    let Some(span) = volume.content_of(cx, &format!("{urn}/idx")).await? else {
        return Ok(Vec::new());
    };
    let txt = read_text(cx, span, 1 << 20).await?;
    Ok(txt
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect())
}

/// One map entry: mapped offset, length, target offset, target index.
fn map_entry(raw: &[u8], at: usize) -> (u64, u64, u64, u32) {
    (
        u64_le(raw, at).unwrap_or(0),
        u64_le(raw, at.saturating_add(8)).unwrap_or(0),
        u64_le(raw, at.saturating_add(16)).unwrap_or(0),
        u32_le(raw, at.saturating_add(24)).unwrap_or(0),
    )
}

async fn map_part(cx: Cx, (volume, urn, entries): (Arc<Volume>, String, bool)) -> Result<()> {
    let names = targets(&cx, &volume, &urn).await?;
    if !entries {
        cx.set_count(Count::Exact(to_u64(names.len())));
        for (i, t) in names.iter().enumerate() {
            cx.push(Node::new(format!("Target {i}")).value(text(t.clone())))
                .await;
        }
        return Ok(());
    }
    let Some(span) = volume.content_of(&cx, &format!("{urn}/map")).await? else {
        return Ok(());
    };
    let count = span.len / 28;
    cx.set_count(Count::Exact(count));
    let mut done = 0u64;
    while done < count {
        let page = (count.saturating_sub(done)).min(1024);
        let raw = cx
            .read(span.sub(done.saturating_mul(28), page.saturating_mul(28)))
            .await?;
        for j in 0..to_usize(page) {
            let at = j.saturating_mul(28);
            let (mapped, len, offset, target) = map_entry(&raw, at);
            let name = names
                .get(to_usize(target.into()))
                .map_or_else(|| format!("target {target}"), |t| local_target(t));
            cx.push(
                Node::new(format!("{mapped:#x}–{:#x}", mapped.saturating_add(len)))
                    .span(span.sub(done.saturating_add(to_u64(j)).saturating_mul(28), 28))
                    .summary(format!("{} from {name} at {offset:#x}", size(len))),
            )
            .await;
        }
        done = done.saturating_add(page);
    }
    Ok(())
}

/// A target's name for display: symbolic streams by their local name.
fn local_target(t: &str) -> String {
    if t.starts_with("http") {
        local(t).to_owned()
    } else {
        t.to_owned()
    }
}

/// Image stream parameters: chunk size, chunks per bevy, size, codec (and
/// whether a chunk of the full chunk size is stored as is).
struct StreamInfo {
    chunk: u64,
    per_bevy: u64,
    size: u64,
    codec: Option<Codec>,
    raw_full: bool,
}

fn compression_name(iri: &str) -> &'static str {
    match iri {
        "https://www.ietf.org/rfc/rfc1950.txt" => "zlib",
        "https://tools.ietf.org/html/rfc1951" => "deflate",
        "http://code.google.com/p/snappy/" | "https://github.com/google/snappy" => "snappy",
        "https://code.google.com/p/lz4/" | "https://github.com/lz4/lz4" => "lz4",
        i if i.ends_with("compression/stored") || i.ends_with("NullCompressor") => "stored",
        _ => "unknown compression",
    }
}

fn stream_info(volume: &Volume, urn: &str) -> StreamInfo {
    let method = volume
        .prop(urn, "compressionMethod")
        .map(|o| o.as_str().to_owned())
        .unwrap_or_default();
    let codec = match compression_name(&method) {
        "zlib" => Some(Codec::Zlib),
        "deflate" => Some(Codec::Deflate),
        "snappy" => Some(Codec::Snappy),
        "lz4" => Some(Codec::Lz4Block),
        "stored" => Some(Codec::Stored),
        // No method: pyaff4's default is zlib.
        _ if method.is_empty() => Some(Codec::Zlib),
        _ => None,
    };
    StreamInfo {
        chunk: volume
            .number(urn, "chunkSize")
            .filter(|&c| c > 0)
            .unwrap_or(32 * 1024),
        per_bevy: volume
            .number(urn, "chunksInSegment")
            .filter(|&c| c > 0)
            .unwrap_or(1024),
        size: volume.number(urn, "size").unwrap_or(0),
        codec,
        // Scudette's snappy streams always compress.
        raw_full: method != "https://github.com/google/snappy",
    }
}

fn bevy_name(urn: &str, i: u64) -> String {
    format!("{urn}/{i:08}")
}

async fn bevies(cx: Cx, (volume, urn): (Arc<Volume>, String)) -> Result<()> {
    let info = stream_info(&volume, &urn);
    let chunks = info.size.div_ceil(info.chunk);
    let count = chunks.div_ceil(info.per_bevy).min(MAX_BEVIES);
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let name = bevy_name(&urn, i);
        let (Some(data), Some(index)) = (
            volume.member(&name),
            volume.member(&format!("{name}.index")),
        ) else {
            cx.push(
                Node::new(format!("Bevy {i}"))
                    .diag(Diagnostic::malformed("bevy or its index is missing")),
            )
            .await;
            continue;
        };
        let (data, index) = (
            volume.content(&cx, data).await?,
            volume.content(&cx, index).await?,
        );
        cx.push(
            Node::new(format!("Bevy {i}"))
                .span(data)
                .summary(format!(
                    "{}, {}",
                    plural(index.len / 12, "chunk"),
                    size(data.len)
                ))
                .lazy(bevy_chunks, (volume.clone(), urn.clone(), data, index)),
        )
        .await;
    }
    Ok(())
}

async fn bevy_chunks(
    cx: Cx,
    (volume, urn, data, index): (Arc<Volume>, String, Span, Span),
) -> Result<()> {
    let info = stream_info(&volume, &urn);
    let count = index.len / 12;
    cx.set_count(Count::Exact(count));
    let raw = cx.read(index.sub(0, count.saturating_mul(12))).await?;
    for i in 0..to_usize(count) {
        let at = i.saturating_mul(12);
        let offset = u64_le(&raw, at).unwrap_or(0);
        let len = u64::from(u32_le(&raw, at.saturating_add(8)).unwrap_or(0));
        let span = data.sub(offset, len);
        let name = format!("Chunk {i}");
        let node = match &info.codec {
            _ if len == info.chunk && info.raw_full => {
                content(name, volume.input, span, Codec::Stored, Some(len)).summary("stored")
            }
            Some(codec) => content(name, volume.input, span, codec.clone(), Some(info.chunk))
                .summary(format!("{} → {}", size(len), size(info.chunk))),
            None => Node::new(name)
                .span(span)
                .diag(Diagnostic::unsupported("compression method")),
        };
        cx.push(node.target(index.sub(to_u64(at), 12))).await;
    }
    Ok(())
}

/// The bytes of an object: an image's data stream, a map, an image stream,
/// a member, or a symbolic stream.
async fn open(cx: &Cx, volume: &Volume, urn: &str) -> Result<Span> {
    let mut urn = urn.to_owned();
    if volume.is(&urn, "Image")
        && let Some(Obj::Iri(stream)) = volume.prop(&urn, "dataStream")
    {
        urn = stream.clone();
    }
    if volume.is(&urn, "Map") {
        return open_map(cx, volume, &urn).await;
    }
    open_leaf(cx, volume, &urn, None)
        .await?
        .ok_or_else(|| Diagnostic::unsupported(format!("no data for {urn}")))
}

/// A stream that is not a map: an image stream, a member, or a symbolic
/// stream (`len` bytes of it).
async fn open_leaf(cx: &Cx, volume: &Volume, urn: &str, len: Option<u64>) -> Result<Option<Span>> {
    if let Some(byte) = symbolic(urn) {
        let len = len.unwrap_or(0);
        return Ok(Some(match byte {
            Some(0) => Span::zeros(len),
            _ => pattern(cx, volume, urn, byte, len).await?,
        }));
    }
    if volume.is(urn, "ImageStream") {
        return Ok(Some(open_stream(cx, volume, urn).await?));
    }
    volume.content_of(cx, urn).await
}

/// A symbolic stream's byte (`None` for the text-filled ones).
fn symbolic(urn: &str) -> Option<Option<u8>> {
    let name = urn
        .strip_prefix("http://aff4.org/Schema#")
        .or_else(|| urn.strip_prefix("http://afflib.org/2009/aff4#"))
        .or_else(|| urn.strip_prefix("http://afflib.org/2012/SymbolicStream#"))?;
    match name {
        "Zero" => Some(Some(0)),
        "FF" => Some(Some(0xff)),
        "UnknownData" | "UnreadableData" => Some(None),
        n => {
            let hex = n.strip_prefix("SymbolicStream").unwrap_or(n);
            u8::from_str_radix(hex, 16).ok().map(Some)
        }
    }
}

/// `len` bytes of a repeated byte or text, as one 64 KiB piece repeated.
async fn pattern(cx: &Cx, volume: &Volume, urn: &str, byte: Option<u8>, len: u64) -> Result<Span> {
    let unit: &[u8] = match (byte, urn.ends_with("UnreadableData")) {
        (Some(_), _) => &[],
        (None, true) => b"UNREADABLEDATA",
        (None, false) => b"UNKNOWN",
    };
    let block: Vec<u8> = match byte {
        Some(b) => vec![b; 0x10000],
        None => {
            let whole =
                0x10000usize.saturating_sub(0x10000usize.checked_rem(unit.len()).unwrap_or(0));
            unit.iter().copied().cycle().take(whole).collect()
        }
    };
    let block_len = to_u64(block.len()).max(1);
    let origin = Origin {
        parent: volume.input.span.sub(0, 0),
        transform: match (byte, urn.ends_with("UnreadableData")) {
            (Some(0xff), _) => "aff4-ff",
            (Some(_), _) => "aff4-symbolic",
            (None, true) => "aff4-unreadable",
            (None, false) => "aff4-unknown",
        },
    };
    let piece = cx.add_derived(origin, block, block_len, None)?.span;
    let mut list = PieceList::new(volume.input.span.sub(0, 0));
    let mut left = len;
    while left > 0 {
        if list.pieces().len().is_multiple_of(4096) {
            cx.checkpoint().await;
        }
        let n = left.min(block_len);
        list.data(piece.sub(0, n));
        left = left.saturating_sub(n);
    }
    list.finish(cx, "aff4-symbolic").await
}

/// An image stream's chunks, each decoded lazily, up to its size.
async fn open_stream(cx: &Cx, volume: &Volume, urn: &str) -> Result<Span> {
    let info = stream_info(volume, urn);
    let codec = info
        .codec
        .clone()
        .ok_or_else(|| Diagnostic::unsupported(format!("compression of {urn}")))?;
    let anchor = volume
        .member(&format!("{}.index", bevy_name(urn, 0)))
        .map_or(volume.input.span.sub(0, 0), |m| m.entry);
    let mut list = PieceList::new(anchor);
    let chunks = info.size.div_ceil(info.chunk);
    let mut bevy = 0u64;
    'bevies: while list.len() < info.size && bevy < chunks.div_ceil(info.per_bevy).min(MAX_BEVIES) {
        let name = bevy_name(urn, bevy);
        bevy = bevy.saturating_add(1);
        let (Some(data), Some(index)) = (
            volume.member(&name),
            volume.member(&format!("{name}.index")),
        ) else {
            cx.diag(Diagnostic::malformed(format!(
                "{name} or its index is missing"
            )));
            break;
        };
        let data = volume.content(cx, data).await?;
        let index = volume.content(cx, index).await?;
        let raw = cx
            .read(index.sub(0, index.len.min(info.per_bevy.saturating_mul(12))))
            .await?;
        for (i, entry) in raw.as_chunks::<12>().0.iter().enumerate() {
            if i.is_multiple_of(1024) {
                cx.checkpoint().await;
            }
            let want = info.chunk.min(info.size.saturating_sub(list.len()));
            if want == 0 {
                break 'bevies;
            }
            let offset = u64_le(entry, 0).unwrap_or(0);
            let len = u64::from(u32_le(entry, 8).unwrap_or(0));
            let span = data.sub(offset, len);
            if (len == info.chunk && info.raw_full) || codec == Codec::Stored {
                list.data(span.sub(0, want));
                list.hole(cx, want.saturating_sub(span.len.min(want)))?;
            } else {
                // The last chunk is padded to the chunk size.
                let decoded = cx.decode_lazy(span, &codec, info.chunk)?;
                list.data(decoded.sub(0, want));
            }
        }
    }
    if list.len() < info.size {
        list.hole(cx, info.size.saturating_sub(list.len()))?;
    }
    list.finish(cx, "aff4-image-stream").await
}

/// A map: its ranges over its targets, holes between them, up to its size.
async fn open_map(cx: &Cx, volume: &Volume, urn: &str) -> Result<Span> {
    let names = targets(cx, volume, urn).await?;
    let Some(map) = volume.content_of(cx, &format!("{urn}/map")).await? else {
        return Err(Diagnostic::malformed(format!("no map member for {urn}")));
    };
    // Targets are opened once each.
    let mut opened: BTreeMap<u32, Option<Span>> = BTreeMap::new();
    let mut list = PieceList::new(map);
    let total = volume.number(urn, "size");
    let count = map.len / 28;
    let mut done = 0u64;
    while done < count {
        let page = count.saturating_sub(done).min(1024);
        let raw = cx
            .read(map.sub(done.saturating_mul(28), page.saturating_mul(28)))
            .await?;
        cx.checkpoint().await;
        for j in 0..to_usize(page) {
            let (mapped, len, offset, target) = map_entry(&raw, j.saturating_mul(28));
            if mapped < list.len() {
                cx.diag(Diagnostic::malformed(
                    "map entries overlap or are out of order",
                ));
                continue;
            }
            list.hole(cx, mapped.saturating_sub(list.len()))?;
            let Some(name) = names.get(to_usize(target.into())) else {
                list.hole(cx, len)?;
                continue;
            };
            if volume.is(name, "Map") {
                cx.diag(Diagnostic::unsupported("a map over another map"));
                list.hole(cx, len)?;
                continue;
            }
            let piece = match symbolic(name) {
                Some(_) => open_leaf(cx, volume, name, Some(len)).await?,
                None => match opened.get(&target) {
                    Some(s) => *s,
                    None => {
                        let s = open_leaf(cx, volume, name, None).await?;
                        opened.insert(target, s);
                        s
                    }
                },
            };
            match piece {
                Some(s) if symbolic(name).is_some() => list.data(s),
                Some(s) => {
                    let part = s.sub(offset, len);
                    list.data(part);
                    list.hole(cx, len.saturating_sub(part.len))?;
                }
                None => {
                    cx.diag(Diagnostic::malformed(format!(
                        "map target {name} not found"
                    )));
                    list.hole(cx, len)?;
                }
            }
        }
        done = done.saturating_add(page);
    }
    if let Some(total) = total
        && total > list.len()
    {
        list.hole(cx, total.saturating_sub(list.len()))?;
    }
    list.finish(cx, "aff4-map").await
}

#[cfg(test)]
mod tests {
    use super::{Obj, RDF_TYPE, Turtle, local, member_urn};

    #[test]
    fn turtle_statements() {
        let src = br#"@prefix aff4: <http://aff4.org/Schema#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
# a comment
<aff4://x> a aff4:DiskImage,
        aff4:Image ;
    aff4:size 98304 ;
    aff4:originalFileName "a \"b\".img"^^xsd:string ;
    aff4:blank [ aff4:x 1 ] .
<aff4://y> aff4:chunkSize 32768.
"#;
        let mut t = Turtle::new(src);
        let mut all = Vec::new();
        while let Some(s) = t.statement() {
            all.extend(s);
        }
        assert_eq!(all.len(), 6);
        assert_eq!(all.first().map(|t| t.1.as_str()), Some(RDF_TYPE));
        assert_eq!(
            all.get(3).map(|t| t.2.clone()),
            Some(Obj::Literal(
                "a \"b\".img".into(),
                Some("http://www.w3.org/2001/XMLSchema#string".into())
            ))
        );
        assert_eq!(all.get(4).map(|t| t.2.clone()), Some(Obj::Blank));
        assert_eq!(
            all.get(5)
                .map(|t| (t.0.as_str(), local(&t.1), t.2.as_str())),
            Some(("aff4://y", "chunkSize", "32768"))
        );
    }

    #[test]
    fn member_names() {
        assert_eq!(
            member_urn("aff4://v", "aff4%3A%2F%2Fs/data/00000000"),
            "aff4://s/data/00000000"
        );
        assert_eq!(
            member_urn("aff4://v", "/docs/a.txt"),
            "aff4://v//docs/a.txt"
        );
    }
}
