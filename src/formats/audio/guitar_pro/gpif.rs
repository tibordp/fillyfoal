//! GPIF, the score XML of Guitar Pro 6 (`score.gpif` inside a `.gpx`) and
//! Guitar Pro 7+ (`Content/score.gpif` inside a `.gp` ZIP).
//!
//! The document is dissected by the generic XML dissector; before it comes
//! a "Score summary" read from the elements a reader cares about: the
//! `Score` texts (title, artist, album, ...), the tempo automations of the
//! `MasterTrack`, the tracks (name, instrument, MIDI program, the `Tuning`
//! and `CapoFret` properties), the master bars (time signatures, sections,
//! repeats) and the sizes of the flat `Bars`/`Voices`/`Beats`/`Notes`/
//! `Rhythms` collections that the master bars refer to by id. Element names
//! are those seen in Guitar Pro 6 files and described by alphaTab's GPIF
//! reader; Guitar Pro 7 moved a track's tuning into `Staves/Staff`, which
//! the summary finds as well since it looks for the properties anywhere in
//! the track.

use std::sync::Arc;

use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::text::xml::{self, Mode};
use crate::formats::text::probe;
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::Value;

use super::{pitch_name, program_name};

/// Documents larger than this get no summary (the XML is still dissected).
const MAX_SUMMARY: u64 = 16 * 1024 * 1024;

fn probe_gpif(h: &Head<'_>) -> bool {
    probe::is_text(h) && xml::root(h).is_some_and(|r| r.is(b"GPIF"))
}

pub static FORMAT: Format = Format {
    name: "gpif",
    title: "Guitar Pro score (GPIF)",
    extensions: &["gpif"],
    mime: "application/xml",
    probe: Probe::Custom(probe_gpif),
    dissect: crate::expander!(dissect: Input),
};

async fn dissect(cx: Cx, input: Input) -> Result<()> {
    // The score texts come first; the head is enough for the annotation.
    let head = cx.read_avail(input.span.sub(0, 64 * 1024)).await?;
    let s = scan(&head);
    let mut note = "Guitar Pro score".to_owned();
    if !s.title.text.is_empty() {
        note.push_str(&format!(": {:?}", s.title.text));
    }
    if !s.artist.text.is_empty() {
        note.push_str(&format!(" by {}", s.artist.text));
    }
    cx.annotate(note);
    cx.emit(
        Node::new("Score summary")
            .span(input.span)
            .summary("from the GPIF elements")
            .lazy(summary, input.span),
    );
    xml::document(&cx, input, Mode::Xml).await
}

// ---------------------------------------------------------------------------
// A minimal scan of the elements the summary needs

/// A text with the span (relative to the document) of its element.
#[derive(Clone, Debug, Default)]
struct Item {
    text: String,
    at: (u64, u64),
}

#[derive(Clone, Debug, Default)]
struct Track {
    at: (u64, u64),
    id: String,
    name: Item,
    instrument: Item,
    program: Item,
    tuning: Item,
    capo: Item,
    /// The MIDI program is from the percussion table (`GeneralMidi`
    /// `table="Percussion"`), not a GM instrument.
    percussion: bool,
}

#[derive(Clone, Debug, Default)]
struct MasterBar {
    at: (u64, u64),
    time: String,
    section: Option<String>,
    repeat: Option<String>,
}

#[derive(Clone, Debug, Default)]
struct Summary {
    revision: Item,
    title: Item,
    subtitle: Item,
    artist: Item,
    album: Item,
    words: Item,
    music: Item,
    copyright: Item,
    tabber: Item,
    /// (bar, value, element span) of tempo automations.
    tempos: Vec<(String, String, (u64, u64))>,
    tracks: Vec<Track>,
    bars: Vec<MasterBar>,
    /// Element counts of the flat collections, with their spans.
    collections: Vec<(&'static str, u64, (u64, u64))>,
    /// Children seen so far in each of [`COLLECTIONS`].
    counts: [u64; 5],
}

/// The flat collections at the top level and the name of their elements.
const COLLECTIONS: [(&str, &str); 5] = [
    ("Bars", "Bar"),
    ("Voices", "Voice"),
    ("Beats", "Beat"),
    ("Notes", "Note"),
    ("Rhythms", "Rhythm"),
];

/// Where a scanned element sits: its name and start offset.
struct Open {
    name: String,
    start: u64,
    /// Attributes we need, by name.
    attrs: Vec<(String, String)>,
}

fn find(data: &[u8], from: usize, pat: &[u8]) -> Option<usize> {
    data.get(from..)?
        .windows(pat.len())
        .position(|w| w == pat)
        .map(|i| i.saturating_add(from))
}

/// The end of a tag starting at `from` (the index after its `>`), honouring
/// quoted attribute values.
fn tag_end(data: &[u8], from: usize) -> Option<usize> {
    let mut quote = None;
    for (i, &b) in data.iter().enumerate().skip(from) {
        match quote {
            Some(q) if b == q => quote = None,
            Some(_) => {}
            None if b == b'"' || b == b'\'' => quote = Some(b),
            None if b == b'>' => return Some(i.saturating_add(1)),
            None => {}
        }
    }
    None
}

fn attributes(tag: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while let Some(eq) = tag.get(i..).and_then(|r| r.iter().position(|&b| b == b'=')) {
        let eq = i.saturating_add(eq);
        let name_end = tag
            .get(..eq)
            .and_then(|r| r.iter().rposition(|b| !b.is_ascii_whitespace()))
            .map_or(0, |p| p.saturating_add(1));
        let name_start = tag
            .get(..name_end)
            .and_then(|r| r.iter().rposition(|b| b.is_ascii_whitespace()))
            .map_or(0, |p| p.saturating_add(1));
        let rest = tag.get(eq.saturating_add(1)..).unwrap_or_default();
        let Some(q) = rest.iter().position(|&b| b == b'"' || b == b'\'') else {
            break;
        };
        let quote = rest.get(q).copied().unwrap_or(b'"');
        let vstart = eq.saturating_add(1).saturating_add(q).saturating_add(1);
        let Some(len) = tag.get(vstart..).and_then(|r| r.iter().position(|&b| b == quote)) else {
            break;
        };
        let name = String::from_utf8_lossy(tag.get(name_start..name_end).unwrap_or_default()).into_owned();
        let value = String::from_utf8_lossy(tag.get(vstart..vstart.saturating_add(len)).unwrap_or_default());
        out.push((name, xml::decode_entities(&value, false)));
        i = vstart.saturating_add(len).saturating_add(1);
    }
    out
}

fn attr<'a>(attrs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    attrs.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
}

fn to64(i: usize) -> u64 {
    crate::bytes::to_u64(i)
}

/// Scans a GPIF document (or a prefix of one).
fn scan(data: &[u8]) -> Summary {
    let mut s = Summary::default();
    let mut stack: Vec<Open> = Vec::new();
    let mut text = String::new();
    let mut track: Option<Track> = None;
    let mut bar: Option<MasterBar> = None;
    // The property being read inside a track, and an automation's fields.
    let mut property: Option<String> = None;
    let mut automation: (String, String, String) = Default::default();
    let mut section: (String, String) = Default::default();
    let mut pos = 0usize;
    while pos < data.len() {
        let Some(lt) = find(data, pos, b"<") else {
            text.push_str(&xml::decode_entities(&String::from_utf8_lossy(data.get(pos..).unwrap_or_default()), false));
            break;
        };
        text.push_str(&xml::decode_entities(&String::from_utf8_lossy(data.get(pos..lt).unwrap_or_default()), false));
        let rest = data.get(lt..).unwrap_or_default();
        if rest.starts_with(b"<![CDATA[") {
            let from = lt.saturating_add(9);
            let end = find(data, from, b"]]>").unwrap_or(data.len());
            text.push_str(&String::from_utf8_lossy(data.get(from..end).unwrap_or_default()));
            pos = end.saturating_add(3);
            continue;
        }
        if rest.starts_with(b"<!--") {
            pos = find(data, lt.saturating_add(4), b"-->").map_or(data.len(), |e| e.saturating_add(3));
            continue;
        }
        if rest.starts_with(b"<?") || rest.starts_with(b"<!") {
            pos = tag_end(data, lt.saturating_add(1)).unwrap_or(data.len());
            continue;
        }
        let Some(end) = tag_end(data, lt.saturating_add(1)) else {
            break;
        };
        pos = end;
        let tag = data.get(lt.saturating_add(1)..end.saturating_sub(1)).unwrap_or_default();
        if let Some(name) = tag.strip_prefix(b"/") {
            let name = String::from_utf8_lossy(name.trim_ascii()).into_owned();
            // Close up to the matching element (tolerating bad nesting).
            let Some(depth) = stack.iter().rposition(|o| o.name == name) else {
                continue;
            };
            stack.truncate(depth.saturating_add(1));
            if let Some(open) = stack.pop() {
                let value = std::mem::take(&mut text).trim().to_owned();
                close(&mut s, &stack, &open, value, to64(end), &mut track, &mut bar, &mut property, &mut automation, &mut section);
            }
            continue;
        }
        let self_closing = tag.ends_with(b"/");
        let tag = if self_closing { tag.get(..tag.len().saturating_sub(1)).unwrap_or_default() } else { tag };
        let name_len = tag.iter().position(|b| b.is_ascii_whitespace()).unwrap_or(tag.len());
        let name = String::from_utf8_lossy(tag.get(..name_len).unwrap_or_default()).into_owned();
        let attrs = attributes(tag.get(name_len..).unwrap_or_default());
        text.clear();
        let open = Open {
            name,
            start: to64(lt),
            attrs,
        };
        opened(&stack, &open, &mut track, &mut bar, &mut property);
        if self_closing {
            close(&mut s, &stack, &open, String::new(), to64(end), &mut track, &mut bar, &mut property, &mut automation, &mut section);
        } else {
            stack.push(open);
        }
    }
    s
}

fn path_is(stack: &[Open], names: &[&str]) -> bool {
    stack.len() == names.len() && stack.iter().zip(names).all(|(o, n)| o.name == *n)
}

fn opened(
    stack: &[Open],
    open: &Open,
    track: &mut Option<Track>,
    bar: &mut Option<MasterBar>,
    property: &mut Option<String>,
) {
    if open.name == "Track" && path_is(stack, &["GPIF", "Tracks"]) {
        *track = Some(Track {
            id: attr(&open.attrs, "id").unwrap_or_default().to_owned(),
            ..Track::default()
        });
    }
    if open.name == "MasterBar" && path_is(stack, &["GPIF", "MasterBars"]) {
        *bar = Some(MasterBar::default());
    }
    if let Some(t) = track.as_mut()
        && open.name == "GeneralMidi"
        && attr(&open.attrs, "table") == Some("Percussion")
    {
        t.percussion = true;
    }
    if open.name == "Property" && track.is_some() {
        *property = attr(&open.attrs, "name").map(str::to_owned);
    }
    if let Some(t) = track.as_mut()
        && open.name == "Instrument"
        && t.instrument.text.is_empty()
        && let Some(r) = attr(&open.attrs, "ref")
    {
        t.instrument = Item {
            text: r.to_owned(),
            at: (open.start, open.start),
        };
    }
    if let Some(b) = bar.as_mut()
        && open.name == "Repeat"
    {
        let start = attr(&open.attrs, "start") == Some("true");
        let end = attr(&open.attrs, "end") == Some("true");
        let count = attr(&open.attrs, "count").unwrap_or("0");
        b.repeat = match (start, end) {
            (true, true) => Some(format!("repeat start and end ×{count}")),
            (true, false) => Some("repeat start".to_owned()),
            (false, true) => Some(format!("repeat end ×{count}")),
            (false, false) => None,
        };
    }
}

#[allow(clippy::too_many_arguments)]
fn close(
    s: &mut Summary,
    stack: &[Open],
    open: &Open,
    value: String,
    end: u64,
    track: &mut Option<Track>,
    bar: &mut Option<MasterBar>,
    property: &mut Option<String>,
    automation: &mut (String, String, String),
    section: &mut (String, String),
) {
    let at = (open.start, end);
    let item = || Item {
        text: value.clone(),
        at,
    };
    let parent = stack.last().map(|o| o.name.as_str()).unwrap_or_default();
    if path_is(stack, &["GPIF", "Score"]) {
        let slot = match open.name.as_str() {
            "Title" => Some(&mut s.title),
            "SubTitle" => Some(&mut s.subtitle),
            "Artist" => Some(&mut s.artist),
            "Album" => Some(&mut s.album),
            "Words" => Some(&mut s.words),
            "Music" => Some(&mut s.music),
            "Copyright" => Some(&mut s.copyright),
            "Tabber" => Some(&mut s.tabber),
            _ => None,
        };
        if let Some(slot) = slot {
            *slot = item();
        }
        return;
    }
    if path_is(stack, &["GPIF"]) {
        match open.name.as_str() {
            "GPRevision" | "GPVersion" => s.revision = item(),
            name => {
                if let Some(i) = COLLECTIONS.iter().position(|(c, _)| *c == name) {
                    let count = s.counts.get(i).copied().unwrap_or(0);
                    let label = COLLECTIONS.get(i).map_or("", |c| c.0);
                    s.collections.push((label, count, at));
                }
            }
        }
        return;
    }
    // Children of the flat collections: count them.
    if stack.len() == 2
        && stack.first().is_some_and(|o| o.name == "GPIF")
        && let Some(i) = COLLECTIONS.iter().position(|(c, one)| *c == parent && *one == open.name)
        && let Some(n) = s.counts.get_mut(i)
    {
        *n = n.saturating_add(1);
    }
    // Tempo automations.
    if stack.len() >= 3 && stack.get(1).is_some_and(|o| o.name == "MasterTrack") {
        match open.name.as_str() {
            "Type" if parent == "Automation" => automation.0 = value.clone(),
            "Bar" if parent == "Automation" => automation.1 = value.clone(),
            "Value" if parent == "Automation" => automation.2 = value.clone(),
            "Automation" => {
                let (kind, bar_no, v) = std::mem::take(automation);
                if kind == "Tempo" {
                    s.tempos.push((bar_no, v, at));
                }
            }
            _ => {}
        }
    }
    if let Some(t) = track.as_mut() {
        match open.name.as_str() {
            "Track" if path_is(stack, &["GPIF", "Tracks"]) => {
                if let Some(mut done) = track.take() {
                    done.at = at;
                    s.tracks.push(done);
                }
            }
            "Name" if stack.len() == 3 && t.name.text.is_empty() => t.name = item(),
            // Guitar Pro 7: <InstrumentSet><Name>.
            "Name" if parent == "InstrumentSet" && t.instrument.text.is_empty() => t.instrument = item(),
            "Instrument" if t.instrument.at.0 == open.start => t.instrument.at = at,
            "Program" if t.program.text.is_empty() => t.program = item(),
            "Pitches" if property.as_deref() == Some("Tuning") && t.tuning.text.is_empty() => t.tuning = item(),
            "Fret" if property.as_deref() == Some("CapoFret") && t.capo.text.is_empty() => t.capo = item(),
            "Property" => *property = None,
            _ => {}
        }
    }
    if let Some(b) = bar.as_mut() {
        match open.name.as_str() {
            "Time" if parent == "MasterBar" => b.time = value,
            "Letter" if parent == "Section" => section.0 = value,
            "Text" if parent == "Section" => section.1 = value,
            "Section" => {
                let (letter, text) = std::mem::take(section);
                let label = format!("{letter} {text}").trim().to_owned();
                if !label.is_empty() {
                    b.section = Some(label);
                }
            }
            "MasterBar" if path_is(stack, &["GPIF", "MasterBars"]) => {
                if let Some(mut done) = bar.take() {
                    done.at = at;
                    s.bars.push(done);
                }
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Rendering

async fn load(cx: &Cx, span: Span) -> Result<Arc<Summary>> {
    if let Some(s) = cx.cached::<Summary>(span, "gpif-summary") {
        return Ok(s);
    }
    if span.len > MAX_SUMMARY {
        return Err(Diagnostic::limit(format!("score larger than {MAX_SUMMARY:#x} bytes")).at(span));
    }
    let data = crate::codec::read_all(cx, span).await?;
    let s = Arc::new(scan(&data));
    cx.cache(span, "gpif-summary", s.clone());
    Ok(s)
}

fn sub(span: Span, at: (u64, u64)) -> Span {
    span.sub(at.0, at.1.saturating_sub(at.0))
}

fn text_node(span: Span, name: &'static str, item: &Item) -> Option<Node> {
    (!item.text.is_empty()).then(|| {
        Node::new(name)
            .span(sub(span, item.at))
            .value(Value::Text(item.text.clone()))
    })
}

fn tuning_names(pitches: &str) -> String {
    pitches
        .split_ascii_whitespace()
        .map(|p| p.parse::<i64>().map_or_else(|_| p.to_owned(), pitch_name))
        .collect::<Vec<_>>()
        .join(" ")
}

fn track_summary(t: &Track) -> String {
    let mut parts = vec![format!("{:?}", t.name.text)];
    if !t.instrument.text.is_empty() {
        parts.push(t.instrument.text.clone());
    }
    if !t.tuning.text.is_empty() {
        parts.push(format!("tuning {}", tuning_names(&t.tuning.text)));
    }
    if !t.capo.text.is_empty() && t.capo.text != "0" {
        parts.push(format!("capo {}", t.capo.text));
    }
    if t.percussion {
        parts.push("percussion".to_owned());
    } else if let Some(p) = t.program.text.parse::<i64>().ok().and_then(program_name) {
        parts.push(p.to_owned());
    }
    parts.join(", ")
}

async fn summary(cx: Cx, span: Span) -> Result<()> {
    let s = load(&cx, span).await?;
    for (name, item) in [
        ("Title", &s.title),
        ("Subtitle", &s.subtitle),
        ("Artist", &s.artist),
        ("Album", &s.album),
        ("Words", &s.words),
        ("Music", &s.music),
        ("Copyright", &s.copyright),
        ("Tabber", &s.tabber),
        ("Guitar Pro revision", &s.revision),
    ] {
        if let Some(node) = text_node(span, name, item) {
            cx.emit(node);
        }
    }
    if let Some((bar, value, at)) = s.tempos.first() {
        let bpm = value.split_ascii_whitespace().next().unwrap_or_default();
        let mut node = Node::new("Tempo")
            .span(sub(span, *at))
            .value(Value::Text(format!("{bpm} BPM")));
        if s.tempos.len() > 1 {
            node = node.summary(format!("from bar {}, {} tempo changes", bar.parse::<u64>().unwrap_or(0).saturating_add(1), s.tempos.len().saturating_sub(1)));
        }
        cx.emit(node);
    }
    cx.emit(
        Node::new("Tracks")
            .summary(format!("{} tracks", s.tracks.len()))
            .lazy(tracks, span),
    );
    cx.emit(
        Node::new("Master bars")
            .summary(bars_summary(&s.bars))
            .lazy(master_bars, span),
    );
    for (name, count, at) in &s.collections {
        cx.emit(
            Node::new(*name)
                .span(sub(span, *at))
                .value(Value::UInt {
                    value: *count,
                    bits: 64,
                    radix: crate::value::Radix::Dec,
                })
                .summary("elements"),
        );
    }
    Ok(())
}

fn bars_summary(bars: &[MasterBar]) -> String {
    let mut times: Vec<(String, usize)> = Vec::new();
    for b in bars {
        match times.iter_mut().find(|(t, _)| *t == b.time) {
            Some(t) => t.1 = t.1.saturating_add(1),
            None => times.push((b.time.clone(), 1)),
        }
    }
    let sections = bars.iter().filter(|b| b.section.is_some()).count();
    let list: Vec<String> = times.iter().take(4).map(|(t, n)| format!("{t} ×{n}")).collect();
    format!("{} bars ({}), {sections} sections", bars.len(), list.join(", "))
}

async fn tracks(cx: Cx, span: Span) -> Result<()> {
    let s = load(&cx, span).await?;
    for (i, t) in s.tracks.iter().enumerate() {
        cx.push(
            Node::new(format!("Track {}", if t.id.is_empty() { i.to_string() } else { t.id.clone() }))
                .span(sub(span, t.at))
                .summary(track_summary(t))
                .lazy(track, (span, i)),
        )
        .await;
    }
    Ok(())
}

async fn track(cx: Cx, (span, i): (Span, usize)) -> Result<()> {
    let s = load(&cx, span).await?;
    let Some(t) = s.tracks.get(i) else {
        return Ok(());
    };
    for (name, item) in [("Name", &t.name), ("Instrument", &t.instrument)] {
        if let Some(node) = text_node(span, name, item) {
            cx.emit(node);
        }
    }
    if let Some(node) = text_node(span, "MIDI program", &t.program) {
        let p = if t.percussion {
            Some("percussion")
        } else {
            t.program.text.parse::<i64>().ok().and_then(program_name)
        };
        cx.emit(match p {
            Some(p) => node.summary(p),
            None => node,
        });
    }
    if let Some(node) = text_node(span, "Tuning", &t.tuning) {
        cx.emit(node.summary(tuning_names(&t.tuning.text)));
    }
    if let Some(node) = text_node(span, "Capo", &t.capo) {
        cx.emit(node);
    }
    Ok(())
}

async fn master_bars(cx: Cx, span: Span) -> Result<()> {
    let s = load(&cx, span).await?;
    for (i, b) in s.bars.iter().enumerate() {
        let mut parts = vec![b.time.clone()];
        if let Some(sec) = &b.section {
            parts.push(format!("section {sec:?}"));
        }
        if let Some(r) = &b.repeat {
            parts.push(r.clone());
        }
        cx.push(
            Node::new(format!("Bar {}", i.saturating_add(1)))
                .span(sub(span, b.at))
                .summary(parts.join(", ")),
        )
        .await;
    }
    Ok(())
}
