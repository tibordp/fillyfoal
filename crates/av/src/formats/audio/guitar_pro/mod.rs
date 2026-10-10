//! Guitar Pro tablature: the binary formats of Guitar Pro 3, 4 and 5
//! (`.gp3`, `.gp4`, `.gp5`, here), Guitar Pro 6 (`.gpx`, a compressed
//! sector file system, [`gpx`]) and the GPIF score XML inside it and inside
//! Guitar Pro 7+ files ([`gpif`]).
//!
//! # GP3/GP4/GP5
//!
//! Little-endian, no offsets: everything is read in sequence. A 31-byte
//! version string (`FICHIER GUITAR PRO v5.10`), the song information
//! (strings with an `i32` size and a byte length), lyrics (GP4+), RSE master
//! effect and page setup (GP5), tempo and key, a table of 64 MIDI channels
//! (4 ports of 16), GP5's 19 direction signs (coda, segno, ...), then the
//! measure and track counts, the measure headers (time signature, repeats,
//! alternative endings, markers, key changes), the track headers (name,
//! string count and tuning, MIDI port and channel, frets, capo, colour, and
//! GP5's RSE settings), and finally the measures: for each measure, for
//! each track, one voice (GP3/GP4) or two (GP5) of beats, each beat with
//! optional chord diagram, text, effects, mix-table change and the notes
//! on the strings it sets.
//!
//! The layout follows PyGuitarPro 0.11 (which reads and writes all three
//! versions) and agrees with TuxGuitar's readers where they overlap. It was
//! checked against real Guitar Pro 5.10 files (parsed to their last byte,
//! with the measure, beat and note counts PyGuitarPro reports) and against
//! GP3, GP4 and GP5 files written by PyGuitarPro (the fixtures). Fields
//! whose meaning no reader documents are shown as `Unknown`/`Padding`.
//! GP5.00 differs from 5.10 in a few places (RSE fields, padding); those
//! paths are only checked against PyGuitarPro's writer. Guitar Pro 1/2 and
//! clipboard files are recognised but not dissected beyond the version.

pub mod gpif;
pub mod gpx;

use std::borrow::Cow;
use std::sync::Arc;

use crate::codec::charset::Charset;
use crate::cx::Cx;
use crate::declare_format;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::audio::midi::GM_PROGRAMS;
use crate::formats::{Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag};

const LE: Endian = Endian::Little;

/// Bytes read in one piece; larger files are dissected up to this point.
const MAX_FILE: u64 = 16 * 1024 * 1024;

fn guitar_pro_probe(h: &Head<'_>) -> bool {
    (h.at(1, b"FICHIER GUITAR PRO") || h.at(1, b"FICHIER GUITARE PRO"))
        && h.data.first().is_some_and(|&n| (18..=30).contains(&n))
}

declare_format!(pub FORMAT = "guitar-pro", "Guitar Pro tablature", ["gp3", "gp4", "gp5", "gtp"], "application/x-guitar-pro",
    Probe::Custom(guitar_pro_probe), dissect);

// ---------------------------------------------------------------------------
// Shared helpers (also used by the GPX/GPIF summaries)

const NOTE_NAMES: [&str; 12] = [
    "C", "C#", "D", "D#", "E", "F", "F#", "G", "G#", "A", "A#", "B",
];

/// A MIDI note number as a name with octave (60 is C4).
pub(crate) fn pitch_name(midi: i64) -> String {
    if !(0..=127).contains(&midi) {
        return format!("{midi}");
    }
    let name = usize::try_from(midi.rem_euclid(12))
        .ok()
        .and_then(|i| NOTE_NAMES.get(i))
        .copied()
        .unwrap_or("?");
    format!("{name}{}", midi.div_euclid(12).saturating_sub(1))
}

/// A General MIDI program name.
pub(crate) fn program_name(program: i64) -> Option<&'static str> {
    usize::try_from(program)
        .ok()
        .and_then(|p| GM_PROGRAMS.get(p))
        .copied()
}

/// Key signature names by number of sharps (negative: flats), -7..=7.
fn key_name(root: i64, minor: bool) -> Option<&'static str> {
    const MAJOR: [&str; 15] = [
        "C♭ major",
        "G♭ major",
        "D♭ major",
        "A♭ major",
        "E♭ major",
        "B♭ major",
        "F major",
        "C major",
        "G major",
        "D major",
        "A major",
        "E major",
        "B major",
        "F♯ major",
        "C♯ major",
    ];
    const MINOR: [&str; 15] = [
        "A♭ minor",
        "E♭ minor",
        "B♭ minor",
        "F minor",
        "C minor",
        "G minor",
        "D minor",
        "A minor",
        "E minor",
        "B minor",
        "F♯ minor",
        "C♯ minor",
        "G♯ minor",
        "D♯ minor",
        "A♯ minor",
    ];
    let i = usize::try_from(root.checked_add(7)?).ok()?;
    if minor {
        MINOR.get(i).copied()
    } else {
        MAJOR.get(i).copied()
    }
}

fn text(bytes: &[u8]) -> String {
    Charset::Windows1252.decode(bytes)
}

/// The span from `start` (relative to the block) to the cursor.
fn since(f: &Fields<'_>, start: u64) -> Span {
    let b = f.block().span;
    Span::new(
        b.source,
        b.offset.saturating_add(start),
        f.pos().saturating_sub(start),
    )
}

fn emit_text(f: &Fields<'_>, name: impl Into<Cow<'static, str>>, start: u64, value: &str) {
    f.node(
        Node::new(name)
            .span(since(f, start))
            .value(Value::Text(value.to_owned())),
    );
}

/// An `i32` size, a byte length, then `size - 1` bytes of which the first
/// `length` are the text (when the size is not positive, `length` bytes).
fn ibstr(f: &mut Fields<'_>, name: &'static str) -> Result<String> {
    let start = f.pos();
    let size = f.int::<i32>(name).get()?;
    let len = f.u8(name).get()?;
    let n = match size.checked_sub(1) {
        Some(n) if n > 0 => u64::try_from(n).unwrap_or(0),
        _ => u64::from(len),
    };
    let bytes = f.bytes(name, n).get()?;
    let value = text(
        bytes
            .get(..usize::from(len).min(bytes.len()))
            .unwrap_or_default(),
    );
    emit_text(f, name, start, &value);
    Ok(value)
}

/// A byte length and a fixed `size`-byte field.
fn bstr(f: &mut Fields<'_>, name: &'static str, size: u64) -> Result<String> {
    let start = f.pos();
    let len = f.u8(name).get()?;
    let bytes = f.bytes(name, size).get()?;
    let value = text(
        bytes
            .get(..usize::from(len).min(bytes.len()))
            .unwrap_or_default(),
    );
    emit_text(f, name, start, &value);
    Ok(value)
}

/// An `i32` length and that many bytes.
fn istr(f: &mut Fields<'_>, name: &'static str) -> Result<String> {
    let start = f.pos();
    let len = f.int::<i32>(name).get()?;
    let bytes = f.bytes(name, u64::try_from(len).unwrap_or(0)).get()?;
    let value = text(&bytes);
    emit_text(f, name, start, &value);
    Ok(value)
}

/// R, G, B and a padding byte.
fn color(f: &mut Fields<'_>, name: &'static str) -> Result<String> {
    let start = f.pos();
    let rgb = f.bytes(name, 4).get()?;
    let get = |i: usize| rgb.get(i).copied().unwrap_or(0);
    let value = format!("#{:02x}{:02x}{:02x}", get(0), get(1), get(2));
    emit_text(f, name, start, &value);
    Ok(value)
}

fn i8f(f: &mut Fields<'_>, name: &'static str) -> Result<i8> {
    f.int::<i8>(name).emit()
}

fn i16f(f: &mut Fields<'_>, name: &'static str) -> Result<i16> {
    f.int::<i16>(name).emit()
}

fn i32f(f: &mut Fields<'_>, name: &'static str) -> Result<i32> {
    f.int::<i32>(name).emit()
}

/// A sub-structure decoded by `layout` from the cursor: emitted as a lazy
/// node of its own (when emitting) and skipped over.
fn group<C, R>(
    f: &mut Fields<'_>,
    name: impl Into<Cow<'static, str>>,
    ctx: &C,
    layout: fn(&mut Fields<'_>, &C) -> Result<R>,
    summary: impl FnOnce(&R) -> Option<String>,
) -> Result<R>
where
    C: Clone + Send + Sync + 'static,
    R: 'static,
{
    let start = f.pos();
    let mut probe = Fields::new(f.block(), LE);
    probe.seek(start);
    let result = layout(&mut probe, ctx);
    let len = probe.pos().saturating_sub(start);
    if f.is_emitting() {
        let mut node = struct_node(name, f.peek_span(len), LE, ctx.clone(), layout);
        if let Some(s) = result.as_ref().ok().and_then(summary) {
            node = node.summary(s);
        }
        f.node(node);
    }
    f.seek(start.saturating_add(len));
    result
}

// ---------------------------------------------------------------------------
// Versions

/// The binary format version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Ver {
    major: u8,
    /// Guitar Pro 5.10 or later (5.00 lacks some RSE fields).
    v510: bool,
}

fn parse_version(s: &str) -> Option<Ver> {
    let rest = s.strip_prefix("FICHIER GUITAR PRO ")?;
    let mut chars = rest.chars();
    let tag = chars.next()?;
    if tag != 'v' && tag != 'L' {
        return None;
    }
    let digits: String = chars.collect();
    let (major, minor) = digits.split_once('.')?;
    let major: u8 = major.parse().ok()?;
    let minor: u32 = minor.get(..2).unwrap_or(minor).parse().ok()?;
    (3..=5).contains(&major).then_some(Ver {
        major,
        v510: major == 5 && minor >= 10,
    })
}

// ---------------------------------------------------------------------------
// Tables

const TRIPLET_FEEL: EnumTable = &[(0, "none"), (1, "eighth"), (2, "sixteenth")];

const HEADER_FOOTER: FlagTable = &[
    flag(0x001, "TITLE"),
    flag(0x002, "SUBTITLE"),
    flag(0x004, "ARTIST"),
    flag(0x008, "ALBUM"),
    flag(0x010, "WORDS"),
    flag(0x020, "MUSIC"),
    flag(0x040, "WORDS_AND_MUSIC"),
    flag(0x080, "COPYRIGHT"),
    flag(0x100, "PAGE_NUMBER"),
];

const MEASURE_FLAGS: FlagTable = &[
    flag(0x01, "NUMERATOR"),
    flag(0x02, "DENOMINATOR"),
    flag(0x04, "REPEAT_START"),
    flag(0x08, "REPEAT_END"),
    flag(0x10, "ALTERNATIVE_ENDING"),
    flag(0x20, "MARKER"),
    flag(0x40, "KEY_SIGNATURE"),
    flag(0x80, "DOUBLE_BAR"),
];

const TRACK_FLAGS: FlagTable = &[
    flag(0x01, "DRUMS"),
    flag(0x02, "TWELVE_STRING"),
    flag(0x04, "BANJO"),
    flag(0x08, "VISIBLE"),
    flag(0x10, "SOLO"),
    flag(0x20, "MUTE"),
    flag(0x40, "RSE"),
    flag(0x80, "SHOW_TUNING"),
];

const TRACK_FLAGS2: FlagTable = &[
    flag(0x0001, "TABLATURE"),
    flag(0x0002, "NOTATION"),
    flag(0x0004, "DIAGRAMS_BELOW"),
    flag(0x0008, "SHOW_RHYTHM"),
    flag(0x0010, "FORCE_HORIZONTAL"),
    flag(0x0020, "FORCE_CHANNELS"),
    flag(0x0040, "DIAGRAM_LIST"),
    flag(0x0080, "DIAGRAMS_IN_SCORE"),
    flag(0x0200, "AUTO_LET_RING"),
    flag(0x0400, "AUTO_BRUSH"),
    flag(0x0800, "EXTEND_RHYTHMIC"),
];

const BEAT_FLAGS: FlagTable = &[
    flag(0x01, "DOTTED"),
    flag(0x02, "CHORD"),
    flag(0x04, "TEXT"),
    flag(0x08, "EFFECTS"),
    flag(0x10, "MIX_TABLE"),
    flag(0x20, "TUPLET"),
    flag(0x40, "STATUS"),
];

const BEAT_FLAGS2: FlagTable = &[
    flag(0x0001, "BREAK_BEAM"),
    flag(0x0002, "BEAM_DOWN"),
    flag(0x0004, "FORCE_BEAM"),
    flag(0x0008, "BEAM_UP"),
    flag(0x0010, "OTTAVA"),
    flag(0x0020, "OTTAVA_BASSA"),
    flag(0x0040, "QUINDICESIMA"),
    flag(0x0100, "QUINDICESIMA_BASSA"),
    flag(0x0200, "TUPLET_BRACKET_START"),
    flag(0x0400, "TUPLET_BRACKET_END"),
    flag(0x0800, "BREAK_SECONDARY"),
    flag(0x1000, "BREAK_SECONDARY_TUPLET"),
    flag(0x2000, "FORCE_TUPLET_BRACKET"),
];

const BEAT_STATUS: EnumTable = &[(0, "empty"), (1, "normal"), (2, "rest")];

const STRING_FLAGS: FlagTable = &[
    flag(0x40, "STRING_1"),
    flag(0x20, "STRING_2"),
    flag(0x10, "STRING_3"),
    flag(0x08, "STRING_4"),
    flag(0x04, "STRING_5"),
    flag(0x02, "STRING_6"),
    flag(0x01, "STRING_7"),
];

const NOTE_FLAGS: FlagTable = &[
    flag(0x01, "TIME_INDEPENDENT_DURATION"),
    flag(0x02, "HEAVY_ACCENT"),
    flag(0x04, "GHOST"),
    flag(0x08, "EFFECTS"),
    flag(0x10, "DYNAMICS"),
    flag(0x20, "TYPE_AND_FRET"),
    flag(0x40, "ACCENT"),
    flag(0x80, "FINGERING"),
];

const NOTE_FLAGS2: FlagTable = &[flag(0x02, "SWAP_ACCIDENTALS")];

const GRACE_FLAGS: FlagTable = &[flag(0x01, "DEAD"), flag(0x02, "ON_BEAT")];

const NOTE_TYPE: EnumTable = &[(1, "normal"), (2, "tie"), (3, "dead")];

const GP3_BEAT_EFFECTS: FlagTable = &[
    flag(0x01, "VIBRATO"),
    flag(0x02, "WIDE_VIBRATO"),
    flag(0x04, "NATURAL_HARMONIC"),
    flag(0x08, "ARTIFICIAL_HARMONIC"),
    flag(0x10, "FADE_IN"),
    flag(0x20, "TREMOLO_BAR_OR_SLAP"),
    flag(0x40, "STROKE"),
];

const BEAT_EFFECTS1: FlagTable = &[
    flag(0x01, "VIBRATO"),
    flag(0x02, "WIDE_VIBRATO"),
    flag(0x04, "NATURAL_HARMONIC"),
    flag(0x08, "ARTIFICIAL_HARMONIC"),
    flag(0x10, "FADE_IN"),
    flag(0x20, "SLAP"),
    flag(0x40, "STROKE"),
];

const BEAT_EFFECTS2: FlagTable = &[
    flag(0x01, "RASGUEADO"),
    flag(0x02, "PICK_STROKE"),
    flag(0x04, "TREMOLO_BAR"),
];

const SLAP: EnumTable = &[(0, "none"), (1, "tapping"), (2, "slapping"), (3, "popping")];

const GP3_NOTE_EFFECTS: FlagTable = &[
    flag(0x01, "BEND"),
    flag(0x02, "HAMMER_PULL"),
    flag(0x04, "SLIDE"),
    flag(0x08, "LET_RING"),
    flag(0x10, "GRACE"),
];

const NOTE_EFFECTS1: FlagTable = &[
    flag(0x01, "BEND"),
    flag(0x02, "HAMMER_PULL"),
    flag(0x08, "LET_RING"),
    flag(0x10, "GRACE"),
];

const NOTE_EFFECTS2: FlagTable = &[
    flag(0x01, "STACCATO"),
    flag(0x02, "PALM_MUTE"),
    flag(0x04, "TREMOLO_PICKING"),
    flag(0x08, "SLIDE"),
    flag(0x10, "HARMONIC"),
    flag(0x20, "TRILL"),
    flag(0x40, "VIBRATO"),
];

const GP5_SLIDES: FlagTable = &[
    flag(0x01, "SHIFT_SLIDE"),
    flag(0x02, "LEGATO_SLIDE"),
    flag(0x04, "OUT_DOWNWARDS"),
    flag(0x08, "OUT_UPWARDS"),
    flag(0x10, "IN_FROM_BELOW"),
    flag(0x20, "IN_FROM_ABOVE"),
];

const HARMONIC: EnumTable = &[
    (1, "natural"),
    (2, "artificial"),
    (3, "tapped"),
    (4, "pinch"),
    (5, "semi"),
    (15, "artificial +5 (GP4)"),
    (17, "artificial +7 (GP4)"),
    (22, "artificial +12 (GP4)"),
];

const BEND_TYPE: EnumTable = &[
    (0, "none"),
    (1, "bend"),
    (2, "bend and release"),
    (3, "bend, release, bend"),
    (4, "pre-bend"),
    (5, "pre-bend and release"),
    (6, "dip"),
    (7, "dive"),
    (8, "release (up)"),
    (9, "inverted dip"),
    (10, "return"),
    (11, "release (down)"),
];

const GRACE_TRANSITION: EnumTable = &[(0, "none"), (1, "slide"), (2, "bend"), (3, "hammer")];

const MIX_FLAGS: FlagTable = &[
    flag(0x01, "VOLUME_ALL_TRACKS"),
    flag(0x02, "BALANCE_ALL_TRACKS"),
    flag(0x04, "CHORUS_ALL_TRACKS"),
    flag(0x08, "REVERB_ALL_TRACKS"),
    flag(0x10, "PHASER_ALL_TRACKS"),
    flag(0x20, "TREMOLO_ALL_TRACKS"),
    flag(0x40, "USE_RSE"),
    flag(0x80, "SHOW_WAH"),
];

const DIRECTIONS: [&str; 19] = [
    "Coda",
    "Double coda",
    "Segno",
    "Segno segno",
    "Fine",
    "Da capo",
    "Da capo al coda",
    "Da capo al double coda",
    "Da capo al fine",
    "Da segno",
    "Da segno al coda",
    "Da segno al double coda",
    "Da segno al fine",
    "Da segno segno",
    "Da segno segno al coda",
    "Da segno segno al double coda",
    "Da segno segno al fine",
    "Da coda",
    "Da double coda",
];

const STRING_NAMES: [&str; 7] = [
    "String 1", "String 2", "String 3", "String 4", "String 5", "String 6", "String 7",
];

fn duration_name(d: i8) -> &'static str {
    match d {
        -2 => "whole",
        -1 => "half",
        0 => "quarter",
        1 => "eighth",
        2 => "sixteenth",
        3 => "thirty-second",
        4 => "sixty-fourth",
        _ => "unknown duration",
    }
}

// ---------------------------------------------------------------------------
// Song header

/// What later parts need: version, measure headers and track headers.
#[derive(Debug, Default)]
struct Song {
    ver: Option<Ver>,
    headers: Vec<Header>,
    tracks: Vec<Track>,
}

#[derive(Clone, Debug, Default)]
struct Header {
    flags: u8,
    numerator: Option<i8>,
    denominator: Option<i8>,
    repeat_close: Option<i8>,
    alternative: Option<u8>,
    marker: Option<String>,
    key: Option<(i8, i8)>,
}

#[derive(Clone, Debug, Default)]
struct Track {
    name: String,
    strings: u8,
    tuning: Vec<i32>,
    drums: bool,
    frets: i32,
    capo: i32,
    channel: i32,
}

#[derive(Clone, Copy, Debug)]
struct Sizes {
    tempo: i32,
    measures: i32,
    tracks: i32,
}

async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let block = cx.block(file.sub(0, file.len.min(MAX_FILE))).await?;
    if file.len > MAX_FILE {
        cx.diag(Diagnostic::limit(format!(
            "only the first {MAX_FILE:#x} bytes are dissected"
        )));
    }
    let mut f = Fields::emitting(&cx, &block, LE);
    let version = bstr(&mut f, "Version", 30)?;
    let Some(ver) = parse_version(&version) else {
        cx.emit(
            Node::new("Song data")
                .span(file.tail(f.pos()))
                .diag(Diagnostic::unsupported(format!(
                    "{version} files are not dissected"
                ))),
        );
        cx.annotate(version);
        return Ok(());
    };
    let info = group(&mut f, "Song information", &ver, info, |i: &Info| {
        Some(i.summary())
    })?;
    let summary = |sizes: Option<Sizes>| {
        let mut s = format!(
            "Guitar Pro {}",
            version
                .rsplit(' ')
                .next()
                .unwrap_or_default()
                .trim_start_matches(['v', 'L'])
        );
        if !info.title.is_empty() {
            s.push_str(&format!(": {:?}", info.title));
        }
        if !info.artist.is_empty() {
            s.push_str(&format!(" by {}", info.artist));
        }
        if let Some(z) = sizes {
            s.push_str(&format!(
                ", {} tracks, {} measures, {} BPM",
                z.tracks, z.measures, z.tempo
            ));
        }
        s
    };
    match song_body(&cx, &mut f, ver, file).await {
        Ok(sizes) => cx.annotate(summary(Some(sizes))),
        Err(e) => {
            cx.annotate(summary(None));
            return Err(e);
        }
    }
    Ok(())
}

#[derive(Debug, Default)]
struct Info {
    title: String,
    artist: String,
}

impl Info {
    fn summary(&self) -> String {
        match (self.title.is_empty(), self.artist.is_empty()) {
            (false, false) => format!("{:?} by {}", self.title, self.artist),
            (false, true) => format!("{:?}", self.title),
            (true, false) => format!("by {}", self.artist),
            (true, true) => "untitled".to_owned(),
        }
    }
}

fn info(f: &mut Fields<'_>, ver: &Ver) -> Result<Info> {
    let title = ibstr(f, "Title")?;
    ibstr(f, "Subtitle")?;
    let artist = ibstr(f, "Artist")?;
    ibstr(f, "Album")?;
    ibstr(f, if ver.major >= 5 { "Words" } else { "Author" })?;
    if ver.major >= 5 {
        ibstr(f, "Music")?;
    }
    ibstr(f, "Copyright")?;
    ibstr(f, "Tab author")?;
    ibstr(f, "Instructions")?;
    let lines = i32f(f, "Notice lines")?;
    for _ in 0..lines.max(0) {
        ibstr(f, "Notice")?;
    }
    Ok(Info { title, artist })
}

fn lyrics(f: &mut Fields<'_>, _: &()) -> Result<usize> {
    i32f(f, "Lyrics track")?;
    let mut used = 0usize;
    for name in ["Line 1", "Line 2", "Line 3", "Line 4", "Line 5"] {
        let text = group(f, name, &(), lyric_line, |(m, t): &(i32, String)| {
            Some(if t.is_empty() {
                "empty".to_owned()
            } else {
                format!("from measure {m}, {} characters", t.chars().count())
            })
        })?;
        if !text.1.is_empty() {
            used = used.saturating_add(1);
        }
    }
    Ok(used)
}

fn lyric_line(f: &mut Fields<'_>, _: &()) -> Result<(i32, String)> {
    let measure = i32f(f, "Starting measure")?;
    let text = istr(f, "Text")?;
    Ok((measure, text))
}

fn equalizer(f: &mut Fields<'_>, bands: &usize) -> Result<()> {
    const NAMES: [&str; 10] = [
        "Band 1", "Band 2", "Band 3", "Band 4", "Band 5", "Band 6", "Band 7", "Band 8", "Band 9",
        "Band 10",
    ];
    for name in NAMES.iter().take(*bands) {
        f.int::<i8>(name).desc("Gain in -0.1 dB steps").emit()?;
    }
    f.int::<i8>("Gain").desc("In -0.1 dB steps").emit()?;
    Ok(())
}

fn master_effect(f: &mut Fields<'_>, _: &()) -> Result<()> {
    i32f(f, "Master volume")?;
    i32f(f, "Reserved")?;
    group(f, "Equalizer", &10usize, equalizer, |_| None)?;
    Ok(())
}

fn page_setup(f: &mut Fields<'_>, _: &()) -> Result<(i32, i32)> {
    let w = f.int::<i32>("Page width").desc("Millimetres").emit()?;
    let h = f.int::<i32>("Page height").desc("Millimetres").emit()?;
    for name in ["Left margin", "Right margin", "Top margin", "Bottom margin"] {
        i32f(f, name)?;
    }
    f.int::<i32>("Score size").summary("percent").emit()?;
    f.u16("Header and footer").flags(HEADER_FOOTER).emit()?;
    for name in [
        "Title template",
        "Subtitle template",
        "Artist template",
        "Album template",
        "Words template",
        "Music template",
        "Words and music template",
        "Copyright template (line 1)",
        "Copyright template (line 2)",
        "Page number template",
    ] {
        ibstr(f, name)?;
    }
    Ok((w, h))
}

fn midi_channel(f: &mut Fields<'_>, _: &()) -> Result<i32> {
    let program = f
        .int::<i32>("Instrument")
        .with(|&p, n| match program_name(i64::from(p)) {
            Some(name) => n.summary(name),
            None => n,
        })
        .emit()?;
    for name in ["Volume", "Balance", "Chorus", "Reverb", "Phaser", "Tremolo"] {
        i8f(f, name)?;
    }
    f.bytes("Padding", 2).emit()?;
    Ok(program)
}

async fn midi_channels(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::new(&block, LE);
    cx.set_count(Count::Exact(64));
    for i in 0..64u32 {
        let start = f.pos();
        let program = midi_channel(&mut f, &())?;
        let at = since(&f, start);
        let name = format!(
            "Port {} channel {}",
            (i / 16).saturating_add(1),
            (i % 16).saturating_add(1)
        );
        let mut node = struct_node(name, at, LE, (), midi_channel);
        if i % 16 == 9 {
            node = node.summary("percussion");
        } else if let Some(p) = program_name(i64::from(program)) {
            node = node.summary(p);
        }
        cx.push(node).await;
    }
    Ok(())
}

fn directions(f: &mut Fields<'_>, _: &()) -> Result<usize> {
    let mut used = 0usize;
    for name in DIRECTIONS {
        let m = f.int::<i16>(name).desc("Measure number, or -1").emit()?;
        if m > 0 {
            used = used.saturating_add(1);
        }
    }
    Ok(used)
}

/// Everything after the song information, at the top level.
async fn song_body(cx: &Cx, f: &mut Fields<'_>, ver: Ver, file: Span) -> Result<Sizes> {
    if ver.major < 5 {
        f.u8("Triplet feel")
            .enumeration(&[(0, "none"), (1, "eighth")])
            .emit()?;
    }
    if ver.major >= 4 {
        group(f, "Lyrics", &(), lyrics, |n| {
            Some(format!("{n} non-empty lines"))
        })?;
    }
    if ver.major >= 5 {
        if ver.v510 {
            group(f, "RSE master effect", &(), master_effect, |_| None)?;
        }
        group(f, "Page setup", &(), page_setup, |(w, h)| {
            Some(format!("{w}×{h} mm"))
        })?;
        ibstr(f, "Tempo name")?;
    }
    let tempo = f.int::<i32>("Tempo").summary("BPM").emit()?;
    if ver.v510 {
        f.u8("Hide tempo").emit()?;
    }
    if ver.major >= 5 {
        f.int::<i8>("Key")
            .with(|&k, n| match key_name(i64::from(k), false) {
                Some(name) => n.summary(name),
                None => n,
            })
            .emit()?;
        i32f(f, "Octave")?;
    } else {
        f.int::<i32>("Key")
            .with(|&k, n| match key_name(i64::from(k), false) {
                Some(name) => n.summary(name),
                None => n,
            })
            .emit()?;
        if ver.major == 4 {
            i8f(f, "Octave")?;
        }
    }
    let channels = f.peek_span(64 * 12);
    f.node(
        Node::new("MIDI channels")
            .span(channels)
            .summary("4 ports × 16 channels")
            .lazy(midi_channels, channels),
    );
    f.skip(64 * 12);
    if ver.major >= 5 {
        group(f, "Directions", &(), directions, |n| {
            Some(format!("{n} used"))
        })?;
        i32f(f, "Master reverb")?;
    }
    let measures = i32f(f, "Measure count")?;
    let tracks = i32f(f, "Track count")?;
    let sizes = Sizes {
        tempo,
        measures,
        tracks,
    };
    let mut song = Song {
        ver: Some(ver),
        ..Song::default()
    };
    // Measure headers.
    let start = f.pos();
    let mut parse = Fields::new(f.block(), LE);
    parse.seek(start);
    let mut failed = None;
    for i in 0..measures.max(0) {
        if i & 0x3ff == 0 {
            cx.checkpoint().await;
        }
        match header(&mut parse, &(ver, i == 0)) {
            Ok(h) => song.headers.push(h),
            Err(e) => {
                failed = Some(e);
                break;
            }
        }
    }
    f.seek(parse.pos());
    let span = since(f, start);
    let headers = Arc::new(song.headers.clone());
    f.node(
        Node::new("Measure headers")
            .span(span)
            .summary(format!("{measures} measures"))
            .lazy(measure_headers, (span, ver, headers)),
    );
    if let Some(e) = failed {
        return Err(e);
    }
    // Track headers.
    let start = f.pos();
    let mut parse = Fields::new(f.block(), LE);
    parse.seek(start);
    for i in 0..tracks.max(0) {
        if i & 0x3ff == 0 {
            cx.checkpoint().await;
        }
        match track(&mut parse, &(ver, i == 0)) {
            Ok(t) => song.tracks.push(t),
            Err(e) => {
                failed = Some(e);
                break;
            }
        }
    }
    f.seek(parse.pos());
    let span = since(f, start);
    f.node(
        Node::new("Tracks")
            .span(span)
            .summary(track_list(&song.tracks))
            .lazy(track_headers, (span, ver)),
    );
    if let Some(e) = failed {
        return Err(e);
    }
    if ver.major >= 5 {
        f.bytes("Padding", if ver.v510 { 1 } else { 2 }).emit()?;
    }
    let rest = file.tail(f.pos());
    let node = Node::new("Measures")
        .span(rest)
        .summary(format!("{measures} measures × {tracks} tracks"));
    // Without tracks a measure holds no data.
    f.node(if song.tracks.is_empty() || song.headers.is_empty() {
        node
    } else {
        node.lazy(measures_walk, (rest, Arc::new(song)))
    });
    Ok(sizes)
}

fn track_list(tracks: &[Track]) -> String {
    let names: Vec<&str> = tracks.iter().map(|t| t.name.as_str()).take(8).collect();
    let mut s = format!("{} tracks", tracks.len());
    if !names.is_empty() {
        s.push_str(&format!(": {}", names.join(", ")));
        if tracks.len() > names.len() {
            s.push_str(", ...");
        }
    }
    s
}

// ---------------------------------------------------------------------------
// Measure headers

fn header(f: &mut Fields<'_>, &(ver, first): &(Ver, bool)) -> Result<Header> {
    if ver.major >= 5 && !first {
        f.u8("Padding").emit()?;
    }
    let flags = f.u8("Flags").flags(MEASURE_FLAGS).emit()?;
    let mut h = Header {
        flags,
        ..Header::default()
    };
    if flags & 0x01 != 0 {
        h.numerator = Some(i8f(f, "Numerator")?);
    }
    if flags & 0x02 != 0 {
        h.denominator = Some(i8f(f, "Denominator")?);
    }
    if flags & 0x08 != 0 {
        // GP5 stores the count plus one (PyGuitarPro, TuxGuitar).
        let gp5 = ver.major >= 5;
        let raw = f
            .int::<i8>("Repeat count")
            .desc(if gp5 {
                "Number of repeats plus one"
            } else {
                "Number of repeats"
            })
            .emit()?;
        h.repeat_close = Some(if gp5 { raw.saturating_sub(1) } else { raw });
    }
    let alternative = |f: &mut Fields<'_>| f.u8("Alternative ending").emit();
    if ver.major < 5 && flags & 0x10 != 0 {
        h.alternative = Some(alternative(f)?);
    }
    if flags & 0x20 != 0 {
        h.marker = Some(group(f, "Marker", &(), marker, |m| Some(format!("{m:?}")))?);
    }
    if flags & 0x40 != 0 {
        let root = f
            .int::<i8>("Key")
            .desc("Sharps (positive) or flats (negative)")
            .emit()?;
        let kind = f
            .int::<i8>("Key type")
            .enumeration(&[(0, "major"), (1, "minor")])
            .emit()?;
        h.key = Some((root, kind));
    }
    if ver.major >= 5 {
        if flags & 0x10 != 0 {
            h.alternative = Some(alternative(f)?);
        }
        if flags & 0x03 != 0 {
            f.bytes("Beam groups", 4)
                .desc("Eighth notes per beam group")
                .emit()?;
        }
        if flags & 0x10 == 0 {
            f.u8("Padding").emit()?;
        }
        f.u8("Triplet feel").enumeration(TRIPLET_FEEL).emit()?;
    }
    Ok(h)
}

fn marker(f: &mut Fields<'_>, _: &()) -> Result<String> {
    let title = ibstr(f, "Title")?;
    color(f, "Colour")?;
    Ok(title)
}

/// Time signatures carried over from previous headers.
fn time_signatures(headers: &[Header]) -> Vec<(i8, i8)> {
    let mut time = (4i8, 4i8);
    headers
        .iter()
        .map(|h| {
            time = (
                h.numerator.unwrap_or(time.0),
                h.denominator.unwrap_or(time.1),
            );
            time
        })
        .collect()
}

fn header_summary(h: &Header, time: (i8, i8)) -> String {
    let mut parts = vec![format!("{}/{}", time.0, time.1)];
    if h.flags & 0x04 != 0 {
        parts.push("repeat start".to_owned());
    }
    if let Some(n) = h.repeat_close {
        parts.push(format!("repeat end ×{n}"));
    }
    if let Some(a) = h.alternative {
        parts.push(format!("alternative {a}"));
    }
    if let Some((root, kind)) = h.key
        && let Some(k) = key_name(i64::from(root), kind == 1)
    {
        parts.push(k.to_owned());
    }
    if let Some(m) = &h.marker {
        parts.push(format!("marker {m:?}"));
    }
    if h.flags & 0x80 != 0 {
        parts.push("double bar".to_owned());
    }
    parts.join(", ")
}

async fn measure_headers(
    cx: Cx,
    (span, ver, headers): (Span, Ver, Arc<Vec<Header>>),
) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::new(&block, LE);
    let times = time_signatures(&headers);
    for (i, (h, &time)) in headers.iter().zip(&times).enumerate() {
        let start = f.pos();
        let ctx = (ver, i == 0);
        header(&mut f, &ctx)?;
        let node = struct_node(
            format!("Measure {}", i.saturating_add(1)),
            since(&f, start),
            LE,
            ctx,
            header,
        )
        .summary(header_summary(h, time));
        cx.push(node).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Track headers

fn track(f: &mut Fields<'_>, &(ver, first): &(Ver, bool)) -> Result<Track> {
    if ver.major >= 5 && (first || !ver.v510) {
        f.u8("Padding").emit()?;
    }
    let flags = f.u8("Flags").flags(TRACK_FLAGS).emit()?;
    let name = bstr(f, "Name", 40)?;
    let count = f.int::<i32>("String count").emit()?;
    let strings = u8::try_from(count.clamp(0, 7)).unwrap_or(0);
    let mut tuning = Vec::new();
    for (i, name) in STRING_NAMES.iter().enumerate() {
        let used = i < usize::from(strings);
        let pitch = f
            .int::<i32>(name)
            .with(|&p, n| {
                if used {
                    n.summary(pitch_name(i64::from(p)))
                } else {
                    n.summary("unused")
                }
            })
            .emit()?;
        if used {
            tuning.push(pitch);
        }
    }
    i32f(f, "MIDI port")?;
    let channel = f
        .int::<i32>("MIDI channel")
        .desc("Index into the channel table, from 1")
        .emit()?;
    f.int::<i32>("Effect channel")
        .desc("Index into the channel table, from 1")
        .emit()?;
    let frets = i32f(f, "Frets")?;
    let capo = i32f(f, "Capo")?;
    color(f, "Colour")?;
    if ver.major >= 5 {
        f.u16("Display flags").flags(TRACK_FLAGS2).emit()?;
        f.u8("Auto accentuation").emit()?;
        f.u8("MIDI bank").emit()?;
        f.u8("Humanize").emit()?;
        i32f(f, "Unknown 1")?;
        i32f(f, "Unknown 2")?;
        i32f(f, "Unknown 3")?;
        f.bytes("Unknown 4", 12).emit()?;
        group(f, "RSE instrument", &ver, rse_instrument, |_| None)?;
        if ver.v510 {
            group(f, "Equalizer", &3usize, equalizer, |_| None)?;
            ibstr(f, "RSE effect")?;
            ibstr(f, "RSE effect category")?;
        }
    }
    Ok(Track {
        name,
        strings,
        tuning,
        drums: flags & 0x01 != 0 || channel == 10,
        frets,
        capo,
        channel,
    })
}

fn rse_instrument(f: &mut Fields<'_>, ver: &Ver) -> Result<()> {
    i32f(f, "Instrument")?;
    i32f(f, "Unknown")?;
    i32f(f, "Sound bank")?;
    if ver.v510 {
        i32f(f, "Effect number")?;
    } else {
        i16f(f, "Effect number")?;
        f.u8("Padding").emit()?;
    }
    Ok(())
}

fn track_summary(t: &Track) -> String {
    let mut s = format!("{:?}", t.name);
    if t.drums {
        s.push_str(", percussion");
    } else {
        let tuning: Vec<String> = t
            .tuning
            .iter()
            .rev()
            .map(|&p| pitch_name(i64::from(p)))
            .collect();
        s.push_str(&format!(", {} strings ({})", t.strings, tuning.join(" ")));
        s.push_str(&format!(", {} frets", t.frets));
        if t.capo > 0 {
            s.push_str(&format!(", capo {}", t.capo));
        }
    }
    s.push_str(&format!(", channel {}", t.channel));
    s
}

async fn track_headers(cx: Cx, (span, ver): (Span, Ver)) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::new(&block, LE);
    let mut i = 0usize;
    while f.remaining() > 0 {
        let start = f.pos();
        let ctx = (ver, i == 0);
        let t = track(&mut f, &ctx)?;
        i = i.saturating_add(1);
        cx.push(
            struct_node(format!("Track {i}"), since(&f, start), LE, ctx, track)
                .summary(track_summary(&t)),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Measures, beats, notes

#[derive(Clone, Copy, Debug, Default)]
struct Tally {
    beats: u64,
    notes: u64,
}

impl Tally {
    fn add(&mut self, other: Tally) {
        self.beats = self.beats.saturating_add(other.beats);
        self.notes = self.notes.saturating_add(other.notes);
    }

    fn summary(&self) -> String {
        format!("{} beats, {} notes", self.beats, self.notes)
    }
}

/// Beats read between two checkpoints.
const BEATS_PER_STEP: i32 = 64;

/// The version measures are read as.
fn song_ver(song: &Song) -> Ver {
    song.ver.unwrap_or(Ver {
        major: 5,
        v510: true,
    })
}

/// Skips one measure across all tracks, charging per track and per beat.
async fn measure(cx: &Cx, f: &mut Fields<'_>, song: &Song) -> Result<Tally> {
    let ver = song_ver(song);
    let mut total = Tally::default();
    for t in &song.tracks {
        cx.checkpoint().await;
        total.add(track_measure(cx, f, &(ver, t.strings)).await?);
    }
    Ok(total)
}

/// The voices of a measure in this version.
fn voices(ver: Ver) -> usize {
    if ver.major >= 5 { 2 } else { 1 }
}

/// Skips one track's part of a measure: its voices.
async fn track_measure(cx: &Cx, f: &mut Fields<'_>, ctx: &(Ver, u8)) -> Result<Tally> {
    let mut total = Tally::default();
    for _ in 0..voices(ctx.0) {
        total.add(voice(cx, f, ctx).await?);
    }
    line_break(f, ctx)?;
    Ok(total)
}

/// Writers may leave out the last measure's line break at the end of the
/// file (PyGuitarPro reads it as 0 then).
fn line_break(f: &mut Fields<'_>, ctx: &(Ver, u8)) -> Result<()> {
    if ctx.0.major >= 5 && f.remaining() > 0 {
        f.u8("Line break")
            .enumeration(&[(0, "none"), (1, "break"), (2, "protect")])
            .emit()?;
    }
    Ok(())
}

/// Skips a voice: its beat count and beats.
async fn voice(cx: &Cx, f: &mut Fields<'_>, ctx: &(Ver, u8)) -> Result<Tally> {
    let count = i32f(f, "Beat count")?;
    let mut tally = Tally::default();
    for i in 0..count.max(0) {
        if i % BEATS_PER_STEP == BEATS_PER_STEP.saturating_sub(1) {
            cx.checkpoint().await;
        }
        let b = beat(f, ctx)?;
        tally.beats = tally.beats.saturating_add(1);
        tally.notes = tally
            .notes
            .saturating_add(crate::bytes::to_u64(b.notes.len()));
    }
    Ok(tally)
}

/// A measure: one node per track.
async fn measure_view(cx: Cx, (span, song): (Span, Arc<Song>)) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::new(&block, LE);
    let ver = song_ver(&song);
    for (i, t) in song.tracks.iter().enumerate() {
        let ctx = (ver, t.strings);
        let start = f.pos();
        let tally = track_measure(&cx, &mut f, &ctx).await;
        let at = since(&f, start);
        let node = Node::new(format!("Track {}", i.saturating_add(1)))
            .span(at)
            .lazy(track_view, (at, ctx));
        match tally {
            Ok(t) => cx.push(node.summary(t.summary())).await,
            Err(e) => {
                cx.push(node).await;
                return Err(e);
            }
        }
    }
    Ok(())
}

/// One track's part of a measure: its voices and line break.
async fn track_view(cx: Cx, (span, ctx): (Span, (Ver, u8))) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::new(&block, LE);
    for name in ["Voice 1", "Voice 2"].into_iter().take(voices(ctx.0)) {
        let start = f.pos();
        let tally = voice(&cx, &mut f, &ctx).await;
        let at = since(&f, start);
        let node = Node::new(name).span(at).lazy(voice_view, (at, ctx));
        match tally {
            Ok(t) => cx.emit(node.summary(t.summary())),
            Err(e) => {
                cx.emit(node);
                return Err(e);
            }
        }
    }
    let mut f2 = Fields::emitting(&cx, &block, LE);
    f2.seek(f.pos());
    line_break(&mut f2, &ctx)
}

/// A voice: its beat count and one node per beat.
async fn voice_view(cx: Cx, (span, ctx): (Span, (Ver, u8))) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    let count = i32f(&mut f, "Beat count")?;
    for i in 0..count.max(0) {
        let start = f.pos();
        let mut probe = Fields::new(&block, LE);
        probe.seek(start);
        let result = beat(&mut probe, &ctx);
        let len = probe.pos().saturating_sub(start);
        let mut node = struct_node(
            format!("Beat {}", i.saturating_add(1)),
            f.peek_span(len),
            LE,
            ctx,
            beat,
        );
        if let Ok(b) = &result {
            node = node.summary(b.summary());
        }
        cx.push(node).await;
        f.seek(start.saturating_add(len));
        result?;
    }
    Ok(())
}

#[derive(Debug, Default)]
struct Beat {
    status: Option<u8>,
    duration: i8,
    dotted: bool,
    tuplet: Option<i32>,
    text: Option<String>,
    notes: Vec<(u8, NoteInfo)>,
}

impl Beat {
    fn summary(&self) -> String {
        let mut s = duration_name(self.duration).to_owned();
        if self.dotted {
            s = format!("dotted {s}");
        }
        if let Some(t) = self.tuplet {
            s.push_str(&format!(" ({t}-tuplet)"));
        }
        match self.status {
            Some(0) => s.push_str(", empty"),
            Some(2) => s.push_str(", rest"),
            _ => {}
        }
        if !self.notes.is_empty() {
            let notes: Vec<String> = self
                .notes
                .iter()
                .map(|(string, n)| n.summary(*string))
                .collect();
            s.push_str(&format!(", {}", notes.join(" ")));
        }
        if let Some(t) = &self.text {
            s.push_str(&format!(", text {t:?}"));
        }
        s
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct NoteInfo {
    kind: Option<u8>,
    fret: Option<i8>,
}

impl NoteInfo {
    fn summary(&self, string: u8) -> String {
        match (self.kind, self.fret) {
            (Some(2), _) => format!("{string}:tie"),
            (Some(3), _) => format!("{string}:x"),
            (_, Some(fret)) => format!("{string}:{fret}"),
            _ => format!("{string}:?"),
        }
    }
}

fn beat(f: &mut Fields<'_>, ctx: &(Ver, u8)) -> Result<Beat> {
    let (ver, strings) = *ctx;
    let flags = f.u8("Flags").flags(BEAT_FLAGS).emit()?;
    let mut b = Beat {
        dotted: flags & 0x01 != 0,
        ..Beat::default()
    };
    if flags & 0x40 != 0 {
        b.status = Some(f.u8("Status").enumeration(BEAT_STATUS).emit()?);
    }
    b.duration = f
        .int::<i8>("Duration")
        .with(|&d, n| n.summary(duration_name(d)))
        .emit()?;
    if flags & 0x20 != 0 {
        b.tuplet = Some(
            f.int::<i32>("Tuplet")
                .desc("Notes played in the time of the next lower power of two")
                .emit()?,
        );
    }
    if flags & 0x02 != 0 {
        group(f, "Chord diagram", &ver, chord, |name| {
            Some(format!("{name:?}"))
        })?;
    }
    if flags & 0x04 != 0 {
        b.text = Some(ibstr(f, "Text")?);
    }
    if flags & 0x08 != 0 {
        group(f, "Beat effects", &ver, beat_effects, |_| None)?;
    }
    if flags & 0x10 != 0 {
        group(f, "Mix table change", &ver, mix_table, |_| None)?;
    }
    let mask = f.u8("Strings").flags(STRING_FLAGS).emit()?;
    for s in 1..=strings.min(7) {
        if mask & (1u8 << (7u8.saturating_sub(s))) != 0 {
            let name = format!("Note (string {s})");
            let n = group(f, name, &ver, note, |n| Some(n.summary(s)))?;
            b.notes.push((s, n));
        }
    }
    if ver.major >= 5 {
        let flags2 = f.u16("Display flags").flags(BEAT_FLAGS2).emit()?;
        if flags2 & 0x0800 != 0 {
            f.u8("Secondary beam break").emit()?;
        }
    }
    Ok(b)
}

fn chord(f: &mut Fields<'_>, ver: &Ver) -> Result<String> {
    let new = f.u8("New format").emit()? != 0;
    if !new {
        let name = ibstr(f, "Name")?;
        let first = i32f(f, "First fret")?;
        if first != 0 {
            for name in STRING_NAMES.iter().take(6) {
                f.int::<i32>(name).summary("fret").emit()?;
            }
        }
        return Ok(name);
    }
    f.u8("Sharp").emit()?;
    f.bytes("Padding", 3).emit()?;
    let gp3 = ver.major == 3;
    let small = |f: &mut Fields<'_>, name: &'static str| -> Result<()> {
        if gp3 {
            i32f(f, name)?;
        } else {
            f.u8(name).emit()?;
        }
        Ok(())
    };
    small(f, "Root")?;
    small(f, "Type")?;
    small(f, "Extension")?;
    i32f(f, "Bass")?;
    i32f(f, "Tonality")?;
    f.u8("Add").emit()?;
    let name = bstr(f, "Name", 22)?;
    small(f, "Fifth")?;
    small(f, "Ninth")?;
    small(f, "Eleventh")?;
    i32f(f, "First fret")?;
    let strings = if gp3 { 6 } else { 7 };
    for name in STRING_NAMES.iter().take(strings) {
        f.int::<i32>(name).summary("fret").emit()?;
    }
    if gp3 {
        i32f(f, "Barre count")?;
        f.bytes("Barre frets", 8).emit()?;
        f.bytes("Barre starts", 8).emit()?;
        f.bytes("Barre ends", 8).emit()?;
    } else {
        f.u8("Barre count").emit()?;
        f.bytes("Barre frets", 5).emit()?;
        f.bytes("Barre starts", 5).emit()?;
        f.bytes("Barre ends", 5).emit()?;
    }
    f.bytes("Omissions", 7).emit()?;
    f.u8("Padding").emit()?;
    if !gp3 {
        f.bytes("Fingerings", 7).emit()?;
        f.u8("Show diagram fingering").emit()?;
    }
    Ok(name)
}

fn beat_effects(f: &mut Fields<'_>, ver: &Ver) -> Result<()> {
    if ver.major == 3 {
        let flags = f.u8("Flags").flags(GP3_BEAT_EFFECTS).emit()?;
        if flags & 0x20 != 0 {
            let slap = f.u8("Slap effect").enumeration(SLAP).emit()?;
            if slap == 0 {
                i32f(f, "Tremolo bar")?;
            } else {
                i32f(f, "Unused")?;
            }
        }
        if flags & 0x40 != 0 {
            i8f(f, "Stroke down")?;
            i8f(f, "Stroke up")?;
        }
        return Ok(());
    }
    let flags1 = f.u8("Flags 1").flags(BEAT_EFFECTS1).emit()?;
    let flags2 = f.u8("Flags 2").flags(BEAT_EFFECTS2).emit()?;
    if flags1 & 0x20 != 0 {
        f.u8("Slap effect").enumeration(SLAP).emit()?;
    }
    if flags2 & 0x04 != 0 {
        group(f, "Tremolo bar", &(), bend, |n| Some(format!("{n} points")))?;
    }
    if flags1 & 0x40 != 0 {
        i8f(f, "Stroke down")?;
        i8f(f, "Stroke up")?;
    }
    if flags2 & 0x02 != 0 {
        f.int::<i8>("Pick stroke")
            .enumeration(&[(0, "none"), (1, "up"), (2, "down")])
            .emit()?;
    }
    Ok(())
}

fn bend(f: &mut Fields<'_>, _: &()) -> Result<i32> {
    f.u8("Type").enumeration(BEND_TYPE).emit()?;
    f.int::<i32>("Value").desc("In 1/100 semitones").emit()?;
    let count = i32f(f, "Point count")?;
    for i in 0..count.max(0) {
        group(
            f,
            format!("Point {}", i.saturating_add(1)),
            &(),
            bend_point,
            |(p, v)| Some(format!("position {p}/60, {v}/100 semitone")),
        )?;
    }
    Ok(count)
}

fn bend_point(f: &mut Fields<'_>, _: &()) -> Result<(i32, i32)> {
    let p = f
        .int::<i32>("Position")
        .desc("In 1/60 of the note")
        .emit()?;
    let v = f.int::<i32>("Value").desc("In 1/100 semitones").emit()?;
    f.u8("Vibrato").emit()?;
    Ok((p, v))
}

fn mix_table(f: &mut Fields<'_>, ver: &Ver) -> Result<()> {
    f.int::<i8>("Instrument")
        .with(|&p, n| match program_name(i64::from(p)) {
            Some(name) => n.summary(name),
            None => n.summary("unchanged"),
        })
        .emit()?;
    if ver.major >= 5 {
        group(f, "RSE instrument", ver, rse_instrument, |_| None)?;
        if !ver.v510 {
            f.u8("Padding").emit()?;
        }
    }
    let mut set = [false; 6];
    for (slot, name) in set
        .iter_mut()
        .zip(["Volume", "Balance", "Chorus", "Reverb", "Phaser", "Tremolo"])
    {
        let v = f
            .int::<i8>(name)
            .with(|&v, n| if v < 0 { n.summary("unchanged") } else { n })
            .emit()?;
        *slot = v >= 0;
    }
    if ver.major >= 5 {
        ibstr(f, "Tempo name")?;
    }
    let tempo = f
        .int::<i32>("Tempo")
        .with(|&v, n| {
            if v < 0 {
                n.summary("unchanged")
            } else {
                n.summary("BPM")
            }
        })
        .emit()?;
    for (on, name) in set.iter().zip([
        "Volume duration",
        "Balance duration",
        "Chorus duration",
        "Reverb duration",
        "Phaser duration",
        "Tremolo duration",
    ]) {
        if *on {
            f.int::<i8>(name).desc("In beats").emit()?;
        }
    }
    if tempo >= 0 {
        f.int::<i8>("Tempo duration").desc("In beats").emit()?;
        if ver.v510 {
            f.u8("Hide tempo").emit()?;
        }
    }
    if ver.major >= 4 {
        f.u8("Flags").flags(MIX_FLAGS).emit()?;
    }
    if ver.major >= 5 {
        f.int::<i8>("Wah").emit()?;
        if ver.v510 {
            ibstr(f, "RSE effect")?;
            ibstr(f, "RSE effect category")?;
        }
    }
    Ok(())
}

fn note(f: &mut Fields<'_>, ver: &Ver) -> Result<NoteInfo> {
    let flags = f.u8("Flags").flags(NOTE_FLAGS).emit()?;
    let mut n = NoteInfo::default();
    if flags & 0x20 != 0 {
        n.kind = Some(f.u8("Type").enumeration(NOTE_TYPE).emit()?);
    }
    if ver.major < 5 && flags & 0x01 != 0 {
        f.int::<i8>("Duration")
            .with(|&d, n| n.summary(duration_name(d)))
            .emit()?;
        i8f(f, "Tuplet")?;
    }
    if flags & 0x10 != 0 {
        f.int::<i8>("Dynamic")
            .with(|&d, n| {
                const DYN: [&str; 8] = ["ppp", "pp", "p", "mp", "mf", "f", "ff", "fff"];
                match usize::try_from(d)
                    .ok()
                    .and_then(|i| i.checked_sub(1))
                    .and_then(|i| DYN.get(i))
                {
                    Some(name) => n.summary(*name),
                    None => n,
                }
            })
            .emit()?;
    }
    if flags & 0x20 != 0 {
        n.fret = Some(i8f(f, "Fret")?);
    }
    if flags & 0x80 != 0 {
        i8f(f, "Left-hand finger")?;
        i8f(f, "Right-hand finger")?;
    }
    if ver.major >= 5 {
        if flags & 0x01 != 0 {
            f.f64("Duration percent").emit()?;
        }
        f.u8("Flags 2").flags(NOTE_FLAGS2).emit()?;
    }
    if flags & 0x08 != 0 {
        group(f, "Note effects", ver, note_effects, |_| None)?;
    }
    Ok(n)
}

fn note_effects(f: &mut Fields<'_>, ver: &Ver) -> Result<()> {
    if ver.major == 3 {
        let flags = f.u8("Flags").flags(GP3_NOTE_EFFECTS).emit()?;
        if flags & 0x01 != 0 {
            group(f, "Bend", &(), bend, |n| Some(format!("{n} points")))?;
        }
        if flags & 0x10 != 0 {
            group(f, "Grace note", ver, grace, |_| None)?;
        }
        return Ok(());
    }
    let flags1 = f.u8("Flags 1").flags(NOTE_EFFECTS1).emit()?;
    let flags2 = f.u8("Flags 2").flags(NOTE_EFFECTS2).emit()?;
    if flags1 & 0x01 != 0 {
        group(f, "Bend", &(), bend, |n| Some(format!("{n} points")))?;
    }
    if flags1 & 0x10 != 0 {
        group(f, "Grace note", ver, grace, |_| None)?;
    }
    if flags2 & 0x04 != 0 {
        f.int::<i8>("Tremolo picking")
            .enumeration(&[(1, "eighth"), (2, "sixteenth"), (3, "thirty-second")])
            .emit()?;
    }
    if flags2 & 0x08 != 0 {
        if ver.major >= 5 {
            f.u8("Slide").flags(GP5_SLIDES).emit()?;
        } else {
            i8f(f, "Slide")?;
        }
    }
    if flags2 & 0x10 != 0 {
        let kind = f.int::<i8>("Harmonic").enumeration(HARMONIC).emit()?;
        if ver.major >= 5 {
            if kind == 2 {
                f.u8("Semitone").emit()?;
                i8f(f, "Accidental")?;
                f.u8("Octave")
                    .enumeration(&[(0, "loco"), (1, "8va"), (2, "15ma")])
                    .emit()?;
            } else if kind == 3 {
                f.u8("Fret").emit()?;
            }
        }
    }
    if flags2 & 0x20 != 0 {
        i8f(f, "Trill fret")?;
        f.int::<i8>("Trill period")
            .enumeration(&[(1, "sixteenth"), (2, "thirty-second"), (3, "sixty-fourth")])
            .emit()?;
    }
    Ok(())
}

fn grace(f: &mut Fields<'_>, ver: &Ver) -> Result<()> {
    if ver.major >= 5 {
        f.u8("Fret").emit()?;
        f.u8("Dynamic").emit()?;
        f.u8("Transition").enumeration(GRACE_TRANSITION).emit()?;
        f.u8("Duration").emit()?;
        f.u8("Flags").flags(GRACE_FLAGS).emit()?;
    } else {
        i8f(f, "Fret")?;
        f.u8("Dynamic").emit()?;
        f.u8("Duration").emit()?;
        f.u8("Transition").enumeration(GRACE_TRANSITION).emit()?;
    }
    Ok(())
}

/// Walks the measures (each across all tracks), pushing one node per
/// measure.
async fn measures_walk(cx: Cx, (span, song): (Span, Arc<Song>)) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::new(&block, LE);
    let times = time_signatures(&song.headers);
    let (pos, first) = cx.resume::<(u64, usize)>().unwrap_or((0, 0));
    f.seek(pos);
    cx.set_count(Count::Exact(crate::bytes::to_u64(song.headers.len())));
    for (i, h) in song.headers.iter().enumerate().skip(first) {
        let start = f.pos();
        cx.mark(move || (start, i));
        let tally = measure(&cx, &mut f, &song).await;
        let at = since(&f, start);
        let mut node = Node::new(format!("Measure {}", i.saturating_add(1)))
            .span(at)
            .lazy(measure_view, (at, song.clone()));
        let time = times.get(i).copied().unwrap_or((4, 4));
        let mut summary = format!("{}/{}", time.0, time.1);
        if let Some(m) = &h.marker {
            summary.push_str(&format!(", {m:?}"));
        }
        match tally {
            Ok(t) => {
                summary.push_str(&format!(", {}", t.summary()));
                cx.push(node.summary(summary)).await;
            }
            Err(e) => {
                node = node.summary(summary).diag(e.clone());
                cx.push(node).await;
                return Err(e);
            }
        }
    }
    if f.remaining() > 0 {
        cx.push(Node::new("Trailing data").span(span.tail(f.pos())))
            .await;
    }
    Ok(())
}
