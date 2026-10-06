//! Standard MIDI files: an `MThd` header chunk and `MTrk` track chunks.
//!
//! Tracks are listed with their names; expanding a track lists its events
//! (paged) with delta and absolute times, decoding channel messages (with
//! note, controller and General MIDI program names), system exclusive
//! messages and meta events (tempo, time and key signatures, texts).

use crate::bytes::{u16_be, u32_be};
use crate::cx::Cx;
use crate::dsl::{Cursor, Record};
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::sound::{decode_text, fourcc, text};
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::EnumTable;

const BE: Endian = Endian::Big;

pub static FORMAT: Format = Format {
    name: "midi",
    title: "Standard MIDI file",
    extensions: &["mid", "midi", "smf", "kar"],
    mime: "audio/midi",
    probe: Probe::Magic(&[(0, b"MThd\0\0\0\x06")]),
    dissect: crate::expander!(dissect: Input),
};

const SMF_FORMAT: EnumTable = &[
    (0, "single track"),
    (1, "simultaneous tracks"),
    (2, "independent sequences"),
];

record! {
    pub struct Header {
        id: ascii[4] "Chunk ID",
        length: u32 "Length",
        format: u16 "Format" .enumeration(SMF_FORMAT),
        tracks: u16 "Tracks",
        division: u16 "Division" .with(|&d, n| n.summary(division(d))),
    }
}

fn division(d: u16) -> String {
    if d & 0x8000 != 0 {
        let fps = (d >> 8) as u8;
        format!(
            "{} fps, {} ticks per frame",
            (fps as i8).unsigned_abs(),
            d & 0xff
        )
    } else {
        format!("{d} ticks per quarter note")
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let (header, span) = Cursor::new(&cx, file, BE).record::<Header>().await?;
    cx.emit(Header::node("Header", span, BE));
    cx.annotate(format!(
        "MIDI format {}, {} tracks, {}",
        header.format,
        header.tracks,
        division(header.division)
    ));
    let mut pos = 8u64.saturating_add(header.length.into());
    let mut index = 0u32;
    while file.len.saturating_sub(pos) >= 8 {
        let head = cx.read(file.sub(pos, 8)).await?;
        let id = head.get(..4).unwrap_or_default().to_vec();
        let len = u64::from(u32_be(&head, 4).unwrap_or(0));
        let span = file.sub(pos, len.saturating_add(8));
        let data = span.tail(8);
        let mut node = if id == b"MTrk" {
            let mut node = Node::new(format!("Track {index}")).span(span);
            let name = track_name(&cx, data).await;
            node = node.summary(match name {
                Some(n) => format!("{n}, {len} bytes"),
                None => format!("{len} bytes"),
            });
            index = index.saturating_add(1);
            node.lazy(track, data)
        } else {
            Node::new(fourcc(&id))
                .span(span)
                .summary(format!("{len} bytes"))
                .desc("Unknown chunk")
        };
        if span.len < len.saturating_add(8) {
            node = node.diag(Diagnostic::truncated(
                Span::new(span.source, span.offset, len.saturating_add(8)),
                span.len,
            ));
        }
        cx.push(node).await;
        pos = pos.saturating_add(len).saturating_add(8);
    }
    if pos < file.len {
        cx.emit(Node::new("Trailing data").span(file.tail(pos)));
    }
    Ok(())
}

/// The track name meta event, if it is among the first events.
async fn track_name(cx: &Cx, data: Span) -> Option<String> {
    let mut cur = Cursor::new(cx, data.sub(0, 512), BE);
    let mut running = None;
    for _ in 0..8 {
        let ev = event(&mut cur, &mut running).await.ok()?;
        if let Event::Meta { kind: 3, data } = ev.event {
            let bytes = cx.read_avail(data.sub(0, 128)).await.ok()?;
            return Some(decode_text(&bytes));
        }
        if matches!(ev.event, Event::Channel { .. }) {
            return None;
        }
    }
    None
}

/// A variable-length quantity (7 bits per byte, at most 4 bytes).
async fn varlen(cur: &mut Cursor<'_>) -> Result<u32> {
    let mut value = 0u32;
    for _ in 0..4 {
        let b = cur.u8().await?;
        value = (value << 7) | u32::from(b & 0x7f);
        if b & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(Diagnostic::malformed("variable-length quantity longer than 4 bytes").at(cur.span(1)))
}

enum Event {
    Channel { status: u8, data: [u8; 2] },
    SysEx { kind: u8, data: Span },
    Meta { kind: u8, data: Span },
}

struct Timed {
    delta: u32,
    event: Event,
}

/// Reads one event; `running` holds the running status.
async fn event(cur: &mut Cursor<'_>, running: &mut Option<u8>) -> Result<Timed> {
    let delta = varlen(cur).await?;
    let first = cur.peek(1).await?;
    let first = *first
        .first()
        .ok_or_else(|| Diagnostic::truncated(cur.span(1), 0))?;
    let status = if first & 0x80 != 0 {
        cur.skip(1);
        first
    } else {
        running.ok_or_else(|| {
            Diagnostic::malformed("data byte without a running status").at(cur.span(1))
        })?
    };
    let event = match status {
        0xff => {
            *running = None;
            let kind = cur.u8().await?;
            let len = varlen(cur).await?;
            let data = cur.span(len.into());
            cur.skip(len.into());
            Event::Meta { kind, data }
        }
        0xf0 | 0xf7 => {
            *running = None;
            let len = varlen(cur).await?;
            let data = cur.span(len.into());
            cur.skip(len.into());
            Event::SysEx { kind: status, data }
        }
        0xf1..=0xfe => {
            return Err(
                Diagnostic::malformed(format!("system message {status:#04x} in a file"))
                    .at(cur.span(1)),
            );
        }
        _ => {
            *running = Some(status);
            let n = if matches!(status & 0xf0, 0xc0 | 0xd0) {
                1
            } else {
                2
            };
            let bytes = cur.bytes(n).await?;
            Event::Channel {
                status,
                data: [
                    bytes.first().copied().unwrap_or(0),
                    bytes.get(1).copied().unwrap_or(0),
                ],
            }
        }
    };
    Ok(Timed { delta, event })
}

async fn track(cx: Cx, data: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, data, BE);
    let mut running = None;
    let mut time = 0u64;
    while !cur.at_end() {
        let start = cur.pos();
        let ev = match event(&mut cur, &mut running).await {
            Ok(ev) => ev,
            Err(e) => {
                cx.emit(Node::new("Unparsed data").span(data.tail(start)).diag(e));
                return Ok(());
            }
        };
        time = time.saturating_add(ev.delta.into());
        let span = cur.since(start);
        let (name, detail, value) = describe(&cx, &ev.event).await?;
        let mut node = Node::new(name)
            .span(span)
            .summary(format!("Δ{} @{time}{detail}", ev.delta));
        if let Some(v) = value {
            node = node.value(text(v));
        }
        cx.push(node).await;
        if let Event::Meta { kind: 0x2f, .. } = ev.event {
            if !cur.at_end() {
                cx.emit(
                    Node::new("Data after end of track")
                        .span(data.tail(cur.pos()))
                        .diag(Diagnostic::warning("bytes after the End of Track event")),
                );
            }
            break;
        }
    }
    Ok(())
}

/// Event name, summary detail and text value.
async fn describe(cx: &Cx, ev: &Event) -> Result<(String, String, Option<String>)> {
    Ok(match ev {
        Event::Channel {
            status,
            data: [a, b],
        } => {
            let ch = (status & 0xf).saturating_add(1);
            let (name, detail) = match status >> 4 {
                0x8 => ("Note off", format!("{}, velocity {b}", note(*a))),
                0x9 if *b == 0 => ("Note on (off)", format!("{}, velocity 0", note(*a))),
                0x9 => ("Note on", format!("{}, velocity {b}", note(*a))),
                0xa => ("Key pressure", format!("{}, pressure {b}", note(*a))),
                0xb => (
                    "Control change",
                    format!(
                        "{} ({a}) = {b}",
                        crate::value::lookup(CONTROLLERS, (*a).into()).unwrap_or("controller")
                    ),
                ),
                0xc => (
                    "Program change",
                    format!(
                        "{a}: {}",
                        GM_PROGRAMS.get(usize::from(*a)).copied().unwrap_or("?")
                    ),
                ),
                0xd => ("Channel pressure", format!("{a}")),
                _ => (
                    "Pitch bend",
                    format!(
                        "{}",
                        i32::from(u16::from(*a) | (u16::from(*b) << 7)).saturating_sub(8192)
                    ),
                ),
            };
            (name.to_owned(), format!(" — ch {ch}, {detail}"), None)
        }
        Event::SysEx { kind, data } => (
            if *kind == 0xf0 {
                "System exclusive".to_owned()
            } else {
                "System exclusive (escape)".to_owned()
            },
            format!(" — {} bytes", data.len),
            None,
        ),
        Event::Meta { kind, data } => {
            let name = crate::value::lookup(META, (*kind).into())
                .map_or_else(|| format!("Meta {kind:#04x}"), str::to_owned);
            let bytes = cx.read_avail(data.sub(0, 256)).await?;
            let (detail, value) = match kind {
                0x01..=0x0f => (String::new(), Some(decode_text(&bytes))),
                0x00 => (format!(" — {}", u16_be(&bytes, 0).unwrap_or(0)), None),
                0x2f => (String::new(), None),
                0x20 | 0x21 => (format!(" — {}", bytes.first().copied().unwrap_or(0)), None),
                0x51 => {
                    let us = crate::bytes::u24_be(&bytes, 0).unwrap_or(0);
                    let bpm = if us > 0 { 60e6 / f64::from(us) } else { 0.0 };
                    (format!(" — {us} µs per quarter ({bpm:.2} BPM)"), None)
                }
                0x54 => (
                    format!(
                        " — {:02}:{:02}:{:02}.{:02}",
                        bytes.first().copied().unwrap_or(0) & 0x1f,
                        bytes.get(1).copied().unwrap_or(0),
                        bytes.get(2).copied().unwrap_or(0),
                        bytes.get(3).copied().unwrap_or(0)
                    ),
                    None,
                ),
                0x58 => {
                    let num = bytes.first().copied().unwrap_or(0);
                    let den = 1u32 << bytes.get(1).copied().unwrap_or(0).min(16);
                    (format!(" — {num}/{den}"), None)
                }
                0x59 => {
                    let sharps = bytes.first().copied().unwrap_or(0) as i8;
                    let minor = bytes.get(1).copied().unwrap_or(0) != 0;
                    (format!(" — {}", key(sharps, minor)), None)
                }
                _ => (format!(" — {} bytes", data.len), None),
            };
            (name, detail, value)
        }
    })
}

const META: EnumTable = &[
    (0x00, "Sequence number"),
    (0x01, "Text"),
    (0x02, "Copyright"),
    (0x03, "Track name"),
    (0x04, "Instrument name"),
    (0x05, "Lyric"),
    (0x06, "Marker"),
    (0x07, "Cue point"),
    (0x08, "Program name"),
    (0x09, "Device name"),
    (0x20, "Channel prefix"),
    (0x21, "MIDI port"),
    (0x2f, "End of track"),
    (0x51, "Set tempo"),
    (0x54, "SMPTE offset"),
    (0x58, "Time signature"),
    (0x59, "Key signature"),
    (0x7f, "Sequencer specific"),
];

const CONTROLLERS: EnumTable = &[
    (0, "Bank select"),
    (1, "Modulation"),
    (2, "Breath"),
    (4, "Foot"),
    (5, "Portamento time"),
    (6, "Data entry"),
    (7, "Volume"),
    (8, "Balance"),
    (10, "Pan"),
    (11, "Expression"),
    (32, "Bank select (LSB)"),
    (64, "Sustain"),
    (65, "Portamento"),
    (66, "Sostenuto"),
    (67, "Soft pedal"),
    (71, "Resonance"),
    (72, "Release time"),
    (73, "Attack time"),
    (74, "Brightness"),
    (91, "Reverb"),
    (93, "Chorus"),
    (98, "NRPN (LSB)"),
    (99, "NRPN (MSB)"),
    (100, "RPN (LSB)"),
    (101, "RPN (MSB)"),
    (120, "All sound off"),
    (121, "Reset all controllers"),
    (123, "All notes off"),
];

fn note(n: u8) -> String {
    const NAMES: [&str; 12] = [
        "C", "C♯", "D", "D♯", "E", "F", "F♯", "G", "G♯", "A", "A♯", "B",
    ];
    let name = NAMES.get(usize::from(n % 12)).copied().unwrap_or("?");
    format!("{name}{} ({n})", i32::from(n / 12).saturating_sub(1))
}

fn key(sharps: i8, minor: bool) -> String {
    const MAJOR: [&str; 15] = [
        "C♭", "G♭", "D♭", "A♭", "E♭", "B♭", "F", "C", "G", "D", "A", "E", "B", "F♯", "C♯",
    ];
    const MINOR: [&str; 15] = [
        "A♭", "E♭", "B♭", "F", "C", "G", "D", "A", "E", "B", "F♯", "C♯", "G♯", "D♯", "A♯",
    ];
    let i = usize::try_from(i16::from(sharps).saturating_add(7)).unwrap_or(usize::MAX);
    let table = if minor { &MINOR } else { &MAJOR };
    match table.get(i) {
        Some(k) => format!("{k} {}", if minor { "minor" } else { "major" }),
        None => format!("{sharps} sharps"),
    }
}

/// General MIDI level 1 instrument names.
pub const GM_PROGRAMS: [&str; 128] = [
    "Acoustic Grand Piano",
    "Bright Acoustic Piano",
    "Electric Grand Piano",
    "Honky-tonk Piano",
    "Electric Piano 1",
    "Electric Piano 2",
    "Harpsichord",
    "Clavinet",
    "Celesta",
    "Glockenspiel",
    "Music Box",
    "Vibraphone",
    "Marimba",
    "Xylophone",
    "Tubular Bells",
    "Dulcimer",
    "Drawbar Organ",
    "Percussive Organ",
    "Rock Organ",
    "Church Organ",
    "Reed Organ",
    "Accordion",
    "Harmonica",
    "Tango Accordion",
    "Acoustic Guitar (nylon)",
    "Acoustic Guitar (steel)",
    "Electric Guitar (jazz)",
    "Electric Guitar (clean)",
    "Electric Guitar (muted)",
    "Overdriven Guitar",
    "Distortion Guitar",
    "Guitar Harmonics",
    "Acoustic Bass",
    "Electric Bass (finger)",
    "Electric Bass (pick)",
    "Fretless Bass",
    "Slap Bass 1",
    "Slap Bass 2",
    "Synth Bass 1",
    "Synth Bass 2",
    "Violin",
    "Viola",
    "Cello",
    "Contrabass",
    "Tremolo Strings",
    "Pizzicato Strings",
    "Orchestral Harp",
    "Timpani",
    "String Ensemble 1",
    "String Ensemble 2",
    "Synth Strings 1",
    "Synth Strings 2",
    "Choir Aahs",
    "Voice Oohs",
    "Synth Voice",
    "Orchestra Hit",
    "Trumpet",
    "Trombone",
    "Tuba",
    "Muted Trumpet",
    "French Horn",
    "Brass Section",
    "Synth Brass 1",
    "Synth Brass 2",
    "Soprano Sax",
    "Alto Sax",
    "Tenor Sax",
    "Baritone Sax",
    "Oboe",
    "English Horn",
    "Bassoon",
    "Clarinet",
    "Piccolo",
    "Flute",
    "Recorder",
    "Pan Flute",
    "Blown Bottle",
    "Shakuhachi",
    "Whistle",
    "Ocarina",
    "Lead 1 (square)",
    "Lead 2 (sawtooth)",
    "Lead 3 (calliope)",
    "Lead 4 (chiff)",
    "Lead 5 (charang)",
    "Lead 6 (voice)",
    "Lead 7 (fifths)",
    "Lead 8 (bass + lead)",
    "Pad 1 (new age)",
    "Pad 2 (warm)",
    "Pad 3 (polysynth)",
    "Pad 4 (choir)",
    "Pad 5 (bowed)",
    "Pad 6 (metallic)",
    "Pad 7 (halo)",
    "Pad 8 (sweep)",
    "FX 1 (rain)",
    "FX 2 (soundtrack)",
    "FX 3 (crystal)",
    "FX 4 (atmosphere)",
    "FX 5 (brightness)",
    "FX 6 (goblins)",
    "FX 7 (echoes)",
    "FX 8 (sci-fi)",
    "Sitar",
    "Banjo",
    "Shamisen",
    "Koto",
    "Kalimba",
    "Bagpipe",
    "Fiddle",
    "Shanai",
    "Tinkle Bell",
    "Agogo",
    "Steel Drums",
    "Woodblock",
    "Taiko Drum",
    "Melodic Tom",
    "Synth Drum",
    "Reverse Cymbal",
    "Guitar Fret Noise",
    "Breath Noise",
    "Seashore",
    "Bird Tweet",
    "Telephone Ring",
    "Helicopter",
    "Applause",
    "Gunshot",
];
