//! Standard MIDI files: an `MThd` header chunk and `MTrk` track chunks.
//!
//! Tracks are listed with their names, event and note counts and channels;
//! expanding a track lists its events (paged) with delta and absolute
//! times, and expanding an event shows its bytes: delta time, status
//! (or running status), and the decoded message: notes by name (General
//! MIDI percussion names on channel 10), controllers, General MIDI
//! programs, pitch bend, system exclusive messages (manufacturer, and the
//! universal GM/GS/XG resets by name) and meta events (texts, tempo, time
//! and key signatures, SMPTE offset). The file summary has the playing
//! time from the tempo map and the instruments used.

use crate::bytes::{to_u64, to_usize, u16_be, u32_be};
use crate::cx::Cx;
use crate::dsl::{Cursor, Record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::sound::{decode_text, duration, fourcc, hex, text, uint};
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Value, lookup};

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
        division: u16 "Division" .with(|&d, n| n.summary(division(d)))
            .desc("Ticks per quarter note, or (top bit set) SMPTE frames per second and ticks per frame"),
    }
}

/// SMPTE frame rates of a negative division (the high byte is -24, -25,
/// -29 or -30).
fn smpte_fps(d: u16) -> Option<f64> {
    let [hi, _] = d.to_be_bytes();
    match (hi as i8).unsigned_abs() {
        24 => Some(24.0),
        25 => Some(25.0),
        29 => Some(30_000.0 / 1001.0),
        30 => Some(30.0),
        _ => None,
    }
}

fn division(d: u16) -> String {
    let [hi, lo] = d.to_be_bytes();
    if d & 0x8000 != 0 {
        let fps = match (hi as i8).unsigned_abs() {
            29 => "29.97 fps drop-frame".to_owned(),
            n => format!("{n} fps"),
        };
        format!("SMPTE {fps}, {lo} ticks per frame")
    } else {
        format!("{d} ticks per quarter note")
    }
}

// ---------------------------------------------------------------------------
// Events

/// A problem decoding an event header.
enum Bad {
    /// The bytes end inside the header.
    Short,
    Invalid(&'static str),
}

#[derive(Clone, Copy, Debug)]
enum Kind {
    Channel([u8; 2]),
    SysEx,
    Meta(u8),
}

/// One decoded event header.
#[derive(Clone, Copy, Debug)]
struct Ev {
    delta: u32,
    delta_len: u64,
    status: u8,
    /// The status byte was omitted (running status).
    running: bool,
    kind: Kind,
    /// Bytes up to the payload of a meta or system exclusive event (the
    /// whole event for channel messages).
    head: u64,
    payload: u64,
}

impl Ev {
    fn len(&self) -> u64 {
        self.head.saturating_add(self.payload)
    }

    /// The running status after this event. Meta and system exclusive
    /// events should cancel it, but players keep it, and so do we.
    fn next_running(&self, running: Option<u8>) -> Option<u8> {
        match self.kind {
            Kind::Channel(_) => Some(self.status),
            _ => running,
        }
    }
}

/// A variable-length quantity at `at`: (value, bytes).
fn varlen(b: &[u8], at: usize) -> std::result::Result<(u32, usize), Bad> {
    let mut value = 0u32;
    for i in 0..4usize {
        let byte = *b.get(at.saturating_add(i)).ok_or(Bad::Short)?;
        value = (value << 7) | u32::from(byte & 0x7f);
        if byte & 0x80 == 0 {
            return Ok((value, i.saturating_add(1)));
        }
    }
    Err(Bad::Invalid("variable-length quantity longer than 4 bytes"))
}

/// Decodes the event header at the start of `b` (at most 10 bytes long).
fn parse(b: &[u8], running: Option<u8>) -> std::result::Result<Ev, Bad> {
    let (delta, dl) = varlen(b, 0)?;
    let first = *b.get(dl).ok_or(Bad::Short)?;
    let (status, is_running, mut at) = if first & 0x80 != 0 {
        (first, false, dl.saturating_add(1))
    } else {
        let status = running.ok_or(Bad::Invalid("data byte without a running status"))?;
        (status, true, dl)
    };
    let (kind, payload) = match status {
        0xff => {
            let kind = *b.get(at).ok_or(Bad::Short)?;
            let (len, n) = varlen(b, at.saturating_add(1))?;
            at = at.saturating_add(1).saturating_add(n);
            (Kind::Meta(kind), len)
        }
        0xf0 | 0xf7 => {
            let (len, n) = varlen(b, at)?;
            at = at.saturating_add(n);
            (Kind::SysEx, len)
        }
        0xf1..=0xfe => return Err(Bad::Invalid("system common or real-time message in a file")),
        _ => {
            let n = if matches!(status & 0xf0, 0xc0 | 0xd0) {
                1
            } else {
                2
            };
            let mut data = [0u8; 2];
            for (i, slot) in data.iter_mut().take(n).enumerate() {
                let byte = *b.get(at.saturating_add(i)).ok_or(Bad::Short)?;
                if byte & 0x80 != 0 {
                    return Err(Bad::Invalid("status byte where a data byte was expected"));
                }
                *slot = byte;
            }
            at = at.saturating_add(n);
            (Kind::Channel(data), 0)
        }
    };
    Ok(Ev {
        delta,
        delta_len: to_u64(dl),
        status,
        running: is_running,
        kind,
        head: to_u64(at),
        payload: payload.into(),
    })
}

/// Bytes enough for any event header.
const PEEK: u64 = 16;

// ---------------------------------------------------------------------------
// Whole-file analysis (playing time, instruments, per-track counts)

/// Files up to this size are analysed when the file is expanded.
const MAX_ANALYSIS: u64 = 1 << 20;

#[derive(Clone, Debug, Default)]
struct TrackInfo {
    name: Option<String>,
    events: u64,
    notes: u64,
    /// Channels with channel messages, bit per channel.
    channels: u16,
}

#[derive(Debug, Default)]
struct Analysis {
    tracks: Vec<TrackInfo>,
    /// (absolute tick, microseconds per quarter note).
    tempos: Vec<(u64, u32)>,
    end: u64,
    /// Melodic GM programs, in order of first use.
    programs: Vec<u8>,
    drums: bool,
    notes: u64,
}

async fn analyse(cx: &Cx, tracks: &[Span]) -> Result<Analysis> {
    let mut a = Analysis::default();
    // Channels whose program has been set (notes on the others play
    // program 0).
    let mut programmed = 0u16;
    for &span in tracks {
        let data = cx.read_avail(span).await?;
        let mut info = TrackInfo::default();
        let mut at = 0usize;
        let mut running = None;
        let mut tick = 0u64;
        while at < data.len() {
            if info.events % 1024 == 0 {
                cx.checkpoint().await;
            }
            let Ok(ev) = parse(data.get(at..).unwrap_or_default(), running) else {
                break;
            };
            running = ev.next_running(running);
            tick = tick.saturating_add(ev.delta.into());
            info.events = info.events.saturating_add(1);
            let payload = data
                .get(at.saturating_add(to_usize(ev.head))..)
                .unwrap_or_default();
            let payload = payload.get(..to_usize(ev.payload)).unwrap_or(payload);
            match ev.kind {
                Kind::Channel([a0, a1]) => {
                    let ch = ev.status & 0xf;
                    info.channels |= 1u16 << ch;
                    match ev.status >> 4 {
                        0x9 if a1 > 0 => {
                            info.notes = info.notes.saturating_add(1);
                            if ch == 9 {
                                a.drums = true;
                            } else if programmed & (1u16 << ch) == 0 {
                                programmed |= 1u16 << ch;
                                if !a.programs.contains(&0) {
                                    a.programs.push(0);
                                }
                            }
                        }
                        0xc if ch != 9 => {
                            programmed |= 1u16 << ch;
                            if !a.programs.contains(&a0) {
                                a.programs.push(a0);
                            }
                        }
                        _ => {}
                    }
                }
                Kind::Meta(0x03) if info.name.is_none() => {
                    info.name = Some(decode_text(payload.get(..128).unwrap_or(payload)));
                }
                Kind::Meta(0x51) => {
                    let us = crate::bytes::u24_be(payload, 0).unwrap_or(0);
                    if us > 0 {
                        a.tempos.push((tick, us));
                    }
                }
                _ => {}
            }
            at = at.saturating_add(to_usize(ev.len()));
            if let Kind::Meta(0x2f) = ev.kind {
                break;
            }
        }
        a.end = a.end.max(tick);
        a.notes = a.notes.saturating_add(info.notes);
        a.tracks.push(info);
    }
    a.tempos.sort_by_key(|&(tick, _)| tick);
    Ok(a)
}

impl Analysis {
    /// Playing time in seconds.
    fn seconds(&self, division: u16) -> Option<f64> {
        if division & 0x8000 != 0 {
            let fps = smpte_fps(division)?;
            let ticks = f64::from(division & 0xff);
            return (ticks > 0.0).then(|| self.end as f64 / (fps * ticks));
        }
        if division == 0 {
            return None;
        }
        let ppq = f64::from(division);
        let mut at = 0u64;
        let mut us = 500_000u32;
        let mut total = 0f64;
        for &(tick, tempo) in self.tempos.iter().take_while(|(t, _)| *t < self.end) {
            total += tick.saturating_sub(at) as f64 * f64::from(us) / ppq;
            at = tick;
            us = tempo;
        }
        total += self.end.saturating_sub(at) as f64 * f64::from(us) / ppq;
        Some(total / 1e6)
    }

    /// "120 BPM" or "90–140 BPM".
    fn tempo(&self) -> String {
        let first = self
            .tempos
            .first()
            .filter(|(t, _)| *t == 0)
            .map_or(500_000, |&(_, us)| us);
        let mut lo = first;
        let mut hi = first;
        for &(_, us) in &self.tempos {
            lo = lo.min(us);
            hi = hi.max(us);
        }
        if lo == hi {
            format!("{} BPM", bpm(lo))
        } else {
            format!("{}–{} BPM", bpm(hi), bpm(lo))
        }
    }

    fn instruments(&self) -> Option<String> {
        let mut names: Vec<String> = self
            .programs
            .iter()
            .take(3)
            .map(|&p| program_name(p).to_owned())
            .collect();
        if self.programs.len() > 3 {
            names.push(format!("{} more", self.programs.len().saturating_sub(3)));
        }
        if self.drums {
            names.push("drums".to_owned());
        }
        (!names.is_empty()).then(|| names.join(", "))
    }
}

/// Beats per minute from microseconds per quarter note.
fn bpm(us: u32) -> String {
    if us == 0 {
        return "?".to_owned();
    }
    let v = 60e6 / f64::from(us);
    if (v - v.round()).abs() < 0.005 {
        format!("{v:.0}")
    } else {
        format!("{v:.2}")
    }
}

fn channel_list(mask: u16) -> String {
    let list: Vec<String> = (0..16u8)
        .filter(|&c| mask & (1u16 << c) != 0)
        .map(|c| c.saturating_add(1).to_string())
        .collect();
    format!("ch {}", list.join(", "))
}

// ---------------------------------------------------------------------------
// The file

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let (header, span) = Cursor::new(&cx, file, BE).record::<Header>().await?;
    cx.emit(Header::node("Header", span, BE));
    let mut line = format!(
        "MIDI format {}, {} track{}",
        header.format,
        header.tracks,
        if header.tracks == 1 { "" } else { "s" }
    );
    cx.annotate(line.clone());

    // The chunks.
    let mut chunks = Vec::new();
    let mut pos = 8u64.saturating_add(header.length.into());
    while file.len.saturating_sub(pos) >= 8 && chunks.len() < 65_536 {
        let head = cx.read(file.sub(pos, 8)).await?;
        let id = crate::bytes::array::<4>(&head, 0).unwrap_or_default();
        let len = u64::from(u32_be(&head, 4).unwrap_or(0));
        chunks.push((id, file.sub(pos, len.saturating_add(8)), len));
        pos = pos.saturating_add(len).saturating_add(8);
    }

    let tracks: Vec<Span> = chunks
        .iter()
        .filter(|(id, _, _)| id == b"MTrk")
        .map(|(_, span, _)| span.tail(8))
        .collect();
    let analysis = if file.len <= MAX_ANALYSIS {
        let a = analyse(&cx, &tracks).await?;
        if let Some(secs) = a.seconds(header.division) {
            line.push_str(&format!(", {}", duration(secs)));
        }
        if header.division & 0x8000 == 0 {
            line.push_str(&format!(", {}", a.tempo()));
        }
        if let Some(i) = a.instruments() {
            line.push_str(&format!(", {i}"));
        }
        cx.annotate(line);
        Some(a)
    } else {
        None
    };

    let mut index = 0usize;
    for (id, span, len) in chunks {
        let data = span.tail(8);
        let mut node = if &id == b"MTrk" {
            let info = analysis.as_ref().and_then(|a| a.tracks.get(index));
            let summary = match info {
                Some(t) => {
                    let mut parts = Vec::new();
                    if let Some(n) = &t.name
                        && !n.is_empty()
                    {
                        parts.push(n.clone());
                    }
                    parts.push(format!("{} events", t.events));
                    if t.notes > 0 {
                        parts.push(format!("{} notes", t.notes));
                    }
                    if t.channels != 0 {
                        parts.push(channel_list(t.channels));
                    }
                    parts.join(", ")
                }
                None => match track_name(&cx, data).await {
                    Some(n) => format!("{n}, {len} bytes"),
                    None => format!("{len} bytes"),
                },
            };
            let node = Node::new(format!("Track {index}"))
                .span(span)
                .summary(summary)
                .lazy(track, data);
            index = index.saturating_add(1);
            node
        } else {
            let mut node = Node::new(fourcc(&id))
                .span(span)
                .summary(format!("{len} bytes"));
            node = node.desc(match &id {
                b"XFIH" => "Yamaha XF information header",
                b"XFKM" => "Yamaha XF karaoke messages",
                _ => "Unknown chunk",
            });
            node
        };
        if span.len < len.saturating_add(8) {
            node = node.diag(Diagnostic::truncated(
                Span::new(span.source, span.offset, len.saturating_add(8)),
                span.len,
            ));
        }
        cx.push(node).await;
    }
    if pos < file.len {
        cx.emit(Node::new("Trailing data").span(file.tail(pos)));
    }
    Ok(())
}

/// The track name meta event, if it is among the first events.
async fn track_name(cx: &Cx, data: Span) -> Option<String> {
    let mut pos = 0u64;
    let mut running = None;
    for _ in 0..8 {
        let head = cx.read_avail(data.sub(pos, PEEK)).await.ok()?;
        let ev = parse(&head, running).ok()?;
        match ev.kind {
            Kind::Meta(3) => {
                let bytes = cx
                    .read_avail(data.sub(pos.saturating_add(ev.head), ev.payload.min(128)))
                    .await
                    .ok()?;
                return Some(decode_text(&bytes));
            }
            Kind::Channel(_) => return None,
            _ => {}
        }
        running = ev.next_running(running);
        pos = pos.saturating_add(ev.len());
    }
    None
}

// ---------------------------------------------------------------------------
// Tracks

async fn track(cx: Cx, data: Span) -> Result<()> {
    let (mut pos, mut time, mut running) = cx
        .resume::<(u64, u64, Option<u8>)>()
        .unwrap_or((0, 0, None));
    while pos < data.len {
        let head = cx.read_avail(data.sub(pos, PEEK)).await?;
        let ev = match parse(&head, running) {
            Ok(ev) => ev,
            Err(e) => {
                let rest = data.tail(pos);
                let diag = match e {
                    Bad::Short => Diagnostic::truncated(rest, rest.len),
                    Bad::Invalid(m) => Diagnostic::malformed(m).at(rest.sub(0, 1)),
                };
                cx.emit(Node::new("Unparsed data").span(rest).diag(diag));
                return Ok(());
            }
        };
        let state = (pos, time, running);
        cx.mark(move || state);
        time = time.saturating_add(ev.delta.into());
        let span = data.sub(pos, ev.len());
        let payload = span.sub(ev.head, ev.payload.min(256));
        let (name, detail, value) = describe(&cx, &ev, payload).await?;
        let mut node = Node::new(name)
            .span(span)
            .summary(format!("Δ{} @{time}{detail}", ev.delta));
        if let Some(v) = value {
            node = node.value(text(v));
        }
        if span.len < ev.len() {
            node = node.diag(Diagnostic::truncated(
                Span::new(span.source, span.offset, ev.len()),
                span.len,
            ));
        }
        cx.progress_in(data, data.offset.saturating_add(pos));
        cx.push(node.lazy(event, (span, running))).await;
        running = ev.next_running(running);
        pos = pos.saturating_add(ev.len());
        if let Kind::Meta(0x2f) = ev.kind {
            if pos < data.len {
                cx.emit(
                    Node::new("Data after end of track")
                        .span(data.tail(pos))
                        .diag(Diagnostic::warning("bytes after the End of Track event")),
                );
            }
            break;
        }
    }
    Ok(())
}

/// Event name, summary detail and text value.
async fn describe(cx: &Cx, ev: &Ev, payload: Span) -> Result<(String, String, Option<String>)> {
    Ok(match ev.kind {
        Kind::Channel([a, b]) => {
            let ch = ev.status & 0xf;
            let (name, detail) = match ev.status >> 4 {
                0x8 => ("Note off", format!("{}, velocity {b}", note(ch, a))),
                0x9 if b == 0 => ("Note on (off)", format!("{}, velocity 0", note(ch, a))),
                0x9 => ("Note on", format!("{}, velocity {b}", note(ch, a))),
                0xa => ("Key pressure", format!("{}, pressure {b}", note(ch, a))),
                0xb => (
                    "Control change",
                    format!(
                        "{} ({a}) = {b}",
                        lookup(CONTROLLERS, a.into()).unwrap_or("controller")
                    ),
                ),
                0xc => ("Program change", format!("{a}: {}", program(ch, a))),
                0xd => ("Channel pressure", format!("{a}")),
                _ => ("Pitch bend", format!("{}", bend(a, b))),
            };
            (
                name.to_owned(),
                format!(" — ch {}, {detail}", ch.saturating_add(1)),
                None,
            )
        }
        Kind::SysEx => {
            let bytes = cx.read_avail(payload.sub(0, 16)).await?;
            let mut detail = format!(" — {} bytes", ev.payload);
            if ev.status == 0xf0 {
                if let Some((maker, _)) = sysex_maker(&bytes) {
                    detail.push_str(&format!(", {maker}"));
                }
                if let Some(name) = sysex_name(&bytes) {
                    detail.push_str(&format!(": {name}"));
                }
            }
            (
                if ev.status == 0xf0 {
                    "System exclusive".to_owned()
                } else {
                    "System exclusive (escape)".to_owned()
                },
                detail,
                None,
            )
        }
        Kind::Meta(kind) => {
            let name = lookup(META, kind.into())
                .map_or_else(|| format!("Meta {kind:#04x}"), str::to_owned);
            let bytes = cx.read_avail(payload).await?;
            let (detail, value) = match kind {
                0x01..=0x0f => (String::new(), Some(decode_text(&bytes))),
                0x00 => (format!(" — {}", u16_be(&bytes, 0).unwrap_or(0)), None),
                0x2f => (String::new(), None),
                0x20 => (
                    format!(
                        " — ch {}",
                        bytes.first().copied().unwrap_or(0).saturating_add(1)
                    ),
                    None,
                ),
                0x21 => (format!(" — {}", bytes.first().copied().unwrap_or(0)), None),
                0x51 => {
                    let us = crate::bytes::u24_be(&bytes, 0).unwrap_or(0);
                    (format!(" — {us} µs per quarter ({} BPM)", bpm(us)), None)
                }
                0x54 => (format!(" — {}", smpte_offset(&bytes)), None),
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
                0x7f => {
                    let mut d = format!(" — {} bytes", ev.payload);
                    if let Some((maker, _)) = sysex_maker(&bytes) {
                        d.push_str(&format!(", {maker}"));
                    }
                    (d, None)
                }
                _ => (format!(" — {} bytes", ev.payload), None),
            };
            (name, detail, value)
        }
    })
}

/// Payload bytes shown when an event is expanded.
const MAX_SHOWN: u64 = 4096;

/// Expands one event into its bytes.
async fn event(cx: Cx, (span, running): (Span, Option<u8>)) -> Result<()> {
    let head = cx.read_avail(span.sub(0, PEEK)).await?;
    let ev = parse(&head, running).map_err(|e| match e {
        Bad::Short => Diagnostic::truncated(span, span.len),
        Bad::Invalid(m) => Diagnostic::malformed(m).at(span),
    })?;
    let shown = ev.payload.min(MAX_SHOWN);
    let block = cx.block(span.sub(0, ev.head.saturating_add(shown))).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    let delta = ev.delta;
    f.bytes("Delta time", ev.delta_len)
        .with(|_, n| n.value(uint(delta, 32)).summary("ticks"))
        .desc("Ticks since the previous event (variable-length quantity)")
        .emit()?;
    let status = ev.status;
    if ev.running {
        f.node(
            Node::new("Status")
                .span(f.peek_span(0))
                .value(hex(status, 8))
                .summary(format!("running status: {}", status_name(status)))
                .desc("Omitted: the status of the previous channel message applies"),
        );
    } else {
        f.u8("Status").hex().summary(status_name(status)).emit()?;
    }
    let ch = status & 0xf;
    match ev.kind {
        Kind::Channel(_) => match status >> 4 {
            0x8..=0xa => {
                f.u8("Note")
                    .with(|&v, n| {
                        n.summary(match lookup(GM_PERCUSSION, v.into()) {
                            Some(drum) if ch == 9 => drum.to_owned(),
                            _ => note_name(v),
                        })
                    })
                    .emit()?;
                f.u8(if status >> 4 == 0xa {
                    "Pressure"
                } else {
                    "Velocity"
                })
                .emit()?;
            }
            0xb => {
                let c = f.u8("Controller").enumeration(CONTROLLERS).emit()?;
                f.u8("Value")
                    .with(|&v, n| {
                        if (64..=69).contains(&c) {
                            n.summary(if v >= 64 { "on" } else { "off" })
                        } else {
                            n
                        }
                    })
                    .emit()?;
            }
            0xc => {
                f.u8("Program")
                    .with(|&v, n| n.summary(program(ch, v)))
                    .emit()?;
            }
            0xd => {
                f.u8("Pressure").emit()?;
            }
            _ => {
                f.bytes("Value", 2)
                    .with(|b, n| {
                        let v = bend(
                            b.first().copied().unwrap_or(0),
                            b.get(1).copied().unwrap_or(0),
                        );
                        n.value(Value::Int {
                            value: v.into(),
                            bits: 14,
                        })
                        .summary("relative to centre (8192); LSB first")
                    })
                    .emit()?;
            }
        },
        Kind::Meta(kind) => {
            f.u8("Type").enumeration(META).emit()?;
            let len = ev.payload;
            f.bytes("Length", ev.head.saturating_sub(f.pos()))
                .with(|_, n| n.value(uint(len, 32)))
                .emit()?;
            meta(&mut f, kind, shown)?;
        }
        Kind::SysEx => {
            let len = ev.payload;
            f.bytes("Length", ev.head.saturating_sub(f.pos()))
                .with(|_, n| n.value(uint(len, 32)))
                .emit()?;
            if status == 0xf0 {
                sysex(&mut f, shown)?;
            } else if shown > 0 {
                f.bytes("Data", shown).emit()?;
            }
        }
    }
    if ev.payload > shown {
        cx.emit(
            Node::new("More data")
                .span(span.tail(ev.head.saturating_add(shown)))
                .summary(format!("{} bytes", ev.payload.saturating_sub(shown))),
        );
    }
    Ok(())
}

fn meta(f: &mut Fields<'_>, kind: u8, len: u64) -> Result<()> {
    match (kind, len) {
        (0x00, 2) => {
            f.u16("Sequence number").emit()?;
        }
        (0x01..=0x0f, _) => {
            f.bytes("Text", len)
                .with(|b, n| n.value(text(decode_text(b))))
                .emit()?;
        }
        (0x20, 1) => {
            f.u8("Channel")
                .with(|&c, n| n.summary(format!("channel {}", c.saturating_add(1))))
                .desc("0-based; following meta and sysex events apply to it")
                .emit()?;
        }
        (0x21, 1) => {
            f.u8("Port").emit()?;
        }
        (0x2f, _) => {}
        (0x51, 3) => {
            crate::formats::util::sound::u24(f, "Microseconds per quarter note", BE)
                .with(|&us, n| n.summary(format!("{} BPM", bpm(us))))
                .emit()?;
        }
        (0x54, 5) => {
            f.u8("Hours")
                .with(|&h, n| {
                    n.value(uint(h & 0x1f, 8)).summary(match h >> 5 & 3 {
                        0 => "24 fps",
                        1 => "25 fps",
                        2 => "29.97 fps drop-frame",
                        _ => "30 fps",
                    })
                })
                .desc("Frame rate in bits 5-6, hours in bits 0-4")
                .emit()?;
            f.u8("Minutes").emit()?;
            f.u8("Seconds").emit()?;
            f.u8("Frames").emit()?;
            f.u8("Fractional frames")
                .desc("Hundredths of a frame")
                .emit()?;
        }
        (0x58, 4) => {
            f.u8("Numerator").emit()?;
            f.u8("Denominator")
                .with(|&d, n| n.summary(format!("{}", 1u32 << d.min(16))))
                .desc("A power of two")
                .emit()?;
            f.u8("Clocks per click")
                .desc("MIDI clocks per metronome click")
                .emit()?;
            f.u8("32nd notes per quarter").emit()?;
        }
        (0x59, 2) => {
            f.int::<i8>("Sharps/flats")
                .with(|&s, n| {
                    n.summary(match s {
                        0 => "no sharps or flats".to_owned(),
                        1 => "1 sharp".to_owned(),
                        -1 => "1 flat".to_owned(),
                        s if s < 0 => format!("{} flats", s.unsigned_abs()),
                        s => format!("{s} sharps"),
                    })
                })
                .emit()?;
            f.u8("Mode").enumeration(MODE).emit()?;
        }
        (0x7f, _) if len > 0 => {
            let first = f.block().data.get(to_usize(f.pos())).copied();
            let n = if first == Some(0) { 3 } else { 1 };
            f.bytes("Manufacturer", n.min(len))
                .with(|b, node| match manufacturer(b) {
                    Some(m) => node.summary(m),
                    None => node,
                })
                .emit()?;
            let rest = len.saturating_sub(n);
            if rest > 0 {
                f.bytes("Data", rest).emit()?;
            }
        }
        (_, 0) => {}
        _ => {
            f.bytes("Data", len).emit()?;
        }
    }
    Ok(())
}

const MODE: EnumTable = &[(0, "major"), (1, "minor")];

const UNIVERSAL_NON_RT: EnumTable = &[
    (0x01, "Sample dump header"),
    (0x02, "Sample data packet"),
    (0x03, "Sample dump request"),
    (0x04, "MIDI time code"),
    (0x05, "Sample dump extensions"),
    (0x06, "General information"),
    (0x07, "File dump"),
    (0x08, "MIDI tuning standard"),
    (0x09, "General MIDI"),
    (0x0a, "Downloadable sounds"),
    (0x7b, "End of file"),
    (0x7c, "Wait"),
    (0x7d, "Cancel"),
    (0x7e, "NAK"),
    (0x7f, "ACK"),
];

const UNIVERSAL_RT: EnumTable = &[
    (0x01, "MIDI time code"),
    (0x02, "MIDI show control"),
    (0x03, "Notation information"),
    (0x04, "Device control"),
    (0x05, "Real-time MTC cueing"),
    (0x06, "MIDI machine control command"),
    (0x07, "MIDI machine control response"),
    (0x08, "MIDI tuning standard"),
    (0x09, "Controller destination"),
    (0x0a, "Key-based instrument control"),
];

fn sysex(f: &mut Fields<'_>, len: u64) -> Result<()> {
    let data = f.block().data.get(to_usize(f.pos())..).unwrap_or_default();
    let data = data.get(..to_usize(len)).unwrap_or(data);
    let Some((maker, n)) = sysex_maker(data) else {
        if len > 0 {
            f.bytes("Data", len).emit()?;
        }
        return Ok(());
    };
    let universal = data.first().copied();
    let name = sysex_name(data);
    f.bytes("Manufacturer", n)
        .summary(maker)
        .desc("MIDI manufacturer ID (one byte, or three starting with 0)")
        .emit()?;
    let mut used = n;
    if matches!(universal, Some(0x7e | 0x7f)) && len >= 4 {
        f.u8("Device ID")
            .with(|&d, node| {
                if d == 0x7f {
                    node.summary("all devices")
                } else {
                    node
                }
            })
            .emit()?;
        let table = if universal == Some(0x7e) {
            UNIVERSAL_NON_RT
        } else {
            UNIVERSAL_RT
        };
        f.u8("Sub-ID #1").enumeration(table).emit()?;
        f.u8("Sub-ID #2").hex().emit()?;
        used = used.saturating_add(3);
    }
    let end = data.last() == Some(&0xf7);
    let body = len.saturating_sub(used).saturating_sub(u64::from(end));
    if body > 0 {
        let mut field = f.bytes("Data", body);
        if let Some(name) = name {
            field = field.summary(name);
        }
        field.emit()?;
    }
    if end {
        f.u8("End of exclusive").hex().emit()?;
    }
    Ok(())
}

/// The manufacturer of a system exclusive message and the ID's length.
fn sysex_maker(data: &[u8]) -> Option<(&'static str, u64)> {
    match data {
        [0, a, b, ..] => Some((
            manufacturer(&[0, *a, *b]).unwrap_or("unknown manufacturer"),
            3,
        )),
        [id, ..] => Some((manufacturer(&[*id]).unwrap_or("unknown manufacturer"), 1)),
        [] => None,
    }
}

/// Well-known system exclusive messages (the bytes after F0).
fn sysex_name(data: &[u8]) -> Option<&'static str> {
    Some(match data {
        [0x7e, _, 0x09, 0x01, ..] => "GM System On",
        [0x7e, _, 0x09, 0x02, ..] => "GM System Off",
        [0x7e, _, 0x09, 0x03, ..] => "GM2 System On",
        [0x7e, _, 0x06, 0x01, ..] => "Identity request",
        [0x7e, _, 0x06, 0x02, ..] => "Identity reply",
        [0x7f, _, 0x04, 0x01, ..] => "Master volume",
        [0x7f, _, 0x04, 0x02, ..] => "Master balance",
        [0x7f, _, 0x04, 0x03, ..] => "Master fine tuning",
        [0x7f, _, 0x04, 0x04, ..] => "Master coarse tuning",
        [0x7f, _, 0x01, 0x01, ..] => "MTC full frame",
        [0x41, _, 0x42, 0x12, 0x40, 0x00, 0x7f, 0x00, ..] => "GS Reset",
        [0x41, _, 0x42, 0x12, 0x00, 0x00, 0x7f, ..] => "GS System Mode Set",
        [0x41, _, 0x42, 0x12, ..] => "Roland GS parameter",
        [0x41, _, _, 0x12, ..] => "Roland data set (DT1)",
        [0x41, _, _, 0x11, ..] => "Roland data request (RQ1)",
        [0x43, d, 0x4c, 0x00, 0x00, 0x7e, 0x00, ..] if d & 0xf0 == 0x10 => "XG System On",
        [0x43, d, 0x4c, 0x00, 0x00, 0x7f, 0x00, ..] if d & 0xf0 == 0x10 => {
            "XG All Parameters Reset"
        }
        [0x43, d, 0x4c, ..] if d & 0xf0 == 0x10 => "Yamaha XG parameter change",
        _ => return None,
    })
}

/// MIDI manufacturer IDs (one byte, or three starting with 0).
pub fn manufacturer(id: &[u8]) -> Option<&'static str> {
    Some(match id {
        [0x01] => "Sequential Circuits",
        [0x04] => "Moog",
        [0x06] => "Lexicon",
        [0x07] => "Kurzweil",
        [0x0f] => "Ensoniq",
        [0x10] => "Oberheim",
        [0x11] => "Apple",
        [0x18] => "E-mu",
        [0x1c] => "Eventide",
        [0x29] => "PPG",
        [0x33] => "Clavia",
        [0x3e] => "Waldorf",
        [0x40] => "Kawai",
        [0x41] => "Roland",
        [0x42] => "Korg",
        [0x43] => "Yamaha",
        [0x44] => "Casio",
        [0x47] => "Akai",
        [0x48] => "Victor (JVC)",
        [0x4c] => "Sony",
        [0x51] => "Fostex",
        [0x52] => "Zoom",
        [0x7d] => "Non-commercial",
        [0x7e] => "Universal non-real-time",
        [0x7f] => "Universal real-time",
        [0x00, 0x00, 0x0e] => "Alesis",
        [0x00, 0x00, 0x3b] => "MOTU",
        [0x00, 0x20, 0x29] => "Focusrite/Novation",
        [0x00, 0x20, 0x32] => "Behringer",
        [0x00, 0x20, 0x33] => "Access",
        [0x00, 0x20, 0x3c] => "Elektron",
        [0x00, 0x20, 0x6b] => "Arturia",
        [0x00, 0x21, 0x09] => "Native Instruments",
        _ => return None,
    })
}

fn status_name(status: u8) -> String {
    let ch = (status & 0xf).saturating_add(1);
    match status >> 4 {
        0x8 => format!("note off, channel {ch}"),
        0x9 => format!("note on, channel {ch}"),
        0xa => format!("key pressure, channel {ch}"),
        0xb => format!("control change, channel {ch}"),
        0xc => format!("program change, channel {ch}"),
        0xd => format!("channel pressure, channel {ch}"),
        0xe => format!("pitch bend, channel {ch}"),
        _ => match status {
            0xf0 => "system exclusive".to_owned(),
            0xf7 => "system exclusive continuation / escape".to_owned(),
            0xff => "meta event".to_owned(),
            _ => "system message".to_owned(),
        },
    }
}

fn bend(lsb: u8, msb: u8) -> i32 {
    i32::from(u16::from(lsb) | (u16::from(msb) << 7)).saturating_sub(8192)
}

fn smpte_offset(b: &[u8]) -> String {
    let get = |i: usize| b.get(i).copied().unwrap_or(0);
    format!(
        "{:02}:{:02}:{:02}:{:02}.{:02}",
        get(0) & 0x1f,
        get(1),
        get(2),
        get(3),
        get(4)
    )
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

/// MIDI 1.0 / General MIDI controller numbers.
const CONTROLLERS: EnumTable = &[
    (0, "Bank select"),
    (1, "Modulation wheel"),
    (2, "Breath controller"),
    (4, "Foot controller"),
    (5, "Portamento time"),
    (6, "Data entry"),
    (7, "Volume"),
    (8, "Balance"),
    (10, "Pan"),
    (11, "Expression"),
    (12, "Effect control 1"),
    (13, "Effect control 2"),
    (16, "General purpose 1"),
    (17, "General purpose 2"),
    (18, "General purpose 3"),
    (19, "General purpose 4"),
    (32, "Bank select (LSB)"),
    (33, "Modulation wheel (LSB)"),
    (34, "Breath controller (LSB)"),
    (36, "Foot controller (LSB)"),
    (37, "Portamento time (LSB)"),
    (38, "Data entry (LSB)"),
    (39, "Volume (LSB)"),
    (40, "Balance (LSB)"),
    (42, "Pan (LSB)"),
    (43, "Expression (LSB)"),
    (44, "Effect control 1 (LSB)"),
    (45, "Effect control 2 (LSB)"),
    (48, "General purpose 1 (LSB)"),
    (49, "General purpose 2 (LSB)"),
    (50, "General purpose 3 (LSB)"),
    (51, "General purpose 4 (LSB)"),
    (64, "Sustain"),
    (65, "Portamento"),
    (66, "Sostenuto"),
    (67, "Soft pedal"),
    (68, "Legato footswitch"),
    (69, "Hold 2"),
    (70, "Sound variation"),
    (71, "Resonance"),
    (72, "Release time"),
    (73, "Attack time"),
    (74, "Brightness"),
    (75, "Decay time"),
    (76, "Vibrato rate"),
    (77, "Vibrato depth"),
    (78, "Vibrato delay"),
    (79, "Sound controller 10"),
    (80, "General purpose 5"),
    (81, "General purpose 6"),
    (82, "General purpose 7"),
    (83, "General purpose 8"),
    (84, "Portamento control"),
    (88, "High-resolution velocity prefix"),
    (91, "Reverb"),
    (92, "Tremolo"),
    (93, "Chorus"),
    (94, "Detune"),
    (95, "Phaser"),
    (96, "Data increment"),
    (97, "Data decrement"),
    (98, "NRPN (LSB)"),
    (99, "NRPN (MSB)"),
    (100, "RPN (LSB)"),
    (101, "RPN (MSB)"),
    (120, "All sound off"),
    (121, "Reset all controllers"),
    (122, "Local control"),
    (123, "All notes off"),
    (124, "Omni off"),
    (125, "Omni on"),
    (126, "Mono on"),
    (127, "Poly on"),
];

/// A note name: "C4" for 60 (middle C), "A♯-1".
pub fn note_name(n: u8) -> String {
    const NAMES: [&str; 12] = [
        "C", "C♯", "D", "D♯", "E", "F", "F♯", "G", "G♯", "A", "A♯", "B",
    ];
    let name = NAMES.get(usize::from(n % 12)).copied().unwrap_or("?");
    format!("{name}{}", i32::from(n / 12).saturating_sub(1))
}

/// A note on `channel` (0-based): its name and number, or the General
/// MIDI percussion instrument on channel 10.
fn note(channel: u8, n: u8) -> String {
    if channel == 9
        && let Some(drum) = lookup(GM_PERCUSSION, n.into())
    {
        return format!("{drum} ({n})");
    }
    format!("{} ({n})", note_name(n))
}

fn program_name(p: u8) -> &'static str {
    GM_PROGRAMS.get(usize::from(p)).copied().unwrap_or("?")
}

/// A program on `channel` (0-based): a GM instrument, or a GS drum kit
/// on channel 10.
fn program(channel: u8, p: u8) -> String {
    if channel == 9 {
        return lookup(GS_DRUM_KITS, p.into())
            .map_or_else(|| format!("drum kit {p}"), |k| format!("{k} drum kit"));
    }
    program_name(p).to_owned()
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

/// Roland GS drum kits (program numbers on channel 10).
const GS_DRUM_KITS: EnumTable = &[
    (0, "Standard"),
    (8, "Room"),
    (16, "Power"),
    (24, "Electronic"),
    (25, "TR-808"),
    (32, "Jazz"),
    (40, "Brush"),
    (48, "Orchestra"),
    (56, "SFX"),
    (127, "CM-64/32L"),
];

/// General MIDI level 1 percussion key map (channel 10).
const GM_PERCUSSION: EnumTable = &[
    (35, "Acoustic Bass Drum"),
    (36, "Bass Drum 1"),
    (37, "Side Stick"),
    (38, "Acoustic Snare"),
    (39, "Hand Clap"),
    (40, "Electric Snare"),
    (41, "Low Floor Tom"),
    (42, "Closed Hi-Hat"),
    (43, "High Floor Tom"),
    (44, "Pedal Hi-Hat"),
    (45, "Low Tom"),
    (46, "Open Hi-Hat"),
    (47, "Low-Mid Tom"),
    (48, "Hi-Mid Tom"),
    (49, "Crash Cymbal 1"),
    (50, "High Tom"),
    (51, "Ride Cymbal 1"),
    (52, "Chinese Cymbal"),
    (53, "Ride Bell"),
    (54, "Tambourine"),
    (55, "Splash Cymbal"),
    (56, "Cowbell"),
    (57, "Crash Cymbal 2"),
    (58, "Vibraslap"),
    (59, "Ride Cymbal 2"),
    (60, "Hi Bongo"),
    (61, "Low Bongo"),
    (62, "Mute Hi Conga"),
    (63, "Open Hi Conga"),
    (64, "Low Conga"),
    (65, "High Timbale"),
    (66, "Low Timbale"),
    (67, "High Agogo"),
    (68, "Low Agogo"),
    (69, "Cabasa"),
    (70, "Maracas"),
    (71, "Short Whistle"),
    (72, "Long Whistle"),
    (73, "Short Guiro"),
    (74, "Long Guiro"),
    (75, "Claves"),
    (76, "Hi Wood Block"),
    (77, "Low Wood Block"),
    (78, "Mute Cuica"),
    (79, "Open Cuica"),
    (80, "Mute Triangle"),
    (81, "Open Triangle"),
];

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
