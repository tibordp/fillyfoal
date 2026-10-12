//! Impulse Tracker modules: `IMPM`, a 192-byte header, the order list,
//! offset tables for instruments (`IMPI`), samples (`IMPS`) and patterns,
//! and an optional song message. OpenMPT appends its extensions after
//! everything else: per-instrument properties (`XTPM`) and song
//! properties (`STPM`), each a list of (code, 16-bit size, data); an MPTM
//! file (OpenMPT's own format, the same header with "Compatible with"
//! 0x888) then carries its sequences and tunings in OpenMPT's
//! serialization (shown, not decoded).

use crate::bytes::{to_u64, u16_le, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::tracker::{
    Cell, Note, Pointers, SampleData, it214_len, letter_effect, named, order_node, pcm_bytes,
    pointed, row_summary, schism_version,
};
use crate::formats::util::fmt::plural;
use crate::formats::util::sound::peek_text;
use crate::formats::util::val::text;
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, flag};

const LE: Endian = Endian::Little;

pub static FORMAT: Format = Format {
    name: "it",
    title: "Impulse Tracker module",
    extensions: &["it"],
    mime: "audio/x-it",
    probe: Probe::Magic(&[(0, b"IMPM")]),
    dissect: crate::expander!(dissect: Input),
};

const FLAGS: FlagTable = &[
    flag(0x1, "STEREO"),
    flag(0x2, "VOL0_MIX_OPTIMISATION"),
    flag(0x4, "INSTRUMENTS"),
    flag(0x8, "LINEAR_SLIDES"),
    flag(0x10, "OLD_EFFECTS"),
    flag(0x20, "LINK_G_MEMORY"),
    flag(0x40, "MIDI_PITCH"),
    flag(0x80, "EMBEDDED_MIDI_CONFIG"),
];

const SPECIAL: FlagTable = &[
    flag(0x1, "MESSAGE"),
    flag(0x2, "EDIT_HISTORY"),
    flag(0x4, "PATTERN_HIGHLIGHT"),
    flag(0x8, "MIDI_CONFIG"),
];

const SAMPLE_FLAGS: FlagTable = &[
    flag(0x1, "HAS_SAMPLE"),
    flag(0x2, "16_BIT"),
    flag(0x4, "STEREO"),
    flag(0x8, "COMPRESSED"),
    flag(0x10, "LOOP"),
    flag(0x20, "SUSTAIN_LOOP"),
    flag(0x40, "PING_PONG_LOOP"),
    flag(0x80, "PING_PONG_SUSTAIN"),
];

const NNA: EnumTable = &[
    (0, "cut"),
    (1, "continue"),
    (2, "note off"),
    (3, "note fade"),
];

fn version(v: u16) -> String {
    format!("{:x}.{:02x}", v >> 8, v & 0xff)
}

/// The "Created with" field alone: a version for Impulse Tracker, the
/// tracker otherwise (Schism Tracker dates its newer versions in the
/// reserved field).
fn created_with(cwt: u16) -> String {
    match cwt >> 12 {
        0 if is_mptm(cwt, 0) => format!("OpenMPT MPTM, format {}", version(cwt)),
        0 => version(cwt),
        // Whether this was a compatibility export shows in the reserved
        // field.
        5 => format!("OpenMPT {}", version(cwt & 0x0fff)),
        1 if cwt & 0x0fff == 0x0fff => "Schism Tracker (dated in the reserved field)".to_owned(),
        _ => tracker(cwt, 0),
    }
}

/// The tracker that wrote the file, from its "Created with" field and
/// the reserved field after the message offset (libxmp's and OpenMPT's
/// identification, abridged).
/// An MPTM file (OpenMPT's `Load_it.cpp`): "Created with" 0x889 to 0xfff,
/// or "Compatible with" 0x888.
fn is_mptm(cwt: u16, cmwt: u16) -> bool {
    cmwt == 0x0888 || (0x0889..=0x0fff).contains(&cwt)
}

fn tracker(cwt: u16, reserved: u32) -> String {
    match cwt >> 12 {
        0 if is_mptm(cwt, 0) => "OpenMPT".to_owned(),
        0 if cwt == 0x0888 => "OpenMPT 1.17".to_owned(),
        0 if cwt >> 8 == 0 => "unmo3".to_owned(),
        0 if reserved == u32::from_le_bytes(*b"CHBI") => "Chibi Tracker".to_owned(),
        0 => format!("Impulse Tracker {}", version(cwt)),
        1 => schism_version(cwt, reserved),
        5 if reserved == u32::from_le_bytes(*b"OMPT") => {
            format!("OpenMPT {}", version(cwt & 0x0fff))
        }
        5 => format!("OpenMPT {} (compatibility export)", version(cwt & 0x0fff)),
        6 => format!("BeRoTracker {}", version(cwt & 0x0fff)),
        7 if cwt == 0x7fff => "munch.py".to_owned(),
        _ => format!("unknown tracker {cwt:#06x}"),
    }
}

record! {
    pub struct Header {
        magic: ascii[4] "Signature",
        name: ascii[26] "Song name",
        highlight: u16 "Pattern row highlight" .hex(),
        orders: u16 "Orders",
        instruments: u16 "Instruments",
        samples: u16 "Samples",
        patterns: u16 "Patterns",
        created: u16 "Created with tracker" .hex() .with(|&v, n| n.summary(created_with(v))),
        compatible: u16 "Compatible with" .hex() .with(|&v, n| n.summary(version(v))),
        flags: u16 "Flags" .flags(FLAGS),
        special: u16 "Special" .flags(SPECIAL),
        global_volume: u8 "Global volume",
        mix_volume: u8 "Mix volume",
        speed: u8 "Initial speed",
        tempo: u8 "Initial tempo",
        separation: u8 "Panning separation",
        pitch_wheel: u8 "Pitch wheel depth",
        message_length: u16 "Message length",
        message_offset: u32 "Message offset" .hex(),
        reserved: u32 "Reserved" .hex() .with(|&v, n| if matches!(created >> 12, 1 | 5) { n.summary(tracker(created, v)) } else { n }) .desc("Tracker-specific: Schism Tracker's version, OpenMPT's \"OMPT\""),
        pan: bytes[64] "Channel panning",
        volume: bytes[64] "Channel volume",
    }
}

record! {
    pub struct Sample {
        magic: ascii[4] "Signature",
        filename: ascii[12] "File name",
        _zero: u8 "Reserved",
        global_volume: u8 "Global volume",
        flags: u8 "Flags" .flags(SAMPLE_FLAGS),
        volume: u8 "Default volume",
        name: ascii[26] "Name",
        convert: u8 "Convert" .hex() .desc("Bit 0: signed samples"),
        pan: u8 "Default panning",
        length: u32 "Length" .desc("In samples"),
        loop_begin: u32 "Loop begin",
        loop_end: u32 "Loop end",
        c5_speed: u32 "C-5 speed" .desc("Hz"),
        sustain_begin: u32 "Sustain loop begin",
        sustain_end: u32 "Sustain loop end",
        pointer: u32 "Sample data offset" .hex(),
        vibrato_speed: u8 "Vibrato speed",
        vibrato_depth: u8 "Vibrato depth",
        vibrato_rate: u8 "Vibrato rate",
        vibrato_type: u8 "Vibrato waveform",
    }
}

record! {
    /// The fixed part of an instrument (format 2.00+).
    pub struct Instrument {
        magic: ascii[4] "Signature",
        filename: ascii[12] "File name",
        _zero: u8 "Reserved",
        nna: u8 "New note action" .enumeration(NNA),
        dct: u8 "Duplicate check type",
        dca: u8 "Duplicate check action",
        fadeout: u16 "Fadeout",
        pps: i8 "Pitch-pan separation",
        ppc: u8 "Pitch-pan center",
        global_volume: u8 "Global volume",
        pan: u8 "Default panning",
        random_volume: u8 "Random volume variation",
        random_pan: u8 "Random panning variation",
        tracker: u16 "Tracker version" .hex(),
        samples: u8 "Samples",
        _x: u8 "Reserved",
        name: ascii[26] "Name",
        cutoff: u8 "Filter cutoff",
        resonance: u8 "Filter resonance",
        midi_channel: u8 "MIDI channel",
        midi_program: u8 "MIDI program",
        midi_bank: u16 "MIDI bank",
        keyboard: bytes[240] "Note-sample table",
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let hspan = file.sub(0, Header::SIZE);
    let h = parse(&cx, hspan, LE, &(), Header::layout).await?;
    cx.emit(Header::node("Header", hspan, LE));
    let mut at = Header::SIZE;
    cx.emit(order_node(&cx, file.sub(at, h.orders.into())).await?);
    at = at.saturating_add(h.orders.into());
    let mut table = |n: u16| {
        let span = file.sub(at, u64::from(n).saturating_mul(4));
        at = at.saturating_add(span.len);
        Pointers {
            table: span,
            width: 4,
            scale: 1,
        }
    };
    let instruments = table(h.instruments);
    let samples = table(h.samples);
    let patterns = table(h.patterns);
    if h.instruments > 0 {
        cx.emit(pointed::<Instrument>(
            "Instruments",
            file,
            instruments,
            "Instrument",
            Some(|i| format!("{}, {}", named(&i.name), plural(i.samples, "sample"))),
            None,
        ));
    }
    cx.emit(pointed::<Sample>(
        "Samples",
        file,
        samples,
        "Sample",
        Some(|s| {
            format!(
                "{}, {} at {} Hz{}",
                named(&s.name),
                plural(s.length, "sample"),
                s.c5_speed,
                if s.flags & 0x8 != 0 {
                    ", compressed"
                } else {
                    ""
                }
            )
        }),
        Some(sample_data),
    ));
    cx.emit(
        Node::new("Patterns")
            .span(patterns.table)
            .summary(plural(h.patterns, "pattern"))
            .lazy(list_patterns, (file, patterns.table)),
    );
    // After the offset tables: the edit history (a count, then 8 bytes
    // per entry) and the embedded MIDI configuration (4896 bytes).
    if h.special & 2 != 0 {
        let count = cx.read_avail(file.sub(at, 2)).await?;
        let count = u64::from(u16_le(&count, 0).unwrap_or(0));
        let span = file.sub(at, count.saturating_mul(8).saturating_add(2));
        at = at.saturating_add(span.len);
        cx.emit(
            Node::new("Edit history")
                .span(span)
                .summary(plural(count, "entry"))
                .lazy(edit_history, span),
        );
    }
    if h.flags & 0x80 != 0 || h.special & 8 != 0 {
        let span = file.sub(at, MIDI_CONFIG);
        cx.emit(
            Node::new("MIDI configuration")
                .span(span)
                .summary("9 global, 16 parametered (SFx) and 128 fixed (Zxx) macros")
                .lazy(midi_config, span),
        );
    }
    if h.special & 1 != 0 && h.message_length > 0 {
        let span = file.sub(h.message_offset.into(), h.message_length.into());
        let message = peek_text(&cx, span, span.len).await?.replace('\r', "\n");
        cx.emit(Node::new("Message").span(span).value(text(message)));
    }
    let end = known_end(&cx, file, &h, at, &instruments, &samples, &patterns).await;
    if let Some(node) = openmpt_extensions(&cx, file, end, h.instruments).await? {
        cx.emit(node);
    }
    let channels = h.pan.iter().filter(|&&p| p & 0x80 == 0).count();
    let kind = if is_mptm(h.created, h.compatible) {
        "MPTM".to_owned()
    } else {
        format!("IT {}", version(h.compatible))
    };
    cx.annotate(format!(
        "{kind}, {}, {channels_channel}, {}, {}, {}, {} — {}",
        tracker(h.created, h.reserved),
        plural(h.orders, "order"),
        plural(h.patterns, "pattern"),
        plural(h.samples, "sample"),
        plural(h.instruments, "instrument"),
        named(&h.name),
        channels_channel = plural(channels, "channel")
    ));
    Ok(())
}

/// Most entries of each table the end of the known data is computed from.
const MAX_TABLE: usize = 4096;
/// An IT 2.x instrument (`IMPI`, with its envelopes).
const INSTRUMENT_SIZE: u64 = 554;

/// Where the data the header accounts for ends: the tables after the
/// header (and the edit history and MIDI configuration, `at`), the
/// message, instruments, patterns and sample data. OpenMPT's extensions
/// start there.
async fn known_end(
    cx: &Cx,
    file: Span,
    h: &Header,
    at: u64,
    instruments: &Pointers,
    samples: &Pointers,
    patterns: &Pointers,
) -> u64 {
    let mut end = at;
    if h.special & 1 != 0 {
        end = end.max(u64::from(h.message_offset).saturating_add(h.message_length.into()));
    }
    let pointers = |data: &[u8]| -> Vec<u64> {
        data.chunks(4)
            .take(MAX_TABLE)
            .filter_map(|c| u32_le(c, 0).map(u64::from))
            .filter(|&p| p != 0)
            .collect()
    };
    if let Ok(t) = cx.read_avail(instruments.table).await {
        for p in pointers(&t) {
            end = end.max(p.saturating_add(INSTRUMENT_SIZE));
        }
    }
    if let Ok(t) = cx.read_avail(patterns.table).await {
        for p in pointers(&t) {
            if let Ok(head) = cx.read_avail(file.sub(p, 2)).await {
                let len = u64::from(u16_le(&head, 0).unwrap_or(0));
                end = end.max(p.saturating_add(8).saturating_add(len));
            }
        }
    }
    if let Ok(t) = cx.read_avail(samples.table).await {
        for p in pointers(&t) {
            end = end.max(p.saturating_add(Sample::SIZE));
            let span = file.sub(p, Sample::SIZE);
            let Ok(s) = parse(cx, span, LE, &(), Sample::layout).await else {
                continue;
            };
            match sample_data(&s, file) {
                Some(SampleData::Plain(span, _)) => {
                    let rel = span.offset.saturating_sub(file.offset);
                    end = end.max(rel.saturating_add(span.len));
                }
                Some(SampleData::It214 {
                    region,
                    frames,
                    sixteen,
                    stereo,
                    ..
                }) => {
                    let len = it214_len(cx, region, frames, sixteen, stereo).await;
                    let rel = region.offset.saturating_sub(file.offset);
                    end = end.max(rel.saturating_add(len));
                }
                None => {}
            }
        }
    }
    end
}

/// The OpenMPT extension blocks at `end`, if there are any.
async fn openmpt_extensions(
    cx: &Cx,
    file: Span,
    end: u64,
    instruments: u16,
) -> Result<Option<Node>> {
    let rest = file.tail(end);
    let magic = cx.read_avail(rest.sub(0, 4)).await?;
    if magic.starts_with(b"228") {
        return Ok(Some(mptm_node(rest)));
    }
    if magic != b"XTPM" && magic != b"STPM" {
        return Ok(None);
    }
    Ok(Some(
        Node::new("OpenMPT extensions")
            .span(rest)
            .desc("Properties OpenMPT keeps beyond the IT format, in (code, size, data) entries")
            .lazy(extensions, (rest, instruments)),
    ))
}

fn mptm_node(span: Span) -> Node {
    Node::new("MPTM data").span(span).desc(
        "Sequences, tunings and other MPTM data in OpenMPT's own serialization (\"228\"); not decoded",
    )
}

/// Song property codes OpenMPT writes (`SaveExtendedSongProperties`), as
/// stored (byte-reversed, except AUTH and CCOL), with what they hold.
const SONG_PROPERTIES: &[(&[u8; 4], &str)] = &[
    (b"...C", "Number of channels"),
    (b"..TD", "Default tempo"),
    (b".BPR", "Rows per beat"),
    (b".MPR", "Rows per measure"),
    (b".VWC", "Created with OpenMPT version"),
    (b"VWSL", "Last saved with OpenMPT version"),
    (b".APS", "Sample pre-amplification"),
    (b"VTSV", "Synth (VSTi) volume"),
    (b".VGD", "Default global volume"),
    (b"..PR", "Restart position"),
    (b".MMP", "Mix levels"),
    (b"..MT", "Tempo mode"),
    (b".FSM", "Playback compatibility flags"),
    (b"AMIM", "MIDI mapping"),
    (b"SnhC", "Channel settings"),
    (b"SEUC", "Cue points"),
    (b"GNWS", "Tempo swing"),
    (b"PMSR", "Resampling mode"),
    (b"AUTH", "Artist"),
    (b"CCOL", "Channel colours"),
];

fn printable(code: &[u8]) -> bool {
    code.iter().all(|&b| (0x20..0x7f).contains(&b))
}

/// The XTPM/STPM entries: a 4-byte code, a 16-bit size, then the data
/// (once per instrument after XTPM). An MPTM's serialized data follows.
async fn extensions(cx: Cx, (span, instruments): (Span, u16)) -> Result<()> {
    let mut pos = 0u64;
    let mut per = 1u64;
    while pos.saturating_add(4) <= span.len {
        cx.checkpoint().await;
        let head = cx.read_avail(span.sub(pos, 6)).await?;
        let code = head.get(..4).unwrap_or_default();
        if code == b"XTPM" || code == b"STPM" {
            let instrument = code == b"XTPM";
            per = if instrument {
                u64::from(instruments).max(1)
            } else {
                1
            };
            cx.push(
                Node::new(crate::text::latin1(code))
                    .span(span.sub(pos, 4))
                    .desc(if instrument {
                        "Instrument properties follow: each entry's data repeats per instrument"
                    } else {
                        "Song properties follow"
                    }),
            )
            .await;
            pos = pos.saturating_add(4);
            continue;
        }
        let size = u64::from(u16_le(&head, 4).unwrap_or(0));
        let total = size.saturating_mul(per);
        if !printable(code)
            || head.len() < 6
            || pos.saturating_add(6).saturating_add(total) > span.len
        {
            break;
        }
        let entry = span.sub(pos, total.saturating_add(6));
        let data = span.sub(pos.saturating_add(6), total);
        let mut node = Node::new(crate::text::latin1(code)).span(entry);
        if let Some((_, m)) = SONG_PROPERTIES.iter().find(|(c, _)| c.as_slice() == code) {
            node = node.desc(*m);
        }
        let bytes = cx.read_avail(data.sub(0, 64)).await?;
        node = match (code, size) {
            (b"AUTH", _) => node.value(text(crate::text::latin1(&bytes))),
            (b"VWSL" | b".VWC", 4) => {
                let v = u32_le(&bytes, 0).unwrap_or(0);
                node.value(crate::formats::util::val::hex(v, 32))
                    .summary(format!(
                        "{:x}.{:02x}.{:02x}.{:02x}",
                        v >> 24,
                        (v >> 16) & 0xff,
                        (v >> 8) & 0xff,
                        v & 0xff
                    ))
            }
            (_, 1 | 2 | 4) if per == 1 => {
                let v = bytes
                    .iter()
                    .take(crate::bytes::to_usize(size))
                    .rev()
                    .fold(0u64, |a, &b| a.wrapping_shl(8) | u64::from(b));
                node.value(crate::formats::util::val::uint(v, 32))
            }
            _ => node.summary(format!("{total} bytes")),
        };
        cx.push(node).await;
        pos = pos.saturating_add(6).saturating_add(total);
    }
    if pos < span.len {
        let rest = span.tail(pos);
        let head = cx.read_avail(rest.sub(0, 3)).await?;
        cx.push(if head == b"228" {
            mptm_node(rest)
        } else {
            Node::new("Trailing data").span(rest)
        })
        .await;
    }
    Ok(())
}

/// Bytes of an embedded MIDI configuration: 153 macros of 32 bytes.
const MIDI_CONFIG: u64 = 153 * 32;

async fn edit_history(cx: Cx, span: Span) -> Result<()> {
    cx.emit(
        Node::new("Entries")
            .span(span.sub(0, 2))
            .value(crate::formats::util::val::uint(
                span.len.saturating_sub(2) / 8,
                16,
            )),
    );
    let mut at = 2u64;
    let mut index = 0u64;
    while at.saturating_add(8) <= span.len {
        let entry = span.sub(at, 8);
        let b = cx.read(entry).await?;
        let date = u16_le(&b, 0).unwrap_or(0);
        let time = u16_le(&b, 2).unwrap_or(0);
        let ticks = u32_le(&b, 4).unwrap_or(0);
        // Run time is counted in PC timer ticks, 18.2065 per second.
        let seconds = u64::from(ticks).saturating_mul(10_000) / 182_065;
        cx.push(
            Node::new(format!("Entry {index}"))
                .span(entry)
                .summary(format!(
                    "opened {}, edited for {}:{:02}:{:02}",
                    crate::text::dos_datetime(date, time),
                    seconds / 3600,
                    seconds / 60 % 60,
                    seconds % 60
                )),
        )
        .await;
        at = at.saturating_add(8);
        index = index.saturating_add(1);
    }
    Ok(())
}

async fn midi_config(cx: Cx, span: Span) -> Result<()> {
    const GLOBAL: [&str; 9] = [
        "Start", "Stop", "Tick", "Note on", "Note off", "Volume", "Pan", "Bank", "Program",
    ];
    let data = cx.read(span).await?;
    for (i, chunk) in data.chunks(32).enumerate() {
        let name = match i {
            0..=8 => GLOBAL.get(i).copied().unwrap_or("?").to_owned(),
            9..=24 => format!("SF{:X}", i.saturating_sub(9)),
            _ => format!("Z{:02X}", i.saturating_sub(25).saturating_add(0x80)),
        };
        let macro_text = crate::text::until_nul(chunk);
        cx.push(
            Node::new(name)
                .span(span.sub(to_u64(i).saturating_mul(32), 32))
                .value(text(macro_text)),
        )
        .await;
    }
    Ok(())
}

/// Where a sample's data is: `pointer`, `length` samples of 8 or 16 bits
/// (stereo: one channel after the other), or IT214 compressed blocks.
fn sample_data(s: &Sample, file: Span) -> Option<SampleData> {
    if s.flags & 1 == 0 || s.length == 0 || s.pointer == 0 {
        return None;
    }
    let at = u64::from(s.pointer);
    let sixteen = s.flags & 2 != 0;
    let stereo = s.flags & 4 != 0;
    if s.flags & 8 != 0 {
        return Some(SampleData::It214 {
            region: file.tail(at),
            frames: s.length,
            sixteen,
            stereo,
            it215: s.convert & 4 != 0,
        });
    }
    let (len, coding) = if s.convert == 0xff {
        (
            16u64.saturating_add(u64::from(s.length).div_ceil(2)),
            "ModPlug ADPCM".to_owned(),
        )
    } else {
        (
            pcm_bytes(s.length, sixteen, stereo),
            format!(
                "{}-bit {} PCM{}{}",
                if sixteen { 16 } else { 8 },
                if s.convert & 1 != 0 {
                    "signed"
                } else {
                    "unsigned"
                },
                if s.convert & 4 != 0 { ", delta" } else { "" },
                if stereo { ", stereo" } else { "" }
            ),
        )
    };
    Some(SampleData::Plain(
        file.sub(at, len),
        format!("{len} bytes, {coding}"),
    ))
}

async fn list_patterns(cx: Cx, (file, table): (Span, Span)) -> Result<()> {
    let ptrs = cx.read(table).await?;
    for (i, chunk) in ptrs.chunks(4).enumerate() {
        let ptr = u64::from(u32_le(chunk, 0).unwrap_or(0));
        let name = format!("Pattern {i}");
        if ptr == 0 {
            cx.push(Node::new(name).summary("empty (64 rows)")).await;
            continue;
        }
        let head = cx.read_avail(file.sub(ptr, 4)).await?;
        let len = u64::from(u16_le(&head, 0).unwrap_or(0));
        let rows = u16_le(&head, 2).unwrap_or(0);
        let span = file.sub(ptr, len.saturating_add(8));
        cx.push(
            Node::new(name)
                .span(span)
                .summary(format!(
                    "{rows_row}, {len} bytes packed",
                    rows_row = plural(rows, "row")
                ))
                .lazy(pattern, (span, rows)),
        )
        .await;
    }
    Ok(())
}

record! {
    pub struct PatternHeader {
        length: u16 "Packed length",
        rows: u16 "Rows",
        _reserved: u32 "Reserved",
    }
}

/// Last values per channel, which a mask bit 0x10-0x80 repeats.
#[derive(Clone, Copy, Default)]
struct Last {
    mask: u8,
    note: u8,
    instrument: u8,
    volume: u8,
    command: u8,
    param: u8,
}

/// The volume/panning column: 0-64 volume, 128-192 panning, and ranges
/// for fine volume up/down (a/b), volume slide up/down (c/d), pitch
/// slide down/up (e/f), portamento (g) and vibrato (h).
fn volume_column(v: u8) -> String {
    let range = |base: u8, letter: char| format!("{letter}{:02}", v.saturating_sub(base));
    match v {
        0..=64 => format!("v{v:02}"),
        65..=74 => range(65, 'a'),
        75..=84 => range(75, 'b'),
        85..=94 => range(85, 'c'),
        95..=104 => range(95, 'd'),
        105..=114 => range(105, 'e'),
        115..=124 => range(115, 'f'),
        128..=192 => range(128, 'p'),
        193..=202 => range(193, 'g'),
        203..=212 => range(203, 'h'),
        _ => format!("?{v:02X}"),
    }
}

fn it_note(n: u8) -> Note {
    match n {
        0..=119 => Note::Key(n),
        255 => Note::Off,
        254 => Note::Cut,
        _ => Note::Fade,
    }
}

/// A packed pattern (ITTECH.TXT): per row, entries of a channel byte
/// (0 ends the row; bit 7: a new mask follows, else the channel's last
/// mask applies), then per mask bit a note (1), instrument (2),
/// volume/panning (4), command and parameter (8), or the channel's last
/// note (0x10), instrument (0x20), volume (0x40) or command (0x80).
async fn pattern(cx: Cx, (span, rows): (Span, u16)) -> Result<()> {
    cx.emit(PatternHeader::node("Header", span.sub(0, 8), LE));
    let packed = span.tail(8);
    let data = cx.read(packed).await?;
    let mut last = [Last::default(); 64];
    let mut pos = 0usize;
    for r in 0..rows {
        if pos >= data.len() {
            cx.diag(Diagnostic::malformed(format!(
                "packed data ends after {r} of {rows} rows"
            )));
            return Ok(());
        }
        let start = pos;
        let mut cells = Vec::new();
        let mut complete = false;
        while let Some(&b) = data.get(pos) {
            pos = pos.saturating_add(1);
            if b == 0 {
                complete = true;
                break;
            }
            let channel = usize::from(b.saturating_sub(1) & 63);
            let mut take = |n: usize| {
                let got = data.get(pos..pos.saturating_add(n));
                pos = pos.saturating_add(n);
                got
            };
            let Some(state) = last.get_mut(channel) else {
                break;
            };
            if b & 0x80 != 0 {
                let Some(&[mask]) = take(1) else { break };
                state.mask = mask;
            }
            let mask = state.mask;
            let mut cell = Cell::EMPTY;
            if mask & 1 != 0 {
                let Some(&[note]) = take(1) else { break };
                state.note = note;
            }
            if mask & 2 != 0 {
                let Some(&[instrument]) = take(1) else { break };
                state.instrument = instrument;
            }
            if mask & 4 != 0 {
                let Some(&[volume]) = take(1) else { break };
                state.volume = volume;
            }
            if mask & 8 != 0 {
                let Some(&[command, param]) = take(2) else {
                    break;
                };
                state.command = command;
                state.param = param;
            }
            if mask & 0x11 != 0 {
                cell.note = it_note(state.note);
            }
            if mask & 0x22 != 0 {
                cell.instrument = state.instrument;
            }
            if mask & 0x44 != 0 {
                cell.volume = Some(volume_column(state.volume));
            }
            if mask & 0x88 != 0 {
                cell.effect = letter_effect(state.command, state.param);
            }
            cells.push((channel, cell));
        }
        let end = pos.min(data.len());
        let mut node = Node::new(format!("Row {r:02}"))
            .span(packed.sub(to_u64(start), to_u64(end.saturating_sub(start))))
            .summary(row_summary(&cells));
        if !complete {
            node = node.diag(Diagnostic::malformed("row ends before its end marker"));
        }
        cx.push(node).await;
        if !complete {
            return Ok(());
        }
    }
    if pos < data.len() {
        cx.emit(
            Node::new("Unused packed bytes")
                .span(packed.sub(to_u64(pos), to_u64(data.len().saturating_sub(pos)))),
        );
    }
    Ok(())
}
