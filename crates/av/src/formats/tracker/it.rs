//! Impulse Tracker modules: `IMPM`, a 192-byte header, the order list,
//! offset tables for instruments (`IMPI`), samples (`IMPS`) and patterns,
//! and an optional song message.

use crate::bytes::{u16_le, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::Result;
use crate::fields::{Endian, parse};
use crate::formats::tracker::{Pointers, named, order_node, pointed};
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

record! {
    pub struct Header {
        magic: ascii[4] "Signature",
        name: ascii[26] "Song name",
        highlight: u16 "Pattern row highlight" .hex(),
        orders: u16 "Orders",
        instruments: u16 "Instruments",
        samples: u16 "Samples",
        patterns: u16 "Patterns",
        created: u16 "Created with tracker" .hex() .with(|&v, n| n.summary(version(v))),
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
        _reserved: u32 "Reserved",
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
            Some(|i| format!("{}, {} samples", named(&i.name), i.samples)),
        ));
    }
    cx.emit(pointed::<Sample>(
        "Samples",
        file,
        samples,
        "Sample",
        Some(|s| {
            format!(
                "{}, {} samples at {} Hz{}",
                named(&s.name),
                s.length,
                s.c5_speed,
                if s.flags & 0x8 != 0 {
                    ", compressed"
                } else {
                    ""
                }
            )
        }),
    ));
    cx.emit(
        Node::new("Patterns")
            .span(patterns.table)
            .summary(format!("{} patterns", h.patterns))
            .lazy(list_patterns, (file, patterns.table)),
    );
    if h.special & 1 != 0 && h.message_length > 0 {
        let span = file.sub(h.message_offset.into(), h.message_length.into());
        let message = peek_text(&cx, span, span.len).await?.replace('\r', "\n");
        cx.emit(Node::new("Message").span(span).value(text(message)));
    }
    let channels = h.pan.iter().filter(|&&p| p & 0x80 == 0).count();
    cx.annotate(format!(
        "IT {}, {channels} channels, {} orders, {} patterns, {} samples, {} instruments — {}",
        version(h.created),
        h.orders,
        h.patterns,
        h.samples,
        h.instruments,
        named(&h.name)
    ));
    Ok(())
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
                .summary(format!("{rows} rows, {len} bytes packed")),
        )
        .await;
    }
    Ok(())
}
