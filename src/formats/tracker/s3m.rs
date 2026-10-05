//! Scream Tracker 3 modules: a 96-byte header with `SCRM` at offset 44,
//! the order list, then parapointer tables (16-byte units) to instrument
//! headers (`SCRS`) and packed patterns.

use crate::bytes::u16_le;
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::Result;
use crate::fields::{Endian, parse};
use crate::formats::tracker::{Pointers, named, order_node, pointed};
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, flag};

const LE: Endian = Endian::Little;

pub static FORMAT: Format = Format {
    name: "s3m",
    title: "Scream Tracker 3 module",
    extensions: &["s3m"],
    mime: "audio/x-s3m",
    probe: Probe::Custom(|h| h.at(44, b"SCRM") && h.at(28, b"\x1a\x10")),
    dissect: crate::expander!(dissect: Input),
};

const FLAGS: FlagTable = &[
    flag(0x1, "ST2_VIBRATO"),
    flag(0x2, "ST2_TEMPO"),
    flag(0x4, "AMIGA_SLIDES"),
    flag(0x8, "ZERO_VOLUME_OPTIMISATION"),
    flag(0x10, "AMIGA_LIMITS"),
    flag(0x20, "SOUNDBLASTER_FILTER"),
    flag(0x40, "FAST_VOLUME_SLIDES"),
    flag(0x80, "SPECIAL_DATA"),
];

const SAMPLE_FORMAT: EnumTable = &[(1, "signed"), (2, "unsigned")];

const INSTRUMENT_TYPE: EnumTable = &[
    (0, "empty"),
    (1, "sample"),
    (2, "AdLib melody"),
    (3, "AdLib bass drum"),
    (4, "AdLib snare"),
    (5, "AdLib tom"),
    (6, "AdLib cymbal"),
    (7, "AdLib hi-hat"),
];

const SAMPLE_FLAGS: FlagTable = &[flag(0x1, "LOOP"), flag(0x2, "STEREO"), flag(0x4, "16_BIT")];

fn tracker(cwtv: u16) -> String {
    let name = match cwtv >> 12 {
        1 => "Scream Tracker",
        2 => "Imago Orpheus",
        3 => "Impulse Tracker",
        4 => "Schism Tracker",
        5 => "OpenMPT",
        6 => "BeRoTracker",
        7 => "CreamTracker",
        _ => "unknown tracker",
    };
    format!("{name} {:x}.{:02x}", (cwtv >> 8) & 0xf, cwtv & 0xff)
}

record! {
    pub struct Header {
        title: ascii[28] "Title",
        eof: u8 "EOF marker" .hex(),
        kind: u8 "Type" .desc("16 = ST3 module"),
        _reserved: u16 "Reserved",
        orders: u16 "Orders",
        instruments: u16 "Instruments",
        patterns: u16 "Patterns",
        flags: u16 "Flags" .flags(FLAGS),
        tracker: u16 "Created with" .hex() .with(|&v, n| n.summary(tracker(v))),
        format: u16 "Sample format" .enumeration(SAMPLE_FORMAT),
        magic: ascii[4] "Signature",
        global_volume: u8 "Global volume",
        speed: u8 "Initial speed",
        tempo: u8 "Initial tempo",
        master_volume: u8 "Master volume" .desc("Bit 7: stereo") .with(|&v, n| n.summary(if v & 0x80 != 0 { "stereo" } else { "mono" })),
        ultra_click: u8 "Ultra click removal",
        default_pan: u8 "Default panning" .desc("252 = panning table present"),
        _reserved2: bytes[8] "Reserved",
        special: u16 "Special pointer",
        channels: bytes[32] "Channel settings",
    }
}

record! {
    pub struct Instrument {
        kind: u8 "Type" .enumeration(INSTRUMENT_TYPE),
        filename: ascii[12] "File name",
        memseg_high: u8 "Sample pointer (high)",
        memseg: u16 "Sample pointer" .with(|&p, n| n.summary(format!("offset {:#x}", ((u32::from(memseg_high) << 16) | u32::from(p)).saturating_mul(16)))),
        length: u32 "Length",
        loop_begin: u32 "Loop begin",
        loop_end: u32 "Loop end",
        volume: u8 "Volume",
        _reserved: u8 "Reserved",
        pack: u8 "Packing" .desc("0 = unpacked"),
        flags: u8 "Flags" .flags(SAMPLE_FLAGS),
        c2spd: u32 "C-4 speed" .desc("Hz"),
        _internal: bytes[12] "Internal",
        name: ascii[28] "Name",
        magic: ascii[4] "Signature",
    }
}

record! {
    pub struct PatternHeader {
        length: u16 "Packed length",
    }
}

/// Channels in use: settings below 16 are enabled PCM channels.
fn used_channels(settings: &[u8]) -> usize {
    settings.iter().filter(|&&c| c < 16).count()
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let hspan = file.sub(0, Header::SIZE);
    let h = parse(&cx, hspan, LE, &(), Header::layout).await?;
    cx.emit(Header::node("Header", hspan, LE));
    let mut at = Header::SIZE;
    cx.emit(order_node(&cx, file.sub(at, h.orders.into())).await?);
    at = at.saturating_add(h.orders.into());
    let instruments = file.sub(at, u64::from(h.instruments).saturating_mul(2));
    at = at.saturating_add(instruments.len);
    let patterns = file.sub(at, u64::from(h.patterns).saturating_mul(2));
    at = at.saturating_add(patterns.len);
    cx.emit(pointed::<Instrument>(
        "Instruments",
        file,
        Pointers {
            table: instruments,
            width: 2,
            scale: 16,
        },
        "Instrument",
        Some(|i| {
            format!(
                "{}, {} bytes, {} Hz",
                named(&i.name),
                i.length,
                i.c2spd
            )
        }),
    ));
    cx.emit(
        Node::new("Patterns")
            .span(patterns)
            .summary(format!("{} patterns", h.patterns))
            .lazy(list_patterns, (file, patterns)),
    );
    if h.default_pan == 252 {
        cx.emit(Node::new("Channel panning").span(file.sub(at, 32)));
    }
    cx.annotate(format!(
        "S3M, {}, {} channels, {} orders, {} patterns, {} instruments — {}",
        tracker(h.tracker),
        used_channels(&h.channels),
        h.orders,
        h.patterns,
        h.instruments,
        named(&h.title)
    ));
    Ok(())
}

async fn list_patterns(cx: Cx, (file, table): (Span, Span)) -> Result<()> {
    let ptrs = cx.read(table).await?;
    for (i, chunk) in ptrs.chunks(2).enumerate() {
        let ptr = u64::from(u16_le(chunk, 0).unwrap_or(0)).saturating_mul(16);
        let name = format!("Pattern {i}");
        if ptr == 0 {
            cx.push(Node::new(name).summary("empty")).await;
            continue;
        }
        let len = cx.read_avail(file.sub(ptr, 2)).await?;
        let len = u64::from(u16_le(&len, 0).unwrap_or(0));
        let span = file.sub(ptr, len.max(2));
        cx.push(
            Node::new(name)
                .span(span)

                .summary(format!("{len} bytes packed, 64 rows")),
        )
        .await;
    }
    Ok(())
}
