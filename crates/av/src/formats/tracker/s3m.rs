//! Scream Tracker 3 modules: a 96-byte header with `SCRM` at offset 44,
//! the order list, then parapointer tables (16-byte units) to instrument
//! headers (`SCRS`) and packed patterns.

use crate::bytes::{to_u64, u16_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::tracker::{
    Cell, Note, Pointers, SampleData, letter_effect, named, order_node, pcm_bytes, pointed,
    row_summary, schism_version,
};
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

/// The tracker named by the "Created with" field; Schism Tracker keeps
/// its full version in the first two reserved bytes after it.
fn tracker(cwtv: u16, reserved: &[u8]) -> String {
    if cwtv >> 12 == 4 && cwtv != 0x4100 {
        let extended = u16_le(reserved, 0).unwrap_or(0);
        return schism_version(cwtv, extended.into());
    }
    tracker_id(cwtv)
}

/// The tracker named by the "Created with" field alone.
fn tracker_id(cwtv: u16) -> String {
    if cwtv >> 12 == 4 && cwtv != 0x4100 {
        return if cwtv & 0x0fff == 0x0fff {
            "Schism Tracker (dated in the reserved bytes)".to_owned()
        } else {
            schism_version(cwtv, 0)
        };
    }
    let name = match cwtv >> 12 {
        1 => "Scream Tracker",
        2 => "Imago Orpheus",
        3 => "Impulse Tracker",
        4 => "BeRoTracker", // 0x4100; Schism Tracker is handled above
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
        tracker: u16 "Created with" .hex() .with(|&v, n| n.summary(tracker_id(v))),
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
        Some(|i| format!("{}, {} bytes, {} Hz", named(&i.name), i.length, i.c2spd)),
        Some(sample_data),
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
        tracker(h.tracker, &h._reserved2),
        used_channels(&h.channels),
        h.orders,
        h.patterns,
        h.instruments,
        named(&h.title)
    ));
    Ok(())
}

/// Where an instrument's sample data is: a 24-bit paragraph pointer and
/// a length in samples (doubled for 16-bit and for stereo, whose channels
/// are stored one after the other).
fn sample_data(i: &Instrument, file: Span) -> Option<SampleData> {
    if i.kind != 1 || i.length == 0 {
        return None;
    }
    let paragraph = (u64::from(i.memseg_high) << 16) | u64::from(i.memseg);
    let at = paragraph.saturating_mul(16);
    let sixteen = i.flags & 4 != 0;
    let stereo = i.flags & 2 != 0;
    let (len, coding) = if i.pack == 4 {
        // ModPlug ADPCM: a 16-byte table, then two samples per byte.
        (
            16u64.saturating_add(u64::from(i.length).div_ceil(2)),
            "ModPlug ADPCM".to_owned(),
        )
    } else {
        (
            pcm_bytes(i.length, sixteen, stereo),
            format!(
                "{}-bit PCM{}",
                if sixteen { 16 } else { 8 },
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
                .summary(format!("{len} bytes packed, 64 rows"))
                .lazy(rows, span),
        )
        .await;
    }
    Ok(())
}

/// A packed pattern: the length word (counting itself), then 64 rows of
/// entries, each a byte with the channel in bits 0-4 and flags for what
/// follows (0x20 note and instrument, 0x40 volume, 0x80 command and
/// parameter); a zero byte ends the row.
async fn rows(cx: Cx, span: Span) -> Result<()> {
    let packed = span.tail(2);
    let length = cx.read_avail(span.sub(0, 2)).await?;
    cx.emit(
        Node::new("Packed length")
            .span(span.sub(0, 2))
            .value(crate::formats::util::val::uint(
                u16_le(&length, 0).unwrap_or(0),
                16,
            ))
            .desc("Including these two bytes"),
    );
    let data = cx.read(packed).await?;
    let mut pos = 0usize;
    for r in 0..64u32 {
        if pos >= data.len() {
            cx.diag(Diagnostic::malformed(format!(
                "packed data ends after {r} of 64 rows"
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
            let mut take = |n: usize| {
                let got = data.get(pos..pos.saturating_add(n));
                pos = pos.saturating_add(n);
                got
            };
            let mut cell = Cell::EMPTY;
            if b & 0x20 != 0 {
                let Some(&[note, instrument]) = take(2) else {
                    break;
                };
                cell.note = match note {
                    255 => Note::None,
                    254 => Note::Cut,
                    n if n & 0x0f < 12 && n >> 4 < 10 => {
                        Note::Key((n >> 4).saturating_mul(12).saturating_add(n & 0x0f))
                    }
                    n => Note::Invalid(n),
                };
                cell.instrument = instrument;
            }
            if b & 0x40 != 0 {
                let Some(&[volume]) = take(1) else { break };
                cell.volume = Some(format!("v{volume:02}"));
            }
            if b & 0x80 != 0 {
                let Some(&[command, param]) = take(2) else {
                    break;
                };
                cell.effect = letter_effect(command, param);
            }
            cells.push((usize::from(b & 0x1f), cell));
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
