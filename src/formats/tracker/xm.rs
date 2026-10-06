//! FastTracker 2 extended modules: `Extended Module: `, a header with the
//! order table, then patterns (header and packed data) and instruments
//! (header, sample headers, sample data), all stored back to back.

use crate::bytes::{u16_le, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::Result;
use crate::fields::{Endian, Fields, parse};
use crate::formats::util::sound::text;
use crate::formats::tracker::{named, note_name};
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, field, flag};

const LE: Endian = Endian::Little;

pub static FORMAT: Format = Format {
    name: "xm",
    title: "FastTracker 2 extended module",
    extensions: &["xm"],
    mime: "audio/x-xm",
    probe: Probe::Magic(&[(0, b"Extended Module: ")]),
    dissect: crate::expander!(dissect: Input),
};

const FLAGS: FlagTable = &[flag(0x1, "LINEAR_FREQUENCIES")];

const SAMPLE_TYPE: FlagTable = &[
    field(0x3, 0x1, "FORWARD_LOOP"),
    field(0x3, 0x2, "PING_PONG_LOOP"),
    flag(0x10, "16_BIT"),
    flag(0x20, "STEREO"),
];

const ENCODING: EnumTable = &[(0, "delta PCM"), (0xad, "ModPlug ADPCM")];

record! {
    pub struct Header {
        magic: ascii[17] "ID text",
        name: ascii[20] "Module name",
        eof: u8 "EOF marker" .hex(),
        tracker: ascii[20] "Tracker name",
        version: u16 "Version" .hex(),
        header_size: u32 "Header size" .desc("From this field to the first pattern"),
        song_length: u16 "Song length",
        restart: u16 "Restart position",
        channels: u16 "Channels",
        patterns: u16 "Patterns",
        instruments: u16 "Instruments",
        flags: u16 "Flags" .flags(FLAGS),
        tempo: u16 "Default tempo",
        bpm: u16 "Default BPM",
    }
}

record! {
    pub struct PatternHeader {
        length: u32 "Header length",
        packing: u8 "Packing type",
        rows: u16 "Rows",
        packed_size: u16 "Packed data size",
    }
}

record! {
    pub struct SampleHeader {
        length: u32 "Length",
        loop_start: u32 "Loop start",
        loop_length: u32 "Loop length",
        volume: u8 "Volume",
        finetune: i8 "Finetune",
        kind: u8 "Type" .flags(SAMPLE_TYPE),
        panning: u8 "Panning",
        relative_note: i8 "Relative note" .with(|&n, node| node.summary(format!("C-4 plays {}", note_name(u8::try_from(48i16.saturating_add(n.into()).clamp(0, 119)).unwrap_or(48))))),
        encoding: u8 "Encoding" .enumeration(ENCODING),
        name: ascii[22] "Name",
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let hspan = file.sub(0, Header::SIZE);
    let h = parse(&cx, hspan, LE, &(), Header::layout).await?;
    cx.emit(Header::node("Header", hspan, LE));
    let orders = file.sub(
        Header::SIZE,
        256.min(u64::from(h.header_size).saturating_sub(20)),
    );
    let list = cx.read_avail(orders).await?;
    cx.emit(
        Node::new("Orders")
            .span(orders)
            .summary(format!("{} used", h.song_length))
            .value(text(crate::formats::tracker::orders(
                list.get(..usize::from(h.song_length)).unwrap_or(&list),
            ))),
    );
    let first_pattern = 60u64.saturating_add(h.header_size.into());
    // Walk the pattern headers to find where the instruments start.
    let mut pos = first_pattern;
    let mut patterns = Vec::new();
    for i in 0..h.patterns {
        if pos >= file.len {
            break;
        }
        let head = cx.read_avail(file.sub(pos, 9)).await?;
        let header_len = u64::from(u32_le(&head, 0).unwrap_or(9)).max(9);
        let packed = u64::from(u16_le(&head, 7).unwrap_or(0));
        let rows = u16_le(&head, 5).unwrap_or(0);
        let span = file.sub(pos, header_len.saturating_add(packed));
        patterns.push((i, span, header_len, rows));
        pos = pos.saturating_add(header_len).saturating_add(packed);
        cx.checkpoint().await;
    }
    let pspan = file.sub(first_pattern, pos.saturating_sub(first_pattern));
    cx.emit(
        Node::new("Patterns")
            .span(pspan)
            .summary(format!("{} patterns", h.patterns))
            .lazy(list_patterns, patterns),
    );
    let ispan = file.tail(pos);
    cx.emit(
        Node::new("Instruments")
            .span(ispan)
            .summary(format!("{} instruments", h.instruments))
            .lazy(list_instruments, (ispan, h.instruments)),
    );
    cx.annotate(format!(
        "XM, {}, {} channels, {} orders, {} patterns, {} instruments, {} BPM — {}",
        h.tracker.trim(),
        h.channels,
        h.song_length,
        h.patterns,
        h.instruments,
        h.bpm,
        named(&h.name)
    ));
    Ok(())
}

async fn list_patterns(cx: Cx, patterns: Vec<(u16, Span, u64, u16)>) -> Result<()> {
    for (i, span, header_len, rows) in patterns {
        cx.push(
            Node::new(format!("Pattern {i}"))
                .span(span)
                .summary(format!(
                    "{rows} rows, {} bytes packed",
                    span.len.saturating_sub(header_len)
                ))
                .lazy(pattern, (span, header_len)),
        )
        .await;
    }
    Ok(())
}

async fn pattern(cx: Cx, (span, header_len): (Span, u64)) -> Result<()> {
    cx.emit(PatternHeader::node(
        "Header",
        span.sub(0, PatternHeader::SIZE),
        LE,
    ));
    let extra = span.sub(
        PatternHeader::SIZE,
        header_len.saturating_sub(PatternHeader::SIZE),
    );
    if !extra.is_empty() {
        cx.emit(Node::new("Extra header bytes").span(extra));
    }
    cx.emit(Node::new("Packed data").span(span.tail(header_len)));
    Ok(())
}

async fn list_instruments(cx: Cx, (region, count): (Span, u16)) -> Result<()> {
    let mut pos = 0u64;
    for i in 0..count {
        if pos >= region.len {
            break;
        }
        let head = cx.read_avail(region.sub(pos, 33)).await?;
        let size = u64::from(u32_le(&head, 0).unwrap_or(0));
        let name = crate::text::until_nul(head.get(4..26).unwrap_or_default());
        let samples = u16_le(&head, 27).unwrap_or(0);
        let shsize = if samples > 0 {
            u64::from(u32_le(&head, 29).unwrap_or(40))
        } else {
            40
        };
        let headers_end = pos
            .saturating_add(size.max(29))
            .saturating_add(shsize.saturating_mul(samples.into()));
        // Sample data follows all the sample headers.
        let mut data_len = 0u64;
        for s in 0..u64::from(samples) {
            let at = pos
                .saturating_add(size.max(29))
                .saturating_add(s.saturating_mul(shsize));
            if at >= region.len {
                break;
            }
            let len = cx.read_avail(region.sub(at, 4)).await?;
            data_len = data_len.saturating_add(u32_le(&len, 0).unwrap_or(0).into());
        }
        let span = region.sub(
            pos,
            headers_end.saturating_add(data_len).saturating_sub(pos),
        );
        let state = (span, size.max(29), samples, shsize);
        cx.push(
            Node::new(format!("Instrument {}", i.saturating_add(1)))
                .span(span)
                .summary(format!("{}, {samples} samples", named(&name)))
                .lazy(instrument, state),
        )
        .await;
        pos = headers_end.saturating_add(data_len);
    }
    Ok(())
}

async fn instrument(cx: Cx, (span, size, samples, shsize): (Span, u64, u16, u64)) -> Result<()> {
    let block = cx.block(span.sub(0, size)).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u32("Header size").emit()?;
    f.ascii("Name", 22).emit()?;
    f.u8("Type").emit()?;
    f.u16("Samples").emit()?;
    if samples > 0 {
        f.u32("Sample header size").emit()?;
        f.bytes("Note-to-sample map", 96).emit()?;
        f.bytes("Volume envelope", 48).emit()?;
        f.bytes("Panning envelope", 48).emit()?;
        f.u8("Volume points").emit()?;
        f.u8("Panning points").emit()?;
        f.u8("Volume sustain point").emit()?;
        f.u8("Volume loop start").emit()?;
        f.u8("Volume loop end").emit()?;
        f.u8("Panning sustain point").emit()?;
        f.u8("Panning loop start").emit()?;
        f.u8("Panning loop end").emit()?;
        f.u8("Volume type").flags(ENVELOPE).emit()?;
        f.u8("Panning type").flags(ENVELOPE).emit()?;
        f.u8("Vibrato type").emit()?;
        f.u8("Vibrato sweep").emit()?;
        f.u8("Vibrato depth").emit()?;
        f.u8("Vibrato rate").emit()?;
        f.u16("Volume fadeout").emit()?;
    }
    let mut data = span.tail(size.saturating_add(shsize.saturating_mul(samples.into())));
    for s in 0..u64::from(samples) {
        let at = size.saturating_add(s.saturating_mul(shsize));
        let hspan = span.sub(at, SampleHeader::SIZE);
        let h = parse(&cx, hspan, LE, &(), SampleHeader::layout).await;
        let mut node = SampleHeader::node(format!("Sample {}", s.saturating_add(1)), hspan, LE);
        match h {
            Ok(h) => {
                let bytes = u64::from(h.length);
                node = node.summary(format!(
                    "{}, {bytes} bytes{}",
                    named(&h.name),
                    if h.kind & 0x10 != 0 { ", 16-bit" } else { "" }
                ));
                cx.emit(node);
                cx.emit(
                    Node::new(format!("Sample {} data", s.saturating_add(1)))
                        .span(data.sub(0, bytes))
                        .desc("Delta-encoded PCM"),
                );
                data = data.tail(bytes);
            }
            Err(e) => {
                cx.emit(node.diag(e));
                break;
            }
        }
    }
    Ok(())
}

const ENVELOPE: FlagTable = &[flag(0x1, "ON"), flag(0x2, "SUSTAIN"), flag(0x4, "LOOP")];
