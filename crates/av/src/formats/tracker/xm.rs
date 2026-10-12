//! FastTracker 2 extended modules: `Extended Module: `, a header with the
//! order table, then patterns (header and packed data) and instruments
//! (header, sample headers, sample data), all stored back to back.
//!
//! Versions 1.02 and 1.03 (FT2 before 2.0x) store the instrument headers
//! first, then the patterns, then all sample data; 1.02 also has 8-byte
//! pattern headers with a one-byte row count minus one (libxmp's
//! `xm_load.c`).

use crate::bytes::{to_u64, u16_le, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::tracker::{Cell, Note, named, note_name, row_summary};
use crate::formats::util::val::text;
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

/// A pattern found by walking the pattern headers.
#[derive(Clone, Copy, Debug)]
struct Pattern {
    span: Span,
    header_len: u64,
    rows: u32,
    /// Version 1.02 header: one-byte row count.
    short: bool,
    channels: u32,
}

/// An instrument found by walking the instrument headers.
#[derive(Clone, Debug)]
struct Instrument {
    /// The instrument header and its sample headers.
    headers: Span,
    /// The instrument's sample data.
    data: Span,
    size: u64,
    samples: u16,
    shsize: u64,
    name: String,
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
    let first = 60u64.saturating_add(h.header_size.into());
    let old = h.version <= 0x0103;
    let short = h.version <= 0x0102;
    let instruments_node = |span: Span| {
        Node::new("Instruments")
            .span(span)
            .summary(format!("{} instruments", h.instruments))
    };
    // Old layout: instrument headers, then patterns, then sample data.
    let mut pos = first;
    let mut old_instruments = Vec::new();
    if old {
        for _ in 0..h.instruments {
            let Some((head, data_len)) = instrument_head(&cx, file, pos).await? else {
                break;
            };
            let headers = file.sub(pos, head.headers_len());
            old_instruments.push((headers, data_len, head));
            pos = pos.saturating_add(headers.len);
        }
    }
    let instruments_end = pos;
    let (patterns, patterns_end) =
        walk_patterns(&cx, file, pos, h.patterns, short, u32::from(h.channels)).await?;
    let pspan = file.sub(pos, patterns_end.saturating_sub(pos));
    if old {
        let mut data = patterns_end;
        let mut list = Vec::new();
        for (headers, data_len, head) in old_instruments {
            list.push(Instrument {
                headers,
                data: file.sub(data, data_len),
                size: head.size,
                samples: head.samples,
                shsize: head.shsize,
                name: head.name,
            });
            data = data.saturating_add(data_len);
        }
        let ispan = file.sub(first, instruments_end.saturating_sub(first));
        cx.emit(instruments_node(ispan).lazy(list_known, list));
        cx.emit(patterns_node(pspan, h.patterns, patterns));
        let sspan = file.sub(patterns_end, data.saturating_sub(patterns_end));
        cx.emit(
            Node::new("Sample data")
                .span(sspan)
                .desc("All instruments' samples, in order (shown under each instrument)"),
        );
    } else {
        cx.emit(patterns_node(pspan, h.patterns, patterns));
        let ispan = file.tail(patterns_end);
        cx.emit(instruments_node(ispan).lazy(list_instruments, (ispan, h.instruments)));
    }
    cx.annotate(format!(
        "XM {}.{:02}, {}, {} channels, {} orders, {} patterns, {} instruments, {} BPM — {}",
        h.version >> 8,
        h.version & 0xff,
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

fn patterns_node(span: Span, count: u16, patterns: Vec<Pattern>) -> Node {
    Node::new("Patterns")
        .span(span)
        .summary(format!("{count} patterns"))
        .lazy(list_patterns, patterns)
}

/// Walks `count` pattern headers from `pos`; returns them and where the
/// last one ends.
async fn walk_patterns(
    cx: &Cx,
    file: Span,
    mut pos: u64,
    count: u16,
    short: bool,
    channels: u32,
) -> Result<(Vec<Pattern>, u64)> {
    let fixed = if short { 8 } else { 9 };
    let mut patterns = Vec::new();
    for _ in 0..count {
        if pos >= file.len {
            break;
        }
        let head = cx.read_avail(file.sub(pos, fixed)).await?;
        let header_len = u64::from(u32_le(&head, 0).unwrap_or(0)).max(fixed);
        let (rows, packed) = if short {
            (
                u32::from(head.get(5).copied().unwrap_or(0)).saturating_add(1),
                u16_le(&head, 6).unwrap_or(0),
            )
        } else {
            let rows = u16_le(&head, 5).unwrap_or(0);
            // Zero rows means 256 (libxmp).
            (
                if rows == 0 { 256 } else { u32::from(rows) },
                u16_le(&head, 7).unwrap_or(0),
            )
        };
        let span = file.sub(pos, header_len.saturating_add(packed.into()));
        patterns.push(Pattern {
            span,
            header_len,
            rows,
            short,
            channels,
        });
        pos = pos.saturating_add(header_len).saturating_add(packed.into());
        cx.checkpoint().await;
    }
    Ok((patterns, pos))
}

async fn list_patterns(cx: Cx, patterns: Vec<Pattern>) -> Result<()> {
    for (i, p) in patterns.into_iter().enumerate() {
        let packed = p.span.len.saturating_sub(p.header_len);
        cx.push(
            Node::new(format!("Pattern {i}"))
                .span(p.span)
                .summary(if packed == 0 {
                    format!("{} rows, empty", p.rows)
                } else {
                    format!("{} rows, {packed} bytes packed", p.rows)
                })
                .lazy(pattern, p),
        )
        .await;
    }
    Ok(())
}

fn pattern_header(f: &mut Fields<'_>, short: &bool) -> Result<()> {
    f.u32("Header length").emit()?;
    f.u8("Packing type").emit()?;
    if *short {
        f.u8("Rows")
            .desc("Stored minus one (version 1.02)")
            .emit()?;
    } else {
        f.u16("Rows").emit()?;
    }
    f.u16("Packed data size").emit()?;
    Ok(())
}

/// XM note column: 1 = C-0 to 96 = B-7, 97 = key off.
fn xm_note(n: u8) -> Note {
    match n {
        0 => Note::None,
        1..=96 => Note::Key(n.saturating_sub(1)),
        97 => Note::Off,
        n => Note::Invalid(n),
    }
}

/// XM volume column: 0x10-0x50 volume 0-64, then by high nibble volume
/// slide down/up (-/+), fine down/up (d/u), vibrato speed/depth (S/V),
/// panning (P), panning slide left/right (L/R) and portamento (M).
fn xm_volume(v: u8) -> Option<String> {
    let kind = match v >> 4 {
        0 => return (v != 0).then(|| format!("?{v:02X}")),
        1..=4 => return Some(format!("v{:02}", v.saturating_sub(0x10))),
        5 if v == 0x50 => return Some("v64".to_owned()),
        6 => '-',
        7 => '+',
        8 => 'd',
        9 => 'u',
        0xa => 'S',
        0xb => 'V',
        0xc => 'P',
        0xd => 'L',
        0xe => 'R',
        0xf => 'M',
        _ => return Some(format!("?{v:02X}")),
    };
    Some(format!("{kind}{:02}", v & 0x0f))
}

/// XM effect column: types 0-9 and A-Z (10-35) with a hex parameter.
fn xm_effect(kind: u8, param: u8) -> Option<String> {
    if kind == 0 && param == 0 {
        return None;
    }
    let letter = match kind {
        0..=9 => char::from(b'0'.saturating_add(kind)),
        10..=35 => char::from(b'A'.saturating_add(kind.saturating_sub(10))),
        _ => '?',
    };
    Some(format!("{letter}{param:02X}"))
}

/// A pattern's header and rows. Each cell is either five bytes (note,
/// instrument, volume, effect type, parameter) or, when the first byte
/// has bit 7 set, that byte's bits 0-4 say which of the five follow.
async fn pattern(cx: Cx, p: Pattern) -> Result<()> {
    let fixed = if p.short { 8 } else { 9 };
    cx.emit(struct_node(
        "Header",
        p.span.sub(0, fixed),
        LE,
        p.short,
        pattern_header,
    ));
    let extra = p.span.sub(fixed, p.header_len.saturating_sub(fixed));
    if !extra.is_empty() {
        cx.emit(Node::new("Extra header bytes").span(extra));
    }
    let packed = p.span.tail(p.header_len);
    if packed.is_empty() {
        return Ok(());
    }
    let data = cx.read(packed).await?;
    let mut pos = 0usize;
    for r in 0..p.rows {
        if pos >= data.len() {
            cx.diag(Diagnostic::malformed(format!(
                "packed data ends after {r} of {} rows",
                p.rows
            )));
            return Ok(());
        }
        let start = pos;
        let mut cells = Vec::new();
        let mut complete = true;
        for ch in 0..p.channels {
            let Some(&b) = data.get(pos) else {
                complete = false;
                break;
            };
            let mut fields = [0u8; 5];
            if b & 0x80 != 0 {
                pos = pos.saturating_add(1);
                for (bit, slot) in fields.iter_mut().enumerate() {
                    if b & (1 << bit) != 0 {
                        let Some(&v) = data.get(pos) else {
                            complete = false;
                            break;
                        };
                        *slot = v;
                        pos = pos.saturating_add(1);
                    }
                }
            } else if let Some(all) = data.get(pos..pos.saturating_add(5)) {
                fields.copy_from_slice(all);
                pos = pos.saturating_add(5);
            } else {
                complete = false;
            }
            if !complete {
                break;
            }
            let [note, instrument, volume, kind, param] = fields;
            cells.push((
                usize::try_from(ch).unwrap_or(usize::MAX),
                Cell {
                    note: xm_note(note),
                    instrument,
                    volume: xm_volume(volume),
                    effect: xm_effect(kind, param),
                },
            ));
        }
        let end = pos.min(data.len());
        let mut node = Node::new(format!("Row {r:02}"))
            .span(packed.sub(to_u64(start), to_u64(end.saturating_sub(start))))
            .summary(row_summary(&cells));
        if !complete {
            node = node.diag(Diagnostic::malformed("row ends inside a cell"));
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

/// An instrument header's sizes, read with its sample headers' lengths.
struct InstrumentHead {
    size: u64,
    samples: u16,
    shsize: u64,
    name: String,
}

impl InstrumentHead {
    /// The instrument header and its sample headers.
    fn headers_len(&self) -> u64 {
        self.size
            .saturating_add(self.shsize.saturating_mul(self.samples.into()))
    }
}

/// Reads the instrument header at `pos` and the lengths in its sample
/// headers; returns it and the bytes of sample data it owns (ModPlug
/// ADPCM samples take a 16-byte table and half a byte per sample).
async fn instrument_head(cx: &Cx, region: Span, pos: u64) -> Result<Option<(InstrumentHead, u64)>> {
    if pos >= region.len {
        return Ok(None);
    }
    let head = cx.read_avail(region.sub(pos, 33)).await?;
    let size = u64::from(u32_le(&head, 0).unwrap_or(0)).max(29);
    let name = crate::text::until_nul(head.get(4..26).unwrap_or_default());
    let samples = u16_le(&head, 27).unwrap_or(0);
    let shsize = if samples > 0 {
        u64::from(u32_le(&head, 29).unwrap_or(40))
    } else {
        40
    };
    let mut data_len = 0u64;
    for s in 0..u64::from(samples) {
        let at = pos
            .saturating_add(size)
            .saturating_add(s.saturating_mul(shsize));
        if at >= region.len {
            break;
        }
        let sh = cx.read_avail(region.sub(at, 18)).await?;
        let len = u64::from(u32_le(&sh, 0).unwrap_or(0));
        let bytes = if sh.get(17) == Some(&0xad) {
            16u64.saturating_add(len.div_ceil(2))
        } else {
            len
        };
        data_len = data_len.saturating_add(bytes);
    }
    Ok(Some((
        InstrumentHead {
            size,
            samples,
            shsize,
            name,
        },
        data_len,
    )))
}

fn instrument_node(index: u16, i: Instrument) -> Node {
    // Version 1.04 keeps the data right after the headers; older versions
    // keep it after the patterns.
    let span = if i.data.source == i.headers.source && i.data.offset == i.headers.end() {
        Span {
            len: i.headers.len.saturating_add(i.data.len),
            ..i.headers
        }
    } else {
        i.headers
    };
    Node::new(format!("Instrument {}", index.saturating_add(1)))
        .span(span)
        .summary(format!("{}, {} samples", named(&i.name), i.samples))
        .lazy(instrument, i)
}

/// Instruments stored with their sample data (version 1.04).
async fn list_instruments(cx: Cx, (region, count): (Span, u16)) -> Result<()> {
    let mut pos = 0u64;
    for i in 0..count {
        let Some((head, data_len)) = instrument_head(&cx, region, pos).await? else {
            break;
        };
        let headers = region.sub(pos, head.headers_len());
        let data = region.sub(pos.saturating_add(head.headers_len()), data_len);
        pos = pos
            .saturating_add(head.headers_len())
            .saturating_add(data_len);
        let entry = Instrument {
            headers,
            data,
            size: head.size,
            samples: head.samples,
            shsize: head.shsize,
            name: head.name,
        };
        cx.push(instrument_node(i, entry)).await;
    }
    Ok(())
}

/// Instruments already walked (versions 1.02 and 1.03).
async fn list_known(cx: Cx, list: Vec<Instrument>) -> Result<()> {
    for (i, entry) in list.into_iter().enumerate() {
        cx.push(instrument_node(u16::try_from(i).unwrap_or(u16::MAX), entry))
            .await;
    }
    Ok(())
}

async fn instrument(cx: Cx, i: Instrument) -> Result<()> {
    let Instrument {
        headers,
        data,
        size,
        samples,
        shsize,
        ..
    } = i;
    let block = cx.block(headers.sub(0, size)).await?;
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
    let mut rest = data;
    for s in 0..u64::from(samples) {
        let at = size.saturating_add(s.saturating_mul(shsize));
        let hspan = headers.sub(at, SampleHeader::SIZE);
        let h = parse(&cx, hspan, LE, &(), SampleHeader::layout).await;
        let mut node = SampleHeader::node(format!("Sample {}", s.saturating_add(1)), hspan, LE);
        match h {
            Ok(h) => {
                let adpcm = h.encoding == 0xad;
                let bytes = if adpcm {
                    16u64.saturating_add(u64::from(h.length).div_ceil(2))
                } else {
                    u64::from(h.length)
                };
                node = node.summary(format!(
                    "{}, {} bytes{}",
                    named(&h.name),
                    h.length,
                    if h.kind & 0x10 != 0 { ", 16-bit" } else { "" }
                ));
                cx.emit(node);
                cx.emit(
                    Node::new(format!("Sample {} data", s.saturating_add(1)))
                        .span(rest.sub(0, bytes))
                        .desc(if adpcm {
                            "ModPlug ADPCM: a 16-byte delta table, then two samples per byte"
                        } else {
                            "Delta-encoded PCM"
                        }),
                );
                rest = rest.tail(bytes);
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
