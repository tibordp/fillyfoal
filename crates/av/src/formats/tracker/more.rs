//! Less common tracker modules: MultiTracker (MTM), Scream Tracker 2
//! (STM), Composer 669, UltraTracker (ULT), OctaMED (MMD0–MMD3) and
//! Oktalyzer (OKT).

use crate::bytes::{u16_be, u32_be};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::Result;
use crate::fields::{Endian, parse};
use crate::formats::tracker::{named, order_node};
use crate::formats::util::sound::{fourcc, peek_text, table};
use crate::formats::util::val::{text, uint};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::FlagTable;

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// MTM

pub static MTM: Format = Format {
    name: "mtm",
    title: "MultiTracker module",
    extensions: &["mtm"],
    mime: "audio/x-mtm",
    probe: Probe::Custom(|h| h.starts_with(b"MTM") && h.data.get(3).is_some_and(|v| *v == 0x10)),
    dissect: crate::expander!(mtm: Input),
};

record! {
    pub struct MtmHeader {
        magic: ascii[3] "Magic",
        version: u8 "Version" .hex(),
        name: ascii[20] "Song name",
        tracks: u16 "Tracks",
        last_pattern: u8 "Last pattern",
        last_order: u8 "Last order",
        comment_length: u16 "Comment length",
        samples: u8 "Samples",
        attributes: u8 "Attributes",
        beats: u8 "Beats per track",
        channels: u8 "Channels",
        pan: bytes[32] "Pan positions",
    }
}

record! {
    pub struct MtmSample {
        name: ascii[22] "Name",
        length: u32 "Length",
        loop_start: u32 "Loop start",
        loop_end: u32 "Loop end",
        finetune: i8 "Finetune",
        volume: u8 "Volume",
        attributes: u8 "Attributes" .desc("Bit 0: 16-bit samples"),
    }
}

pub async fn mtm(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h = parse(
        &cx,
        file.sub(0, MtmHeader::SIZE),
        LE,
        &(),
        MtmHeader::layout,
    )
    .await?;
    cx.emit(MtmHeader::node("Header", file.sub(0, MtmHeader::SIZE), LE));
    let mut at = MtmHeader::SIZE;
    let samples = file.sub(at, u64::from(h.samples).saturating_mul(MtmSample::SIZE));
    cx.emit(table::<MtmSample>(
        "Samples",
        samples,
        LE,
        "Sample",
        Some(|s| format!("{}, {} bytes", named(&s.name), s.length)),
    ));
    at = at.saturating_add(samples.len);
    cx.emit(order_node(&cx, file.sub(at, u64::from(h.last_order).saturating_add(1))).await?);
    at = at.saturating_add(128);
    let tracks = file.sub(at, u64::from(h.tracks).saturating_mul(192));
    cx.emit(
        Node::new("Tracks")
            .span(tracks)
            .summary(format!("{} tracks of 64 rows", h.tracks)),
    );
    at = at.saturating_add(tracks.len);
    let seq = file.sub(
        at,
        u64::from(h.last_pattern)
            .saturating_add(1)
            .saturating_mul(64),
    );
    cx.emit(Node::new("Pattern track sequences").span(seq));
    at = at.saturating_add(seq.len);
    if h.comment_length > 0 {
        let span = file.sub(at, h.comment_length.into());
        let t = peek_text(&cx, span, span.len).await?;
        cx.emit(Node::new("Comment").span(span).value(text(t)));
        at = at.saturating_add(span.len);
    }
    cx.emit(Node::new("Sample data").span(file.tail(at)));
    cx.annotate(format!(
        "MTM {}.{}, {} channels, {} patterns, {} samples — {}",
        h.version >> 4,
        h.version & 0xf,
        h.channels,
        u16::from(h.last_pattern).saturating_add(1),
        h.samples,
        named(&h.name)
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// STM

pub static STM: Format = Format {
    name: "stm",
    title: "Scream Tracker 2 module",
    extensions: &["stm"],
    mime: "audio/x-stm",
    probe: Probe::Custom(|h| {
        (h.at(20, b"!Scream!") || h.at(20, b"BMOD2STM") || h.at(20, b"WUZAMOD!"))
            && h.at(28, b"\x1a\x02")
    }),
    dissect: crate::expander!(stm: Input),
};

record! {
    pub struct StmHeader {
        name: ascii[20] "Song name",
        tracker: ascii[8] "Tracker",
        eof: u8 "EOF marker" .hex(),
        kind: u8 "Type" .desc("2 = module"),
        major: u8 "Version (major)",
        minor: u8 "Version (minor)",
        tempo: u8 "Tempo",
        patterns: u8 "Patterns",
        volume: u8 "Global volume",
        _reserved: bytes[13] "Reserved",
    }
}

record! {
    pub struct StmSample {
        filename: ascii[12] "File name",
        _zero: u8 "Reserved",
        disk: u8 "Instrument disk",
        offset: u16 "Data offset" .desc("In 16-byte paragraphs"),
        length: u16 "Length",
        loop_start: u16 "Loop start",
        loop_end: u16 "Loop end",
        volume: u8 "Volume",
        _reserved: u8 "Reserved",
        c3: u16 "C-3 speed",
        _reserved2: bytes[6] "Reserved",
    }
}

pub async fn stm(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h = parse(
        &cx,
        file.sub(0, StmHeader::SIZE),
        LE,
        &(),
        StmHeader::layout,
    )
    .await?;
    cx.emit(StmHeader::node("Header", file.sub(0, StmHeader::SIZE), LE));
    let samples = file.sub(StmHeader::SIZE, StmSample::SIZE.saturating_mul(31));
    cx.emit(table::<StmSample>(
        "Samples",
        samples,
        LE,
        "Sample",
        Some(|s| format!("{}, {} bytes", named(&s.filename), s.length)),
    ));
    let order_len = if h.minor >= 21 || h.major > 2 {
        128
    } else {
        64
    };
    let order_at = samples.end().saturating_sub(file.offset);
    // Orders end at the first 99.
    let list = cx.read_avail(file.sub(order_at, order_len)).await?;
    let used = list.iter().position(|&o| o == 99).unwrap_or(list.len());
    cx.emit(
        order_node(&cx, file.sub(order_at, crate::bytes::to_u64(used)))
            .await?
            .span(file.sub(order_at, order_len)),
    );
    let patterns = file.sub(
        order_at.saturating_add(order_len),
        u64::from(h.patterns).saturating_mul(1024),
    );
    cx.emit(
        Node::new("Patterns")
            .span(patterns)
            .summary(format!("{} patterns of 64 rows × 4 channels", h.patterns)),
    );
    cx.emit(Node::new("Sample data").span(file.tail(patterns.end().saturating_sub(file.offset))));
    cx.annotate(format!(
        "STM {}.{:02} ({}), {} patterns — {}",
        h.major,
        h.minor,
        h.tracker.trim(),
        h.patterns,
        named(&h.name)
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Composer 669

pub static COMPOSER669: Format = Format {
    name: "669",
    title: "Composer 669 module",
    extensions: &["669"],
    mime: "audio/x-669",
    probe: Probe::Custom(probe_669),
    dissect: crate::expander!(composer669: Input),
};

fn probe_669(h: &Head<'_>) -> bool {
    let (Some(&samples), Some(&patterns), Some(&loop_order)) =
        (h.data.get(0x6e), h.data.get(0x6f), h.data.get(0x70))
    else {
        return false;
    };
    let size = 0x1f1u64
        .saturating_add(u64::from(samples).saturating_mul(25))
        .saturating_add(u64::from(patterns).saturating_mul(1536));
    (h.starts_with(b"if") || h.starts_with(b"JN"))
        && samples <= 64
        && (1..=128).contains(&patterns)
        && loop_order < 128
        && size <= h.len
        // Tempos are 0..=15 and breaks below 64.
        && h.data.get(0xf1..0x171).is_some_and(|t| t.iter().all(|&v| v < 16))
        && h.data.get(0x171..0x1f1).is_some_and(|b| b.iter().all(|&v| v < 64))
}

record! {
    pub struct Sample669 {
        filename: ascii[13] "File name",
        length: u32 "Length",
        loop_start: u32 "Loop start",
        loop_end: u32 "Loop end",
    }
}

pub async fn composer669(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 0x71)).await?;
    let samples = head.get(0x6e).copied().unwrap_or(0);
    let patterns = head.get(0x6f).copied().unwrap_or(0);
    cx.emit(
        Node::new("Magic")
            .span(file.sub(0, 2))
            .value(text(fourcc(head.get(..2).unwrap_or_default()))),
    );
    let message = file.sub(2, 108);
    let t = peek_text(&cx, message, 108).await?;
    cx.emit(Node::new("Message").span(message).value(text(t.clone())));
    for (name, at, v) in [("Samples", 0x6e, samples), ("Patterns", 0x6f, patterns)] {
        cx.emit(Node::new(name).span(file.sub(at, 1)).value(uint(v, 8)));
    }
    cx.emit(
        Node::new("Loop order")
            .span(file.sub(0x70, 1))
            .value(uint(head.get(0x70).copied().unwrap_or(0), 8)),
    );
    cx.emit(order_node(&cx, file.sub(0x71, 128)).await?);
    cx.emit(Node::new("Tempo list").span(file.sub(0xf1, 128)));
    cx.emit(Node::new("Break list").span(file.sub(0x171, 128)));
    let sspan = file.sub(0x1f1, u64::from(samples).saturating_mul(Sample669::SIZE));
    cx.emit(table::<Sample669>(
        "Samples",
        sspan,
        LE,
        "Sample",
        Some(|s| format!("{}, {} bytes", named(&s.filename), s.length)),
    ));
    let pspan = file.sub(
        sspan.end().saturating_sub(file.offset),
        u64::from(patterns).saturating_mul(1536),
    );
    cx.emit(
        Node::new("Patterns")
            .span(pspan)
            .summary(format!("{patterns} patterns of 64 rows × 8 channels")),
    );
    cx.emit(Node::new("Sample data").span(file.tail(pspan.end().saturating_sub(file.offset))));
    cx.annotate(format!(
        "669, 8 channels, {patterns} patterns, {samples} samples — {}",
        crate::formats::util::sound::clip(&t, 36)
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// UltraTracker

pub static ULT: Format = Format {
    name: "ult",
    title: "UltraTracker module",
    extensions: &["ult"],
    mime: "audio/x-ult",
    probe: Probe::Magic(&[(0, b"MAS_UTrack_V00")]),
    dissect: crate::expander!(ult: Input),
};

const ULT_FLAGS: FlagTable = &[
    crate::value::flag(0x4, "16_BIT"),
    crate::value::flag(0x8, "LOOP"),
    crate::value::flag(0x10, "BIDIRECTIONAL"),
];

record! {
    pub struct UltSample {
        name: ascii[32] "Name",
        filename: ascii[12] "File name",
        loop_start: u32 "Loop start",
        loop_end: u32 "Loop end",
        size_start: u32 "Size start",
        size_end: u32 "Size end",
        volume: u8 "Volume",
        flags: u8 "Flags" .flags(ULT_FLAGS),
        finetune: i16 "Finetune",
    }
}

pub async fn ult(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 48)).await?;
    let version = head.get(14).copied().unwrap_or(b'1');
    cx.emit(
        Node::new("Magic")
            .span(file.sub(0, 15))
            .value(text(String::from_utf8_lossy(
                head.get(..15).unwrap_or_default(),
            ))),
    );
    let title = crate::text::until_nul(head.get(15..47).unwrap_or_default());
    cx.emit(
        Node::new("Title")
            .span(file.sub(15, 32))
            .value(text(title.clone())),
    );
    let text_len = u64::from(head.get(47).copied().unwrap_or(0)).saturating_mul(32);
    let mut at = 48u64;
    if text_len > 0 {
        let span = file.sub(at, text_len);
        let t = peek_text(&cx, span, span.len).await?;
        cx.emit(Node::new("Text").span(span).value(text(t)));
        at = at.saturating_add(text_len);
    }
    let count = cx
        .read(file.sub(at, 1))
        .await?
        .first()
        .copied()
        .unwrap_or(0);
    at = at.saturating_add(1);
    let record = if version >= b'4' { 66 } else { 64 };
    let samples = file.sub(at, u64::from(count).saturating_mul(record));
    cx.emit(
        Node::new("Samples")
            .span(samples)
            .summary(format!("{count} samples"))
            .lazy(ult_samples, (samples, record)),
    );
    at = at.saturating_add(samples.len);
    cx.emit(order_node(&cx, file.sub(at, 256)).await?);
    at = at.saturating_add(256);
    let counts = cx.read_avail(file.sub(at, 2)).await?;
    let channels = u16::from(counts.first().copied().unwrap_or(0)).saturating_add(1);
    let patterns = u16::from(counts.get(1).copied().unwrap_or(0)).saturating_add(1);
    cx.emit(
        Node::new("Channels − 1")
            .span(file.sub(at, 1))
            .value(uint(channels.saturating_sub(1), 8)),
    );
    cx.emit(
        Node::new("Patterns − 1")
            .span(file.sub(at.saturating_add(1), 1))
            .value(uint(patterns.saturating_sub(1), 8)),
    );
    at = at.saturating_add(2);
    if version >= b'3' {
        cx.emit(Node::new("Pan positions").span(file.sub(at, channels.into())));
        at = at.saturating_add(channels.into());
    }
    cx.emit(Node::new("Pattern and sample data").span(file.tail(at)));
    cx.annotate(format!(
        "ULT v{}, {channels} channels, {patterns} patterns, {count} samples — {}",
        char::from(version),
        named(&title)
    ));
    Ok(())
}

async fn ult_samples(cx: Cx, (span, record): (Span, u64)) -> Result<()> {
    let mut at = 0u64;
    let mut i = 0u32;
    while span.len.saturating_sub(at) >= UltSample::SIZE {
        let s = span.sub(at, record);
        let r = parse(&cx, s.sub(0, UltSample::SIZE), LE, &(), UltSample::layout).await?;
        i = i.saturating_add(1);
        cx.push(
            UltSample::node(format!("Sample {i}"), s.sub(0, UltSample::SIZE), LE)
                .summary(named(&r.name)),
        )
        .await;
        at = at.saturating_add(record);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// OctaMED

pub static MED: Format = Format {
    name: "med",
    title: "OctaMED module",
    extensions: &["med", "mmd0", "mmd1", "mmd2", "mmd3"],
    mime: "audio/x-med",
    probe: Probe::Custom(|h| {
        matches!(h.data.get(..4), Some(b"MMD0" | b"MMD1" | b"MMD2" | b"MMD3"))
            && u32_be(h.data, 8).is_some_and(|p| p >= 52 && u64::from(p) < h.len)
    }),
    dissect: crate::expander!(med: Input),
};

record! {
    pub struct MedHeader {
        id: ascii[4] "ID",
        length: u32 "Module length",
        song: u32 "Song offset" .hex(),
        _reserved0: u32 "Reserved",
        blocks: u32 "Block array offset" .hex(),
        _reserved1: u32 "Reserved",
        samples: u32 "Sample array offset" .hex(),
        _reserved2: u32 "Reserved",
        expansion: u32 "Expansion data offset" .hex(),
        _reserved3: u32 "Reserved",
        pstate: u16 "Player state",
        pblock: u16 "Playing block",
        pline: u16 "Playing line",
        pseqnum: u16 "Playing sequence",
        actplayline: i16 "Active play line",
        counter: u8 "Counter",
        extra_songs: u8 "Extra songs",
    }
}

record! {
    /// The part of MMD0song after the 63 instrument entries.
    pub struct MedSong {
        blocks: u16 "Blocks",
        length: u16 "Song length",
        sequence: bytes[256] "Play sequence",
        tempo: u16 "Default tempo",
        transpose: i8 "Transpose",
        flags: u8 "Flags" .hex(),
        flags2: u8 "Flags 2" .hex(),
        tempo2: u8 "Ticks per line",
        track_volumes: bytes[16] "Track volumes",
        master_volume: u8 "Master volume",
        samples: u8 "Samples",
    }
}

pub async fn med(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h = parse(
        &cx,
        file.sub(0, MedHeader::SIZE),
        BE,
        &(),
        MedHeader::layout,
    )
    .await?;
    cx.emit(MedHeader::node("Header", file.sub(0, MedHeader::SIZE), BE));
    let song_at = u64::from(h.song);
    cx.emit(
        Node::new("Instruments")
            .span(file.sub(song_at, 63 * 8))
            .summary("63 entries"),
    );
    let sspan = file.sub(song_at.saturating_add(63 * 8), MedSong::SIZE);
    let song = parse(&cx, sspan, BE, &(), MedSong::layout).await?;
    cx.emit(MedSong::node("Song", sspan, BE));
    let mut name = String::new();
    if h.expansion != 0 {
        let exp = cx.read_avail(file.sub(h.expansion.into(), 52)).await?;
        if let (Some(at), Some(len)) = (u32_be(&exp, 44), u32_be(&exp, 48))
            && at != 0
        {
            let span = file.sub(at.into(), u64::from(len).min(256));
            name = peek_text(&cx, span, span.len).await?;
            cx.emit(Node::new("Song name").span(span).value(text(name.clone())));
        }
    }
    cx.annotate(format!(
        "OctaMED ({}), {} blocks, {} samples — {}",
        h.id,
        song.blocks,
        song.samples,
        named(&name)
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Oktalyzer

pub static OKT: Format = Format {
    name: "okt",
    title: "Oktalyzer module",
    extensions: &["okt", "okta"],
    mime: "audio/x-okt",
    probe: Probe::Magic(&[(0, b"OKTASONGCMOD")]),
    dissect: crate::expander!(okt: Input),
};

record! {
    pub struct OktSample {
        name: ascii[20] "Name",
        length: u32 "Length",
        repeat_start: u16 "Repeat start" .desc("In words"),
        repeat_length: u16 "Repeat length" .desc("In words"),
        _pad: u8 "Pad",
        volume: u8 "Volume",
        mode: u16 "Mode" .enumeration(&[(0, "8-bit"), (1, "7-bit"), (2, "both")]),
    }
}

pub async fn okt(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(
        Node::new("Magic")
            .span(file.sub(0, 8))
            .value(text("OKTASONG")),
    );
    let mut pos = 8u64;
    let (mut patterns, mut samples, mut channels) = (0u32, 0u32, 0u32);
    while file.len.saturating_sub(pos) >= 8 {
        let h = cx.read(file.sub(pos, 8)).await?;
        let id: [u8; 4] = crate::bytes::array(&h, 0).unwrap_or_default();
        let size = u64::from(u32_be(&h, 4).unwrap_or(0));
        let span = file.sub(pos, size.saturating_add(8));
        let data = span.tail(8);
        let mut node = Node::new(fourcc(&id))
            .span(span)
            .summary(format!("{size} bytes"));
        match &id {
            b"CMOD" => {
                let v = cx.read_avail(data.sub(0, 8)).await?;
                channels = v
                    .chunks(2)
                    .map(|c| {
                        if c.get(1).is_some_and(|b| *b != 0) {
                            2
                        } else {
                            1
                        }
                    })
                    .sum();
                node = node
                    .summary(format!("{channels} channels"))
                    .lazy(okt_words, data);
            }
            b"SAMP" => {
                node = table::<OktSample>(
                    "SAMP",
                    data,
                    BE,
                    "Sample",
                    Some(|s| format!("{}, {} bytes", named(&s.name), s.length)),
                )
                .span(span)
                .desc("Sample headers");
            }
            b"SPEE" | b"SLEN" | b"PLEN" => {
                let v = cx.read_avail(data.sub(0, 2)).await?;
                let v = u16_be(&v, 0).unwrap_or(0);
                node = node.value(uint(v, 16)).desc(match &id {
                    b"SPEE" => "Initial speed",
                    b"SLEN" => "Number of patterns",
                    _ => "Song length",
                });
            }
            b"PATT" => node = order_node(&cx, data).await?.span(span),
            b"PBOD" => {
                patterns = patterns.saturating_add(1);
                let rows = cx.read_avail(data.sub(0, 2)).await?;
                node = node.summary(format!(
                    "pattern {}, {} rows",
                    patterns.saturating_sub(1),
                    u16_be(&rows, 0).unwrap_or(0)
                ));
            }
            b"SBOD" => {
                samples = samples.saturating_add(1);
                node = node.summary(format!("sample data, {size} bytes"));
            }
            _ => {}
        }
        cx.push(node).await;
        pos = pos.saturating_add(size).saturating_add(8);
    }
    cx.annotate(format!(
        "Oktalyzer, {channels} channels, {patterns} patterns, {samples} samples"
    ));
    Ok(())
}

async fn okt_words(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = crate::fields::Fields::emitting(&cx, &block, BE);
    while f.remaining() >= 2 {
        f.u16("Channel pair")
            .desc("1 = split into two channels")
            .emit()?;
    }
    Ok(())
}
