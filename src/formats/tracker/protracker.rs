//! ProTracker-style MOD files: a 20-byte title, 31 sample headers, the
//! order list, a format tag at offset 1080 (`M.K.`, `6CHN`, `FLT8`, ...),
//! then the patterns (64 rows of 4-byte cells per channel) and the sample
//! data.

use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::Result;
use crate::fields::Endian;
use crate::formats::tracker::{named, note_name, order_node};
use crate::formats::util::sound::{table, text};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;

const BE: Endian = Endian::Big;
const TAG_AT: usize = 1080;

pub static FORMAT: Format = Format {
    name: "mod",
    title: "ProTracker module",
    extensions: &["mod", "nst", "m15"],
    mime: "audio/x-mod",
    probe: Probe::Custom(|h| channels(h).is_some()),
    dissect: crate::expander!(dissect: Input),
};

/// The channel count implied by the format tag.
fn channels_for(tag: &[u8]) -> Option<u64> {
    let digit = |b: u8| {
        b.is_ascii_digit()
            .then(|| u64::from(b.saturating_sub(b'0')))
    };
    Some(match tag {
        b"M.K." | b"M!K!" | b"M&K!" | b"N.T." | b"FLT4" | b"4CHN" => 4,
        b"FLT8" | b"OKTA" | b"OCTA" | b"CD81" | b"FA08" => 8,
        b"FA04" => 4,
        b"FA06" => 6,
        [b'T', b'D', b'Z', n] => digit(*n)?,
        [n, b'C', b'H', b'N'] => digit(*n)?,
        [a, b, b'C', b'H' | b'N'] => digit(*a)?.saturating_mul(10).saturating_add(digit(*b)?),
        _ => return None,
    })
    .filter(|&n| (1..=32).contains(&n))
}

fn channels(h: &Head<'_>) -> Option<u64> {
    channels_for(h.data.get(TAG_AT..TAG_AT.saturating_add(4))?)
}

record! {
    pub struct Sample {
        name: ascii[22] "Name",
        length: u16 "Length" .desc("In 16-bit words") .with(|&l, n| n.summary(format!("{} bytes", u32::from(l).saturating_mul(2)))),
        finetune: u8 "Finetune" .with(|&f, n| n.summary(format!("{}", ((f & 0xf) as i8) << 4 >> 4))),
        volume: u8 "Volume" .desc("0–64"),
        repeat_start: u16 "Repeat start" .desc("In words"),
        repeat_length: u16 "Repeat length" .desc("In words; 1 = no loop"),
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 1084)).await?;
    let tag = head.get(TAG_AT..).unwrap_or_default();
    let channels = channels_for(tag).unwrap_or(4);
    let title = crate::text::until_nul(head.get(..20).unwrap_or_default());
    cx.emit(
        Node::new("Title")
            .span(file.sub(0, 20))
            .value(text(title.clone())),
    );
    let samples_span = file.sub(20, Sample::SIZE.saturating_mul(31));
    let mut lengths = Vec::new();
    let mut used = 0u32;
    for i in 0..31usize {
        let at = 20usize
            .saturating_add(i.saturating_mul(30))
            .saturating_add(22);
        let words = crate::bytes::u16_be(&head, at).unwrap_or(0);
        if words > 0 {
            used = used.saturating_add(1);
        }
        lengths.push(u64::from(words).saturating_mul(2));
    }
    cx.emit(
        table::<Sample>(
            "Samples",
            samples_span,
            BE,
            "Sample",
            Some(|s| {
                format!(
                    "{}, {} bytes",
                    named(&s.name),
                    u32::from(s.length).saturating_mul(2)
                )
            }),
        )
        .summary(format!("{used} of 31 used")),
    );
    let song_length = head.get(950).copied().unwrap_or(0);
    cx.emit(
        Node::new("Song length")
            .span(file.sub(950, 1))
            .value(crate::formats::util::sound::uint(song_length, 8)),
    );
    cx.emit(Node::new("Restart position").span(file.sub(951, 1)).value(
        crate::formats::util::sound::uint(head.get(951).copied().unwrap_or(0), 8),
    ));
    let order_span = file.sub(952, u64::from(song_length.min(128)));
    cx.emit(order_node(&cx, order_span).await?);
    cx.emit(
        Node::new("Format tag")
            .span(file.sub(1080, 4))
            .value(text(crate::formats::util::sound::fourcc(tag)))
            .summary(format!("{channels} channels")),
    );
    let all_orders = head.get(952..1080).unwrap_or_default();
    let patterns = u64::from(all_orders.iter().copied().max().unwrap_or(0)).saturating_add(1);
    let pattern_len = channels.saturating_mul(4).saturating_mul(64);
    let pspan = file.sub(1084, patterns.saturating_mul(pattern_len));
    cx.emit(
        Node::new("Patterns")
            .span(pspan)
            .summary(format!("{patterns} patterns"))
            .lazy(list_patterns, (pspan, channels, patterns)),
    );
    let mut at = pspan.end().saturating_sub(file.offset);
    let data_start = at;
    let mut data = Vec::new();
    for (i, len) in lengths.iter().enumerate() {
        if *len > 0 {
            data.push((i, file.sub(at, *len)));
        }
        at = at.saturating_add(*len);
    }
    cx.emit(
        Node::new("Sample data")
            .span(file.sub(data_start, at.saturating_sub(data_start)))
            .lazy(sample_data, data),
    );
    if at < file.len {
        cx.emit(Node::new("Trailing data").span(file.tail(at)));
    }
    cx.annotate(format!(
        "MOD ({}), {channels} channels, {} orders, {patterns} patterns, {used} samples — {}",
        crate::formats::util::sound::fourcc(tag),
        song_length,
        named(&title)
    ));
    Ok(())
}

async fn sample_data(cx: Cx, data: Vec<(usize, Span)>) -> Result<()> {
    for (i, span) in data {
        cx.push(
            Node::new(format!("Sample {}", i.saturating_add(1)))
                .span(span)
                .summary(format!("{} bytes", span.len)),
        )
        .await;
    }
    Ok(())
}

async fn list_patterns(cx: Cx, (span, channels, count): (Span, u64, u64)) -> Result<()> {
    cx.set_count(Count::Exact(count));
    let len = channels.saturating_mul(256);
    for i in 0..count {
        let p = span.sub(i.saturating_mul(len), len);
        if p.is_empty() {
            break;
        }
        cx.push(
            Node::new(format!("Pattern {i}"))
                .span(p)
                .summary("64 rows")
                .lazy(rows, (p, channels)),
        )
        .await;
    }
    Ok(())
}

/// Amiga periods for octaves 1–3 (C-1 = 856).
const PERIODS: [u16; 36] = [
    856, 808, 762, 720, 678, 640, 604, 570, 538, 508, 480, 453, 428, 404, 381, 360, 339, 320, 302,
    285, 269, 254, 240, 226, 214, 202, 190, 180, 170, 160, 151, 143, 135, 127, 120, 113,
];

fn period_note(period: u16) -> String {
    if period == 0 {
        return "---".to_owned();
    }
    let closest = PERIODS
        .iter()
        .enumerate()
        .min_by_key(|(_, p)| p.abs_diff(period))
        .map_or(0, |(i, _)| i);
    note_name(u8::try_from(closest.saturating_add(12)).unwrap_or(0))
}

async fn rows(cx: Cx, (span, channels): (Span, u64)) -> Result<()> {
    cx.set_count(Count::Exact(64));
    let row_len = channels.saturating_mul(4);
    for r in 0..64u64 {
        let row = span.sub(r.saturating_mul(row_len), row_len);
        let data = cx.read(row).await?;
        let cells: Vec<String> = data
            .chunks(4)
            .map(|c| {
                let b = |i: usize| c.get(i).copied().unwrap_or(0);
                let sample = (b(0) & 0xf0) | (b(2) >> 4);
                let period = (u16::from(b(0) & 0x0f) << 8) | u16::from(b(1));
                let effect = b(2) & 0x0f;
                let sample = if sample == 0 {
                    "..".to_owned()
                } else {
                    format!("{sample:02}")
                };
                let fx = if effect == 0 && b(3) == 0 {
                    "...".to_owned()
                } else {
                    format!("{effect:X}{:02X}", b(3))
                };
                format!("{} {sample} {fx}", period_note(period))
            })
            .collect();
        cx.push(
            Node::new(format!("Row {r:02}"))
                .span(row)
                .summary(cells.join(" | ")),
        )
        .await;
    }
    Ok(())
}
