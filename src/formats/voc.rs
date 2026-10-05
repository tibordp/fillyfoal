//! Creative Voice files: a 26-byte header, then typed blocks (sound data,
//! silence, markers, text, repeat loops, extended and new-format sound
//! data) up to a terminator.

use crate::bytes::{u16_le, u32_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::sound::{channels, duration, leaf, peek_text, text, u24};
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::EnumTable;

const LE: Endian = Endian::Little;

pub static FORMAT: Format = Format {
    name: "voc",
    title: "Creative Voice",
    extensions: &["voc"],
    mime: "audio/x-voc",
    probe: Probe::Magic(&[(0, b"Creative Voice File\x1a")]),
    dissect: crate::expander!(dissect: Input),
};

const BLOCK: EnumTable = &[
    (0, "Terminator"),
    (1, "Sound data"),
    (2, "Sound continuation"),
    (3, "Silence"),
    (4, "Marker"),
    (5, "Text"),
    (6, "Repeat start"),
    (7, "Repeat end"),
    (8, "Extended"),
    (9, "Sound data (new format)"),
];

const CODEC: EnumTable = &[
    (0, "8-bit unsigned PCM"),
    (1, "4-bit Creative ADPCM"),
    (2, "2.6-bit Creative ADPCM"),
    (3, "2-bit Creative ADPCM"),
    (4, "16-bit signed PCM"),
    (6, "A-law"),
    (7, "µ-law"),
    (0x200, "4-bit Creative ADPCM (CT4)"),
];

fn header(f: &mut Fields<'_>, _: &()) -> Result<u16> {
    f.ascii("Signature", 20).emit()?;
    let size = f.u16("Header size").emit()?;
    let version = f
        .u16("Version")
        .with(|&v, n| n.summary(format!("{}.{:02}", v >> 8, v & 0xff)))
        .emit()?;
    f.u16("Checksum")
        .hex()
        .check(|&c| {
            (c != (!version).wrapping_add(0x1234))
                .then(|| Diagnostic::warning("checksum is not ~version + 0x1234"))
        })
        .emit()?;
    Ok(size)
}

/// Sample rate from the classic time constant.
fn rate_of(divisor: u8) -> u64 {
    1_000_000u64
        .checked_div(256u64.saturating_sub(divisor.into()))
        .unwrap_or(0)
}

/// What the first sound block says, plus the total amount of sound data.
#[derive(Clone, Copy, Debug, Default)]
struct Summary {
    rate: u64,
    bits: u64,
    channels: u64,
    codec: u16,
    bytes: u64,
    silence: f64,
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let hspan = file.sub(0, 26);
    let header_size = parse(&cx, hspan, LE, &(), header).await?;
    cx.emit(struct_node("Header", hspan, LE, (), header));
    let mut pos = u64::from(header_size).max(26);
    let mut sum = Summary::default();
    let mut blocks = Vec::new();
    while pos < file.len && blocks.len() < 4096 {
        let head = cx.read_avail(file.sub(pos, 16)).await?;
        let kind = head.first().copied().unwrap_or(0);
        if kind == 0 {
            blocks.push((kind, file.sub(pos, 1)));
            pos = pos.saturating_add(1);
            break;
        }
        let len = u64::from(crate::bytes::u24_le(&head, 1).unwrap_or(0));
        let span = file.sub(pos, len.saturating_add(4));
        match kind {
            1 if sum.rate == 0 => {
                sum.rate = rate_of(head.get(4).copied().unwrap_or(0));
                sum.codec = head.get(5).copied().unwrap_or(0).into();
                sum.bits = if sum.codec == 4 { 16 } else { 8 };
                sum.channels = 1;
            }
            9 if sum.rate == 0 => {
                sum.rate = u32_le(&head, 4).unwrap_or(0).into();
                sum.bits = head.get(8).copied().unwrap_or(0).into();
                sum.channels = head.get(9).copied().unwrap_or(0).into();
                sum.codec = u16_le(&head, 10).unwrap_or(0);
            }
            _ => {}
        }
        match kind {
            1 => sum.bytes = sum.bytes.saturating_add(len.saturating_sub(2)),
            2 => sum.bytes = sum.bytes.saturating_add(len),
            9 => sum.bytes = sum.bytes.saturating_add(len.saturating_sub(12)),
            3 => {
                let n = u64::from(u16_le(&head, 4).unwrap_or(0)).saturating_add(1);
                let rate = rate_of(head.get(6).copied().unwrap_or(0));
                if rate > 0 {
                    sum.silence += n as f64 / rate as f64;
                }
            }
            _ => {}
        }
        blocks.push((kind, span));
        pos = pos.saturating_add(len).saturating_add(4);
    }
    let codec = crate::value::lookup(CODEC, sum.codec.into()).unwrap_or("unknown codec");
    let mut line = format!(
        "Creative Voice, {codec}, {} Hz, {}",
        sum.rate,
        channels(sum.channels)
    );
    let bytes_per_second = sum
        .rate
        .saturating_mul(sum.bits)
        .saturating_mul(sum.channels)
        / 8;
    if bytes_per_second > 0 && matches!(sum.codec, 0 | 4 | 6 | 7) {
        line.push_str(&format!(
            ", {}",
            duration(sum.bytes as f64 / bytes_per_second as f64 + sum.silence)
        ));
    }
    cx.annotate(line);
    for (kind, span) in blocks {
        let name = crate::value::lookup(BLOCK, kind.into())
            .map_or_else(|| format!("Block type {kind}"), str::to_owned);
        let summary = block_summary(&cx, kind, span).await?;
        cx.push(
            Node::new(name)
                .span(span)
                .summary(summary)
                .lazy(block, (kind, span)),
        )
        .await;
    }
    if pos < file.len {
        cx.emit(Node::new("Trailing data").span(file.tail(pos)));
    }
    Ok(())
}

async fn block_summary(cx: &Cx, kind: u8, span: Span) -> Result<String> {
    let head = cx.read_avail(span.sub(0, 16)).await?;
    Ok(match kind {
        1 => format!(
            "{} Hz, {}, {} bytes",
            rate_of(head.get(4).copied().unwrap_or(0)),
            crate::value::lookup(CODEC, head.get(5).copied().unwrap_or(0).into()).unwrap_or("?"),
            span.len.saturating_sub(6)
        ),
        9 => format!(
            "{} Hz, {}-bit, {} ch, {} bytes",
            u32_le(&head, 4).unwrap_or(0),
            head.get(8).copied().unwrap_or(0),
            head.get(9).copied().unwrap_or(0),
            span.len.saturating_sub(16)
        ),
        3 => format!(
            "{} samples at {} Hz",
            u32::from(u16_le(&head, 4).unwrap_or(0)).saturating_add(1),
            rate_of(head.get(6).copied().unwrap_or(0))
        ),
        5 => peek_text(cx, span.tail(4), 80).await?,
        _ => format!("{} bytes", span.len),
    })
}

async fn block(cx: Cx, (kind, span): (u8, Span)) -> Result<()> {
    if kind == 0 {
        cx.emit(leaf("Type", span, crate::formats::sound::uint(0u8, 8)));
        return Ok(());
    }
    let head = cx.block(span.sub(0, 16)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.u8("Type").enumeration(BLOCK).emit()?;
    u24(&mut f, "Length", LE).emit()?;
    let rest = |n: u64| span.tail(4u64.saturating_add(n));
    match kind {
        1 => {
            f.u8("Frequency divisor")
                .with(|&d, n| n.summary(format!("{} Hz", rate_of(d))))
                .emit()?;
            f.u8("Codec").enumeration(CODEC).emit()?;
            cx.emit(Node::new("Samples").span(rest(2)));
        }
        2 => cx.emit(Node::new("Samples").span(rest(0))),
        3 => {
            f.u16("Length − 1").emit()?;
            f.u8("Frequency divisor")
                .with(|&d, n| n.summary(format!("{} Hz", rate_of(d))))
                .emit()?;
        }
        4 => {
            f.u16("Marker").emit()?;
        }
        5 => {
            let t = peek_text(&cx, rest(0), rest(0).len).await?;
            cx.emit(leaf("Text", rest(0), text(t)));
        }
        6 => {
            f.u16("Count").desc("0xffff = endless").emit()?;
        }
        8 => {
            f.u16("Time constant")
                .with(|&t, n| {
                    let r = 256_000_000u64
                        .checked_div(65536u64.saturating_sub(t.into()))
                        .unwrap_or(0);
                    n.summary(format!("{r} Hz (divide by channels)"))
                })
                .emit()?;
            f.u8("Codec").enumeration(CODEC).emit()?;
            f.u8("Mode")
                .enumeration(&[(0, "mono"), (1, "stereo")])
                .emit()?;
        }
        9 => {
            f.u32("Sample rate").emit()?;
            f.u8("Bits per sample").emit()?;
            f.u8("Channels").emit()?;
            f.u16("Codec").enumeration(CODEC).emit()?;
            f.u32("Reserved").emit()?;
            cx.emit(Node::new("Samples").span(rest(12)));
        }
        _ => cx.emit(Node::new("Data").span(rest(0))),
    }
    Ok(())
}
