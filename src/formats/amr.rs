//! AMR and AMR-WB storage format (RFC 4867, section 5): a magic line, then
//! 20 ms frames, each a table-of-contents byte (frame type and quality)
//! followed by a payload whose size depends on the frame type.

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::sound::{Bits, bits_node, duration};
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::EnumTable;

pub static FORMAT: Format = Format {
    name: "amr",
    title: "Adaptive Multi-Rate audio",
    extensions: &["amr", "awb"],
    mime: "audio/amr",
    probe: Probe::Magic(&[
        (0, b"#!AMR\n"),
        (0, b"#!AMR-WB\n"),
        (0, b"#!AMR_MC1.0\n"),
        (0, b"#!AMR-WB_MC1.0\n"),
    ]),
    dissect: crate::expander!(dissect: Input),
};

/// Payload bytes per frame type.
const NB_SIZES: [u64; 16] = [12, 13, 15, 17, 19, 20, 26, 31, 5, 0, 0, 0, 0, 0, 0, 0];
const WB_SIZES: [u64; 16] = [17, 23, 32, 36, 40, 46, 50, 58, 60, 5, 0, 0, 0, 0, 0, 0];

const NB_MODES: EnumTable = &[
    (0, "4.75 kbit/s"),
    (1, "5.15 kbit/s"),
    (2, "5.90 kbit/s"),
    (3, "6.70 kbit/s"),
    (4, "7.40 kbit/s"),
    (5, "7.95 kbit/s"),
    (6, "10.2 kbit/s"),
    (7, "12.2 kbit/s"),
    (8, "SID (comfort noise)"),
    (15, "no data"),
];

const WB_MODES: EnumTable = &[
    (0, "6.60 kbit/s"),
    (1, "8.85 kbit/s"),
    (2, "12.65 kbit/s"),
    (3, "14.25 kbit/s"),
    (4, "15.85 kbit/s"),
    (5, "18.25 kbit/s"),
    (6, "19.85 kbit/s"),
    (7, "23.05 kbit/s"),
    (8, "23.85 kbit/s"),
    (9, "SID (comfort noise)"),
    (15, "no data"),
];

#[derive(Clone, Copy, Debug)]
struct Kind {
    wide: bool,
    channels: u64,
}

impl Kind {
    fn sizes(self) -> &'static [u64; 16] {
        if self.wide { &WB_SIZES } else { &NB_SIZES }
    }

    fn modes(self) -> EnumTable {
        if self.wide { WB_MODES } else { NB_MODES }
    }

    fn valid(self, toc: u8) -> bool {
        let ft = (toc >> 3) & 0xf;
        toc & 0x83 == 0 && (ft <= 9 || ft == 15) && !(ft == 9 && !self.wide)
    }

    /// The whole frame (header and payload) for each channel.
    fn frame_len(self, toc: u8) -> u64 {
        let ft = usize::from((toc >> 3) & 0xf);
        self.sizes().get(ft).copied().unwrap_or(0).saturating_add(1)
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 20)).await?;
    let wide = head.starts_with(b"#!AMR-WB");
    let multi = head.starts_with(b"#!AMR_MC") || head.starts_with(b"#!AMR-WB_MC");
    let magic_len = head
        .iter()
        .position(|&b| b == b'\n')
        .map_or(6, |p| to_u64(p).saturating_add(1));
    cx.emit(
        Node::new("Magic")
            .span(file.sub(0, magic_len))
            .value(crate::formats::util::sound::text(
                String::from_utf8_lossy(
                    head.get(..to_usize(magic_len).saturating_sub(1))
                        .unwrap_or_default(),
                )
                .into_owned(),
            )),
    );
    let mut pos = magic_len;
    let mut channels = 1u64;
    if multi {
        let raw = cx.read(file.sub(pos, 4)).await?;
        let desc = crate::bytes::u32_be(&raw, 0).unwrap_or(0);
        channels = u64::from(desc & 0xf).max(1);
        cx.emit(
            Node::new("Channel description")
                .span(file.sub(pos, 4))
                .value(crate::formats::util::sound::hex(desc, 32))
                .summary(format!("{channels} channels")),
        );
        pos = pos.saturating_add(4);
    }
    let kind = Kind { wide, channels };
    let frames_span = file.tail(pos);

    // Count frames in the first 64 KiB; extrapolate for longer files.
    let window = cx.read_avail(frames_span.sub(0, 0x10000)).await?;
    let mut at = 0usize;
    let mut count = 0u64;
    while let Some(&toc) = window.get(at) {
        if !kind.valid(toc) {
            break;
        }
        at = at.saturating_add(to_usize(kind.frame_len(toc).saturating_mul(channels)));
        count = count.saturating_add(1);
    }
    let exact = to_u64(window.len()) == frames_span.len;
    let frames = if exact || at == 0 {
        count
    } else {
        frames_span
            .len
            .saturating_mul(count)
            .checked_div(to_u64(at))
            .unwrap_or(count)
    };
    let rate = if wide { 16000 } else { 8000 };
    cx.annotate(format!(
        "{}, {rate} Hz, {} ch, {}{}",
        if wide { "AMR-WB" } else { "AMR-NB" },
        channels,
        if exact { "" } else { "≈" },
        duration(frames as f64 * 0.02)
    ));
    cx.emit(
        Node::new("Frames")
            .span(frames_span)
            .summary(format!(
                "{}{frames} frames of 20 ms",
                if exact { "" } else { "≈" }
            ))
            .lazy(list_frames, (frames_span, kind)),
    );
    Ok(())
}

async fn list_frames(cx: Cx, (region, kind): (Span, Kind)) -> Result<()> {
    let mut pos = 0u64;
    let mut index = 0u64;
    while pos < region.len {
        let toc = cx.read(region.sub(pos, 1)).await?;
        let toc = toc.first().copied().unwrap_or(0);
        if !kind.valid(toc) {
            cx.emit(
                Node::new("Unparsed data")
                    .span(region.tail(pos))
                    .diag(Diagnostic::malformed(format!(
                        "invalid frame header {toc:#04x}"
                    ))),
            );
            return Ok(());
        }
        let len = kind.frame_len(toc).saturating_mul(kind.channels);
        let span = region.sub(pos, len);
        let mode = crate::value::lookup(kind.modes(), ((toc >> 3) & 0xf).into()).unwrap_or("?");
        let mut node = Node::new(format!("Frame {index}"))
            .span(span)
            .summary(format!("{mode}, {len} bytes"));
        if span.len < len {
            node = node.diag(Diagnostic::truncated(
                Span::new(span.source, span.offset, len),
                span.len,
            ));
        }
        let header = if kind.wide { toc_wb } else { toc_nb };
        node = node.lazy(frame, (span, header));
        cx.push(node).await;
        pos = pos.saturating_add(len);
        index = index.saturating_add(1);
    }
    Ok(())
}

async fn frame(cx: Cx, (span, header): (Span, crate::formats::util::sound::BitLayout<()>)) -> Result<()> {
    cx.emit(bits_node("Header", span.sub(0, 1), header, false));
    cx.emit(Node::new("Speech data").span(span.tail(1)));
    Ok(())
}

fn toc(b: &mut Bits<'_>, modes: EnumTable) -> Result<()> {
    b.field("Padding", 1).emit()?;
    b.field("Frame type", 4).enumeration(modes).emit()?;
    b.field("Quality", 1)
        .with(|v, n| n.summary(if v == 1 { "good" } else { "damaged" }))
        .emit()?;
    b.field("Padding", 2).emit()?;
    Ok(())
}

fn toc_nb(b: &mut Bits<'_>) -> Result<()> {
    toc(b, NB_MODES)
}

fn toc_wb(b: &mut Bits<'_>) -> Result<()> {
    toc(b, WB_MODES)
}
