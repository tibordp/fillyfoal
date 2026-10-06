//! Blu-ray PGS subtitle streams (`.sup`).

use crate::bytes::u16_be;
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record};
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::{Input, Probe};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, lookup};

const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// Blu-ray PGS subtitles (SUP)

/// "PG" is weak: also require a known segment type and a second segment
/// right after the first.
fn pgs_probe(h: &crate::formats::Head<'_>) -> bool {
    let kind = h.data.get(10).copied().unwrap_or(0);
    let size = usize::from(u16_be(h.data, 11).unwrap_or(0));
    h.starts_with(b"PG")
        && lookup(PGS_SEGMENTS, kind.into()).is_some()
        && (h.at(13usize.saturating_add(size), b"PG") || h.len == 13u64.saturating_add(size as u64))
}

declare_format!(pub PGS = "pgs", "Blu-ray PGS subtitles", ["sup"], "application/x-pgs",
    Probe::Custom(pgs_probe), pgs);

const PGS_SEGMENTS: EnumTable = &[
    (0x14, "Palette definition"),
    (0x15, "Object definition"),
    (0x16, "Presentation composition"),
    (0x17, "Window definition"),
    (0x80, "End of display set"),
];

record! {
    pub struct PgsHeader {
        magic: ascii[2] "Magic",
        pts: u32 "Presentation timestamp (90 kHz)",
        dts: u32 "Decoding timestamp (90 kHz)",
        kind: u8 "Segment type" .enumeration(PGS_SEGMENTS),
        size: u16 "Segment size",
    }
}

async fn pgs(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, BE);
    let mut sets = 0u32;
    let mut last = 0u32;
    while cur.remaining() >= PgsHeader::SIZE {
        let (h, span) = cur.record::<PgsHeader>().await?;
        if h.magic != "PG" {
            cx.diag(Diagnostic::malformed("expected a PG segment").at(span));
            break;
        }
        let body = cur.span(h.size.into());
        cur.skip(h.size.into());
        if h.kind == 0x80 {
            sets = sets.saturating_add(1);
        }
        last = h.pts;
        let seconds = h.pts / 90_000;
        let name = lookup(PGS_SEGMENTS, h.kind.into()).unwrap_or("Unknown segment");
        cx.push(
            PgsHeader::node(
                name,
                Span::new(span.source, span.offset, span.len.saturating_add(body.len)),
                BE,
            )
            .summary(format!(
                "{}:{:02}:{:02}.{:03}",
                seconds / 3600,
                seconds / 60 % 60,
                seconds % 60,
                h.pts % 90_000 / 90
            )),
        )
        .await;
    }
    let seconds = last / 90_000;
    cx.annotate(format!(
        "{sets} display set(s), until {}:{:02}:{:02}",
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60
    ));
    Ok(())
}
