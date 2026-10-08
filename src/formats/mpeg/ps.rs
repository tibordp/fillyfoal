//! MPEG program streams: MPEG-1 system streams (ISO 11172-1) and MPEG-2
//! program streams (ISO 13818-1, DVD VOB). A sequence of pack headers,
//! system headers and PES packets, listed in pages.

use crate::bytes::u16_be;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::vidutil::{self, flag_node, hex, uint};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;

use super::{mpeg1_pts, pes_header, pes_times, seconds_90k, stream_id_name};

pub static MPEG2_PS: Format = Format {
    name: "mpeg-ps",
    title: "MPEG-2 program stream",
    extensions: &["vob", "mpg", "mpeg", "ps", "evo", "vro"],
    mime: "video/mpeg",
    probe: Probe::Custom(|h| pack_kind(h) == Some(2)),
    dissect: crate::expander!(dissect: Input),
};

pub static MPEG1_SYSTEM: Format = Format {
    name: "mpeg1-system",
    title: "MPEG-1 system stream",
    extensions: &["mpg", "mpeg", "m1s", "dat"],
    mime: "video/mpeg",
    probe: Probe::Custom(|h| pack_kind(h) == Some(1)),
    dissect: crate::expander!(dissect: Input),
};

/// 1 for an MPEG-1 pack header at offset 0, 2 for MPEG-2.
fn pack_kind(h: &Head<'_>) -> Option<u8> {
    if !h.starts_with(b"\x00\x00\x01\xba") {
        return None;
    }
    let b = *h.data.get(4)?;
    if b & 0xc4 == 0x44 {
        // MPEG-2: '01' + marker bits at fixed positions.
        let ok = h.data.get(6).is_some_and(|x| x & 4 != 0)
            && h.data.get(8).is_some_and(|x| x & 4 != 0)
            && h.data.get(9).is_some_and(|x| x & 1 != 0);
        return ok.then_some(2);
    }
    if b & 0xf1 == 0x21 {
        let ok = h.data.get(6).is_some_and(|x| x & 1 != 0)
            && h.data.get(8).is_some_and(|x| x & 1 != 0)
            && h.data.get(9).is_some_and(|x| x & 0x80 != 0);
        return ok.then_some(1);
    }
    None
}

/// SCR of a pack header (`d` starts at `00 00 01 BA`), in 90 kHz ticks,
/// with the MPEG-2 extension in 27 MHz units if present.
fn scr(d: &[u8]) -> Option<(u64, Option<u64>)> {
    let b4 = *d.get(4)?;
    if b4 & 0xc0 == 0x40 {
        let b = |i: usize| d.get(i).copied().map(u64::from);
        let base = ((b(4)? >> 3) & 7) << 30
            | (b(4)? & 3) << 28
            | b(5)? << 20
            | (b(6)? >> 3) << 15
            | (b(6)? & 3) << 13
            | b(7)? << 5
            | b(8)? >> 3;
        let ext = (b(8)? & 3) << 7 | b(9)? >> 1;
        Some((base, Some(ext)))
    } else {
        super::timestamp(d.get(4..9)?).map(|t| (t, None))
    }
}

/// Length of the unit starting with `d` (a start code).
fn unit_len(d: &[u8]) -> Option<u64> {
    let code = *d.get(3)?;
    match code {
        0xba => {
            let b4 = *d.get(4)?;
            if b4 & 0xc0 == 0x40 {
                Some(14u64.saturating_add(u64::from(d.get(13)? & 7)))
            } else {
                Some(12)
            }
        }
        0xb9 => Some(4),
        0xbb..=0xff => Some(6u64.saturating_add(u16_be(d, 4)?.into())),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug)]
struct Unit {
    span: Span,
    code: u8,
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.annotate(
        summary(&cx, file)
            .await
            .unwrap_or_else(|| "MPEG program stream".to_owned()),
    );
    let mut pos = 0u64;
    while pos < file.len {
        let d = cx.read_avail(file.sub(pos, 32)).await?;
        let len = if d.starts_with(&[0, 0, 1]) {
            unit_len(&d)
        } else {
            None
        };
        let Some(len) = len.filter(|&l| l > 0) else {
            // Resynchronise at the next start code.
            let next = vidutil::next_start_code(&cx, file, pos.saturating_add(1)).await?;
            let end = next.unwrap_or(file.len);
            cx.push(
                Node::new("Unparsed data")
                    .span(file.sub(pos, end.saturating_sub(pos)))
                    .diag(Diagnostic::malformed("expected a start code")),
            )
            .await;
            pos = end;
            continue;
        };
        let code = d.get(3).copied().unwrap_or(0);
        let unit = Unit {
            span: file.sub(pos, len),
            code,
        };
        let mut node = Node::new(stream_id_name(code))
            .span(unit.span)
            .summary(unit_summary(&d, len))
            .lazy(expand_unit, unit);
        if unit.span.len < len {
            node = node.diag(Diagnostic::truncated(
                Span::new(file.source, unit.span.offset, len),
                unit.span.len,
            ));
        }
        cx.progress_in(file, file.offset.saturating_add(pos));
        cx.push(node).await;
        pos = pos.saturating_add(len);
        if code == 0xb9 && pos < file.len {
            cx.emit(Node::new("Trailing data").span(file.tail(pos)));
            break;
        }
    }
    Ok(())
}

fn unit_summary(d: &[u8], len: u64) -> String {
    let code = d.get(3).copied().unwrap_or(0);
    match code {
        0xba => match scr(d) {
            Some((base, _)) => format!(
                "{}, SCR {}",
                if d.get(4).is_some_and(|b| b & 0xc0 == 0x40) {
                    "MPEG-2"
                } else {
                    "MPEG-1"
                },
                seconds_90k(base)
            ),
            None => String::new(),
        },
        0xbb => format!("{len} bytes"),
        0xb9 => "end".to_owned(),
        _ => {
            let pts = if d.get(6).is_some_and(|b| b & 0xc0 == 0x80) {
                pes_times(d).0
            } else {
                mpeg1_pts(d)
            };
            match pts {
                Some(p) => format!("{len} bytes, PTS {}", seconds_90k(p)),
                None => format!("{len} bytes"),
            }
        }
    }
}

async fn expand_unit(cx: Cx, unit: Unit) -> Result<()> {
    let span = unit.span;
    let d = cx.read_avail(span.sub(0, 0x200)).await?;
    match unit.code {
        0xba => pack_header(&cx, span, &d),
        0xbb => system_header(&cx, span, &d),
        0xb9 => cx.emit(hex("End code", span, 0x1b9, 32)),
        _ => {
            let (header, _) = pes_header(&cx, span, &d);
            let payload = span.tail(header);
            cx.emit(
                Node::new("Payload")
                    .span(payload)
                    .summary(format!("{} bytes", payload.len)),
            );
        }
    }
    Ok(())
}

fn pack_header(cx: &Cx, span: Span, d: &[u8]) {
    cx.emit(hex("Start code", span.sub(0, 4), 0x1ba, 32));
    let mpeg2 = d.get(4).is_some_and(|b| b & 0xc0 == 0x40);
    if let Some((base, ext)) = scr(d) {
        let scr_span = span.sub(4, if mpeg2 { 6 } else { 5 });
        cx.emit(uint("SCR base", scr_span, base, 33).summary(seconds_90k(base)));
        if let Some(e) = ext {
            cx.emit(uint("SCR extension", scr_span, e, 9));
        }
    }
    if mpeg2 {
        let rate = crate::bytes::u24_be(d, 10).unwrap_or(0) >> 2;
        cx.emit(
            uint("Program mux rate", span.sub(10, 3), rate.into(), 22)
                .summary(format!("{} bytes/s", u64::from(rate).saturating_mul(50))),
        );
        let stuffing = d.get(13).copied().unwrap_or(0) & 7;
        cx.emit(uint("Stuffing length", span.sub(13, 1), stuffing.into(), 3));
        if stuffing > 0 {
            cx.emit(Node::new("Stuffing").span(span.sub(14, stuffing.into())));
        }
    } else {
        let rate = (crate::bytes::u24_be(d, 9).unwrap_or(0) >> 1) & 0x3f_ffff;
        cx.emit(
            uint("Mux rate", span.sub(9, 3), rate.into(), 22)
                .summary(format!("{} bytes/s", u64::from(rate).saturating_mul(50))),
        );
    }
}

fn system_header(cx: &Cx, span: Span, d: &[u8]) {
    cx.emit(hex("Start code", span.sub(0, 4), 0x1bb, 32));
    let len = u16_be(d, 4).unwrap_or(0);
    cx.emit(uint("Header length", span.sub(4, 2), len.into(), 16));
    let rate = (crate::bytes::u24_be(d, 6).unwrap_or(0) >> 1) & 0x3f_ffff;
    cx.emit(uint("Rate bound", span.sub(6, 3), rate.into(), 22));
    let b9 = d.get(9).copied().unwrap_or(0);
    cx.emit(uint("Audio bound", span.sub(9, 1), (b9 >> 2).into(), 6));
    cx.emit(flag_node("Fixed bitrate", span.sub(9, 1), b9 & 2 != 0));
    cx.emit(flag_node(
        "Constrained parameters",
        span.sub(9, 1),
        b9 & 1 != 0,
    ));
    let b10 = d.get(10).copied().unwrap_or(0);
    cx.emit(flag_node(
        "System audio lock",
        span.sub(10, 1),
        b10 & 0x80 != 0,
    ));
    cx.emit(flag_node(
        "System video lock",
        span.sub(10, 1),
        b10 & 0x40 != 0,
    ));
    cx.emit(uint("Video bound", span.sub(10, 1), (b10 & 0x1f).into(), 5));
    let end = usize::from(len).saturating_add(6).min(d.len());
    let mut at = 12usize;
    while at.saturating_add(3) <= end {
        let id = d.get(at).copied().unwrap_or(0);
        if id & 0x80 == 0 {
            break;
        }
        let w = u16_be(d, at.saturating_add(1)).unwrap_or(0);
        let scale = if w & 0x2000 != 0 { 1024 } else { 128 };
        cx.emit(
            hex(stream_id_name(id), vidutil::at(span, at, 3), id.into(), 8).summary(format!(
                "P-STD buffer {} bytes",
                u64::from(w & 0x1fff).saturating_mul(scale)
            )),
        );
        at = at.saturating_add(3);
    }
}

/// "MPEG-2 program stream, video 0xe0 + audio 0xc0, 00:00:00.120".
async fn summary(cx: &Cx, file: Span) -> Option<String> {
    let mut ids: Vec<u8> = Vec::new();
    let mut first_scr = None;
    let mut pos = 0u64;
    let mut kind = "MPEG program stream";
    for _ in 0..256 {
        let d = cx.read_avail(file.sub(pos, 32)).await.ok()?;
        if !d.starts_with(&[0, 0, 1]) {
            break;
        }
        let code = d.get(3).copied()?;
        if code == 0xba {
            if first_scr.is_none() {
                first_scr = scr(&d).map(|s| s.0);
                kind = if d.get(4).is_some_and(|b| b & 0xc0 == 0x40) {
                    "MPEG-2 program stream"
                } else {
                    "MPEG-1 system stream"
                };
            }
        } else if (0xbd..=0xef).contains(&code) && code != 0xbe && !ids.contains(&code) {
            ids.push(code);
        }
        let Some(len) = unit_len(&d) else {
            break;
        };
        pos = pos.saturating_add(len);
    }
    ids.sort_unstable();
    let mut parts = vec![kind.to_owned()];
    if !ids.is_empty() {
        let names: Vec<String> = ids
            .iter()
            .map(|&i| stream_id_name(i).to_lowercase())
            .collect();
        parts.push(names.join(" + "));
    }
    // The last SCR: search the tail for a pack header.
    let tail_start = file.len.saturating_sub(0x10000);
    let tail = cx.read_avail(file.tail(tail_start)).await.ok()?;
    let last = tail
        .windows(4)
        .enumerate()
        .rev()
        .filter(|(_, w)| *w == [0, 0, 1, 0xba])
        .find_map(|(i, _)| tail.get(i..).and_then(scr))
        .map(|s| s.0);
    if let (Some(a), Some(b)) = (first_scr, last)
        && b > a
    {
        parts.push(vidutil::seconds_f64(b.saturating_sub(a) as f64 / 90_000.0));
    }
    Some(parts.join(", "))
}
