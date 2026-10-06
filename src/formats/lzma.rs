//! LZMA-family single-stream containers: legacy `.lzma` ("LZMA alone") and
//! lzip.
//!
//! Both are a small header (LZMA properties, dictionary size) in front of a
//! raw LZMA stream; lzip adds a trailer per member with the CRC and sizes, so
//! members are found from the end. The LZMA data is an unsupported leaf.

use crate::bytes::{to_u64, u32_le, u64_le};
use crate::cx::Cx;
use crate::dsl::{Cursor, Record};
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::arcutil::{count, human_size, unsupported};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;

const LE: Endian = Endian::Little;
const MAX_MEMBERS: usize = 1 << 16;

pub static LZMA: Format = Format {
    name: "lzma",
    title: "LZMA compressed data (legacy .lzma)",
    extensions: &["lzma", "tlz"],
    mime: "application/x-lzma",
    probe: Probe::Custom(probe_lzma),
    dissect: crate::expander!(dissect_lzma: Input),
};

pub static LZIP: Format = Format {
    name: "lzip",
    title: "lzip compressed data",
    extensions: &["lz", "tlz"],
    mime: "application/x-lzip",
    probe: Probe::Custom(probe_lzip),
    dissect: crate::expander!(dissect_lzip: Input),
};

/// `.lzma` has no magic: check that the properties byte is valid, the
/// dictionary size is one LZMA encoders produce, the size is plausible, and
/// the range coder's first byte is zero.
fn probe_lzma(h: &Head<'_>) -> bool {
    let (Some(&props), Some(dict), Some(size)) =
        (h.data.first(), u32_le(h.data, 1), u64_le(h.data, 5))
    else {
        return false;
    };
    // Encoders use 2^n or 3 * 2^n dictionaries.
    let dict_ok = dict >= 1 << 12
        && (dict.is_power_of_two()
            || (dict % 3 == 0 && (dict / 3).is_power_of_two())
            || dict == u32::MAX);
    // liblzma rejects lc + lp > 4, so real streams stay within it.
    let lclp_ok = (props % 9).saturating_add((props / 9) % 5) <= 4;
    // LZMA rarely compresses better than about 7000:1.
    let ratio_ok = size == u64::MAX || size <= h.len.saturating_mul(1 << 14);
    props < 225
        && lclp_ok
        && ratio_ok
        && dict_ok
        && (size == u64::MAX || size < 1 << 48)
        // An empty stream is a handful of bytes; a zero size on a longer
        // input is more likely a structure with a zero field (jump lists).
        && (size != 0 || h.len <= 64)
        && h.data.get(13) == Some(&0)
        && h.len > 13
}

fn probe_lzip(h: &Head<'_>) -> bool {
    h.starts_with(b"LZIP") && h.data.get(4).is_some_and(|&v| v <= 1)
}

/// lc, lp and pb from the properties byte.
fn props_summary(props: u8) -> String {
    format!("lc={} lp={} pb={}", props % 9, (props / 9) % 5, props / 45)
}

record! {
    pub struct LzmaHeader {
        props: u8 "Properties" .with(|&p, n| n.summary(props_summary(p))),
        dict: u32 "Dictionary size" .with(|&d, n| n.summary(human_size(d.into()))),
        size: u64 "Uncompressed size"
            .with(|&s, n| n.summary(if s == u64::MAX { "unknown (end marker)".to_owned() } else { human_size(s) })),
    }
}

pub async fn dissect_lzma(cx: Cx, input: Input) -> Result<()> {
    let mut cur = Cursor::new(&cx, input.span, LE);
    let (header, span) = cur.record::<LzmaHeader>().await?;
    cx.emit(LzmaHeader::node("Header", span, LE));
    let body = input.span.tail(LzmaHeader::SIZE);
    cx.emit(unsupported("Compressed data", body, "LZMA"));
    let size = if header.size == u64::MAX {
        "unknown size".to_owned()
    } else {
        format!("{} uncompressed", human_size(header.size))
    };
    cx.annotate(format!(
        "LZMA, {size}, dictionary {}, {}",
        human_size(header.dict.into()),
        props_summary(header.props)
    ));
    Ok(())
}

/// lzip's coded dictionary size: a power of two minus some sixteenths.
fn lzip_dict(b: u8) -> u64 {
    let base = 1u64 << (b & 0x1f).min(40);
    base.saturating_sub((base / 16).saturating_mul(u64::from(b >> 5)))
}

record! {
    pub struct LzipHeader {
        magic: ascii[4] "Magic",
        version: u8 "Version",
        dict: u8 "Coded dictionary size" .with(|&b, n| n.summary(human_size(lzip_dict(b)))),
    }
}

record! {
    pub struct LzipTrailer {
        crc: u32 "CRC32" .hex() .desc("CRC32 of the uncompressed data"),
        data_size: u64 "Data size" .with(|&s, n| n.summary(human_size(s))) .desc("Uncompressed size"),
        member_size: u64 "Member size" .with(|&s, n| n.summary(human_size(s))) .desc("Header, compressed data and trailer"),
    }
}

#[derive(Clone, Copy, Debug)]
struct Member {
    span: Span,
    data_size: u64,
}

pub async fn dissect_lzip(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    // Members from the end: each trailer gives the member's size.
    let mut members = Vec::new();
    let mut end = file.len;
    let mut error = None;
    while end > 0 && members.len() < MAX_MEMBERS {
        let Some(at) = end.checked_sub(LzipTrailer::SIZE) else {
            error = Some(Diagnostic::malformed("no member trailer").at(file.sub(0, end)));
            break;
        };
        let trailer = crate::fields::parse(
            &cx,
            file.sub(at, LzipTrailer::SIZE),
            LE,
            &(),
            LzipTrailer::layout,
        )
        .await?;
        let start = end.checked_sub(trailer.member_size);
        let magic = match start {
            Some(s) if trailer.member_size >= 26 => cx.read_avail(file.sub(s, 4)).await?,
            _ => Vec::new(),
        };
        let (Some(start), b"LZIP") = (start, magic.as_slice()) else {
            error = Some(
                Diagnostic::malformed("member size in the trailer does not lead to a header")
                    .at(file.sub(at, LzipTrailer::SIZE)),
            );
            break;
        };
        members.push(Member {
            span: file.sub(start, trailer.member_size),
            data_size: trailer.data_size,
        });
        end = start;
        cx.checkpoint().await;
    }
    members.reverse();

    if let Some(e) = error {
        // Damaged or truncated: show the first member's header at least.
        let mut cur = Cursor::new(&cx, file, LE);
        let (_, span) = cur.record::<LzipHeader>().await?;
        cx.emit(LzipHeader::node("Header", span, LE));
        cx.emit(unsupported(
            "Compressed data",
            file.tail(LzipHeader::SIZE),
            "LZMA",
        ));
        cx.diag(e);
        cx.annotate("lzip (trailer missing or damaged)");
        return Ok(());
    }

    let total = members
        .iter()
        .fold(0u64, |a, m| a.saturating_add(m.data_size));
    cx.annotate(format!(
        "lzip, {}, {} uncompressed",
        count(to_u64(members.len()), "member", "members"),
        human_size(total)
    ));
    if let [member] = members.as_slice() {
        return emit_member(&cx, member.span).await;
    }
    for (i, m) in members.iter().enumerate() {
        cx.push(
            Node::new(format!("Member {i}"))
                .span(m.span)
                .summary(format!("{} uncompressed", human_size(m.data_size)))
                .lazy(member, m.span),
        )
        .await;
    }
    Ok(())
}

async fn member(cx: Cx, span: Span) -> Result<()> {
    emit_member(&cx, span).await
}

async fn emit_member(cx: &Cx, span: Span) -> Result<()> {
    cx.emit(LzipHeader::node(
        "Header",
        span.sub(0, LzipHeader::SIZE),
        LE,
    ));
    let body_len = span
        .len
        .saturating_sub(LzipHeader::SIZE)
        .saturating_sub(LzipTrailer::SIZE);
    cx.emit(unsupported(
        "Compressed data",
        span.sub(LzipHeader::SIZE, body_len),
        "LZMA",
    ));
    cx.emit(LzipTrailer::node(
        "Trailer",
        span.tail(span.len.saturating_sub(LzipTrailer::SIZE)),
        LE,
    ));
    Ok(())
}
