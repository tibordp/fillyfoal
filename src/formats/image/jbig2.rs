//! JBIG2 bi-level images (the standalone file format).
//!
//! An 8-byte ID, flags and an optional page count, then segments. Each
//! segment header has a number, a type, referred-to segments, a page
//! association and a data length. In sequential files each header is
//! followed by its data; in random-access files all headers come first.

use crate::cx::Cx;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, flag, lookup};

use super::dims;

const BE: Endian = Endian::Big;

pub static FORMAT: Format = Format {
    name: "jbig2",
    title: "JBIG2 image",
    extensions: &["jb2", "jbig2"],
    mime: "image/x-jbig2",
    probe: Probe::Magic(&[(0, b"\x97JB2\r\n\x1a\n")]),
    dissect: crate::expander!(dissect: Input),
};

const FILE_FLAGS: FlagTable = &[flag(0x1, "SEQUENTIAL"), flag(0x2, "UNKNOWN_PAGE_COUNT")];

const SEGMENT_TYPES: EnumTable = &[
    (0, "Symbol dictionary"),
    (4, "Intermediate text region"),
    (6, "Immediate text region"),
    (7, "Immediate lossless text region"),
    (16, "Pattern dictionary"),
    (20, "Intermediate halftone region"),
    (22, "Immediate halftone region"),
    (23, "Immediate lossless halftone region"),
    (36, "Intermediate generic region"),
    (38, "Immediate generic region"),
    (39, "Immediate lossless generic region"),
    (40, "Intermediate generic refinement region"),
    (42, "Immediate generic refinement region"),
    (43, "Immediate lossless generic refinement region"),
    (48, "Page information"),
    (49, "End of page"),
    (50, "End of stripe"),
    (51, "End of file"),
    (52, "Profiles"),
    (53, "Tables"),
    (54, "Color palette"),
    (62, "Extension"),
];

/// Segments listed before giving up on a bogus file.
const MAX_SEGMENTS: u64 = 1_000_000;

#[derive(Clone, Copy, Debug)]
struct Header {
    number: u32,
    kind: u8,
    page: u32,
    data_len: u32,
    span: Span,
}

async fn segment_header(cur: &mut Cursor<'_>) -> Result<Header> {
    let start = cur.pos();
    let number = cur.u32().await?;
    let flags = cur.u8().await?;
    let first = cur.u8().await?;
    let mut count = u64::from(first >> 5);
    if count == 7 {
        cur.seek(start.saturating_add(5));
        count = u64::from(cur.u32().await? & 0x1fff_ffff);
        cur.skip(count.saturating_add(1).div_ceil(8));
    }
    let ref_size: u64 = if number <= 256 {
        1
    } else if number <= 65536 {
        2
    } else {
        4
    };
    cur.skip(count.saturating_mul(ref_size));
    let page = if flags & 0x40 != 0 {
        cur.u32().await?
    } else {
        cur.u8().await?.into()
    };
    let data_len = cur.u32().await?;
    Ok(Header {
        number,
        kind: flags & 0x3f,
        page,
        data_len,
        span: cur.since(start),
    })
}

fn page_info(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("Width").emit()?;
    f.u32("Height").desc("0xffffffff: unknown (striped)").emit()?;
    f.u32("X resolution").desc("Pixels per metre").emit()?;
    f.u32("Y resolution").desc("Pixels per metre").emit()?;
    f.u8("Flags").hex().emit()?;
    f.u16("Striping").hex().emit()?;
    Ok(())
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let block = cx.block(file.sub(0, 13)).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    f.bytes("ID string", 8).emit()?;
    let flags = f.u8("Flags").flags(FILE_FLAGS).emit()?;
    let mut pos = 9u64;
    let mut pages = None;
    if flags & 2 == 0 {
        pages = Some(f.u32("Number of pages").emit()?);
        pos = 13;
    }
    let sequential = flags & 1 != 0;
    let mut cur = Cursor::new(&cx, file, BE);
    cur.seek(pos);
    let mut pending = Vec::new();
    let mut annotated = false;
    for _ in 0..MAX_SEGMENTS {
        if cur.at_end() {
            break;
        }
        let h = segment_header(&mut cur).await?;
        let data = if sequential {
            if h.data_len == u32::MAX {
                return Err(Diagnostic::unsupported("segment of unknown length").at(h.span));
            }
            let data = cur.span(h.data_len.into());
            cur.skip(h.data_len.into());
            data
        } else {
            pending.push(h);
            if h.kind == 51 {
                break;
            }
            continue;
        };
        if h.kind == 48 && !annotated {
            annotated = true;
            annotate(&cx, data, pages).await;
        }
        cx.push(segment_node(h, data)).await;
        if h.kind == 51 {
            break;
        }
    }
    // Random-access organization: the data parts follow all headers.
    for h in pending {
        let data = cur.span(h.data_len.into());
        cur.skip(h.data_len.into());
        if h.kind == 48 && !annotated {
            annotated = true;
            annotate(&cx, data, pages).await;
        }
        cx.push(segment_node(h, data)).await;
    }
    Ok(())
}

async fn annotate(cx: &Cx, data: Span, pages: Option<u32>) {
    let Ok(b) = cx.read_avail(data.sub(0, 8)).await else {
        return;
    };
    let (Some(w), Some(h)) = (crate::bytes::u32_be(&b, 0), crate::bytes::u32_be(&b, 4)) else {
        return;
    };
    let pages = pages.map_or_else(|| "unknown page count".to_owned(), |p| format!("{p} pages"));
    cx.annotate(format!("{}, {pages}", dims(w, h)));
}

fn segment_node(h: Header, data: Span) -> Node {
    let kind = lookup(SEGMENT_TYPES, h.kind.into()).map_or_else(|| format!("Segment type {}", h.kind), str::to_owned);
    Node::new(format!("Segment {}", h.number))
        .span(h.span)
        .summary(format!("{kind}, page {}, {} bytes", h.page, data.len))
        .target(data)
        .lazy(segment, (h.span, data, h.kind))
}

async fn segment(cx: Cx, (header, data, kind): (Span, Span, u8)) -> Result<()> {
    let block = cx.block(header.sub(0, 5)).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    f.u32("Segment number").emit()?;
    f.u8("Flags")
        .hex()
        .with(|&v, n| n.summary(lookup(SEGMENT_TYPES, (v & 0x3f).into()).unwrap_or("unknown type")))
        .emit()?;
    let rest = header.tail(5);
    cx.emit(
        Node::new("Referred-to segments, page association, data length")
            .span(rest)
            .summary(format!("{} bytes", rest.len)),
    );
    if kind == 48 {
        cx.emit(struct_node("Page information", data, BE, (), page_info));
    } else {
        cx.emit(Node::new("Data").span(data));
    }
    Ok(())
}
