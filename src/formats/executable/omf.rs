//! Intel Object Module Format (OMF-86/386): 16- and 32-bit DOS, OS/2 and
//! Windows `.obj` files (Borland, Watcom, MASM, OpenWatcom) and OMF
//! libraries. A stream of records (type, length, contents, checksum); name
//! lists, public/external symbols, segments and comments are decoded.

use crate::bytes::u16_le;
use crate::cx::Cx;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::binutil::{NodeExt, ellipsize, name_or};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::EnumTable;

pub static FORMAT: Format = Format {
    name: "omf",
    title: "OMF object module or library",
    extensions: &["obj", "lib"],
    mime: "application/x-omf",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    let kind = h.data.first().copied().unwrap_or(0);
    let len = usize::from(u16_le(h.data, 1).unwrap_or(0));
    match kind {
        // THEADR/LHEADR: a counted name and the checksum fill the record.
        0x80 | 0x82 => {
            let n = usize::from(h.data.get(3).copied().unwrap_or(0));
            n > 0
                && n.saturating_add(2) == len
                && h.data
                    .get(4..4usize.saturating_add(n))
                    .is_some_and(|s| s.iter().all(|b| b.is_ascii_graphic() || *b == b' '))
        }
        // Library header: page size is a power of two.
        0xf0 => {
            let page = len.saturating_add(3);
            page.is_power_of_two() && page >= 16 && h.at(page, b"\x80")
        }
        _ => false,
    }
}

const RECORD: EnumTable = &[
    (0x80, "THEADR"),
    (0x82, "LHEADR"),
    (0x88, "COMENT"),
    (0x8a, "MODEND"),
    (0x8b, "MODEND32"),
    (0x8c, "EXTDEF"),
    (0x90, "PUBDEF"),
    (0x91, "PUBDEF32"),
    (0x94, "LINNUM"),
    (0x95, "LINNUM32"),
    (0x96, "LNAMES"),
    (0x98, "SEGDEF"),
    (0x99, "SEGDEF32"),
    (0x9a, "GRPDEF"),
    (0x9c, "FIXUPP"),
    (0x9d, "FIXUPP32"),
    (0xa0, "LEDATA"),
    (0xa1, "LEDATA32"),
    (0xa2, "LIDATA"),
    (0xa3, "LIDATA32"),
    (0xb0, "COMDEF"),
    (0xb2, "BAKPAT"),
    (0xb3, "BAKPAT32"),
    (0xb4, "LEXTDEF"),
    (0xb6, "LPUBDEF"),
    (0xb7, "LPUBDEF32"),
    (0xb8, "LCOMDEF"),
    (0xbc, "CEXTDEF"),
    (0xc2, "COMDAT"),
    (0xc3, "COMDAT32"),
    (0xc4, "LINSYM"),
    (0xc5, "LINSYM32"),
    (0xc6, "ALIAS"),
    (0xc8, "NBKPAT"),
    (0xc9, "NBKPAT32"),
    (0xca, "LLNAMES"),
    (0xcc, "VERNUM"),
    (0xce, "VENDEXT"),
    (0xf0, "LIBHDR"),
    (0xf1, "LIBEND"),
];

const COMMENT_CLASS: EnumTable = &[
    (0x00, "Translator"),
    (0x01, "Intel copyright"),
    (0x9d, "Memory model"),
    (0x9e, "DOSSEG"),
    (0x9f, "Default library"),
    (0xa0, "OMF extensions"),
    (0xa1, "Debug info type"),
    (0xa2, "Link pass separator"),
    (0xa3, "LIBMOD"),
    (0xa4, "EXESTR"),
    (0xa6, "INCERR"),
    (0xa7, "NOPAD"),
    (0xa8, "WKEXT"),
    (0xa9, "LZEXT"),
    (0xda, "Comment"),
    (0xdb, "Compiler"),
    (0xdc, "Date"),
    (0xdd, "Timestamp"),
    (0xdf, "User"),
    (0xe9, "Dependency file"),
    (0xff, "Command line"),
];

/// Counted strings until the data ends; `skip` gives where the next one
/// starts after each string's end (to step over indices and offsets).
fn counted(data: &[u8], mut at: usize, skip: impl Fn(&[u8], usize) -> usize) -> Vec<String> {
    let mut out = Vec::new();
    while let Some(&n) = data.get(at) {
        let start = at.saturating_add(1);
        let end = start.saturating_add(usize::from(n));
        let Some(s) = data.get(start..end) else { break };
        out.push(String::from_utf8_lossy(s).into_owned());
        at = skip(data, end);
        if out.len() >= 4096 {
            break;
        }
    }
    out
}

/// An OMF index: one byte, or two if the high bit is set.
fn index_len(data: &[u8], at: usize) -> usize {
    match data.get(at) {
        Some(b) if b & 0x80 != 0 => 2,
        _ => 1,
    }
}

fn describe(kind: u8, data: &[u8]) -> String {
    let wide = kind & 1 == 1;
    match kind {
        0x80 | 0x82 => counted(data, 0, |_, e| e)
            .into_iter()
            .next()
            .unwrap_or_default(),
        0x96 | 0xca => counted(data, 0, |_, e| e).join(", "),
        0x8c | 0xb4 => counted(data, 0, |d, e| e.saturating_add(index_len(d, e))).join(", "),
        0x90 | 0x91 | 0xb6 | 0xb7 => {
            // Group index, segment index (base frame if both zero), names.
            let mut at = index_len(data, 0);
            let seg_at = at;
            at = at.saturating_add(index_len(data, seg_at));
            if data.first() == Some(&0) && data.get(seg_at) == Some(&0) {
                at = at.saturating_add(2);
            }
            let offset = if wide { 4 } else { 2 };
            counted(data, at, |d, e| {
                e.saturating_add(offset)
                    .saturating_add(index_len(d, e.saturating_add(offset)))
            })
            .join(", ")
        }
        0x88 => {
            let class = data.get(1).copied().unwrap_or(0);
            let body = data.get(2..).unwrap_or_default();
            let counted = body
                .first()
                .is_some_and(|&n| usize::from(n) == body.len().saturating_sub(1));
            let body = if counted {
                body.get(1..).unwrap_or_default()
            } else {
                body
            };
            let textual = String::from_utf8_lossy(body);
            format!(
                "{}: {}",
                name_or(COMMENT_CLASS, class.into(), "class"),
                ellipsize(textual.trim_end_matches('\0'), 80)
            )
        }
        0x98 | 0x99 => {
            let attr = data.first().copied().unwrap_or(0);
            let align = match attr >> 5 {
                0 => "absolute",
                1 => "byte",
                2 => "word",
                3 => "paragraph",
                4 => "page",
                5 => "dword",
                _ => "?",
            };
            let combine = match (attr >> 2) & 7 {
                0 => "private",
                2 | 4 | 7 => "public",
                5 => "stack",
                6 => "common",
                _ => "?",
            };
            let len_at = if attr >> 5 == 0 { 4 } else { 1 };
            let length = if wide {
                crate::bytes::u32_le(data, len_at).unwrap_or(0)
            } else {
                u16_le(data, len_at).unwrap_or(0).into()
            };
            format!(
                "{align} aligned, {combine}, {length:#x} bytes{}",
                if attr & 1 != 0 { ", 32-bit" } else { "" }
            )
        }
        0xa0 | 0xa1 => {
            let n = data
                .len()
                .saturating_sub(index_len(data, 0))
                .saturating_sub(if wide { 4 } else { 2 });
            format!("{n} bytes of data")
        }
        _ => String::new(),
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, Endian::Little);
    let mut module = None;
    let mut records = 0u32;
    let mut library_page = 0u64;
    let mut nodes = Vec::new();
    while cur.remaining() >= 3 {
        let start = cur.pos();
        let head = cur.bytes(3).await?;
        let kind = head.first().copied().unwrap_or(0);
        let len = u64::from(u16_le(&head, 1).unwrap_or(0));
        let span = file.sub(start, len.saturating_add(3));
        let data = cx
            .read_avail(span.sub(3, len.saturating_sub(1).min(0x10000)))
            .await?;
        let record = cx.read_avail(span).await?;
        let sum = record.iter().fold(0u8, |a, &b| a.wrapping_add(b));
        let stored = record.last().copied().unwrap_or(0);
        let mut node = Node::new(name_or(RECORD, kind.into(), "record"))
            .span(span)
            .maybe_summary(describe(kind, &data))
            .lazy(record_fields, span);
        if stored != 0 && sum != 0 && kind != 0xf0 && kind != 0xf1 {
            node = node.diag(Diagnostic::warning("checksum mismatch"));
        }
        if matches!(kind, 0x80 | 0x82) && module.is_none() {
            module = Some(describe(kind, &data));
        }
        if kind == 0xf0 {
            library_page = len.saturating_add(3);
        }
        nodes.push(node);
        records = records.saturating_add(1);
        cur.seek(start.saturating_add(len).saturating_add(3));
        // Library members start on page boundaries.
        if library_page > 0 && matches!(kind, 0x8a | 0x8b | 0xf0) {
            let p = cur
                .pos()
                .checked_next_multiple_of(library_page)
                .unwrap_or(u64::MAX);
            cur.seek(p);
        }
        if kind == 0xf1 {
            break;
        }
        cx.progress_in(file, file.offset.saturating_add(cur.pos()));
        cx.checkpoint().await;
    }
    cx.annotate(format!(
        "OMF {}{}, {records} records",
        if library_page > 0 {
            "library"
        } else {
            "object module"
        },
        module.map(|m| format!(" {m}")).unwrap_or_default()
    ));
    for n in nodes {
        cx.push(n).await;
    }
    Ok(())
}

async fn record_fields(cx: Cx, span: Span) -> Result<()> {
    let head = cx.block(span.sub(0, 3)).await?;
    let mut f = crate::fields::Fields::emitting(&cx, &head, Endian::Little);
    f.u8("type").enumeration(RECORD).emit()?;
    f.u16("length").emit()?;
    let body = span.sub(3, span.len.saturating_sub(4));
    cx.emit(Node::new("contents").span(body));
    let checksum = span.sub(span.len.saturating_sub(1), 1);
    let byte = cx.read_avail(checksum).await?;
    cx.emit(
        Node::new("checksum")
            .span(checksum)
            .value(crate::formats::util::binutil::hex(
                byte.first().copied().unwrap_or(0).into(),
                8,
            )),
    );
    Ok(())
}
