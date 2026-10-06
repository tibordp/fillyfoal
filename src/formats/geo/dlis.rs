//! More geoscience formats: ER Mapper raster headers and DLIS well logs.

use crate::bytes::u16_be;
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::lines::{Lines, is_text, number, tally};
use crate::formats::{Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, flag, lookup};

const BE: Endian = Endian::Big;

declare_format!(pub ERMAPPER_ERS = "ermapper-ers", "ER Mapper raster header (.ers)", ["ers"], "text/x-ermapper",
    Probe::Custom(|h| is_text(h) && h.data.trim_ascii_start().starts_with(b"DatasetHeader Begin")), ermapper);

/// One `X Begin … X End` block: name, span, entries and nested blocks.
#[derive(Clone, Debug)]
struct ErsBlock {
    name: String,
    span: Span,
    items: Vec<(String, String, Span)>,
    children: Vec<ErsBlock>,
}

async fn ermapper(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut stack: Vec<ErsBlock> = vec![ErsBlock {
        name: String::new(),
        span: file,
        items: Vec::new(),
        children: Vec::new(),
    }];
    while let Some(line) = lines.next().await? {
        let t = line.text();
        let t = t.trim();
        if let Some(name) = t.strip_suffix(" Begin") {
            if stack.len() < 64 {
                stack.push(ErsBlock {
                    name: name.trim().to_owned(),
                    span: line.span,
                    items: Vec::new(),
                    children: Vec::new(),
                });
            }
        } else if t.ends_with(" End") && stack.len() > 1 {
            if let Some(mut done) = stack.pop() {
                done.span = Span::new(
                    done.span.source,
                    done.span.offset,
                    line.span.end().saturating_sub(done.span.offset),
                );
                if let Some(top) = stack.last_mut() {
                    top.children.push(done);
                }
            }
        } else if let Some((k, v)) = t.split_once('=')
            && let Some(top) = stack.last_mut()
            && top.items.len() < 10_000
        {
            top.items.push((
                k.trim().to_owned(),
                v.trim().trim_matches('"').to_owned(),
                line.content(),
            ));
        }
    }
    while stack.len() > 1 {
        if let Some(done) = stack.pop()
            && let Some(top) = stack.last_mut()
        {
            top.children.push(done);
        }
    }
    let root = stack.pop().map(|r| r.children).unwrap_or_default();
    let find = |blocks: &[ErsBlock], key: &str| -> String {
        let mut todo: Vec<&ErsBlock> = blocks.iter().collect();
        while let Some(b) = todo.pop() {
            if let Some((_, v, _)) = b.items.iter().find(|(k, _, _)| k == key) {
                return v.clone();
            }
            todo.extend(b.children.iter());
        }
        String::new()
    };
    let summary = format!(
        "ER Mapper header, {}×{} × {} band(s), {}, datum {}",
        find(&root, "NrOfCellsPerLine"),
        find(&root, "NrOfLines"),
        find(&root, "NrOfBands"),
        find(&root, "CellType"),
        find(&root, "Datum")
    );
    ers_emit(&cx, root).await;
    cx.annotate(summary);
    Ok(())
}

async fn ers_emit(cx: &Cx, blocks: Vec<ErsBlock>) {
    for b in blocks {
        let n = b.items.len().saturating_add(b.children.len());
        cx.push(
            Node::new(b.name.clone())
                .span(b.span)
                .summary(format!("{n} entr(ies)"))
                .lazy(ers_block, b),
        )
        .await;
    }
}

async fn ers_block(cx: Cx, b: ErsBlock) -> Result<()> {
    for (k, v, span) in b.items {
        cx.push(Node::new(k).span(span).value(number(&v))).await;
    }
    for c in b.children {
        let n = c.items.len().saturating_add(c.children.len());
        cx.push(
            Node::new(c.name.clone())
                .span(c.span)
                .summary(format!("{n} entr(ies)"))
                .lazy(crate::expander!(self::ers_block: ErsBlock), c),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// DLIS (RP66 v1) well logs

declare_format!(pub DLIS = "dlis", "Digital Log Interchange Standard (DLIS)", ["dlis", "dls"], "application/x-dlis",
    Probe::Custom(|h| h.data.get(4..9) == Some(b"V1.00") && h.data.get(9..15) == Some(b"RECORD")), dlis);

const DLIS_ATTRS: FlagTable = &[
    flag(0x80, "explicitly formatted"),
    flag(0x40, "has predecessor"),
    flag(0x20, "has successor"),
    flag(0x10, "encrypted"),
    flag(0x08, "encryption packet"),
    flag(0x04, "checksum"),
    flag(0x02, "trailing length"),
    flag(0x01, "padding"),
];
const DLIS_EFLR: EnumTable = &[
    (0, "FHLR (file header)"),
    (1, "OLR (origin)"),
    (2, "AXIS"),
    (3, "CHANNL (channels)"),
    (4, "FRAME"),
    (5, "STATIC"),
    (6, "SCRIPT"),
    (7, "UPDATE"),
    (8, "UDI"),
    (9, "LNAME"),
    (10, "SPEC"),
    (11, "DICT"),
];
const DLIS_IFLR: EnumTable = &[(0, "FDATA (frame data)"), (1, "NOFORM"), (127, "EOD")];

async fn dlis(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let sul = cx.read(file.sub(0, 80)).await?;
    let field = |r: std::ops::Range<usize>| {
        String::from_utf8_lossy(sul.get(r).unwrap_or_default())
            .trim()
            .to_owned()
    };
    cx.emit(
        Node::new("Storage unit label")
            .span(file.sub(0, 80))
            .lazy(dlis_sul, file.sub(0, 80)),
    );
    let set_id = field(20..80);
    let mut cur = Cursor::new(&cx, file, BE);
    cur.seek(80);
    let mut visible = 0u64;
    let mut kinds: Vec<(String, u64)> = Vec::new();
    while cur.remaining() >= 4 {
        let start = cur.pos();
        let len = u64::from(cur.u16().await?);
        let marker = cur.u16().await?;
        if len < 4 || marker != 0xff01 {
            cx.diag(
                Diagnostic::malformed(format!("visible record header {len:#x} {marker:#06x}"))
                    .at(file.sub(start, 4)),
            );
            break;
        }
        let vr = file.sub(start, len);
        let mut segs = Vec::new();
        let mut at = 4u64;
        while at.saturating_add(4) <= len {
            let h = cx.read(vr.sub(at, 4)).await?;
            let slen = u64::from(u16_be(&h, 0).unwrap_or(0));
            let attrs = h.get(2).copied().unwrap_or(0);
            let kind = h.get(3).copied().unwrap_or(0);
            if slen < 4 {
                break;
            }
            let name = if attrs & 0x80 != 0 {
                lookup(DLIS_EFLR, kind.into())
            } else {
                lookup(DLIS_IFLR, kind.into())
            }
            .map_or_else(|| format!("type {kind}"), str::to_owned);
            if attrs & 0x40 == 0 {
                tally(&mut kinds, &name, 64);
            }
            segs.push((vr.sub(at, slen), attrs, kind, name));
            at = at.saturating_add(slen);
        }
        let n = segs.len();
        cx.push(
            Node::new(format!("Visible record {visible}"))
                .span(vr)
                .summary(format!("{n} segment(s)"))
                .lazy(dlis_segments, segs),
        )
        .await;
        visible = visible.saturating_add(1);
        cur.seek(start.saturating_add(len));
    }
    let parts: Vec<String> = kinds
        .iter()
        .map(|(k, n)| format!("{n} {}", k.split(' ').next().unwrap_or_default()))
        .collect();
    cx.annotate(format!(
        "DLIS {:?}, {visible} visible record(s); {}",
        set_id,
        parts.join(", ")
    ));
    Ok(())
}

async fn dlis_sul(cx: Cx, span: Span) -> Result<()> {
    let b = cx.block(span).await?;
    let mut f = crate::fields::Fields::emitting(&cx, &b, BE);
    f.ascii("Sequence number", 4).emit()?;
    f.ascii("DLIS version", 5).emit()?;
    f.ascii("Storage unit structure", 6).emit()?;
    f.ascii("Maximum record length", 5).emit()?;
    f.ascii("Storage set identifier", 60).emit()?;
    Ok(())
}

async fn dlis_segments(cx: Cx, segs: Vec<(Span, u8, u8, String)>) -> Result<()> {
    for (span, attrs, _, name) in segs {
        let mut node = Node::new(name)
            .span(span)
            .value(crate::formats::util::lines::flags(
                DLIS_ATTRS,
                attrs.into(),
                8,
            ));
        if attrs & 0x80 != 0 && attrs & 0x40 == 0 {
            // EFLR bodies start with a SET component: descriptor, type, name.
            let b = cx.read_avail(span.sub(4, 256)).await?;
            let desc = b.first().copied().unwrap_or(0);
            if desc >> 5 >= 5 {
                let n = usize::from(b.get(1).copied().unwrap_or(0));
                let set_type =
                    String::from_utf8_lossy(b.get(2..2usize.saturating_add(n)).unwrap_or_default())
                        .into_owned();
                node = node.summary(format!("set {set_type}"));
            }
        }
        cx.push(node).await;
    }
    Ok(())
}
