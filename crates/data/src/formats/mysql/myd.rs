//! MyISAM data files (`.MYD`). They have no header: rows start at offset
//! 0. With dynamic rows (tables with variable-length columns) every row
//! is in one or more blocks whose first byte gives the block type, its
//! lengths and the link to the row's next part; deleted blocks are linked
//! into a free list. Fixed-length rows have nothing to delimit them but
//! the row length, which the table's `.MYI` index file records, so they
//! are shown as one region. The format has no signature: it is offered by
//! extension.

use crate::bytes::{to_usize, u16_be, u32_be, u64_be};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::fmt::size;
use crate::formats::util::val::{hex, uint};
use crate::formats::{Format, Input, Probe};
use crate::node::{Count, Node};
use crate::span::{Origin, Span};
use crate::value::{EnumTable, Value, lookup};

pub static FORMAT: Format = Format {
    name: "myisam-data",
    title: "MyISAM data file (MYD)",
    extensions: &["myd"],
    mime: "application/x-myisam-data",
    probe: Probe::Never,
    dissect: crate::expander!(dissect: Input),
};

/// Parts of one row followed.
const MAX_PARTS: usize = 4096;

const BLOCK_TYPES: EnumTable = &[
    (0, "deleted"),
    (1, "whole row"),
    (2, "whole row (long)"),
    (3, "whole row with unused space"),
    (4, "whole row with unused space (long)"),
    (5, "first part of a row"),
    (6, "first part of a row (long)"),
    (7, "last part of a row"),
    (8, "last part of a row (long)"),
    (9, "last part with unused space"),
    (10, "last part with unused space (long)"),
    (11, "middle part of a row"),
    (12, "middle part of a row (long)"),
    (13, "first part of a row (very long)"),
];

/// A dynamic-row block header.
#[derive(Clone, Copy, Debug, Default)]
struct Block {
    kind: u8,
    header: u64,
    /// The whole row's length (blocks that start a row).
    row: Option<u64>,
    /// Row bytes in this block.
    data: u64,
    /// Unused bytes after the data.
    unused: u64,
    next: Option<u64>,
    /// Deleted blocks: the previous free block.
    prev: Option<u64>,
}

impl Block {
    fn total(&self) -> u64 {
        self.header
            .saturating_add(self.data)
            .saturating_add(self.unused)
    }
}

fn u24(b: &[u8], at: usize) -> Option<u64> {
    crate::bytes::u24_be(b, at).map(u64::from)
}

fn u16v(b: &[u8], at: usize) -> Option<u64> {
    u16_be(b, at).map(u64::from)
}

/// Decodes a block header (`_mi_get_block_info`).
fn block(b: &[u8]) -> Option<Block> {
    let kind = *b.first()?;
    let mut k = Block {
        kind,
        ..Block::default()
    };
    match kind {
        0 => {
            let total = u24(b, 1)?;
            k.header = 20;
            k.unused = total.checked_sub(20)?;
            k.next = u64_be(b, 4);
            k.prev = u64_be(b, 12);
        }
        1 | 7 => {
            k.header = 3;
            k.data = u16v(b, 1)?;
        }
        2 | 8 => {
            k.header = 4;
            k.data = u24(b, 1)?;
        }
        3 | 9 => {
            k.header = 4;
            k.data = u16v(b, 1)?;
            k.unused = (*b.get(3)?).into();
        }
        4 | 10 => {
            k.header = 5;
            k.data = u24(b, 1)?;
            k.unused = (*b.get(4)?).into();
        }
        5 => {
            k.header = 13;
            k.row = u16v(b, 1);
            k.data = u16v(b, 3)?;
            k.next = u64_be(b, 5);
        }
        6 => {
            k.header = 15;
            k.row = u24(b, 1);
            k.data = u24(b, 4)?;
            k.next = u64_be(b, 7);
        }
        11 => {
            k.header = 11;
            k.data = u16v(b, 1)?;
            k.next = u64_be(b, 3);
        }
        12 => {
            k.header = 12;
            k.data = u24(b, 1)?;
            k.next = u64_be(b, 4);
        }
        13 => {
            k.header = 16;
            k.row = u32_be(b, 1).map(u64::from);
            k.data = u24(b, 5)?;
            k.next = u64_be(b, 8);
        }
        _ => return None,
    }
    if matches!(kind, 1..=4) {
        k.row = Some(k.data);
    }
    // Blocks are at least 20 bytes (but a row's last part may be shorter
    // when it ends the file) and 4-byte aligned.
    (k.total() != 0).then_some(k)
}

/// Whether the file starts like dynamic rows: a few blocks that decode and
/// fit, each starting where the previous one ended.
async fn is_dynamic(cx: &Cx, file: Span) -> Result<bool> {
    let mut pos = 0u64;
    for _ in 0..8 {
        if pos >= file.len {
            return Ok(pos == file.len && pos != 0);
        }
        let b = cx.read(file.sub(pos, 20)).await?;
        let Some(k) = block(&b) else {
            return Ok(false);
        };
        if pos.saturating_add(k.total()) > file.len {
            return Ok(false);
        }
        pos = pos.saturating_add(k.total());
    }
    Ok(true)
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    if file.len == 0 {
        cx.annotate("MyISAM data file, empty");
        return Ok(());
    }
    // Opened by its extension, a file myisampack compressed.
    let head = cx.read_avail(file.sub(0, 8)).await?;
    if super::mypack::is_packed(&head) {
        let _ = cx.hand_off(&input, &super::mypack::FORMAT);
        return super::mypack::dissect(cx, input).await;
    }
    if is_dynamic(&cx, file).await? {
        cx.emit(
            Node::new("Blocks")
                .span(file)
                .summary("dynamic rows")
                .lazy(blocks, input),
        );
        cx.annotate(format!(
            "MyISAM data file, dynamic rows, {}",
            size(file.len)
        ));
    } else {
        cx.emit(
            Node::new("Rows")
                .span(file)
                .summary(size(file.len))
                .desc("Fixed-length or compressed rows: their length is in the table's .MYI file. A deleted fixed-length row starts with a zero byte and the next deleted row's position"),
        );
        cx.annotate(format!(
            "MyISAM data file, fixed-length or compressed rows, {}",
            size(file.len)
        ));
    }
    Ok(())
}

fn position(v: Option<u64>) -> String {
    match v {
        Some(u64::MAX) | None => "none".to_owned(),
        Some(p) => format!("{p:#x}"),
    }
}

async fn blocks(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let (mut pos, mut i) = cx.resume::<(u64, u64)>().unwrap_or((0, 0));
    while pos < file.len {
        cx.progress_in(file, pos);
        let at = (pos, i);
        cx.mark(move || at);
        let b = cx.read(file.sub(pos, 20)).await?;
        let Some(k) = block(&b).filter(|k| pos.saturating_add(k.total()) <= file.len) else {
            cx.push(
                Node::new("Unparsed data")
                    .span(file.tail(pos))
                    .diag(Diagnostic::malformed("not a valid block header")),
            )
            .await;
            break;
        };
        let span = file.sub(pos, k.total());
        let kind = lookup(BLOCK_TYPES, k.kind.into()).unwrap_or("?");
        let mut summary = match k.kind {
            0 => format!("deleted, {}", size(k.total())),
            _ => match k.row {
                Some(r) if k.next.is_some() => {
                    format!("{kind}: {} of a {}-byte row", size(k.data), r)
                }
                Some(r) => format!("{kind}: {r} bytes"),
                None => format!("{kind}: {}", size(k.data)),
            },
        };
        if let Some(n) = k.next.filter(|_| k.kind != 0) {
            summary.push_str(&format!(", continues at {n:#x}"));
        }
        let name = if matches!(k.kind, 1..=6 | 13) {
            let n = format!("Row at {pos:#x}");
            i = i.saturating_add(1);
            n
        } else {
            format!("Block at {pos:#x}")
        };
        cx.push(
            Node::new(name)
                .span(span)
                .summary(summary)
                .lazy(block_fields, (input, pos, k)),
        )
        .await;
        pos = pos.saturating_add(k.total());
    }
    cx.set_count(Count::Unknown);
    Ok(())
}

async fn block_fields(cx: Cx, (input, pos, k): (Input, u64, Block)) -> Result<()> {
    let file = input.span;
    let (header, data, unused) = (k.header, k.data, k.unused);
    let span = file.sub(pos, k.total());
    let b = cx.read(span.sub(0, header)).await?;
    let kind8 = k.kind;
    cx.emit(
        Node::new("Block type")
            .span(span.sub(0, 1))
            .value(Value::Enum {
                raw: kind8.into(),
                bits: 8,
                name: lookup(BLOCK_TYPES, kind8.into()),
            }),
    );
    let (row_at, row_len, data_at, data_len, unused_at, next_at) = match kind8 {
        0 => (None, 0, Some(1u64), 3u64, None, Some(4u64)),
        1 | 7 => (None, 0, Some(1), 2, None, None),
        2 | 8 => (None, 0, Some(1), 3, None, None),
        3 | 9 => (None, 0, Some(1), 2, Some(3u64), None),
        4 | 10 => (None, 0, Some(1), 3, Some(4), None),
        5 => (Some(1u64), 2, Some(3), 2, None, Some(5)),
        6 => (Some(1), 3, Some(4), 3, None, Some(7)),
        11 => (None, 0, Some(1), 2, None, Some(3)),
        12 => (None, 0, Some(1), 3, None, Some(4)),
        13 => (Some(1), 4, Some(5), 3, None, Some(8)),
        _ => (None, 0, None, 0, None, None),
    };
    if let Some(o) = row_at {
        cx.emit(
            Node::new("Row length")
                .span(span.sub(o, row_len))
                .value(uint(k.row.unwrap_or(0), 32)),
        );
    }
    if let Some(o) = data_at {
        cx.emit(
            Node::new(if kind8 == 0 {
                "Block length"
            } else {
                "Data length"
            })
            .span(span.sub(o, data_len))
            .value(uint(if kind8 == 0 { span.len } else { data }, 32)),
        );
    }
    if let Some(o) = unused_at {
        cx.emit(
            Node::new("Unused length")
                .span(span.sub(o, 1))
                .value(uint(unused, 8)),
        );
    }
    if let Some(o) = next_at {
        let v = u64_be(&b, to_usize(o)).unwrap_or(0);
        let mut n = Node::new(if kind8 == 0 {
            "Next deleted block"
        } else {
            "Next part"
        })
        .span(span.sub(o, 8))
        .value(hex(v, 64))
        .summary(position(Some(v)));
        if v < file.len {
            n = n.target(file.sub(v, 1));
        }
        cx.emit(n);
    }
    if kind8 == 0 {
        let v = u64_be(&b, 12).unwrap_or(0);
        let mut n = Node::new("Previous deleted block")
            .span(span.sub(12, 8))
            .value(hex(v, 64))
            .summary(position(Some(v)));
        if v < file.len {
            n = n.target(file.sub(v, 1));
        }
        cx.emit(n);
        cx.emit(Node::new("Free space").span(span.tail(20)));
        return Ok(());
    }
    cx.emit(
        Node::new("Row data")
            .span(span.sub(header, data))
            .summary(size(data)),
    );
    if unused != 0 {
        cx.emit(Node::new("Unused").span(span.sub(header.saturating_add(data), unused)));
    }
    if matches!(kind8, 5 | 6 | 13) {
        match row_pieces(&cx, file, pos).await {
            Ok(whole) => cx.emit(
                Node::new("Whole row")
                    .span(whole)
                    .summary(format!("{} bytes from its parts", whole.len))
                    .lazy(crate::formats::dissect_or_data, input.nested(whole)),
            ),
            Err(e) => cx.diag(e),
        }
    }
    Ok(())
}

/// A split row's parts, followed from its first block, as one piecewise
/// span.
async fn row_pieces(cx: &Cx, file: Span, start: u64) -> Result<Span> {
    let mut pieces = Vec::new();
    let mut pos = start;
    let mut seen = std::collections::BTreeSet::new();
    loop {
        if !seen.insert(pos) || pieces.len() >= MAX_PARTS {
            return Err(Diagnostic::malformed("the row's parts loop"));
        }
        let b = cx.read(file.sub(pos, 20)).await?;
        let Some(k) = block(&b).filter(|k| k.kind != 0) else {
            return Err(Diagnostic::malformed(format!("no row part at {pos:#x}")));
        };
        pieces.push(file.sub(pos.saturating_add(k.header), k.data));
        match k.next {
            Some(n) if matches!(k.kind, 5 | 6 | 11 | 12 | 13) => pos = n,
            _ => break,
        }
    }
    cx.add_pieces(
        Origin {
            parent: file.sub(start, 1),
            transform: "myisam-row",
        },
        pieces,
    )
}
