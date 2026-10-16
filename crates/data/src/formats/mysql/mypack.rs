//! MyISAM data files compressed by `myisampack` (`mi_packrec.c`): a
//! 32-byte header (magic `FE FE 08`, version), a bit-packed description
//! of every column (how it is packed and which Huffman tree codes it),
//! the Huffman trees (byte trees, or trees over a column's distinct
//! values followed by those values), then the records: each a length
//! (and a blob length for tables with BLOB columns) and its Huffman-coded
//! columns.
//!
//! The number of columns and their lengths are only in the table's
//! `.MYI` index file. The column count is found from the header instead:
//! it is the one for which the column descriptions and the trees after
//! them fill the header exactly, as the server requires. The column
//! lengths are not recoverable, so records are delimited but their
//! columns are not decoded.

use crate::bytes::{to_u64, to_usize, u16_le, u32_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::fmt::{grouped_count, plural, size};
use crate::formats::util::val::{hex, uint};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, Value, lookup};

pub static FORMAT: Format = Format {
    name: "myisam-packed",
    title: "MyISAM compressed data file (myisampack)",
    extensions: &["myd"],
    mime: "application/x-myisam-packed",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

const HEAD: u64 = 32;
/// Header bytes read at most (the column descriptions and the trees).
const MAX_HEADER: u64 = 256 << 10;
/// Columns a MyISAM table can have.
const MAX_FIELDS: usize = 4096;

const FIELD_TYPES: EnumTable = &[
    (0, "normal"),
    (1, "skip end spaces"),
    (2, "skip leading spaces"),
    (3, "skip zeros"),
    (4, "BLOB"),
    (5, "constant"),
    (6, "distinct values"),
    (7, "always zero"),
    (8, "VARCHAR"),
    (9, "check"),
];

/// The magic, a known version and a header that fits.
pub fn is_packed(d: &[u8]) -> bool {
    d.starts_with(&[0xfe, 0xfe, 0x08])
        && matches!(d.get(3), Some(1 | 2))
        && u32_le(d, 4).is_some_and(|h| u64::from(h) >= HEAD)
}

fn probe(h: &Head<'_>) -> bool {
    is_packed(h.data) && u32_le(h.data, 4).is_some_and(|l| !h.len_known || u64::from(l) <= h.len)
}

/// A big-endian bit reader (`get_bits`).
struct Bits<'a> {
    b: &'a [u8],
    bit: u64,
}

impl Bits<'_> {
    fn get(&mut self, n: u32) -> Option<u32> {
        let mut v = 0u32;
        for _ in 0..n {
            let byte = *self.b.get(to_usize(self.bit / 8))?;
            let shift = 7u64.saturating_sub(self.bit % 8);
            let bit = byte
                .checked_shr(u32::try_from(shift).unwrap_or(0))
                .unwrap_or(0)
                & 1;
            v = (v << 1) | u32::from(bit);
            self.bit = self.bit.saturating_add(1);
        }
        Some(v)
    }

    fn align(&mut self) {
        self.bit = self.bit.div_ceil(8).saturating_mul(8);
    }

    fn byte(&self) -> u64 {
        self.bit / 8
    }
}

/// One column's description.
#[derive(Clone, Copy, Debug)]
struct Field {
    base: u32,
    pack: u32,
    space_bits: u32,
    tree: u32,
}

/// One Huffman tree.
#[derive(Clone, Debug)]
struct Tree {
    /// Byte offset in the header area and length (with its values).
    at: u64,
    len: u64,
    /// Codes distinct values (stored after the tree) rather than bytes.
    values: bool,
    min_chr: u32,
    elements: u32,
    char_bits: u32,
    offset_bits: u32,
    interval_len: u32,
    /// The decode table: entries with the high bit are leaves.
    table: Vec<u16>,
}

/// Bits per tree index (`max_bit`).
fn tree_bits(trees: u32) -> u32 {
    let mut v = trees.saturating_sub(1);
    let mut power: u32 = 1;
    while v > 1 {
        v >>= 1;
        power = power.saturating_add(1);
    }
    power
}

/// Reads one tree (`read_huff_table`) at the reader's position.
fn read_tree(r: &mut Bits<'_>, end: u64) -> Option<Tree> {
    let at = r.byte();
    let values = r.get(1)? == 1;
    let (min_chr, elements, interval_len) = if values {
        (0, r.get(15)?, r.get(16)?)
    } else {
        (r.get(8)?, r.get(9)?, 0)
    };
    let char_bits = r.get(5)?;
    let offset_bits = r.get(5)?;
    if elements == 0 {
        return None;
    }
    let size = usize::try_from(elements.saturating_mul(2).saturating_sub(2)).ok()?;
    let mut table = Vec::with_capacity(size.min(1 << 16));
    for i in 0..size {
        if r.get(1)? == 1 {
            let off = r.get(offset_bits)?;
            if off == 0 || i.saturating_add(to_usize(off.into())) >= size {
                return None;
            }
            table.push(u16::try_from(off).ok()?);
        } else {
            let c = r.get(char_bits)?.checked_add(min_chr)?;
            table.push(0x8000 | u16::try_from(c).ok()?);
        }
    }
    r.align();
    if values {
        r.bit = r
            .bit
            .checked_add(u64::from(interval_len).saturating_mul(8))?;
    }
    if r.byte() > end {
        return None;
    }
    Some(Tree {
        at,
        len: r.byte().saturating_sub(at),
        values,
        min_chr,
        elements,
        char_bits,
        offset_bits,
        interval_len,
        table,
    })
}

/// The column descriptions and trees, if `n` columns make them fill the
/// header exactly.
fn layout(area: &[u8], n: usize, trees: u32) -> Option<(Vec<Field>, Vec<Tree>)> {
    let tb = tree_bits(trees);
    let mut r = Bits { b: area, bit: 0 };
    let mut fields = Vec::with_capacity(n);
    for _ in 0..n {
        let f = Field {
            base: r.get(5)?,
            pack: r.get(6)?,
            space_bits: r.get(5)?,
            tree: r.get(tb)?,
        };
        fields.push(f);
    }
    r.align();
    let end = to_u64(area.len());
    let mut out = Vec::new();
    for _ in 0..trees {
        out.push(read_tree(&mut r, end)?);
    }
    (r.byte() == end).then_some((fields, out))
}

/// A column description's fields are in range.
fn valid(f: &Field, trees: u32) -> bool {
    f.base <= 9 && f.pack <= 7 && f.space_bits <= 31 && (f.tree < trees || trees == 0)
}

/// Finds the column count: the smallest whose descriptions are valid and
/// whose trees end exactly at the end of the header.
async fn find_layout(cx: &Cx, area: &[u8], trees: u32) -> Option<(Vec<Field>, Vec<Tree>)> {
    let tb = tree_bits(trees);
    let mut r = Bits { b: area, bit: 0 };
    for n in 1..=MAX_FIELDS {
        let f = Field {
            base: r.get(5)?,
            pack: r.get(6)?,
            space_bits: r.get(5)?,
            tree: r.get(tb)?,
        };
        if !valid(&f, trees) {
            return None;
        }
        let found = layout(area, n, trees);
        // Each try reads the trees once.
        cx.charge(to_u64(area.len()) / 64).await;
        if found.is_some() {
            return found;
        }
    }
    None
}

/// A record's length (`read_pack_length`): the value and its bytes.
fn pack_length(b: &[u8], at: usize, version: u8) -> Option<(u64, u64)> {
    let first = *b.get(at)?;
    Some(match first {
        0..=253 => (first.into(), 1),
        254 => (u16_le(b, at.checked_add(1)?)?.into(), 3),
        _ if version == 1 => (crate::bytes::u24_le(b, at.checked_add(1)?)?.into(), 4),
        _ => (u32_le(b, at.checked_add(1)?)?.into(), 5),
    })
}

/// What every expansion needs.
#[derive(Clone)]
struct Packed {
    file: Span,
    header_len: u64,
    version: u8,
    blobs: bool,
    min_len: u64,
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, HEAD)).await?;
    if !is_packed(&head) {
        return Err(Diagnostic::malformed("not a myisampack data file"));
    }
    let version = head.get(3).copied().unwrap_or(2);
    let header_len = u64::from(u32_le(&head, 4).unwrap_or(0));
    let min_len = u32_le(&head, 8).unwrap_or(0);
    let max_len = u32_le(&head, 12).unwrap_or(0);
    let elements = u32_le(&head, 16).unwrap_or(0);
    let interval_len = u32_le(&head, 20).unwrap_or(0);
    let trees = u32::from(u16_le(&head, 24).unwrap_or(0));
    cx.emit(
        Node::new("Header")
            .span(file.sub(0, HEAD))
            .summary(format!(
                "version {version}, {} of column descriptions and trees, {}",
                size(header_len.saturating_sub(HEAD)),
                plural(trees, "Huffman tree")
            ))
            .lazy(header, file),
    );
    if header_len > MAX_HEADER || header_len > file.len {
        return Err(Diagnostic::malformed(format!(
            "header of {header_len} bytes in a {}-byte file",
            file.len
        ))
        .at(file.sub(4, 4)));
    }
    let area_span = file.sub(HEAD, header_len.saturating_sub(HEAD));
    let area = cx.read(area_span).await?;
    let layout = find_layout(&cx, &area, trees).await;
    let blobs = layout
        .as_ref()
        .is_some_and(|(f, _)| f.iter().any(|f| f.base == 4));
    match &layout {
        Some((fields, tree_list)) => {
            let fields_end = tree_list.first().map_or(to_u64(area.len()), |t| t.at);
            cx.emit(
                Node::new("Columns")
                    .span(area_span.sub(0, fields_end))
                    .summary(format!(
                        "{}, bit-packed",
                        plural(fields.len(), "column")
                    ))
                    .desc("How each column is packed and which tree codes it; the first describes the null flags")
                    .lazy(columns, (area_span, trees, fields.len())),
            );
            cx.emit(
                Node::new("Huffman trees")
                    .span(area_span.sub(fields_end, to_u64(area.len()).saturating_sub(fields_end)))
                    .summary(format!(
                        "{}, {} in all",
                        plural(trees, "tree"),
                        plural(elements, "element")
                    ))
                    .lazy(tree_nodes, (area_span, trees, fields.len())),
            );
        }
        None => cx.emit(Node::new("Columns and trees").span(area_span).diag(
            Diagnostic::malformed(
                "no column count makes the descriptions and trees fill the header",
            ),
        )),
    }
    let p = Packed {
        file,
        header_len,
        version,
        blobs,
        min_len: min_len.into(),
    };
    cx.emit(
        Node::new("Records")
            .span(file.tail(header_len))
            .summary(size(file.len.saturating_sub(header_len)))
            .desc("Each: its length (and its BLOB data's length), then its Huffman-coded columns")
            .lazy(records, p),
    );
    let _ = interval_len;
    cx.annotate(format!(
        "MyISAM data file compressed by myisampack (version {version}){}, records of {min_len} to {max_len} bytes",
        layout
            .as_ref()
            .map(|(f, _)| format!(", {}", plural(f.len(), "column")))
            .unwrap_or_default()
    ));
    Ok(())
}

async fn header(cx: Cx, file: Span) -> Result<()> {
    let span = file.sub(0, HEAD);
    let b = cx.read(span).await?;
    let u32_at = |o: usize| u32_le(&b, o).unwrap_or(0);
    cx.emit(
        Node::new("Magic")
            .span(span.sub(0, 3))
            .value(Value::Bytes(b.get(..3).unwrap_or_default().to_vec())),
    );
    cx.emit(
        Node::new("Version")
            .span(span.sub(3, 1))
            .value(uint(b.get(3).copied().unwrap_or(0), 8))
            .desc("1: record lengths of up to 3 bytes after 0xff; 2: up to 4"),
    );
    for (name, at, desc) in [
        ("Header length", 4, "Records start here"),
        ("Shortest record", 8, ""),
        ("Longest record", 12, ""),
        ("Tree elements", 16, "In all the trees"),
        (
            "Distinct values length",
            20,
            "Bytes of the values coded by distinct-value trees",
        ),
    ] {
        let mut n = Node::new(name)
            .span(span.sub(at, 4))
            .value(uint(u32_at(to_usize(at)), 32));
        if !desc.is_empty() {
            n = n.desc(desc);
        }
        cx.emit(n);
    }
    cx.emit(
        Node::new("Trees")
            .span(span.sub(24, 2))
            .value(uint(u16_le(&b, 24).unwrap_or(0), 16)),
    );
    cx.emit(
        Node::new("Reference length")
            .span(span.sub(26, 1))
            .value(uint(b.get(26).copied().unwrap_or(0), 8))
            .desc("Bytes read to decode a record's lengths"),
    );
    cx.emit(
        Node::new("Record pointer length")
            .span(span.sub(27, 1))
            .value(uint(b.get(27).copied().unwrap_or(0), 8)),
    );
    Ok(())
}

fn pack_flags(p: u32) -> String {
    let mut out = Vec::new();
    if p & 1 != 0 {
        out.push("selected");
    }
    if p & 2 != 0 {
        out.push("space fields");
    }
    if p & 4 != 0 {
        out.push("zero fill");
    }
    if out.is_empty() {
        "none".to_owned()
    } else {
        out.join(", ")
    }
}

async fn columns(cx: Cx, (area_span, trees, n): (Span, u32, usize)) -> Result<()> {
    let area = cx.read(area_span).await?;
    let Some((fields, _)) = layout(&area, n, trees) else {
        return Ok(());
    };
    let tb = tree_bits(trees);
    let per = 16u64.saturating_add(tb.into());
    cx.set_count(Count::Exact(to_u64(fields.len())));
    for (i, f) in fields.iter().enumerate() {
        let start = to_u64(i).saturating_mul(per);
        let end = start.saturating_add(per);
        let bytes = area_span.sub(start / 8, end.div_ceil(8).saturating_sub(start / 8));
        let mut summary = format!("tree {}", f.tree);
        if f.pack != 0 {
            summary.push_str(&format!(", {}", pack_flags(f.pack)));
        }
        if f.space_bits != 0 {
            summary.push_str(&format!(", {}-bit space counts", f.space_bits));
        }
        let node = Node::new(if i == 0 {
            "Column 0 (null flags)".to_owned()
        } else {
            format!("Column {i}")
        })
        .span(bytes)
        .summary(summary)
        .value(Value::Enum {
            raw: f.base.into(),
            bits: 5,
            name: lookup(FIELD_TYPES, f.base.into()).map(Into::into),
        });
        cx.push(node).await;
    }
    Ok(())
}

async fn tree_nodes(cx: Cx, (area_span, trees, n): (Span, u32, usize)) -> Result<()> {
    let area = cx.read(area_span).await?;
    let Some((_, list)) = layout(&area, n, trees) else {
        return Ok(());
    };
    cx.set_count(Count::Exact(to_u64(list.len())));
    for (i, t) in list.iter().enumerate() {
        cx.checkpoint().await;
        let summary = if t.values {
            format!(
                "{} distinct values, {} of them",
                t.elements,
                size(t.interval_len.into())
            )
        } else {
            format!("{} byte values from {:#04x}", t.elements, t.min_chr)
        };
        cx.push(
            Node::new(format!("Tree {i}"))
                .span(area_span.sub(t.at, t.len))
                .summary(summary)
                .lazy(tree_codes, (area_span, trees, n, i)),
        )
        .await;
    }
    Ok(())
}

/// One tree's codes, from its decode table.
async fn tree_codes(cx: Cx, (area_span, trees, n, i): (Span, u32, usize, usize)) -> Result<()> {
    let area = cx.read(area_span).await?;
    let Some((_, list)) = layout(&area, n, trees) else {
        return Ok(());
    };
    let Some(t) = list.get(i) else {
        return Ok(());
    };
    cx.emit(
        Node::new("Codes").value(Value::Text(
            if t.values {
                "distinct column values"
            } else {
                "byte values"
            }
            .to_owned(),
        )),
    );
    cx.emit(Node::new("Elements").value(uint(t.elements, 32)));
    cx.emit(Node::new("Value bits").value(uint(t.char_bits, 8)));
    cx.emit(Node::new("Offset bits").value(uint(t.offset_bits, 8)));
    // Walk the table depth first: (entry, code so far, its length).
    let mut codes = Vec::new();
    let mut stack = vec![(0usize, 0u64, 0u32)];
    while let Some((node, code, len)) = stack.pop() {
        if codes.len() >= 1024 || len >= 64 {
            break;
        }
        for bit in [1u64, 0] {
            let at = node.saturating_add(to_usize(bit));
            let Some(&v) = t.table.get(at) else {
                continue;
            };
            let c = (code << 1) | bit;
            if v & 0x8000 != 0 {
                codes.push((v & 0x7fff, c, len.saturating_add(1)));
            } else {
                stack.push((at.saturating_add(v.into()), c, len.saturating_add(1)));
            }
        }
    }
    codes.sort_unstable();
    let mut node =
        Node::new("Code list").summary(grouped_count(to_u64(codes.len()), "code", "codes"));
    if t.values && t.interval_len != 0 {
        node = node.desc("Leaves are indexes into the distinct values after the tree");
    }
    cx.emit(node.lazy(code_list, codes));
    Ok(())
}

async fn code_list(cx: Cx, codes: Vec<(u16, u64, u32)>) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(codes.len())));
    for (v, code, len) in codes {
        let bits: String = (0..len)
            .rev()
            .map(|i| if (code >> i) & 1 == 1 { '1' } else { '0' })
            .collect();
        cx.push(Node::new(bits).value(hex(v, 16))).await;
    }
    Ok(())
}

async fn records(cx: Cx, p: Packed) -> Result<()> {
    let file = p.file;
    let (mut pos, mut i) = cx.resume::<(u64, u64)>().unwrap_or((p.header_len, 0));
    while pos < file.len {
        cx.progress_in(file, pos);
        let at = (pos, i);
        cx.mark(move || at);
        let b = cx.read_avail(file.sub(pos, 10)).await?;
        let Some((len, n1)) = pack_length(&b, 0, p.version) else {
            break;
        };
        if len < p.min_len.max(1) {
            // myisampack ends the file with a few zero bytes (for memory
            // mapping); anything else is not a record.
            let rest = file.tail(pos);
            let tail = cx.read_avail(rest.sub(0, 64)).await?;
            let node = Node::new("Padding").span(rest);
            cx.push(if rest.len <= 64 && tail.iter().all(|&x| x == 0) {
                node.summary(size(rest.len))
            } else {
                node.diag(Diagnostic::malformed(format!(
                    "a {len}-byte record, shorter than the shortest ({})",
                    p.min_len
                )))
            })
            .await;
            break;
        }
        let (blob, n2) = if p.blobs {
            match pack_length(&b, to_usize(n1), p.version) {
                Some(v) => (Some(v.0), v.1),
                None => break,
            }
        } else {
            (None, 0)
        };
        let head = n1.saturating_add(n2);
        let total = head.saturating_add(len);
        if pos.saturating_add(total) > file.len {
            cx.push(Node::new(format!("Record {i}")).span(file.tail(pos)).diag(
                Diagnostic::truncated(file.sub(pos, total), file.len.saturating_sub(pos)),
            ))
            .await;
            break;
        }
        let span = file.sub(pos, total);
        let mut summary = format!("{len} bytes of coded columns");
        if let Some(bl) = blob {
            summary.push_str(&format!(", {bl} bytes of BLOB data"));
        }
        cx.push(
            Node::new(format!("Record {i}"))
                .span(span)
                .summary(summary)
                .lazy(record, (span, n1, n2, len, blob)),
        )
        .await;
        pos = pos.saturating_add(total.max(1));
        i = i.saturating_add(1);
    }
    Ok(())
}

async fn record(
    cx: Cx,
    (span, n1, n2, len, blob): (Span, u64, u64, u64, Option<u64>),
) -> Result<()> {
    cx.emit(
        Node::new("Length")
            .span(span.sub(0, n1))
            .value(uint(len, 32)),
    );
    if let Some(bl) = blob {
        cx.emit(
            Node::new("BLOB length")
                .span(span.sub(n1, n2))
                .value(uint(bl, 32))
                .desc("Bytes of all the record's BLOB values once decoded"),
        );
    }
    cx.emit(
        Node::new("Coded columns")
            .span(span.sub(n1.saturating_add(n2), len))
            .desc("A bit stream: each column as its description says, coded by its tree; their lengths are in the .MYI file"),
    );
    Ok(())
}
