//! Rows: locating them on data pages, splitting them into columns (null
//! mask, fixed area, variable-length offset table), decoding values, long
//! values (memo and OLE) stored inline or on long-value pages, and the
//! usage maps that list a table's pages.

use std::collections::BTreeSet;

use super::tdef::{self, Column, TableDef};
use super::{Fmt, pointer, pointer_text};
use crate::bytes::{i16_le, i32_le, i64_le, to_u64, to_usize, u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::civil::ole_date;
use crate::formats::util::datakit::guid_le;
use crate::formats::util::{fmt as ufmt, val};
use crate::formats::{Input, dissect_or_data};
use crate::node::Node;
use crate::span::{Origin, Span};
use crate::value::Value;

/// Row offset flags.
pub const DELETED: u16 = 0x8000;
pub const OVERFLOW: u16 = 0x4000;
const OFFSET_MASK: u16 = 0x1fff;

/// Long values are previewed up to this many bytes.
const PREVIEW: usize = 4096;
/// ... and shown up to this many characters.
const PREVIEW_CHARS: usize = 1024;
/// OLE values at least this long are offered for format detection.
const MIN_DISSECT: usize = 16;
/// A long value chained over more pages than this is cut short.
const MAX_CHAIN: usize = 1 << 16;

/// One row of a data page: its offset word and its bounds in the page.
#[derive(Clone, Copy, Debug)]
pub struct Slot {
    pub raw: u16,
    pub start: usize,
    pub end: usize,
}

/// The rows of a data page. Rows are stored from the end of the page
/// downwards: row 0 ends at the end of the page, row i at the start of
/// row i-1.
pub fn slots(page: &[u8], fmt: Fmt) -> Vec<Slot> {
    let at = fmt.rows_at();
    let count = u16_le(page, at).unwrap_or(0);
    let mut out = Vec::new();
    let mut end = to_usize(fmt.page).min(page.len());
    for i in 0..usize::from(count) {
        let Some(raw) = u16_le(
            page,
            at.saturating_add(2).saturating_add(i.saturating_mul(2)),
        ) else {
            break;
        };
        let start = usize::from(raw & OFFSET_MASK);
        out.push(Slot {
            raw,
            start,
            end: end.max(start),
        });
        end = start.min(page.len());
    }
    out
}

/// Reads row `row` of page `page`: its span, bytes and offset word.
pub async fn locate(
    cx: &Cx,
    file: Span,
    fmt: Fmt,
    page: u32,
    row: u8,
) -> Result<(Span, Vec<u8>, u16)> {
    let span = fmt.page_span(file, page);
    let data = cx.read(span).await?;
    if data.first() != Some(&1) {
        return Err(Diagnostic::malformed(format!("page {page} is not a data page")).at(span));
    }
    let slot = slots(&data, fmt)
        .get(usize::from(row))
        .copied()
        .ok_or_else(|| Diagnostic::malformed(format!("page {page} has no row {row}")).at(span))?;
    let bytes = data.get(slot.start..slot.end).unwrap_or_default().to_vec();
    let len = slot.end.saturating_sub(slot.start);
    Ok((span.sub(to_u64(slot.start), to_u64(len)), bytes, slot.raw))
}

/// The pages a usage map lists, ascending. A map is a row whose first byte
/// is its type: 0 holds a start page and a bitmap inline, 1 lists the
/// pages of bitmaps (type 0x05 pages, the bitmap from offset 4), each
/// covering `(page size - 4) * 8` pages.
pub async fn usage_map(cx: &Cx, file: Span, fmt: Fmt, ptr: u32) -> Result<Vec<u32>> {
    let (page, row) = pointer(ptr);
    let (span, map, _) = locate(cx, file, fmt, page, row).await?;
    let total = u32::try_from(fmt.pages(file)).unwrap_or(u32::MAX);
    let mut out = BTreeSet::new();
    let mut bits = |bitmap: &[u8], base: u64| {
        for (i, &b) in bitmap.iter().enumerate() {
            if b == 0 {
                continue;
            }
            for bit in 0..8u64 {
                if b & (1u8 << bit) != 0 {
                    let no = base
                        .saturating_add(to_u64(i).saturating_mul(8))
                        .saturating_add(bit);
                    if let Ok(no) = u32::try_from(no)
                        && no < total
                    {
                        out.insert(no);
                    }
                }
            }
        }
    };
    match map.first() {
        Some(0) => {
            let start = u32_le(&map, 1).unwrap_or(0);
            bits(map.get(5..).unwrap_or_default(), start.into());
        }
        Some(1) => {
            let per = fmt.page.saturating_sub(4).saturating_mul(8);
            for (j, chunk) in map
                .get(1..)
                .unwrap_or_default()
                .as_chunks::<4>()
                .0
                .iter()
                .enumerate()
            {
                let pg = u32::from_le_bytes(*chunk);
                if pg == 0 || pg >= total {
                    continue;
                }
                let bitmap = cx.read(fmt.page_span(file, pg)).await?;
                bits(
                    bitmap.get(4..).unwrap_or_default(),
                    to_u64(j).saturating_mul(per),
                );
            }
        }
        Some(&t) => {
            return Err(Diagnostic::unsupported(format!("usage map type {t}")).at(span));
        }
        None => return Err(Diagnostic::malformed("empty usage map").at(span)),
    }
    Ok(out.into_iter().collect())
}

/// Where a column's value is in a row.
#[derive(Clone, Copy, Debug)]
pub enum Loc {
    Null,
    Bool(bool),
    /// Start and end in the row.
    Bytes(usize, usize),
}

/// Splits a row into its columns (in definition order). After the column
/// count (1 byte in Jet 3, 2 in Jet 4) come the fixed-length columns at
/// their offsets; the row ends with the variable-length offset table, the
/// variable column count and the null mask (a set bit means present; for
/// Boolean columns it is the value).
pub fn crack(row: &[u8], fmt: Fmt, def: &TableDef) -> std::result::Result<Vec<Loc>, String> {
    let len = row.len();
    let (row_cols, ccs) = if fmt.jet3 {
        (row.first().map(|&c| usize::from(c)), 1usize)
    } else {
        (u16_le(row, 0).map(usize::from), 2usize)
    };
    let row_cols = row_cols.ok_or("row too short for its column count")?;
    let mask_len = row_cols.div_ceil(8);
    let mask_start = len
        .checked_sub(mask_len)
        .filter(|&m| m >= ccs)
        .ok_or("row too short for its null mask")?;
    let mask = row.get(mask_start..).unwrap_or_default();
    let mut var: Vec<usize> = Vec::new();
    let mut row_var_cols = 0usize;
    if def.num_var_cols > 0 {
        if fmt.jet3 {
            let at = mask_start.checked_sub(1).ok_or("row too short")?;
            row_var_cols = usize::from(*row.get(at).ok_or("row too short")?);
            var = jet3_offsets(row, mask_len, row_var_cols)
                .ok_or("variable offset table out of the row")?;
        } else {
            let at = mask_start.checked_sub(2).ok_or("row too short")?;
            row_var_cols = usize::from(u16_le(row, at).ok_or("row too short")?);
            if row_var_cols.saturating_mul(2) > at {
                return Err("variable column count exceeds the row".into());
            }
            for i in 0..=row_var_cols {
                let o = at
                    .checked_sub(2usize.saturating_mul(i.saturating_add(1)))
                    .ok_or("variable offset table out of the row")?;
                var.push(usize::from(u16_le(row, o).unwrap_or(0)));
            }
        }
    }
    let fixed_limit = mask_start;
    let mut out = Vec::with_capacity(def.columns.len());
    for col in &def.columns {
        let n = usize::from(col.number);
        let present = n < row_cols && mask.get(n / 8).is_some_and(|&b| b & (1u8 << (n % 8)) != 0);
        if col.kind == 1 {
            out.push(Loc::Bool(present));
            continue;
        }
        if !present {
            out.push(Loc::Null);
            continue;
        }
        if col.fixed() {
            let start = ccs.saturating_add(usize::from(col.fixed_offset));
            let end = start.saturating_add(usize::from(col.size));
            if end > fixed_limit {
                return Err(format!("fixed column {} runs past the row", col.name));
            }
            out.push(Loc::Bytes(start, end));
        } else {
            let vi = usize::from(col.var_index);
            if vi >= row_var_cols {
                out.push(Loc::Null);
                continue;
            }
            let start = var.get(vi).copied().unwrap_or(0);
            let end = var.get(vi.saturating_add(1)).copied().unwrap_or(0);
            if start > end || end > len {
                return Err(format!("variable column {} has bad offsets", col.name));
            }
            out.push(Loc::Bytes(start, end));
        }
    }
    Ok(out)
}

/// Jet 3 stores one-byte variable offsets; rows longer than 256 bytes add
/// a jump table (the variable column index at which each 256-byte boundary
/// is crossed) between the count and the null mask, as in mdbtools.
fn jet3_offsets(row: &[u8], mask_len: usize, row_var_cols: usize) -> Option<Vec<usize>> {
    let len = row.len();
    let last = len.checked_sub(1)?;
    let mut num_jumps = last / 256;
    let col_ptr = last
        .checked_sub(mask_len)?
        .checked_sub(num_jumps)?
        .checked_sub(1)?;
    if col_ptr.saturating_sub(row_var_cols) / 256 < num_jumps {
        num_jumps = num_jumps.saturating_sub(1);
    }
    let mut jumps = 0usize;
    let mut out = Vec::with_capacity(row_var_cols.saturating_add(1).min(len));
    for i in 0..=row_var_cols {
        while jumps < num_jumps {
            let at = last
                .checked_sub(mask_len)?
                .checked_sub(jumps)?
                .checked_sub(1)?;
            if usize::from(*row.get(at)?) == i {
                jumps = jumps.saturating_add(1);
            } else {
                break;
            }
        }
        let b = *row.get(col_ptr.checked_sub(i)?)?;
        out.push(usize::from(b).saturating_add(jumps.saturating_mul(256)));
    }
    Some(out)
}

/// A long value's 12-byte header: the length and kind (top two bits: 0x80
/// inline, 0x40 one row elsewhere, 0 a chain of rows), then a row pointer.
#[derive(Clone, Copy, Debug)]
pub struct LongRef {
    pub len: u32,
    pub kind: u8,
    pub ptr: u32,
}

impl LongRef {
    pub fn parse(b: &[u8]) -> Option<LongRef> {
        let word = u32_le(b, 0)?;
        Some(LongRef {
            len: word & 0x3fff_ffff,
            kind: u8::try_from(word.wrapping_shr(24) & 0xc0).unwrap_or(0),
            ptr: u32_le(b, 4)?,
        })
    }
}

/// A decoded value with a short form for summaries.
pub struct Decoded {
    pub value: Option<Value>,
    pub preview: String,
    pub long: Option<LongRef>,
}

fn plain(value: Value, preview: String) -> Decoded {
    Decoded {
        value: Some(value),
        preview,
        long: None,
    }
}

/// Text: Jet 3 in the database code page; Jet 4 in UTF-16LE, or
/// "compressed" when it starts with FF FE: one byte per character, a zero
/// byte switching between that and UTF-16LE pairs (as mdbtools reads it).
pub fn text(b: &[u8], fmt: Fmt) -> String {
    if fmt.jet3 {
        return fmt.decode_bytes(b);
    }
    let Some(rest) = b.strip_prefix(&[0xff, 0xfe]) else {
        return crate::text::utf16(b, crate::fields::Endian::Little);
    };
    let mut units: Vec<u16> = Vec::with_capacity(rest.len());
    let mut compressed = true;
    let mut i = 0usize;
    while let Some(&c) = rest.get(i) {
        if c == 0 {
            compressed = !compressed;
            i = i.saturating_add(1);
        } else if compressed {
            units.push(c.into());
            i = i.saturating_add(1);
        } else {
            let Some(u) = u16_le(rest, i) else { break };
            units.push(u);
            i = i.saturating_add(2);
        }
    }
    String::from_utf16_lossy(&units)
}

fn bytes_preview(b: &[u8]) -> String {
    let hex: String = b.iter().take(16).map(|x| format!("{x:02x}")).collect();
    if b.len() > 16 {
        format!("{hex}…")
    } else {
        hex
    }
}

fn decimal(negative: bool, magnitude: u128, scale: u8) -> String {
    crate::formats::data::valuetree::decimal_string(
        negative,
        &magnitude.to_string(),
        0i64.saturating_sub(i64::from(scale)),
    )
}

/// Decodes a column value from its bytes.
pub fn value(col: &Column, b: &[u8], fmt: Fmt) -> Decoded {
    let n = b.len();
    let v = match col.kind {
        0x02 if n == 1 => b.first().map(|&x| plain(val::uint(x, 8), x.to_string())),
        0x03 => i16_le(b, 0)
            .filter(|_| n == 2)
            .map(|x| plain(val::int(x, 16), x.to_string())),
        0x04 | 0x12 => i32_le(b, 0)
            .filter(|_| n == 4)
            .map(|x| plain(val::int(x, 32), x.to_string())),
        0x13 => i64_le(b, 0)
            .filter(|_| n == 8)
            .map(|x| plain(val::int(x, 64), x.to_string())),
        0x05 => i64_le(b, 0).filter(|_| n == 8).map(|x| {
            let s = decimal(x < 0, x.unsigned_abs().into(), 4);
            plain(val::text(s.clone()), s)
        }),
        0x06 => u32_le(b, 0).filter(|_| n == 4).map(|x| {
            let f = f32::from_bits(x);
            plain(Value::f32(f), f.to_string())
        }),
        0x07 => u64_le(b, 0).filter(|_| n == 8).map(|x| {
            let f = f64::from_bits(x);
            plain(Value::f64(f), f.to_string())
        }),
        0x08 => u64_le(b, 0).filter(|_| n == 8).map(|x| {
            let days = f64::from_bits(x);
            match ole_date(days) {
                Some(unix_seconds) => plain(
                    Value::Timestamp { unix_seconds },
                    crate::formats::util::civil::date(unix_seconds),
                ),
                None => plain(Value::f64(days), days.to_string()),
            }
        }),
        0x0f if n == 16 => {
            let g = guid_le(b);
            Some(plain(Value::Guid(g), format!("{{{g}}}")))
        }
        // Decimal: a sign byte, then 16 bytes of magnitude as four
        // little-endian 32-bit words, most significant first.
        0x10 if n == 17 => {
            let mut m: u128 = 0;
            for w in 0..4usize {
                let word = u32_le(b, 1usize.saturating_add(w.saturating_mul(4))).unwrap_or(0);
                m = m.wrapping_shl(32) | u128::from(word);
            }
            let negative = b.first().is_some_and(|&s| s & 0x80 != 0);
            let s = decimal(negative, m, col.misc[1]);
            Some(plain(val::text(s.clone()), s))
        }
        0x0a => {
            let s = text(b, fmt);
            Some(plain(val::text(s.clone()), ufmt::preview(&s, 40)))
        }
        0x0b | 0x0c => {
            let r = LongRef::parse(b);
            match r {
                Some(r) if r.kind == 0x80 => {
                    let data = b
                        .get(12..12usize.saturating_add(to_usize(r.len.into())))
                        .unwrap_or_else(|| b.get(12..).unwrap_or_default());
                    Some(if col.kind == 0x0c {
                        let s = text(data, fmt);
                        plain(val::text(s.clone()), ufmt::preview(&s, 40))
                    } else {
                        plain(
                            Value::Bytes(data.iter().take(64).copied().collect()),
                            bytes_preview(data),
                        )
                    })
                }
                Some(r) => Some(Decoded {
                    value: None,
                    preview: format!("({})", ufmt::size(r.len.into())),
                    long: Some(r),
                }),
                None => None,
            }
        }
        _ => None,
    };
    v.unwrap_or_else(|| {
        plain(
            Value::Bytes(b.iter().take(64).copied().collect()),
            bytes_preview(b),
        )
    })
}

/// Where a row came from, for its lazy expansion.
#[derive(Clone, Copy, Debug)]
pub struct RowRef {
    pub input: Input,
    pub fmt: Fmt,
    pub tdef: u32,
    pub span: Span,
}

/// The list node for a row: a summary of its first values, the columns
/// on expansion.
pub fn row_node(name: String, bytes: &[u8], def: &TableDef, at: RowRef) -> Node {
    let node = Node::new(name).span(at.span);
    match crack(bytes, at.fmt, def) {
        Err(msg) => node.diag(Diagnostic::malformed(msg).at(at.span)),
        Ok(locs) => {
            let mut parts = Vec::new();
            for (col, loc) in def.columns.iter().zip(&locs).take(4) {
                parts.push(match *loc {
                    Loc::Null => "null".to_owned(),
                    Loc::Bool(v) => v.to_string(),
                    Loc::Bytes(s, e) => {
                        value(col, bytes.get(s..e).unwrap_or_default(), at.fmt).preview
                    }
                });
            }
            if def.columns.len() > 4 {
                parts.push("…".to_owned());
            }
            node.summary(parts.join(", ")).lazy(row_fields, at)
        }
    }
}

async fn row_fields(cx: Cx, at: RowRef) -> Result<()> {
    let def = tdef::load(&cx, at.input.span, at.fmt, at.tdef).await?;
    let bytes = cx.read(at.span).await?;
    let locs = crack(&bytes, at.fmt, &def).map_err(|m| Diagnostic::malformed(m).at(at.span))?;
    let mask_len = if at.fmt.jet3 {
        bytes.first().map(|&c| usize::from(c))
    } else {
        u16_le(&bytes, 0).map(usize::from)
    }
    .unwrap_or(0)
    .div_ceil(8);
    let mask_start = bytes.len().saturating_sub(mask_len);
    for (col, loc) in def.columns.iter().zip(locs) {
        let node = Node::new(col.name.clone());
        let n = usize::from(col.number);
        let mask_byte = at.span.sub(to_u64(mask_start.saturating_add(n / 8)), 1);
        let node = match loc {
            Loc::Null => node.summary("null").span(mask_byte),
            Loc::Bool(v) => node.value(Value::Bool(v)).span(mask_byte),
            Loc::Bytes(s, e) => {
                let span = at.span.sub(to_u64(s), to_u64(e.saturating_sub(s)));
                let raw = bytes.get(s..e).unwrap_or_default();
                let d = value(col, raw, at.fmt);
                let mut node = node.span(span);
                if let Some(v) = d.value {
                    node = node.value(v);
                }
                if let Some(r) = d.long {
                    node = node.summary(long_summary(r)).lazy(
                        long_value,
                        LongAt {
                            input: at.input,
                            fmt: at.fmt,
                            header: span.sub(0, 12),
                            r,
                            memo: col.kind == 0x0c,
                        },
                    );
                } else if col.kind == 0x0b && raw.len() >= 12 + MIN_DISSECT {
                    node = node.lazy(dissect_or_data, at.input.nested(span.tail(12)));
                }
                node
            }
        };
        cx.emit(node);
    }
    Ok(())
}

fn long_summary(r: LongRef) -> String {
    let (page, row) = pointer(r.ptr);
    let place = if r.kind == 0x40 {
        format!("page {page} row {row}")
    } else {
        format!("chain from page {page} row {row}")
    };
    format!("{}, {place}", ufmt::size(r.len.into()))
}

#[derive(Clone, Copy, Debug)]
pub struct LongAt {
    input: Input,
    fmt: Fmt,
    header: Span,
    r: LongRef,
    memo: bool,
}

/// Resolves a long value stored outside its row into one source: the row
/// it points to (kind 0x40), or a chain of rows each starting with the
/// pointer to the next (kind 0).
async fn long_value(cx: Cx, at: LongAt) -> Result<()> {
    let LongAt {
        input,
        fmt,
        header,
        r,
        memo,
    } = at;
    cx.emit(
        Node::new("Length")
            .span(header.sub(0, 4))
            .value(val::uint(r.len, 32))
            .summary(match r.kind {
                0x40 => "one long-value row",
                0 => "chain of long-value rows",
                _ => "unknown kind",
            }),
    );
    cx.emit(
        Node::new("Pointer")
            .span(header.sub(4, 4))
            .value(val::hex(r.ptr, 32))
            .summary(pointer_text(r.ptr)),
    );
    let file = input.span;
    let want = u64::from(r.len);
    let mut pieces = Vec::new();
    let mut got = 0u64;
    let mut problem = None;
    match r.kind {
        0x40 => {
            let (page, row) = pointer(r.ptr);
            let (span, _, _) = locate(&cx, file, fmt, page, row).await?;
            pieces.push(span.sub(0, want));
            got = span.len.min(want);
        }
        0 => {
            let mut ptr = r.ptr;
            let mut seen = BTreeSet::new();
            while got < want && ptr != 0 {
                if !seen.insert(ptr) || seen.len() > MAX_CHAIN {
                    problem = Some(Diagnostic::malformed("long value chain loops"));
                    break;
                }
                let (page, row) = pointer(ptr);
                let (span, bytes, _) = match locate(&cx, file, fmt, page, row).await {
                    Ok(x) => x,
                    Err(e) => {
                        problem = Some(e);
                        break;
                    }
                };
                let part = span.tail(4).sub(0, want.saturating_sub(got));
                if part.is_empty() && span.len <= 4 {
                    problem = Some(Diagnostic::malformed("empty long value row"));
                    break;
                }
                got = got.saturating_add(part.len);
                pieces.push(part);
                ptr = u32_le(&bytes, 0).unwrap_or(0);
            }
        }
        k => {
            return Err(Diagnostic::unsupported(format!("long value kind {k:#04x}")).at(header));
        }
    }
    if got < want && problem.is_none() {
        problem = Some(Diagnostic::malformed(format!(
            "long value has {got} of {want} bytes"
        )));
    }
    if pieces.is_empty() {
        return match problem {
            Some(p) => Err(p.at(header)),
            None => Ok(()),
        };
    }
    let span = cx
        .add_pieces_stepped(
            Origin {
                parent: header,
                transform: "jet-long-value",
            },
            &pieces,
        )
        .await?;
    let mut node = if memo {
        let head = cx.read(span.sub(0, to_u64(PREVIEW))).await?;
        let mut s = ufmt::clip(&text(&head, fmt), PREVIEW_CHARS);
        if span.len > to_u64(PREVIEW) && !s.ends_with('…') {
            s.push('…');
        }
        Node::new("Text").span(span).value(val::text(s))
    } else {
        let data = Node::new("Data").span(span);
        if span.len >= to_u64(MIN_DISSECT) {
            data.lazy(dissect_or_data, input.nested(span))
        } else {
            data
        }
    };
    if let Some(p) = problem {
        node = node.diag(p.at(header));
    }
    cx.emit(node);
    Ok(())
}
