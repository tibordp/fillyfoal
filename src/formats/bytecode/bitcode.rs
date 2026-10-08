//! LLVM bitcode (`BC C0 DE`, optionally inside the `0x0B17C0DE` wrapper
//! Apple toolchains add).
//!
//! The bitstream is a tree of blocks holding records, encoded with
//! per-block abbreviations (some defined in a `BLOCKINFO` block). Expanding
//! a block decodes its records in pages; nested blocks are listed with their
//! size and decoded only when expanded. Known record kinds are named, and
//! records whose operands are characters are shown as text.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::bytes::{to_u64, u32_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::util::binutil::{NodeExt, ellipsize, name_or, text};
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Value};

/// Largest bitstream decoded in memory.
const MAX_STREAM: u64 = 32 << 20;
/// Operands kept per record (the rest are skipped).
const MAX_OPERANDS: usize = 4096;
const MAX_DEPTH: u32 = 32;

pub static FORMAT: Format = Format {
    name: "llvm-bitcode",
    title: "LLVM bitcode",
    extensions: &["bc"],
    mime: "application/x-llvm-bitcode",
    probe: Probe::Magic(&[(0, b"BC\xc0\xde"), (0, b"\xde\xc0\x17\x0b")]),
    dissect: crate::expander!(dissect: Input),
};

const BLOCK: EnumTable = &[
    (0, "BLOCKINFO"),
    (8, "MODULE_BLOCK"),
    (9, "PARAMATTR_BLOCK"),
    (10, "PARAMATTR_GROUP_BLOCK"),
    (11, "CONSTANTS_BLOCK"),
    (12, "FUNCTION_BLOCK"),
    (13, "IDENTIFICATION_BLOCK"),
    (14, "VALUE_SYMTAB_BLOCK"),
    (15, "METADATA_BLOCK"),
    (16, "METADATA_ATTACHMENT"),
    (17, "TYPE_BLOCK_NEW"),
    (18, "USELIST_BLOCK"),
    (19, "MODULE_STRTAB_BLOCK"),
    (20, "GLOBALVAL_SUMMARY_BLOCK"),
    (21, "OPERAND_BUNDLE_TAGS_BLOCK"),
    (22, "METADATA_KIND_BLOCK"),
    (23, "STRTAB_BLOCK"),
    (24, "FULL_LTO_GLOBALVAL_SUMMARY_BLOCK"),
    (25, "SYMTAB_BLOCK"),
    (26, "SYNC_SCOPE_NAMES_BLOCK"),
];

const MODULE_CODES: EnumTable = &[
    (1, "VERSION"),
    (2, "TRIPLE"),
    (3, "DATALAYOUT"),
    (4, "ASM"),
    (5, "SECTIONNAME"),
    (6, "DEPLIB"),
    (7, "GLOBALVAR"),
    (8, "FUNCTION"),
    (9, "ALIAS_OLD"),
    (11, "GCNAME"),
    (12, "COMDAT"),
    (13, "VSTOFFSET"),
    (14, "ALIAS"),
    (16, "SOURCE_FILENAME"),
    (17, "HASH"),
    (18, "IFUNC"),
];

const IDENTIFICATION_CODES: EnumTable = &[(1, "STRING"), (2, "EPOCH")];
const BLOCKINFO_CODES: EnumTable = &[(1, "SETBID"), (2, "BLOCKNAME"), (3, "SETRECORDNAME")];
const BLOB_CODES: EnumTable = &[(1, "BLOB")];
const TYPE_CODES: EnumTable = &[
    (1, "NUMENTRY"),
    (2, "VOID"),
    (3, "FLOAT"),
    (4, "DOUBLE"),
    (5, "LABEL"),
    (6, "OPAQUE"),
    (7, "INTEGER"),
    (8, "POINTER"),
    (11, "ARRAY"),
    (12, "VECTOR"),
    (16, "METADATA"),
    (18, "STRUCT_ANON"),
    (19, "STRUCT_NAME"),
    (20, "STRUCT_NAMED"),
    (21, "FUNCTION"),
    (25, "OPAQUE_POINTER"),
];

fn record_names(block: u64) -> EnumTable {
    match block {
        0 => BLOCKINFO_CODES,
        8 => MODULE_CODES,
        13 => IDENTIFICATION_CODES,
        17 => TYPE_CODES,
        23 | 25 => BLOB_CODES,
        _ => &[],
    }
}

// ---------------------------------------------------------------------------
// Bit reading

struct Bits<'a> {
    data: &'a [u8],
    /// Position in bits.
    pos: u64,
}

impl Bits<'_> {
    fn remaining(&self) -> u64 {
        to_u64(self.data.len())
            .saturating_mul(8)
            .saturating_sub(self.pos)
    }

    fn read(&mut self, n: u32) -> Option<u64> {
        if n > 64 || u64::from(n) > self.remaining() {
            return None;
        }
        let mut value = 0u64;
        let mut got = 0u32;
        while got < n {
            let byte = *self.data.get(crate::bytes::to_usize(self.pos >> 3))?;
            let offset = u32::try_from(self.pos & 7).ok()?;
            let take = (8u32.checked_sub(offset)?).min(n.checked_sub(got)?);
            let bits = u64::from(byte >> offset) & ((1u64 << take).checked_sub(1)?);
            value |= bits.checked_shl(got)?;
            got = got.checked_add(take)?;
            self.pos = self.pos.checked_add(take.into())?;
        }
        Some(value)
    }

    fn vbr(&mut self, n: u32) -> Option<u64> {
        if !(2..=32).contains(&n) {
            return None;
        }
        let high = 1u64 << n.checked_sub(1)?;
        let mut value = 0u64;
        let mut shift = 0u32;
        loop {
            let piece = self.read(n)?;
            value |= (piece & high.checked_sub(1)?).checked_shl(shift)?;
            if piece & high == 0 {
                return Some(value);
            }
            shift = shift.checked_add(n.checked_sub(1)?)?;
            if shift >= 64 {
                return None;
            }
        }
    }

    fn align32(&mut self) {
        self.pos = self.pos.checked_next_multiple_of(32).unwrap_or(u64::MAX);
    }
}

#[derive(Clone, Debug)]
enum Op {
    Literal(u64),
    Fixed(u32),
    Vbr(u32),
    Array,
    Char6,
    Blob,
}

type Abbrev = Vec<Op>;

/// Abbreviations defined in BLOCKINFO, per block ID.
type BlockInfo = Arc<BTreeMap<u64, Vec<Abbrev>>>;

fn read_abbrev(b: &mut Bits<'_>) -> Option<Abbrev> {
    let n = b.vbr(5)?;
    let mut ops = Vec::new();
    for _ in 0..n.min(256) {
        let literal = b.read(1)?;
        if literal == 1 {
            ops.push(Op::Literal(b.vbr(8)?));
            continue;
        }
        ops.push(match b.read(3)? {
            1 => Op::Fixed(u32::try_from(b.vbr(5)?).ok().filter(|&w| w <= 64)?),
            2 => Op::Vbr(u32::try_from(b.vbr(5)?).ok().filter(|&w| w <= 32)?),
            3 => Op::Array,
            4 => Op::Char6,
            5 => Op::Blob,
            _ => return None,
        });
    }
    Some(ops)
}

fn scalar(b: &mut Bits<'_>, op: &Op) -> Option<u64> {
    match op {
        Op::Literal(v) => Some(*v),
        Op::Fixed(w) => b.read(*w),
        Op::Vbr(w) => b.vbr(*w),
        Op::Char6 => {
            let v = b.read(6)?;
            Some(u64::from(match v {
                0..=25 => b'a'.checked_add(u8::try_from(v).ok()?)?,
                26..=51 => b'A'.checked_add(u8::try_from(v.checked_sub(26)?).ok()?)?,
                52..=61 => b'0'.checked_add(u8::try_from(v.checked_sub(52)?).ok()?)?,
                62 => b'.',
                _ => b'_',
            }))
        }
        Op::Array | Op::Blob => None,
    }
}

struct Record {
    code: u64,
    operands: Vec<u64>,
    /// Byte range of a blob operand, relative to the stream.
    blob: Option<(u64, u64)>,
}

fn push_operand(ops: &mut Vec<u64>, v: u64) {
    if ops.len() < MAX_OPERANDS {
        ops.push(v);
    }
}

fn unabbreviated(b: &mut Bits<'_>) -> Option<Record> {
    let code = b.vbr(6)?;
    let n = b.vbr(6)?;
    if n > b.remaining() {
        return None;
    }
    let mut operands = Vec::new();
    for _ in 0..n {
        push_operand(&mut operands, b.vbr(6)?);
    }
    Some(Record {
        code,
        operands,
        blob: None,
    })
}

fn abbreviated(b: &mut Bits<'_>, abbrev: &Abbrev) -> Option<Record> {
    let mut values = Vec::new();
    let mut blob = None;
    let mut i = 0usize;
    while let Some(op) = abbrev.get(i) {
        match op {
            Op::Array => {
                let element = abbrev.get(i.checked_add(1)?)?;
                let n = b.vbr(6)?;
                // Every element costs at least one bit, except literals.
                if n > b.remaining().saturating_add(1)
                    || matches!(element, Op::Literal(_)) && n > 0x1_0000
                {
                    return None;
                }
                for _ in 0..n {
                    push_operand(&mut values, scalar(b, element)?);
                }
                i = i.checked_add(2)?;
                continue;
            }
            Op::Blob => {
                let n = b.vbr(6)?;
                b.align32();
                let start = b.pos >> 3;
                let bits = n.checked_mul(8)?;
                if bits > b.remaining() {
                    return None;
                }
                b.pos = b.pos.checked_add(bits)?;
                b.align32();
                blob = Some((start, n));
            }
            other => push_operand(&mut values, scalar(b, other)?),
        }
        i = i.checked_add(1)?;
    }
    let mut it = values.into_iter();
    let code = it.next()?;
    Some(Record {
        code,
        operands: it.collect(),
        blob,
    })
}

// ---------------------------------------------------------------------------
// Blocks

#[derive(Clone)]
struct Stream {
    data: Arc<Vec<u8>>,
    span: Span,
}

#[derive(Clone)]
struct BlockState {
    stream: Stream,
    id: u64,
    /// Bit position of the first abbreviation ID inside the block.
    start: u64,
    /// Bit position just past the block.
    end: u64,
    width: u32,
    info: BlockInfo,
    depth: u32,
}

/// Reads an ENTER_SUBBLOCK header (after its abbreviation ID).
fn enter(b: &mut Bits<'_>) -> Option<(u64, u32, u64)> {
    let id = b.vbr(8)?;
    let width = u32::try_from(b.vbr(4)?)
        .ok()
        .filter(|&w| (1..=32).contains(&w))?;
    b.align32();
    let words = b.read(32)?;
    let start = b.pos;
    let end = start.checked_add(words.checked_mul(32)?)?;
    Some((id, width, end))
}

/// Collects the abbreviations a BLOCKINFO block defines.
async fn read_blockinfo(
    cx: &Cx,
    data: &[u8],
    start: u64,
    end: u64,
    width: u32,
    info: &mut BTreeMap<u64, Vec<Abbrev>>,
) -> Option<()> {
    let mut b = Bits { data, pos: start };
    let mut current = None;
    while b.pos < end {
        cx.checkpoint().await;
        match b.read(width)? {
            0 => return Some(()),
            2 => {
                let abbrev = read_abbrev(&mut b)?;
                info.entry(current?).or_default().push(abbrev);
            }
            3 => {
                let r = unabbreviated(&mut b)?;
                if r.code == 1 {
                    current = r.operands.first().copied();
                }
            }
            _ => return None,
        }
    }
    Some(())
}

fn as_text(ops: &[u64]) -> Option<String> {
    if ops.is_empty() || ops.len() >= MAX_OPERANDS {
        return None;
    }
    let bytes: Option<Vec<u8>> = ops
        .iter()
        .map(|&v| {
            u8::try_from(v)
                .ok()
                .filter(|c| c.is_ascii_graphic() || *c == b' ')
        })
        .collect();
    bytes.map(|b| String::from_utf8_lossy(&b).into_owned())
}

fn block_label(id: u64) -> String {
    name_or(BLOCK, id, "block")
}

/// Walks a block's contents: records become nodes (decoded), nested blocks
/// become lazy nodes. `visit` sees every record (for summaries).
async fn walk(
    cx: &Cx,
    s: &BlockState,
    emit: bool,
    visit: &mut (dyn FnMut(u64, &Record) + Send),
) -> Result<()> {
    let mut b = Bits {
        data: &s.stream.data,
        pos: s.start,
    };
    let mut abbrevs: Vec<Abbrev> = s.info.get(&s.id).cloned().unwrap_or_default();
    // BLOCKINFO contents are attributed to the block named by SETBID.
    let mut info = (*s.info).clone();
    let mut current: Option<u64> = None;
    let bad =
        |pos: u64| Diagnostic::malformed("malformed bitstream").at(s.stream.span.sub(pos >> 3, 1));
    let span_of = |from: u64, to: u64| {
        s.stream.span.sub(
            from >> 3,
            (to.saturating_add(7) >> 3).saturating_sub(from >> 3),
        )
    };
    while b.pos < s.end {
        cx.checkpoint().await;
        let at = b.pos;
        let id = b.read(s.width).ok_or_else(|| bad(at))?;
        match id {
            0 => break, // END_BLOCK
            1 => {
                let (child, width, end) = enter(&mut b).ok_or_else(|| bad(at))?;
                let start = b.pos;
                if end > s.end {
                    return Err(bad(at));
                }
                if child == 0 {
                    // Abbreviations defined here apply to the blocks after it.
                    read_blockinfo(cx, &s.stream.data, start, end, width, &mut info).await;
                }
                b.pos = end;
                if emit {
                    let state = BlockState {
                        stream: s.stream.clone(),
                        id: child,
                        start,
                        end,
                        width,
                        info: Arc::new(info.clone()),
                        depth: s.depth.saturating_add(1),
                    };
                    let mut node = Node::new(block_label(child))
                        .span(span_of(at, end))
                        .summary(format!("{:#x} bytes", end.saturating_sub(start) >> 3));
                    node = if s.depth >= MAX_DEPTH {
                        node.diag(Diagnostic::limit("blocks nested too deeply"))
                    } else {
                        node.lazy(crate::expander!(self::block: BlockState), state)
                    };
                    cx.push(node).await;
                }
            }
            2 => {
                let abbrev = read_abbrev(&mut b).ok_or_else(|| bad(at))?;
                if s.id == 0 {
                    if let Some(target) = current {
                        info.entry(target).or_default().push(abbrev);
                    }
                } else {
                    abbrevs.push(abbrev);
                }
                if emit {
                    cx.push(Node::new("DEFINE_ABBREV").span(span_of(at, b.pos)))
                        .await;
                }
            }
            _ => {
                let record = if id == 3 {
                    unabbreviated(&mut b)
                } else {
                    usize::try_from(id.saturating_sub(4))
                        .ok()
                        .and_then(|i| abbrevs.get(i))
                        .cloned()
                        .and_then(|a| abbreviated(&mut b, &a))
                }
                .ok_or_else(|| bad(at))?;
                if s.id == 0 && record.code == 1 {
                    current = record.operands.first().copied();
                }
                visit(s.id, &record);
                if emit {
                    cx.push(record_node(s, &record, span_of(at, b.pos))).await;
                }
            }
        }
    }
    Ok(())
}

fn record_node(s: &BlockState, r: &Record, span: Span) -> Node {
    let name = name_or(record_names(s.id), r.code, "record");
    let mut node = Node::new(name).span(span);
    if let Some((start, len)) = r.blob {
        let blob = s.stream.span.sub(start, len);
        let preview = s
            .stream
            .data
            .get(crate::bytes::to_usize(start)..crate::bytes::to_usize(start.saturating_add(len)))
            .unwrap_or_default();
        let shown = preview.get(..64).unwrap_or(preview).to_vec();
        return node
            .value(Value::Bytes(shown))
            .summary(format!("blob of {len} bytes"))
            .target(blob);
    }
    let textual = matches!((s.id, r.code), (8, 2 | 3 | 4 | 5 | 6 | 11 | 16) | (13, 1))
        || (s.id == 0 && matches!(r.code, 2 | 3));
    if textual && let Some(t) = as_text(&r.operands) {
        node = node.value(text(t));
    } else {
        let shown: Vec<String> = r.operands.iter().take(16).map(u64::to_string).collect();
        let mut s = shown.join(", ");
        if r.operands.len() > 16 {
            s.push_str(&format!(", … ({} operands)", r.operands.len()));
        }
        node = node.maybe_summary(s);
    }
    node
}

async fn block(cx: Cx, s: BlockState) -> Result<()> {
    walk(&cx, &s, true, &mut |_, _| {}).await
}

// ---------------------------------------------------------------------------
// Entry point

fn wrapper(f: &mut Fields<'_>, _: &()) -> Result<(u32, u32)> {
    f.u32("magic").hex().desc("0x0B17C0DE").emit()?;
    f.u32("version").emit()?;
    let offset = f.u32("offset").hex().emit()?;
    let size = f.u32("size").hex().emit()?;
    f.u32("cputype")
        .enumeration(crate::formats::executable::macho::tables::CPU_TYPE)
        .emit()?;
    Ok((offset, size))
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 20)).await?;
    let mut stream_span = file;
    if head.starts_with(b"\xde\xc0\x17\x0b") {
        cx.emit(struct_node(
            "Wrapper Header",
            file.sub(0, 20),
            Endian::Little,
            (),
            wrapper,
        ));
        let offset = u32_le(&head, 8).unwrap_or(0);
        let size = u32_le(&head, 12).unwrap_or(0);
        stream_span = file.sub(offset.into(), size.into());
    }
    if stream_span.len > MAX_STREAM {
        return Err(Diagnostic::limit("bitcode too large to decode").at(stream_span));
    }
    let data = Arc::new(cx.read(stream_span).await?);
    cx.emit(
        Node::new("Magic")
            .span(stream_span.sub(0, 4))
            .value(text("BC 0xC0DE")),
    );
    let stream = Stream {
        data,
        span: stream_span,
    };
    let top = BlockState {
        stream: stream.clone(),
        id: u64::MAX,
        start: 32,
        end: stream_span.len.saturating_mul(8),
        width: 2,
        info: Arc::new(BTreeMap::new()),
        depth: 0,
    };
    // A quick pass over the identification and module records for the
    // summary, then the real (paged) walk of the top level.
    let mut producer = None;
    let mut triple = None;
    let mut source = None;
    {
        let mut b = Bits {
            data: &stream.data,
            pos: 32,
        };
        while b.pos < top.end {
            cx.checkpoint().await;
            if b.read(2) != Some(1) {
                break;
            }
            let Some((id, width, end)) = enter(&mut b) else {
                break;
            };
            let state = BlockState {
                start: b.pos,
                end,
                id,
                width,
                ..top.clone()
            };
            if id == 13 || id == 8 {
                let _ = walk(&cx, &state, false, &mut |block, r| match (block, r.code) {
                    (13, 1) => producer = as_text(&r.operands),
                    (8, 2) => triple = as_text(&r.operands),
                    (8, 16) => source = as_text(&r.operands),
                    _ => {}
                })
                .await;
            }
            b.pos = end;
            b.align32();
        }
    }
    let mut summary = "LLVM bitcode".to_owned();
    if let Some(p) = producer {
        summary.push_str(&format!(", producer {p}"));
    }
    if let Some(t) = triple {
        summary.push_str(&format!(", target {t}"));
    }
    if let Some(s) = source {
        summary.push_str(&format!(", from {}", ellipsize(&s, 60)));
    }
    cx.annotate(summary);
    walk(&cx, &top, true, &mut |_, _| {}).await
}
