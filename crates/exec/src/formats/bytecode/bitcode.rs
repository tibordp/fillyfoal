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
use crate::formats::util::binutil::NodeExt;
use crate::formats::util::fmt::{clip, plural};
use crate::formats::util::val::{name_or, text};
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
    (15, "METADATA_VALUES_UNUSED"),
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
    (9, "FUNCTION_OLD"),
    (10, "HALF"),
    (11, "ARRAY"),
    (12, "VECTOR"),
    (13, "X86_FP80"),
    (14, "FP128"),
    (15, "PPC_FP128"),
    (16, "METADATA"),
    (17, "X86_MMX"),
    (18, "STRUCT_ANON"),
    (19, "STRUCT_NAME"),
    (20, "STRUCT_NAMED"),
    (21, "FUNCTION"),
    (22, "TOKEN"),
    (23, "BFLOAT"),
    (24, "X86_AMX"),
    (25, "OPAQUE_POINTER"),
    (26, "TARGET_TYPE"),
];
const PARAMATTR_CODES: EnumTable = &[(1, "ENTRY_OLD"), (2, "ENTRY"), (3, "GRP_ENTRY")];
const VST_CODES: EnumTable = &[
    (1, "ENTRY"),
    (2, "BBENTRY"),
    (3, "FNENTRY"),
    (5, "COMBINED_ENTRY"),
];
const CONSTANTS_CODES: EnumTable = &[
    (1, "SETTYPE"),
    (2, "NULL"),
    (3, "UNDEF"),
    (4, "INTEGER"),
    (5, "WIDE_INTEGER"),
    (6, "FLOAT"),
    (7, "AGGREGATE"),
    (8, "STRING"),
    (9, "CSTRING"),
    (10, "CE_BINOP"),
    (11, "CE_CAST"),
    (12, "CE_GEP_OLD"),
    (13, "CE_SELECT"),
    (14, "CE_EXTRACTELT"),
    (15, "CE_INSERTELT"),
    (16, "CE_SHUFFLEVEC"),
    (17, "CE_CMP"),
    (18, "INLINEASM_OLD"),
    (19, "CE_SHUFVEC_EX"),
    (20, "CE_INBOUNDS_GEP"),
    (21, "BLOCKADDRESS"),
    (22, "DATA"),
    (23, "INLINEASM_OLD2"),
    (24, "CE_GEP_WITH_INRANGE_INDEX_OLD"),
    (25, "CE_UNOP"),
    (26, "POISON"),
    (27, "DSO_LOCAL_EQUIVALENT"),
    (28, "INLINEASM_OLD3"),
    (29, "NO_CFI_VALUE"),
    (30, "INLINEASM"),
    (31, "CE_GEP_WITH_INRANGE"),
    (32, "CE_GEP"),
    (33, "PTRAUTH"),
];
const FUNCTION_CODES: EnumTable = &[
    (1, "DECLAREBLOCKS"),
    (2, "INST_BINOP"),
    (3, "INST_CAST"),
    (4, "INST_GEP_OLD"),
    (5, "INST_SELECT"),
    (6, "INST_EXTRACTELT"),
    (7, "INST_INSERTELT"),
    (8, "INST_SHUFFLEVEC"),
    (9, "INST_CMP"),
    (10, "INST_RET"),
    (11, "INST_BR"),
    (12, "INST_SWITCH"),
    (13, "INST_INVOKE"),
    (15, "INST_UNREACHABLE"),
    (16, "INST_PHI"),
    (19, "INST_ALLOCA"),
    (20, "INST_LOAD"),
    (23, "INST_VAARG"),
    (24, "INST_STORE_OLD"),
    (26, "INST_EXTRACTVAL"),
    (27, "INST_INSERTVAL"),
    (28, "INST_CMP2"),
    (29, "INST_VSELECT"),
    (30, "INST_INBOUNDS_GEP_OLD"),
    (31, "INST_INDIRECTBR"),
    (33, "DEBUG_LOC_AGAIN"),
    (34, "INST_CALL"),
    (35, "DEBUG_LOC"),
    (36, "INST_FENCE"),
    (37, "INST_CMPXCHG_OLD"),
    (38, "INST_ATOMICRMW_OLD"),
    (39, "INST_RESUME"),
    (40, "INST_LANDINGPAD_OLD"),
    (41, "INST_LOADATOMIC"),
    (42, "INST_STOREATOMIC_OLD"),
    (43, "INST_GEP"),
    (44, "INST_STORE"),
    (45, "INST_STOREATOMIC"),
    (46, "INST_CMPXCHG"),
    (47, "INST_LANDINGPAD"),
    (48, "INST_CLEANUPRET"),
    (49, "INST_CATCHRET"),
    (50, "INST_CATCHPAD"),
    (51, "INST_CLEANUPPAD"),
    (52, "INST_CATCHSWITCH"),
    (55, "OPERAND_BUNDLE"),
    (56, "INST_UNOP"),
    (57, "INST_CALLBR"),
    (58, "INST_FREEZE"),
    (59, "INST_ATOMICRMW"),
    (60, "BLOCKADDR_USERS"),
    (61, "DEBUG_RECORD_VALUE"),
    (62, "DEBUG_RECORD_DECLARE"),
    (63, "DEBUG_RECORD_ASSIGN"),
    (64, "DEBUG_RECORD_VALUE_SIMPLE"),
    (65, "DEBUG_RECORD_LABEL"),
];
const METADATA_CODES: EnumTable = &[
    (1, "STRING_OLD"),
    (2, "VALUE"),
    (3, "NODE"),
    (4, "NAME"),
    (5, "DISTINCT_NODE"),
    (6, "KIND"),
    (7, "LOCATION"),
    (8, "OLD_NODE"),
    (9, "OLD_FN_NODE"),
    (10, "NAMED_NODE"),
    (11, "ATTACHMENT"),
    (12, "GENERIC_DEBUG"),
    (13, "SUBRANGE"),
    (14, "ENUMERATOR"),
    (15, "BASIC_TYPE"),
    (16, "FILE"),
    (17, "DERIVED_TYPE"),
    (18, "COMPOSITE_TYPE"),
    (19, "SUBROUTINE_TYPE"),
    (20, "COMPILE_UNIT"),
    (21, "SUBPROGRAM"),
    (22, "LEXICAL_BLOCK"),
    (23, "LEXICAL_BLOCK_FILE"),
    (24, "NAMESPACE"),
    (25, "TEMPLATE_TYPE"),
    (26, "TEMPLATE_VALUE"),
    (27, "GLOBAL_VAR"),
    (28, "LOCAL_VAR"),
    (29, "EXPRESSION"),
    (30, "OBJC_PROPERTY"),
    (31, "IMPORTED_ENTITY"),
    (32, "MODULE"),
    (33, "MACRO"),
    (34, "MACRO_FILE"),
    (35, "STRINGS"),
    (36, "GLOBAL_DECL_ATTACHMENT"),
    (37, "GLOBAL_VAR_EXPR"),
    (38, "INDEX_OFFSET"),
    (39, "INDEX"),
    (40, "LABEL"),
    (41, "STRING_TYPE"),
    (44, "COMMON_BLOCK"),
    (45, "GENERIC_SUBRANGE"),
    (46, "ARG_LIST"),
    (47, "ASSIGN_ID"),
];
const USELIST_CODES: EnumTable = &[(1, "DEFAULT"), (2, "BB")];
const MODULE_STRTAB_CODES: EnumTable = &[(1, "ENTRY"), (2, "HASH")];
const TAG_CODES: EnumTable = &[(1, "TAG")];
const SYNC_SCOPE_CODES: EnumTable = &[(1, "NAME")];

/// Record names per block ID (LLVM `LLVMBitCodes.h`).
fn record_names(block: u64) -> EnumTable {
    match block {
        0 => BLOCKINFO_CODES,
        8 => MODULE_CODES,
        9 | 10 => PARAMATTR_CODES,
        11 => CONSTANTS_CODES,
        12 => FUNCTION_CODES,
        13 => IDENTIFICATION_CODES,
        14 => VST_CODES,
        15 | 16 | 22 => METADATA_CODES,
        17 => TYPE_CODES,
        18 => USELIST_CODES,
        19 => MODULE_STRTAB_CODES,
        21 => TAG_CODES,
        23 | 25 => BLOB_CODES,
        26 => SYNC_SCOPE_CODES,
        _ => &[],
    }
}

// ---------------------------------------------------------------------------
// Bit reading

/// A reader of LLVM bitstreams (bitcode, Clang modules and serialized
/// Swift modules): fields are packed least significant bit first, in
/// little-endian 32-bit words. All reads return `None` (and leave the
/// position where it was reached) at the end of `data` or on an
/// out-of-range width.
pub struct Bits<'a> {
    pub data: &'a [u8],
    /// Position in bits from the start of `data`.
    pub pos: u64,
}

impl<'a> Bits<'a> {
    /// A reader at the start of `data`.
    pub fn new(data: &'a [u8]) -> Self {
        Bits { data, pos: 0 }
    }

    /// Bits left after the position.
    pub fn remaining(&self) -> u64 {
        to_u64(self.data.len())
            .saturating_mul(8)
            .saturating_sub(self.pos)
    }

    /// A fixed-width field of `n` (at most 64) bits.
    pub fn read(&mut self, n: u32) -> Option<u64> {
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

    /// A variable-width field in `n`-bit chunks (2 to 32), each with a
    /// continuation bit at the top; `None` beyond 64 bits.
    pub fn vbr(&mut self, n: u32) -> Option<u64> {
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

    /// Skips to the next 32-bit word boundary.
    pub fn align32(&mut self) {
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

/// Abbreviations defined in BLOCKINFO, per block ID; shared by the blocks
/// that follow until BLOCKINFO changes again.
type BlockInfo = Arc<Infos>;

/// The most BLOCKINFO abbreviations kept (LLVM defines a few dozen).
const MAX_INFO_ABBREVS: usize = 1 << 16;

#[derive(Clone, Default)]
struct Infos {
    by_block: BTreeMap<u64, Vec<Abbrev>>,
    total: usize,
}

/// Adds an abbreviation for `block`, copying `info` first if it is shared
/// (charged by its size).
async fn add_info(cx: &Cx, info: &mut BlockInfo, block: u64, abbrev: Abbrev) {
    if info.total >= MAX_INFO_ABBREVS {
        return;
    }
    if Arc::strong_count(info) > 1 {
        for _ in 0..info.total >> 8 {
            cx.checkpoint().await;
        }
    }
    let info = Arc::make_mut(info);
    info.total = info.total.saturating_add(1);
    info.by_block.entry(block).or_default().push(abbrev);
}

/// Operands read between checkpoints.
const OPERAND_STEP: u64 = 4096;

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

async fn unabbreviated(cx: &Cx, b: &mut Bits<'_>) -> Option<Record> {
    let code = b.vbr(6)?;
    let n = b.vbr(6)?;
    if n > b.remaining() {
        return None;
    }
    let mut operands = Vec::new();
    for k in 0..n {
        if k > 0 && k.is_multiple_of(OPERAND_STEP) {
            cx.checkpoint().await;
        }
        push_operand(&mut operands, b.vbr(6)?);
    }
    Some(Record {
        code,
        operands,
        blob: None,
    })
}

async fn abbreviated(cx: &Cx, b: &mut Bits<'_>, abbrev: &Abbrev) -> Option<Record> {
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
                for k in 0..n {
                    if k > 0 && k.is_multiple_of(OPERAND_STEP) {
                        cx.checkpoint().await;
                    }
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
    /// Byte range of the top-level STRTAB blob (bitcode version 2).
    strtab: Option<(u64, u64)>,
}

impl Stream {
    /// `len` bytes at `start` (fewer at the end of the stream).
    fn bytes(&self, start: u64, len: u64) -> &[u8] {
        let from = crate::bytes::to_usize(start).min(self.data.len());
        let to = crate::bytes::to_usize(start.saturating_add(len)).min(self.data.len());
        self.data.get(from..to).unwrap_or_default()
    }

    /// The string-table name an `[offset, size, ...]` record starts with.
    fn strtab_name(&self, ops: &[u64]) -> Option<String> {
        let (start, len) = self.strtab?;
        let (&offset, &size) = (ops.first()?, ops.get(1)?);
        if size == 0 || offset.checked_add(size)? > len {
            return None;
        }
        let name = self.bytes(start.checked_add(offset)?, size.min(1024));
        Some(clip(&String::from_utf8_lossy(name), 200))
    }
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
    info: &mut BlockInfo,
) -> Option<()> {
    let mut b = Bits { data, pos: start };
    let mut current = None;
    while b.pos < end {
        cx.checkpoint().await;
        match b.read(width)? {
            0 => return Some(()),
            2 => {
                let abbrev = read_abbrev(&mut b)?;
                add_info(cx, info, current?, abbrev).await;
            }
            3 => {
                let r = unabbreviated(cx, &mut b).await?;
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
    let mut abbrevs: Vec<Abbrev> = s.info.by_block.get(&s.id).cloned().unwrap_or_default();
    // BLOCKINFO contents are attributed to the block named by SETBID.
    let mut info = s.info.clone();
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
                        info: info.clone(),
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
                        add_info(cx, &mut info, target, abbrev).await;
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
                    unabbreviated(cx, &mut b).await
                } else {
                    match usize::try_from(id.saturating_sub(4))
                        .ok()
                        .and_then(|i| abbrevs.get(i))
                    {
                        Some(a) => abbreviated(cx, &mut b, a).await,
                        None => None,
                    }
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
    let node = Node::new(name).span(span);
    if let Some((start, len)) = r.blob {
        let blob = s.stream.span.sub(start, len);
        let preview = s.stream.bytes(start, len);
        if s.id == 15 && r.code == 35 {
            // METADATA_STRINGS: [count, offset size] + a blob of VBR6
            // lengths followed by the characters.
            let count = r.operands.first().copied().unwrap_or(0);
            let lengths = r.operands.get(1).copied().unwrap_or(0);
            return node
                .summary(format!(
                    "{count_string} in {len} bytes",
                    count_string = plural(count, "string")
                ))
                .target(blob)
                .lazy(
                    crate::expander!(self::metadata_strings: (Stream, u64, u64, u64, u64)),
                    (s.stream.clone(), start, len, count, lengths),
                );
        }
        if s.id == 23 {
            // The string table names are concatenated without separators.
            let shown = preview.get(..1024).unwrap_or(preview);
            return node
                .value(text(clip(&String::from_utf8_lossy(shown), 120)))
                .summary(format!("string table of {len} bytes"))
                .target(blob);
        }
        let shown = preview.get(..64).unwrap_or(preview).to_vec();
        return node
            .value(Value::Bytes(shown))
            .summary(format!("blob of {len} bytes"))
            .target(blob);
    }
    // Module records of bitcode version 2 start with a name as an offset
    // and size in the string table.
    if s.id == 8
        && matches!(r.code, 7 | 8 | 12 | 14 | 18)
        && let Some(name) = s.stream.strtab_name(&r.operands)
    {
        return node
            .value(text(name))
            .maybe_summary(operand_list(r.operands.get(2..).unwrap_or_default()));
    }
    // Records whose operands (after a prefix of numbers) are characters.
    let prefix = match (s.id, r.code) {
        (8, 2 | 3 | 4 | 5 | 6 | 11 | 16)
        | (13, 1)
        | (0, 2 | 3)
        | (11, 8 | 9)
        | (15, 1 | 4)
        | (17, 19)
        | (21, 1)
        | (26, 1) => Some(0),
        (14, 1 | 2) | (15 | 22, 6) => Some(1),
        (14, 3) => Some(2),
        _ => None,
    };
    if let Some(k) = prefix
        && let (Some(head), Some(rest)) = (r.operands.get(..k), r.operands.get(k..))
        && let Some(t) = as_text(rest)
    {
        return node.value(text(t)).maybe_summary(operand_list(head));
    }
    node.maybe_summary(operand_list(&r.operands))
}

/// Up to 16 operands, comma-separated.
fn operand_list(ops: &[u64]) -> String {
    let shown: Vec<String> = ops.iter().take(16).map(u64::to_string).collect();
    let mut s = shown.join(", ");
    if ops.len() > 16 {
        s.push_str(&format!(", … ({} operands)", ops.len()));
    }
    s
}

/// The strings of a METADATA_STRINGS blob at `start` (`len` bytes): `count`
/// VBR6 lengths in the first `lengths` bytes, then the characters.
async fn metadata_strings(
    cx: Cx,
    (stream, start, len, count, lengths): (Stream, u64, u64, u64, u64),
) -> Result<()> {
    let data = stream.bytes(start, len);
    let table = data
        .get(..crate::bytes::to_usize(lengths))
        .unwrap_or_default();
    let mut b = Bits::new(table);
    let mut pos = lengths;
    for i in 0..count {
        if i.is_multiple_of(256) {
            cx.checkpoint().await;
        }
        let at = stream.span.sub(start.saturating_add(pos), 0);
        let Some(n) = b.vbr(6) else {
            cx.diag(Diagnostic::malformed(format!("string length {i} is missing")).at(at));
            break;
        };
        let end = pos.saturating_add(n);
        if end > len {
            cx.diag(Diagnostic::truncated(
                stream.span.sub(start.saturating_add(pos), n),
                len.saturating_sub(pos),
            ));
            break;
        }
        let bytes = stream.bytes(start.saturating_add(pos), n);
        let shown = bytes.get(..1024).unwrap_or(bytes);
        cx.push(
            Node::new(format!("[{i}]"))
                .span(stream.span.sub(start.saturating_add(pos), n))
                .value(text(clip(&String::from_utf8_lossy(shown), 200))),
        )
        .await;
        pos = end;
    }
    Ok(())
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
    let mut stream = Stream {
        data,
        span: stream_span,
        strtab: None,
    };
    let top = BlockState {
        stream: stream.clone(),
        id: u64::MAX,
        start: 32,
        end: stream_span.len.saturating_mul(8),
        width: 2,
        info: Arc::new(Infos::default()),
        depth: 0,
    };
    // A quick pass over the identification and module records for the
    // summary, then the real (paged) walk of the top level.
    let mut producer = None;
    let mut triple = None;
    let mut source = None;
    let mut strtab = None;
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
            if matches!(id, 8 | 13 | 23) {
                let _ = walk(&cx, &state, false, &mut |block, r| match (block, r.code) {
                    (13, 1) => producer = as_text(&r.operands),
                    (8, 2) => triple = as_text(&r.operands),
                    (8, 16) => source = as_text(&r.operands),
                    (23, 1) if strtab.is_none() => strtab = r.blob,
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
        summary.push_str(&format!(", from {}", clip(&s, 60)));
    }
    cx.annotate(summary);
    stream.strtab = strtab;
    let top = BlockState { stream, ..top };
    walk(&cx, &top, true, &mut |_, _| {}).await
}
