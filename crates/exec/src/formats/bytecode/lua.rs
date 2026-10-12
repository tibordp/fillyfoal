//! Precompiled Lua chunks (`luac` output, `\x1bLua`), versions 5.0 to 5.5.
//!
//! The header records the version, the format and the sizes (and test
//! values) of the C types the chunk was compiled for. It is followed by the
//! main function prototype, which holds its code, constants, upvalues,
//! nested prototypes and debug information, in an order and encoding each
//! version changes (`lundump.c` of 5.0 to 5.5). Expanding the file decodes
//! the whole chunk once, in budgeted steps, into an index of prototypes
//! whose nodes are emitted as they are expanded.

use std::sync::Arc;

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::arcutil::{emit_nodes, push_nodes};
use crate::formats::util::binutil::Reader;
use crate::formats::util::fmt::plural;
use crate::formats::util::val::{text, uint};
use crate::formats::{Format, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::Value;

pub static FORMAT: Format = Format {
    name: "lua",
    title: "Lua bytecode",
    extensions: &["luac", "out", "lub"],
    mime: "application/x-lua-bytecode",
    probe: Probe::Custom(|h| {
        h.starts_with(b"\x1bLua") && h.data.get(4).is_some_and(|v| (0x50..=0x55).contains(v))
    }),
    dissect: crate::expander!(dissect: Input),
};

const LUAC_DATA: &[u8] = b"\x19\x93\r\n\x1a\n";

#[derive(Clone, Copy, Debug)]
struct Sizes {
    endian: Endian,
    int: u8,
    size_t: u8,
    instruction: u8,
    integer: u8,
    number: u8,
}

fn size_field(f: &mut Fields<'_>, name: &'static str) -> Result<u8> {
    f.u8(name).emit()
}

/// Decodes the header; returns the sizes the function prototypes use.
fn header(f: &mut Fields<'_>, version: &u8) -> Result<Sizes> {
    f.bytes("signature", 4).desc("\"\\x1bLua\"").emit()?;
    f.u8("version")
        .hex()
        .with(|&v, n| n.summary(format!("Lua {}.{}", v >> 4, v & 0xf)))
        .emit()?;
    let mut s = Sizes {
        endian: Endian::Little,
        int: 4,
        size_t: 8,
        instruction: 4,
        integer: 8,
        number: 8,
    };
    match *version {
        0x50 => {
            s.endian = endian(f.u8("endianness").desc("1: little-endian").emit()?);
            s.int = size_field(f, "sizeof(int)")?;
            s.size_t = size_field(f, "sizeof(size_t)")?;
            s.instruction = size_field(f, "sizeof(Instruction)")?;
            for name in ["SIZE_OP", "SIZE_A", "SIZE_B", "SIZE_C"] {
                f.u8(name).emit()?;
            }
            s.number = size_field(f, "sizeof(lua_Number)")?;
            f.f64("test number").emit()?;
        }
        0x51 | 0x52 => {
            f.u8("format").desc("0: official format").emit()?;
            s.endian = endian(f.u8("endianness").desc("1: little-endian").emit()?);
            s.int = size_field(f, "sizeof(int)")?;
            s.size_t = size_field(f, "sizeof(size_t)")?;
            s.instruction = size_field(f, "sizeof(Instruction)")?;
            s.number = size_field(f, "sizeof(lua_Number)")?;
            f.u8("integral")
                .desc("1: lua_Number is an integer type")
                .emit()?;
            if *version == 0x52 {
                f.bytes("LUAC_TAIL", 6).emit()?;
            }
        }
        0x53 => {
            f.u8("format").emit()?;
            f.bytes("LUAC_DATA", 6).emit()?;
            s.int = size_field(f, "sizeof(int)")?;
            s.size_t = size_field(f, "sizeof(size_t)")?;
            s.instruction = size_field(f, "sizeof(Instruction)")?;
            s.integer = size_field(f, "sizeof(lua_Integer)")?;
            s.number = size_field(f, "sizeof(lua_Number)")?;
            s.endian = test_integer(f, s.integer)?;
            test_number(f, s.number, s.endian)?;
            f.u8("sizeupvalues").emit()?;
        }
        0x54 => {
            f.u8("format").emit()?;
            f.bytes("LUAC_DATA", 6).emit()?;
            s.instruction = size_field(f, "sizeof(Instruction)")?;
            s.integer = size_field(f, "sizeof(lua_Integer)")?;
            s.number = size_field(f, "sizeof(lua_Number)")?;
            s.endian = test_integer(f, s.integer)?;
            test_number(f, s.number, s.endian)?;
            f.u8("sizeupvalues").emit()?;
        }
        _ => {
            // 5.5: each type's size is followed by a test value.
            f.u8("format").emit()?;
            f.bytes("LUAC_DATA", 6).emit()?;
            s.int = size_field(f, "sizeof(int)")?;
            f.bytes("LUAC_INT (int)", s.int.into()).emit()?;
            s.instruction = size_field(f, "sizeof(Instruction)")?;
            f.bytes("LUAC_INST", s.instruction.into()).emit()?;
            s.integer = size_field(f, "sizeof(lua_Integer)")?;
            s.endian = test_integer(f, s.integer)?;
            s.number = size_field(f, "sizeof(lua_Number)")?;
            test_number(f, s.number, s.endian)?;
            f.u8("sizeupvalues").emit()?;
        }
    }
    Ok(s)
}

fn endian(flag: u8) -> Endian {
    if flag == 0 {
        Endian::Big
    } else {
        Endian::Little
    }
}

/// `LUAC_INT` (0x5678, or -0x5678 in 5.5) in the chunk's byte order, which
/// also reveals that order.
fn test_integer(f: &mut Fields<'_>, size: u8) -> Result<Endian> {
    let span = f.peek_span(size.into());
    let bytes = f.bytes("LUAC_INT", size.into()).get()?;
    let le = i64::from_le_bytes(sign_extend(&bytes, false));
    let be = i64::from_be_bytes(sign_extend(&bytes, true));
    let (endian, value) = if le.unsigned_abs() == 0x5678 {
        (Endian::Little, le)
    } else {
        (Endian::Big, be)
    };
    f.node(
        Node::new("LUAC_INT")
            .span(span)
            .value(Value::Int {
                value,
                bits: size.saturating_mul(8),
            })
            .summary(match endian {
                Endian::Little => "little-endian",
                Endian::Big => "big-endian",
            }),
    );
    Ok(endian)
}

fn sign_extend(bytes: &[u8], big: bool) -> [u8; 8] {
    let negative = if big { bytes.first() } else { bytes.last() }.is_some_and(|b| b & 0x80 != 0);
    let mut out = [if negative { 0xff } else { 0 }; 8];
    let n = bytes.len().min(8);
    if big {
        if let Some(dst) = out.get_mut(8usize.saturating_sub(n)..) {
            dst.copy_from_slice(bytes.get(..n).unwrap_or_default());
        }
    } else if let Some(dst) = out.get_mut(..n) {
        dst.copy_from_slice(bytes.get(..n).unwrap_or_default());
    }
    out
}

fn test_number(f: &mut Fields<'_>, size: u8, endian: Endian) -> Result<()> {
    let span = f.peek_span(size.into());
    let bytes = f.bytes("LUAC_NUM", size.into()).get()?;
    let value = match (size, endian) {
        (8, Endian::Little) => bytes.as_slice().try_into().ok().map(f64::from_le_bytes),
        (8, Endian::Big) => bytes.as_slice().try_into().ok().map(f64::from_be_bytes),
        (4, Endian::Little) => bytes
            .as_slice()
            .try_into()
            .ok()
            .map(|b| f64::from(f32::from_le_bytes(b))),
        (4, Endian::Big) => bytes
            .as_slice()
            .try_into()
            .ok()
            .map(|b| f64::from(f32::from_be_bytes(b))),
        _ => None,
    };
    let node = Node::new("LUAC_NUM").span(span);
    f.node(match value {
        Some(v) => node.value(Value::Float(v)).desc("370.5 (or -370.5 in 5.5)"),
        None => node.value(Value::Bytes(bytes)),
    });
    Ok(())
}

// ---------------------------------------------------------------------------
// Function prototypes

/// Most bytes of a chunk decoded (the whole chunk is read to index its
/// prototypes).
const MAX_CHUNK: u64 = 64 << 20;
/// Prototypes nest; `luac` allows 200 levels (LUAI_MAXCCALLS).
const MAX_NESTING: u32 = 200;
/// Items decoded between two checkpoints.
const STEP: usize = 256;

/// One decoded prototype: nodes ready to emit, and its children by index.
#[derive(Default)]
struct Proto {
    span: (usize, usize),
    label: String,
    summary: String,
    /// Leading scalar fields, code, and the section groups.
    fields: Vec<Node>,
    /// Constants, upvalues and debug items, emitted by group nodes.
    constants: (usize, usize, Arc<Vec<Node>>),
    upvalues: (usize, usize, Arc<Vec<Node>>),
    protos: (usize, usize, Vec<usize>),
    debug: (usize, usize, Arc<Vec<Node>>),
    /// Sections decoded (`SEEN_*`), so a truncated prototype lists only
    /// those.
    seen: u8,
    numparams: u8,
    instructions: u64,
    source: Option<String>,
}

const SEEN_CONSTANTS: u8 = 1;
const SEEN_UPVALUES: u8 = 2;
const SEEN_PROTOS: u8 = 4;
const SEEN_DEBUG: u8 = 8;

/// All prototypes of a chunk, the main one first.
struct Index {
    span: Span,
    protos: Vec<Proto>,
}

struct Parser<'a> {
    r: Reader<'a>,
    span: Span,
    version: u8,
    s: Sizes,
    /// Offset of `data` in the chunk (5.5 aligns relative to the chunk).
    base: usize,
    protos: Vec<Proto>,
    /// 5.5: the strings saved so far, which later strings may refer to.
    saved: Vec<String>,
    steps: usize,
}

type Step<T> = Option<T>;

impl Parser<'_> {
    fn at(&self, start: usize) -> Span {
        self.span.sub(
            to_u64(start),
            to_u64(self.r.pos().saturating_sub(start)),
        )
    }

    fn uint(&mut self, size: u8) -> Step<u64> {
        let e = self.s.endian;
        match size {
            1 => self.r.u8().map(u64::from),
            2 => self.r.int::<u16>(e).map(u64::from),
            4 => self.r.int::<u32>(e).map(u64::from),
            8 => self.r.int::<u64>(e),
            _ => None,
        }
    }

    /// An MSB-first varint: 5.4 ends on a byte with the high bit set, 5.5
    /// on one with it clear.
    fn varint(&mut self) -> Step<u64> {
        let mut v = 0u64;
        for _ in 0..10 {
            let b = self.r.u8()?;
            v = v.checked_shl(7)? | u64::from(b & 0x7f);
            let last = if self.version == 0x54 {
                b & 0x80 != 0
            } else {
                b & 0x80 == 0
            };
            if last {
                return Some(v);
            }
        }
        None
    }

    /// An `int`: native before 5.4, a varint from 5.4.
    fn int(&mut self) -> Step<u64> {
        if self.version >= 0x54 {
            self.varint()
        } else {
            let size = self.s.int;
            self.uint(size)
        }
    }

    /// A count of items, each at least `min` bytes, that must fit.
    fn count(&mut self, min: usize) -> Step<u64> {
        let n = self.int()?;
        let left = to_u64(self.r.rest().len());
        (n.saturating_mul(to_u64(min)) <= left).then_some(n)
    }

    /// A string: `None` if malformed, `Some(None)` for a null string.
    fn string(&mut self) -> Step<Option<String>> {
        let v = self.version;
        let size = match v {
            0x50..=0x52 => {
                let size = self.s.size_t;
                self.uint(size)?
            }
            0x53 => match self.r.u8()? {
                0xff => {
                    let size = self.s.size_t;
                    self.uint(size)?
                }
                b => b.into(),
            },
            _ => self.varint()?,
        };
        if size == 0 {
            if v < 0x55 {
                return Some(None);
            }
            // 5.5: a reference to a string saved earlier (0: none).
            let index = self.varint()?;
            if index == 0 {
                return Some(None);
            }
            let saved = usize::try_from(index.checked_sub(1)?).ok()?;
            return self.saved.get(saved).cloned().map(Some);
        }
        let n = usize::try_from(size).ok()?;
        // Before 5.3 and in 5.5 the stored bytes end with a NUL that `size`
        // counts; 5.3 and 5.4 store `size - 1` bytes.
        let stored = if matches!(v, 0x53 | 0x54) {
            n.checked_sub(1)?
        } else {
            n
        };
        let bytes = self.r.bytes(stored)?;
        let chars = if stored == n {
            bytes.get(..n.saturating_sub(1)).unwrap_or_default()
        } else {
            bytes
        };
        let s = String::from_utf8_lossy(chars).into_owned();
        if v >= 0x55 {
            self.saved.push(s.clone());
        }
        Some(Some(s))
    }

    fn number(&mut self) -> Step<Value> {
        let e = self.s.endian;
        Some(match self.s.number {
            8 => Value::Float(f64::from_bits(self.r.int::<u64>(e)?)),
            4 => Value::Float(f64::from(f32::from_bits(self.r.int::<u32>(e)?))),
            n => Value::Bytes(self.r.bytes(n.into())?.to_vec()),
        })
    }

    fn integer(&mut self) -> Step<Value> {
        if self.version >= 0x55 {
            // Zigzag: 2x for x >= 0, -2x - 1 for x < 0.
            let u = self.varint()?;
            let half = i64::try_from(u >> 1).ok()?;
            let v = if u & 1 != 0 { !half } else { half };
            return Some(Value::Int { value: v, bits: 64 });
        }
        let size = self.s.integer;
        let raw = self.uint(size)?;
        let bits = u32::from(size).saturating_mul(8);
        let v = if bits >= 64 {
            i64::from_ne_bytes(raw.to_ne_bytes())
        } else {
            let shift = 64u32.saturating_sub(bits);
            i64::from_ne_bytes(raw.checked_shl(shift)?.to_ne_bytes()) >> shift
        };
        Some(Value::Int {
            value: v,
            bits: size.saturating_mul(8),
        })
    }

    /// 5.5: skips padding to a multiple of `align` from the chunk start.
    fn align(&mut self, align: u8) -> Step<()> {
        let align = usize::from(align.max(1));
        let pos = self.base.saturating_add(self.r.pos());
        let pad = align
            .saturating_sub(pos.checked_rem(align).unwrap_or(0))
            .checked_rem(align)
            .unwrap_or(0);
        self.r.bytes(pad).map(|_| ())
    }

    async fn tick(&mut self, cx: &Cx) {
        self.steps = self.steps.saturating_add(1);
        if self.steps.is_multiple_of(STEP) {
            cx.checkpoint().await;
        }
    }

    fn leaf(&self, name: &'static str, start: usize, value: Value) -> Node {
        Node::new(name).span(self.at(start)).value(value)
    }
}

/// One constant: its kind and value.
fn constant(p: &mut Parser<'_>, tag: u8) -> Step<(&'static str, Value)> {
    let v = p.version;
    let string = |p: &mut Parser<'_>| -> Step<Value> {
        Some(text(p.string()?.unwrap_or_default()))
    };
    Some(match (v, tag) {
        (_, 0) => ("nil", text("nil")),
        (0x51..=0x53, 1) => {
            let b = p.r.u8()?;
            ("boolean", text(if b != 0 { "true" } else { "false" }))
        }
        (0x54.., 1) => ("boolean", text("false")),
        (0x54.., 0x11) => ("boolean", text("true")),
        (0x50..=0x52, 3) | (0x53, 3) | (0x54.., 0x13) => ("float", p.number()?),
        (0x53, 0x13) | (0x54.., 3) => ("integer", p.integer()?),
        (0x50..=0x52, 4) => ("string", string(p)?),
        (0x53.., 4) => ("short string", string(p)?),
        (0x53.., 0x14) => ("long string", string(p)?),
        _ => return None,
    })
}

type ProtoFuture<'f> = std::pin::Pin<Box<dyn std::future::Future<Output = Step<usize>> + Send + 'f>>;

/// Decodes the prototype at the parser's position (and, recursively, the
/// ones it contains); returns its index. On a malformed field the
/// prototype keeps what was decoded and `None` is returned.
fn prototype<'f>(cx: &'f Cx, p: &'f mut Parser<'_>, depth: u32, parent: Option<String>) -> ProtoFuture<'f> {
    Box::pin(async move {
        cx.checkpoint().await;
        let index = p.protos.len();
        let start = p.r.pos();
        p.protos.push(Proto {
            label: if depth == 0 {
                "Main function".to_owned()
            } else {
                "function".to_owned()
            },
            ..Proto::default()
        });
        let result = prototype_body(cx, p, depth, parent, index).await;
        let end = p.r.pos();
        if let Some(proto) = p.protos.get_mut(index) {
            proto.span = (start, end.saturating_sub(start));
            let mut parts = vec![plural(proto.instructions, "instruction")];
            parts.push(plural(to_u64(proto.constants.2.len()), "constant"));
            if !proto.protos.2.is_empty() {
                parts.push(plural(to_u64(proto.protos.2.len()), "function"));
            }
            parts.push(plural(proto.numparams, "parameter"));
            proto.summary = parts.join(", ");
        }
        result.map(|()| index)
    })
}

async fn prototype_body(
    cx: &Cx,
    p: &mut Parser<'_>,
    depth: u32,
    parent: Option<String>,
    index: usize,
) -> Step<()> {
    if depth > MAX_NESTING {
        return None;
    }
    let v = p.version;
    let mut fields = Vec::new();
    let mut source = parent.clone();
    // Source (in the debug section in 5.2 and 5.5).
    if matches!(v, 0x50 | 0x51 | 0x53 | 0x54) {
        let start = p.r.pos();
        let s = p.string()?;
        let node = p.leaf("source", start, text(s.clone().unwrap_or_default()));
        fields.push(if s.is_none() {
            node.desc("none: the parent's source")
        } else {
            node
        });
        if s.is_some() {
            source = s;
        }
    }
    let mut line = 0;
    let names: &[&'static str] = if v == 0x50 {
        &["lineDefined"]
    } else {
        &["linedefined", "lastlinedefined"]
    };
    for (i, name) in names.iter().enumerate() {
        let start = p.r.pos();
        let n = p.int()?;
        if i == 0 {
            line = n;
        }
        fields.push(p.leaf(name, start, uint(n, 32)));
    }
    let bytes: &[&'static str] = match v {
        0x50 | 0x51 => &["nups", "numparams", "is_vararg", "maxstacksize"],
        0x55 => &["numparams", "flag", "maxstacksize"],
        _ => &["numparams", "is_vararg", "maxstacksize"],
    };
    let mut numparams = 0;
    for name in bytes {
        let start = p.r.pos();
        let b = p.r.u8()?;
        if *name == "numparams" {
            numparams = b;
        }
        fields.push(p.leaf(name, start, uint(b, 8)));
    }
    if let Some(proto) = p.protos.get_mut(index) {
        proto.label = if depth == 0 {
            "Main function".to_owned()
        } else {
            format!("function at line {line}")
        };
        proto.source.clone_from(&source);
        proto.numparams = numparams;
    }
    if let Some(proto) = p.protos.get_mut(index) {
        proto.fields.append(&mut fields);
    }
    if v == 0x50 {
        // 5.0: debug information first, then constants, then code.
        debug(cx, p, index).await?;
        constants(cx, p, depth, index, &source).await?;
        code(p, index)?;
    } else {
        code(p, index)?;
        constants(cx, p, depth, index, &source).await?;
        if v >= 0x52 {
            upvalues(cx, p, index).await?;
        }
        if v >= 0x53 {
            protos(cx, p, depth, index, &source).await?;
        }
        if v == 0x55 {
            let start = p.r.pos();
            let s = p.string()?;
            let node = p.leaf("source", start, text(s.clone().unwrap_or_default()));
            if let Some(proto) = p.protos.get_mut(index) {
                proto.fields.push(node);
                if s.is_some() {
                    proto.source = s;
                }
            }
        }
        debug(cx, p, index).await?;
    }
    Some(())
}

fn code(p: &mut Parser<'_>, index: usize) -> Step<()> {
    let start = p.r.pos();
    let n = p.int()?;
    if p.version >= 0x55 {
        let size = p.s.instruction;
        p.align(size)?;
    }
    let len = usize::try_from(n.checked_mul(p.s.instruction.into())?).ok()?;
    p.r.bytes(len)?;
    let node = Node::new("code")
        .span(p.at(start))
        .value(uint(n, 32))
        .summary(format!("{n} instructions of {} bytes", p.s.instruction));
    let proto = p.protos.get_mut(index)?;
    proto.fields.push(node);
    proto.instructions = n;
    Some(())
}

async fn constants(
    cx: &Cx,
    p: &mut Parser<'_>,
    depth: u32,
    index: usize,
    source: &Option<String>,
) -> Step<()> {
    let start = p.r.pos();
    let n = p.count(1)?;
    let mut items = Vec::new();
    for i in 0..n {
        p.tick(cx).await;
        let at = p.r.pos();
        let tag = p.r.u8()?;
        let (kind, value) = constant(p, tag)?;
        items.push(
            Node::new(format!("[{i}]"))
                .span(p.at(at))
                .value(value)
                .summary(kind),
        );
    }
    let span = (start, p.r.pos().saturating_sub(start));
    if let Some(proto) = p.protos.get_mut(index) {
        proto.constants = (span.0, span.1, Arc::new(items));
        proto.seen |= SEEN_CONSTANTS;
    }
    // Before 5.3 the nested prototypes follow the constants.
    if p.version <= 0x52 {
        protos(cx, p, depth, index, source).await?;
    }
    Some(())
}

async fn upvalues(cx: &Cx, p: &mut Parser<'_>, index: usize) -> Step<()> {
    let start = p.r.pos();
    let width = if p.version >= 0x54 { 3 } else { 2 };
    let n = p.count(width)?;
    let mut items = Vec::new();
    for i in 0..n {
        p.tick(cx).await;
        let at = p.r.pos();
        let instack = p.r.u8()?;
        let idx = p.r.u8()?;
        let mut summary = if instack != 0 {
            format!("register {idx} of the enclosing function")
        } else {
            format!("upvalue {idx} of the enclosing function")
        };
        if width == 3 {
            let kind = p.r.u8()?;
            summary.push_str(match kind {
                0 => ", regular",
                1 => ", local constant",
                2 => ", to-be-closed",
                3 => ", compile-time constant",
                _ => ", kind ?",
            });
        }
        items.push(Node::new(format!("[{i}]")).span(p.at(at)).summary(summary));
    }
    let span = (start, p.r.pos().saturating_sub(start));
    if let Some(proto) = p.protos.get_mut(index) {
        proto.upvalues = (span.0, span.1, Arc::new(items));
        proto.seen |= SEEN_UPVALUES;
    }
    Some(())
}

async fn protos(
    cx: &Cx,
    p: &mut Parser<'_>,
    depth: u32,
    index: usize,
    source: &Option<String>,
) -> Step<()> {
    let start = p.r.pos();
    let n = p.count(1)?;
    let mut ok = true;
    for _ in 0..n {
        // `prototype` adds the child at the end of the list first.
        let child = p.protos.len();
        ok = prototype(cx, p, depth.saturating_add(1), source.clone())
            .await
            .is_some();
        if let Some(proto) = p.protos.get_mut(index) {
            proto.protos.2.push(child);
        }
        if !ok {
            break;
        }
    }
    let len = p.r.pos().saturating_sub(start);
    if let Some(proto) = p.protos.get_mut(index) {
        proto.protos.0 = start;
        proto.protos.1 = len;
        proto.seen |= SEEN_PROTOS;
    }
    ok.then_some(())
}

async fn debug(cx: &Cx, p: &mut Parser<'_>, index: usize) -> Step<()> {
    let v = p.version;
    let start = p.r.pos();
    let mut items = Vec::new();
    if v == 0x52 {
        let at = p.r.pos();
        let s = p.string()?;
        let node = p.leaf("source", at, text(s.clone().unwrap_or_default()));
        items.push(node);
        if let Some(proto) = p.protos.get_mut(index)
            && s.is_some()
        {
            proto.source = s;
        }
    }
    // Line information: per instruction, ints before 5.4, byte deltas from
    // 5.4 (with absolute lines every so often).
    let at = p.r.pos();
    let width = if v >= 0x54 { 1 } else { usize::from(p.s.int) };
    let n = p.count(width)?;
    p.r.bytes(usize::try_from(n).ok()?.saturating_mul(width))?;
    items.push(
        Node::new("lineinfo")
            .span(p.at(at))
            .value(uint(n, 32))
            .summary(if v >= 0x54 {
                format!("{n} line deltas")
            } else {
                format!("{n} lines")
            }),
    );
    if v >= 0x54 {
        let at = p.r.pos();
        let n = p.count(2)?;
        let mut pairs = Vec::new();
        if v == 0x55 && n > 0 {
            let size = p.s.int;
            p.align(size)?;
        }
        for _ in 0..n {
            p.tick(cx).await;
            let one = p.r.pos();
            let (pc, line) = if v == 0x55 {
                let size = p.s.int;
                (p.uint(size)?, p.uint(size)?)
            } else {
                (p.int()?, p.int()?)
            };
            pairs.push(
                Node::new(format!("pc {pc}"))
                    .span(p.at(one))
                    .value(uint(line, 32))
                    .summary("line"),
            );
        }
        let node = Node::new("abslineinfo")
            .span(p.at(at))
            .summary(plural(n, "absolute line"));
        items.push(group(node, pairs));
    }
    // 5.0 keeps locals, then upvalue names here.
    let at = p.r.pos();
    let n = p.count(3)?;
    let mut locals = Vec::new();
    for _ in 0..n {
        p.tick(cx).await;
        let one = p.r.pos();
        let name = p.string()?.unwrap_or_default();
        let from = p.int()?;
        let to = p.int()?;
        locals.push(
            Node::new(name)
                .span(p.at(one))
                .summary(format!("pc {from}..{to}")),
        );
    }
    let node = Node::new("locvars")
        .span(p.at(at))
        .summary(plural(n, "local variable"));
    items.push(group(node, locals));
    let at = p.r.pos();
    let mut n = p.count(1)?;
    if v >= 0x54 && n != 0 {
        // The count only says whether names are present; there is one per
        // upvalue.
        n = p
            .protos
            .get(index)
            .map_or(0, |proto| to_u64(proto.upvalues.2.len()));
    }
    let mut names = Vec::new();
    for i in 0..n {
        p.tick(cx).await;
        let one = p.r.pos();
        let name = p.string()?.unwrap_or_default();
        names.push(Node::new(format!("[{i}]")).span(p.at(one)).value(text(name)));
    }
    let node = Node::new("upvalue names")
        .span(p.at(at))
        .summary(plural(n, "name"));
    items.push(group(node, names));
    let span = (start, p.r.pos().saturating_sub(start));
    if let Some(proto) = p.protos.get_mut(index) {
        proto.debug = (span.0, span.1, Arc::new(items));
        proto.seen |= SEEN_DEBUG;
    }
    Some(())
}

/// A node whose children are `items` (pushed on expansion), or a leaf if
/// there are none.
fn group(node: Node, items: Vec<Node>) -> Node {
    if items.is_empty() {
        node
    } else {
        node.lazy(push_nodes, Arc::new(items))
    }
}

/// The children of prototype `index`.
async fn prototype_node(cx: Cx, (index, i): (Arc<Index>, usize)) -> Result<()> {
    let proto = index
        .protos
        .get(i)
        .ok_or_else(|| Diagnostic::internal("prototype index out of range"))?;
    for node in &proto.fields {
        cx.emit(node.clone());
    }
    let span = |(start, len): (usize, usize)| index.span.sub(to_u64(start), to_u64(len));
    let (start, len, items) = &proto.constants;
    if proto.seen & SEEN_CONSTANTS != 0 {
        cx.emit(group(
        Node::new("constants")
            .span(span((*start, *len)))
            .summary(plural(to_u64(items.len()), "constant")),
        items.as_ref().clone(),
    ));
    }
    let (start, len, items) = &proto.upvalues;
    if proto.seen & SEEN_UPVALUES != 0 {
        cx.emit(group(
            Node::new("upvalues")
                .span(span((*start, *len)))
                .summary(plural(to_u64(items.len()), "upvalue")),
            items.as_ref().clone(),
        ));
    }
    let (start, len, children) = &proto.protos;
    if proto.seen & SEEN_PROTOS != 0 {
        let node = Node::new("functions")
            .span(span((*start, *len)))
            .summary(plural(to_u64(children.len()), "function"));
        cx.emit(if children.is_empty() {
            node
        } else {
            node.lazy(prototype_list, (index.clone(), i))
        });
    }
    let (start, len, items) = &proto.debug;
    if proto.seen & SEEN_DEBUG != 0 {
        cx.emit(
            Node::new("debug")
                .span(span((*start, *len)))
                .lazy(emit_nodes, items.clone()),
        );
    }
    Ok(())
}

async fn prototype_list(cx: Cx, (index, i): (Arc<Index>, usize)) -> Result<()> {
    let children = index
        .protos
        .get(i)
        .map(|p| p.protos.2.clone())
        .unwrap_or_default();
    cx.set_count(Count::Exact(to_u64(children.len())));
    for c in children {
        cx.push(proto_entry(&index, c)).await;
    }
    Ok(())
}

fn proto_entry(index: &Arc<Index>, i: usize) -> Node {
    let Some(proto) = index.protos.get(i) else {
        return Node::new("function");
    };
    Node::new(proto.label.clone())
        .span(index.span.sub(to_u64(proto.span.0), to_u64(proto.span.1)))
        .summary(proto.summary.clone())
        .lazy(
            crate::expander!(self::prototype_node: (Arc<Index>, usize)),
            (index.clone(), i),
        )
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 64)).await?;
    let version = head.get(4).copied().unwrap_or(0);
    let block = cx.block(file.sub(0, 64)).await?;
    let mut probe = Fields::new(&block, Endian::Little);
    let sizes = header(&mut probe, &version)?;
    let header_len = probe.pos();
    let hspan = file.sub(0, header_len);
    cx.emit(crate::fields::struct_node(
        "Header",
        hspan,
        Endian::Little,
        version,
        header,
    ));
    if matches!(version, 0x53..=0x55) && head.get(6..12) != Some(LUAC_DATA) {
        cx.diag(Diagnostic::warning(
            "LUAC_DATA does not match (corrupted by a text conversion?)",
        ));
    }
    let body = file.tail(header_len);
    let mut summary = format!("Lua {}.{} bytecode", version >> 4, version & 0xf);
    if body.len > MAX_CHUNK {
        cx.annotate(summary);
        return Err(Diagnostic::limit("chunk too large to decode").at(body));
    }
    let data = cx.read(body).await?;
    let mut p = Parser {
        r: Reader::new(&data),
        span: body,
        version,
        s: sizes,
        base: crate::bytes::to_usize(header_len),
        protos: Vec::new(),
        saved: Vec::new(),
        steps: 0,
    };
    let ok = prototype(&cx, &mut p, 0, None).await.is_some();
    let end = p.r.pos();
    let index = Arc::new(Index {
        span: body,
        protos: std::mem::take(&mut p.protos),
    });
    if let Some(main) = index.protos.first() {
        if let Some(source) = &main.source
            && !source.is_empty()
        {
            summary.push_str(&format!(", from {}", source.trim_start_matches(['@', '='])));
        }
        let functions = index.protos.len().saturating_sub(1);
        summary.push_str(&format!(
            ", main function of {} instructions",
            main.instructions
        ));
        if functions > 0 {
            summary.push_str(&format!(", {}", plural(to_u64(functions), "nested function")));
        }
    }
    cx.annotate(summary);
    let mut main = proto_entry(&index, 0);
    if !ok {
        main = main.diag(
            Diagnostic::malformed("truncated or malformed function prototype")
                .at(body.sub(to_u64(end), 1)),
        );
    }
    cx.emit(main);
    if ok && to_u64(end) < body.len {
        cx.emit(
            Node::new("Trailing data")
                .span(body.tail(to_u64(end)))
                .diag(Diagnostic::warning("data after the main function")),
        );
    }
    Ok(())
}
