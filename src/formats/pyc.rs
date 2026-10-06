//! Python byte-compiled modules (`.pyc`): a header (magic number, flags,
//! source timestamp and size, or a source hash) and a marshalled code
//! object.
//!
//! Marshal data is sequential and nested, so it is decoded once into a
//! tree (bounded by the input size and a nesting limit) that is displayed
//! lazily. Code objects show their fields; nested code objects (functions,
//! classes, comprehensions) appear among their parent's constants.

use std::sync::Arc;

use crate::bytes::{to_u64, u16_le, u32_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::binutil::{NodeExt, Reader, Tree, ellipsize, text};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{FlagTable, Value, decode_flags, flag};

const LE: Endian = Endian::Little;
/// Largest marshal stream decoded.
const MAX_DATA: u64 = 8 << 20;
const MAX_DEPTH: u32 = 100;

pub static FORMAT: Format = Format {
    name: "pyc",
    title: "Python byte-compiled module",
    extensions: &["pyc", "pyo"],
    mime: "application/x-python-code",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    let Some(v) = u16_le(h.data, 0).and_then(version) else {
        return false;
    };
    let header = if v >= (3, 7) {
        16
    } else if v >= (3, 3) {
        12
    } else {
        8
    };
    // The marshalled code object follows the header ('c', possibly with
    // the reference flag set).
    h.at(2, b"\r\n") && matches!(h.data.get(header), Some(b'c' | 0xe3))
}

/// The Python version a magic number belongs to, as `(major, minor)`.
pub fn version(magic: u16) -> Option<(u8, u8)> {
    Some(match magic {
        20121 => (1, 5),
        50428 => (1, 6),
        50823 => (2, 0),
        60202 => (2, 1),
        60717 => (2, 2),
        62011..=62021 => (2, 3),
        62041..=62061 => (2, 4),
        62071..=62131 => (2, 5),
        62151..=62161 => (2, 6),
        62171..=62211 => (2, 7),
        3000..=3131 => (3, 0),
        3132..=3151 => (3, 1),
        3152..=3180 => (3, 2),
        3181..=3230 => (3, 3),
        3231..=3310 => (3, 4),
        3311..=3351 => (3, 5),
        3352..=3379 => (3, 6),
        3380..=3394 => (3, 7),
        3395..=3413 => (3, 8),
        3414..=3425 => (3, 9),
        3426..=3439 => (3, 10),
        3440..=3495 => (3, 11),
        3496..=3531 => (3, 12),
        3532..=3571 => (3, 13),
        3572..=3627 => (3, 14),
        3628..=3699 => (3, 15),
        _ => return None,
    })
}

const PYC_FLAGS: FlagTable = &[flag(1, "HASH_BASED"), flag(2, "CHECK_SOURCE")];

const CO_FLAGS: FlagTable = &[
    flag(0x1, "OPTIMIZED"),
    flag(0x2, "NEWLOCALS"),
    flag(0x4, "VARARGS"),
    flag(0x8, "VARKEYWORDS"),
    flag(0x10, "NESTED"),
    flag(0x20, "GENERATOR"),
    flag(0x40, "NOFREE"),
    flag(0x80, "COROUTINE"),
    flag(0x100, "ITERABLE_COROUTINE"),
    flag(0x200, "ASYNC_GENERATOR"),
    flag(0x400, "HAS_DOCSTRING"),
    flag(0x800, "METHOD"),
    flag(0x2_0000, "FUTURE_DIVISION"),
    flag(0x4_0000, "FUTURE_ABSOLUTE_IMPORT"),
    flag(0x8_0000, "FUTURE_WITH_STATEMENT"),
    flag(0x10_0000, "FUTURE_PRINT_FUNCTION"),
    flag(0x20_0000, "FUTURE_UNICODE_LITERALS"),
    flag(0x100_0000, "FUTURE_ANNOTATIONS"),
];

// ---------------------------------------------------------------------------
// Header

fn header(f: &mut Fields<'_>, v: &(u8, u8)) -> Result<()> {
    f.u16("magic")
        .with(|_, n| n.summary(format!("Python {}.{}", v.0, v.1)))
        .emit()?;
    f.bytes("\\r\\n", 2).emit()?;
    if *v >= (3, 7) {
        let flags = f.u32("flags").flags(PYC_FLAGS).emit()?;
        if flags & 1 != 0 {
            f.bytes("source_hash", 8)
                .with(|b, n| n.summary(crate::formats::binutil::hex_string(b)))
                .desc("SipHash of the source file")
                .emit()?;
        } else {
            f.u32("mtime").timestamp().desc("Source modification time").emit()?;
            f.u32("source_size").emit()?;
        }
        Ok(())
    } else if *v >= (3, 3) {
        f.u32("mtime").timestamp().emit()?;
        f.u32("source_size").emit()?;
        Ok(())
    } else {
        f.u32("mtime").timestamp().emit()?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Marshal

type Step<T> = std::result::Result<T, Diagnostic>;

struct Unmarshal<'a> {
    r: Reader<'a>,
    span: Span,
    version: (u8, u8),
    tree: Tree,
    /// Short descriptions of objects flagged as references.
    refs: Vec<String>,
}

/// A decoded object: its node in the tree and a one-line description.
struct Obj {
    node: usize,
    short: String,
    text: Option<String>,
}

impl Unmarshal<'_> {
    fn at(&self, start: usize) -> Span {
        self.span
            .sub(to_u64(start), to_u64(self.r.pos().saturating_sub(start)))
    }

    fn fail(&self, what: &str) -> Diagnostic {
        Diagnostic::malformed(format!("truncated or malformed {what}"))
            .at(self.span.sub(to_u64(self.r.pos()), 1))
    }

    fn i32(&mut self) -> Step<i32> {
        self.r.int::<i32>(LE).ok_or_else(|| self.fail("integer"))
    }

    fn u32(&mut self) -> Step<u32> {
        self.r.int::<u32>(LE).ok_or_else(|| self.fail("length"))
    }

    fn bytes(&mut self, n: u64) -> Step<&[u8]> {
        let n = usize::try_from(n).unwrap_or(usize::MAX);
        match self.r.bytes(n) {
            Some(b) => Ok(b),
            None => Err(self.fail("data")),
        }
    }

    fn leaf(&mut self, parent: usize, label: &str, start: usize, value: Value, short: String) -> Obj {
        let node = self.tree.add(
            Some(parent),
            Node::new(label.to_owned()).span(self.at(start)).value(value),
        );
        Obj {
            node,
            short,
            text: None,
        }
    }

    /// One marshalled object, added under `parent` as `label`.
    fn object(&mut self, parent: usize, label: &str, depth: u32) -> Step<Obj> {
        if depth > MAX_DEPTH {
            return Err(Diagnostic::limit("objects nested too deeply")
                .at(self.span.sub(to_u64(self.r.pos()), 1)));
        }
        let start = self.r.pos();
        let byte = self.r.u8().ok_or_else(|| self.fail("object"))?;
        let flagged = byte & 0x80 != 0;
        // Reserve the reference slot before decoding children, as CPython does.
        let slot = if flagged {
            self.refs.push(String::new());
            Some(self.refs.len().saturating_sub(1))
        } else {
            None
        };
        let obj = self.body(parent, label, depth, start, byte & 0x7f)?;
        if let Some(slot) = slot
            && let Some(r) = self.refs.get_mut(slot)
        {
            r.clone_from(&obj.short);
        }
        Ok(obj)
    }

    fn string(&mut self, parent: usize, label: &str, start: usize, len: u64, bytes: bool) -> Step<Obj> {
        let data = self.bytes(len)?;
        if bytes {
            let preview = data.get(..64).unwrap_or(data).to_vec();
            let short = format!("bytes[{len}]");
            let node = self.tree.add(
                Some(parent),
                Node::new(label.to_owned())
                    .span(self.at(start))
                    .value(Value::Bytes(preview))
                    .summary(format!("{len} bytes")),
            );
            Ok(Obj {
                node,
                short,
                text: None,
            })
        } else {
            let s = String::from_utf8_lossy(data).into_owned();
            let mut obj = self.leaf(
                parent,
                label,
                start,
                text(s.clone()),
                format!("{:?}", ellipsize(&s, 40)),
            );
            obj.text = Some(s);
            Ok(obj)
        }
    }

    fn sequence(&mut self, parent: usize, label: &str, start: usize, n: u64, kind: &str, depth: u32) -> Step<Obj> {
        let node = self.tree.add(Some(parent), Node::new(label.to_owned()));
        let mut items = Vec::new();
        for i in 0..n {
            let obj = self.object(node, &format!("[{i}]"), depth.saturating_add(1))?;
            if items.len() < 8 {
                items.push(obj.short);
            }
        }
        let span = self.at(start);
        let joined = ellipsize(&items.join(", "), 100);
        self.tree.update(node, |x| {
            x.span(span)
                .value(text(format!("{kind} of {n}")))
                .maybe_summary(joined.clone())
        });
        Ok(Obj {
            node,
            short: format!("{kind}[{n}]"),
            text: None,
        })
    }

    fn body(&mut self, parent: usize, label: &str, depth: u32, start: usize, code: u8) -> Step<Obj> {
        let deeper = depth.saturating_add(1);
        match code {
            b'0' => Ok(self.leaf(parent, label, start, text("NULL"), "NULL".to_owned())),
            b'N' => Ok(self.leaf(parent, label, start, text("None"), "None".to_owned())),
            b'F' => Ok(self.leaf(parent, label, start, Value::Bool(false), "False".to_owned())),
            b'T' => Ok(self.leaf(parent, label, start, Value::Bool(true), "True".to_owned())),
            b'S' => Ok(self.leaf(parent, label, start, text("StopIteration"), "StopIteration".to_owned())),
            b'.' => Ok(self.leaf(parent, label, start, text("Ellipsis"), "...".to_owned())),
            b'i' => {
                let v = self.i32()?;
                Ok(self.leaf(parent, label, start, Value::Int { value: v.into(), bits: 32 }, v.to_string()))
            }
            b'I' => {
                let v = self.r.int::<i64>(LE).ok_or_else(|| self.fail("integer"))?;
                Ok(self.leaf(parent, label, start, Value::Int { value: v, bits: 64 }, v.to_string()))
            }
            b'g' => {
                let v = self.r.int::<f64>(LE).ok_or_else(|| self.fail("float"))?;
                Ok(self.leaf(parent, label, start, Value::Float(v), v.to_string()))
            }
            b'f' => {
                let n = self.r.u8().ok_or_else(|| self.fail("float"))?;
                let s = String::from_utf8_lossy(self.bytes(n.into())?).into_owned();
                Ok(self.leaf(parent, label, start, text(s.clone()), s))
            }
            b'y' => {
                let re = self.r.int::<f64>(LE).ok_or_else(|| self.fail("complex"))?;
                let im = self.r.int::<f64>(LE).ok_or_else(|| self.fail("complex"))?;
                let s = format!("({re}+{im}j)");
                Ok(self.leaf(parent, label, start, text(s.clone()), s))
            }
            b'x' => {
                let a = self.r.u8().ok_or_else(|| self.fail("complex"))?;
                self.bytes(a.into())?;
                let b = self.r.u8().ok_or_else(|| self.fail("complex"))?;
                self.bytes(b.into())?;
                Ok(self.leaf(parent, label, start, text("complex"), "complex".to_owned()))
            }
            b'l' => {
                let n = self.i32()?;
                let digits = u64::from(n.unsigned_abs());
                let data = self.bytes(digits.saturating_mul(2))?;
                // Base 2^15 digits, least significant first.
                let mut value: i128 = 0;
                let mut fits = digits <= 8;
                for (i, d) in data.chunks(2).enumerate() {
                    let d = i128::from(u16_le(d, 0).unwrap_or(0));
                    let shift = u32::try_from(i.saturating_mul(15)).unwrap_or(u32::MAX);
                    match d.checked_shl(shift) {
                        Some(v) if shift < 120 => value = value.saturating_add(v),
                        _ => fits = false,
                    }
                }
                if n < 0 {
                    value = value.saturating_neg();
                }
                let s = if fits {
                    value.to_string()
                } else {
                    format!("<{digits}-digit integer>")
                };
                Ok(self.leaf(parent, label, start, text(s.clone()), s))
            }
            b's' => {
                let len = self.u32()?;
                // Python 2 `str` is text; Python 3 marshals bytes here.
                let binary = self.version.0 >= 3 || {
                    let n = usize::try_from(len).unwrap_or(usize::MAX);
                    let rest = Reader::at(self.r.rest(), 0).bytes(n).unwrap_or_default();
                    !crate::text::looks_like_text(rest) && !rest.is_empty()
                };
                self.string(parent, label, start, len.into(), binary)
            }
            b't' | b'u' | b'a' | b'A' => {
                let len = self.u32()?;
                self.string(parent, label, start, len.into(), false)
            }
            b'z' | b'Z' => {
                let len = self.r.u8().ok_or_else(|| self.fail("string"))?;
                self.string(parent, label, start, len.into(), false)
            }
            b'R' | b'r' => {
                let index = self.u32()?;
                let target = self
                    .refs
                    .get(usize::try_from(index).unwrap_or(usize::MAX))
                    .cloned()
                    .unwrap_or_else(|| "?".to_owned());
                let short = target.clone();
                let mut obj = self.leaf(
                    parent,
                    label,
                    start,
                    text(format!("→ ref {index}")),
                    short,
                );
                self.tree.update(obj.node, |n| n.summary(target.clone()));
                if target.starts_with('"') {
                    obj.text = Some(target.trim_matches('"').to_owned());
                }
                Ok(obj)
            }
            b'(' | b'[' | b'<' | b'>' => {
                let n = self.u32()?;
                let kind = match code {
                    b'(' => "tuple",
                    b'[' => "list",
                    b'<' => "set",
                    _ => "frozenset",
                };
                self.sequence(parent, label, start, n.into(), kind, depth)
            }
            b')' => {
                let n = self.r.u8().ok_or_else(|| self.fail("tuple"))?;
                self.sequence(parent, label, start, n.into(), "tuple", depth)
            }
            b'{' => {
                let node = self.tree.add(Some(parent), Node::new(label.to_owned()));
                let mut n = 0u64;
                loop {
                    if self.r.peek() == Some(b'0') {
                        self.r.u8();
                        break;
                    }
                    let key = self.object(node, "key", deeper)?;
                    self.object(node, &format!("[{}]", key.short), deeper)?;
                    n = n.saturating_add(1);
                }
                let span = self.at(start);
                self.tree
                    .update(node, |x| x.span(span).value(text(format!("dict of {n}"))));
                Ok(Obj {
                    node,
                    short: format!("dict[{n}]"),
                    text: None,
                })
            }
            b':' => {
                let node = self.tree.add(Some(parent), Node::new(label.to_owned()));
                for part in ["start", "stop", "step"] {
                    self.object(node, part, deeper)?;
                }
                let span = self.at(start);
                self.tree.update(node, |x| x.span(span).value(text("slice")));
                Ok(Obj {
                    node,
                    short: "slice".to_owned(),
                    text: None,
                })
            }
            b'c' => self.code(parent, label, start, depth),
            other => Err(Diagnostic::unsupported(format!(
                "marshal type {:?}",
                char::from(other)
            ))
            .at(self.span.sub(to_u64(start), 1))),
        }
    }

    fn int_field(&mut self, node: usize, name: &str) -> Step<i32> {
        let start = self.r.pos();
        let v = self.i32()?;
        let value = if name == "co_flags" {
            let raw = u64::from(u32::from_le_bytes(v.to_le_bytes()));
            let (set, unknown) = decode_flags(CO_FLAGS, raw);
            Value::Flags {
                raw,
                bits: 32,
                set,
                unknown,
            }
        } else {
            Value::Int {
                value: v.into(),
                bits: 32,
            }
        };
        self.leaf(node, name, start, value, String::new());
        Ok(v)
    }

    fn code(&mut self, parent: usize, label: &str, start: usize, depth: u32) -> Step<Obj> {
        let node = self.tree.add(Some(parent), Node::new(label.to_owned()));
        let v = self.version;
        let deeper = depth.saturating_add(1);
        let mut ints: Vec<&str> = vec!["co_argcount"];
        if v >= (3, 8) {
            ints.push("co_posonlyargcount");
        }
        if v.0 >= 3 {
            ints.push("co_kwonlyargcount");
        }
        if v < (3, 11) {
            ints.push("co_nlocals");
        }
        ints.push("co_stacksize");
        ints.push("co_flags");
        for name in ints {
            self.int_field(node, name)?;
        }
        let code = self.object(node, "co_code", deeper)?;
        let consts = self.object(node, "co_consts", deeper)?;
        self.object(node, "co_names", deeper)?;
        if v >= (3, 11) {
            self.object(node, "co_localsplusnames", deeper)?;
            self.object(node, "co_localspluskinds", deeper)?;
        } else {
            self.object(node, "co_varnames", deeper)?;
            self.object(node, "co_freevars", deeper)?;
            self.object(node, "co_cellvars", deeper)?;
        }
        let filename = self.object(node, "co_filename", deeper)?;
        let name = self.object(node, "co_name", deeper)?;
        if v >= (3, 11) {
            self.object(node, "co_qualname", deeper)?;
        }
        let line = self.int_field(node, "co_firstlineno")?;
        self.object(
            node,
            if v >= (3, 10) { "co_linetable" } else { "co_lnotab" },
            deeper,
        )?;
        if v >= (3, 11) {
            self.object(node, "co_exceptiontable", deeper)?;
        }
        let name = name.text.unwrap_or_else(|| name.short.clone());
        let filename = filename.text.unwrap_or_else(|| filename.short.clone());
        let span = self.at(start);
        let summary = format!("{filename}:{line}, code {}, consts {}", code.short, consts.short);
        self.tree.update(node, |x| {
            x.span(span)
                .value(text(format!("code object {name}")))
                .summary(summary.clone())
        });
        Ok(Obj {
            node,
            short: format!("<code {name}>"),
            text: Some(format!("{name}\0{filename}")),
        })
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 16)).await?;
    let magic = u16_le(&head, 0).unwrap_or(0);
    let v = version(magic).ok_or_else(|| Diagnostic::unsupported("unknown magic number"))?;
    let hlen = if v >= (3, 7) {
        16
    } else if v >= (3, 3) {
        12
    } else {
        8
    };
    let hspan = file.sub(0, hlen);
    let body = file.tail(hlen);
    if body.len > MAX_DATA {
        return Err(Diagnostic::limit("marshal data too large to decode").at(body));
    }
    let data = cx.read(body).await?;
    let mut u = Unmarshal {
        r: Reader::new(&data),
        span: body,
        version: v,
        tree: Tree::default(),
        refs: Vec::new(),
    };
    let root = u.tree.add(None, Node::new("root"));
    u.tree.add(Some(root), struct_node("Header", hspan, LE, v, header));
    let mut summary = format!("Python {}.{} byte-compiled", v.0, v.1);
    if v >= (3, 7) && u32_le(&head, 4).is_some_and(|f| f & 1 != 0) {
        summary.push_str(" (hash-based)");
    }
    match u.object(root, "Code", 0) {
        Ok(obj) => {
            if let Some(t) = obj.text
                && let Some((_, filename)) = t.split_once('\0')
            {
                summary.push_str(&format!(", from {filename}"));
            }
            if !u.r.at_end() {
                cx.diag(Diagnostic::warning("data after the code object"));
            }
        }
        Err(e) => {
            u.tree.add(Some(root), Node::new("Undecoded").span(body).diag(e));
        }
    }
    cx.annotate(summary);
    let tree = Arc::new(u.tree);
    Tree::emit_children(&cx, &tree, root).await;
    Ok(())
}
