//! Component-model section bodies (`Binary.md` of the component model):
//! core types, core instances, instances, types, canonical functions,
//! aliases and the start function. Encodings follow what wasm-tools
//! (wasmparser) reads and writes.

use std::sync::Arc;

use super::{
    CORE_SORT, PRIMITIVE, extern_desc, extern_name, import_desc, name, sort, sort_index, sub_type,
};
use crate::bytes::to_u64;
use crate::formats::util::arcutil::push_nodes;
use crate::formats::util::binutil::Reader;
use crate::formats::util::fmt::{clip, count};
use crate::formats::util::val::{name_or, text};
use crate::node::Node;

/// Type declarations nest (instance types in component types ...).
const MAX_DEPTH: u32 = 16;

fn with_children(node: Node, children: Vec<Node>) -> Node {
    if children.is_empty() {
        node
    } else {
        node.lazy(push_nodes, Arc::new(children))
    }
}

/// `<T>?`: 0x00 for none, 0x01 and the value.
fn optional<T>(
    r: &mut Reader<'_>,
    f: impl FnOnce(&mut Reader<'_>) -> Option<T>,
) -> Option<Option<T>> {
    match r.u8()? {
        0x00 => Some(None),
        0x01 => f(r).map(Some),
        _ => None,
    }
}

/// A `vec(T)`, decoded by `f`.
fn list<T>(r: &mut Reader<'_>, mut f: impl FnMut(&mut Reader<'_>) -> Option<T>) -> Option<Vec<T>> {
    let n = r.uleb()?;
    let mut out = Vec::new();
    for _ in 0..n {
        out.push(f(r)?);
    }
    Some(out)
}

/// A component `valtype`: a primitive or a type index.
fn valtype(r: &mut Reader<'_>) -> Option<String> {
    let b = r.peek()?;
    if b == 0x64 || b >= 0x73 {
        r.u8()?;
        return Some(name_or(PRIMITIVE, b.into(), "primitive"));
    }
    if b >= 0x40 {
        // Type indices are non-negative s33s: one byte below 0x40.
        return None;
    }
    Some(format!("type {}", r.uleb()?))
}

/// A `defvaltype` after its first byte.
fn defvaltype(r: &mut Reader<'_>, b: u8) -> Option<String> {
    let labels = |r: &mut Reader<'_>| list(r, name).map(|l| l.join(", "));
    Some(match b {
        0x64 | 0x73..=0x7f => name_or(PRIMITIVE, b.into(), "primitive"),
        0x72 => {
            let fields = list(r, |r| Some(format!("{}: {}", name(r)?, valtype(r)?)))?;
            format!("record {{{}}}", fields.join(", "))
        }
        0x71 => {
            let cases = list(r, |r| {
                let label = name(r)?;
                let t = optional(r, valtype)?;
                // Older encodings: a `refines` case index.
                optional(r, |r| r.uleb())?;
                Some(match t {
                    Some(t) => format!("{label}({t})"),
                    None => label,
                })
            })?;
            format!("variant {{{}}}", cases.join(", "))
        }
        0x70 => format!("list<{}>", valtype(r)?),
        0x67 => {
            let t = valtype(r)?;
            format!("list<{t}, {}>", r.uleb()?)
        }
        0x6f => format!("tuple<{}>", list(r, valtype)?.join(", ")),
        0x6e => format!("flags {{{}}}", labels(r)?),
        0x6d => format!("enum {{{}}}", labels(r)?),
        0x6b => format!("option<{}>", valtype(r)?),
        0x6a => {
            let ok = optional(r, valtype)?;
            let err = optional(r, valtype)?;
            match (ok, err) {
                (None, None) => "result".to_owned(),
                (Some(ok), None) => format!("result<{ok}>"),
                (None, Some(err)) => format!("result<_, {err}>"),
                (Some(ok), Some(err)) => format!("result<{ok}, {err}>"),
            }
        }
        0x69 => format!("own<type {}>", r.uleb()?),
        0x68 => format!("borrow<type {}>", r.uleb()?),
        0x66 => match optional(r, valtype)? {
            Some(t) => format!("stream<{t}>"),
            None => "stream".to_owned(),
        },
        0x65 => match optional(r, valtype)? {
            Some(t) => format!("future<{t}>"),
            None => "future".to_owned(),
        },
        _ => return None,
    })
}

/// A component `functype` after its first byte (0x40, or 0x43 async).
fn functype(r: &mut Reader<'_>, b: u8) -> Option<String> {
    let params = list(r, |r| Some(format!("{}: {}", name(r)?, valtype(r)?)))?;
    let results = match r.u8()? {
        0x00 => valtype(r)?,
        // 0x01 and a (formerly named) result list, empty today.
        0x01 => {
            let named = list(r, |r| Some(format!("{}: {}", name(r)?, valtype(r)?)))?;
            if named.is_empty() {
                String::new()
            } else {
                format!("({})", named.join(", "))
            }
        }
        _ => return None,
    };
    let kind = if b == 0x43 { "async func" } else { "func" };
    Some(if results.is_empty() {
        format!("{kind} ({})", params.join(", "))
    } else {
        format!("{kind} ({}) -> {results}", params.join(", "))
    })
}

/// A component `deftype`: its rendering and, for component and instance
/// types, one node per declaration.
fn deftype(r: &mut Reader<'_>, depth: u32) -> Option<(String, Vec<Node>)> {
    if depth > MAX_DEPTH {
        return None;
    }
    let b = r.u8()?;
    Some(match b {
        0x40 | 0x43 => (functype(r, b)?, Vec::new()),
        0x41 | 0x42 => {
            let component = b == 0x41;
            let decls = list(r, |r| decl(r, depth.saturating_add(1), component))?;
            let what = if component {
                "component type"
            } else {
                "instance type"
            };
            (
                format!(
                    "{what}, {}",
                    count(to_u64(decls.len()), "declaration", "declarations")
                ),
                decls,
            )
        }
        0x3f => {
            if r.u8()? != 0x7f {
                return None;
            }
            match optional(r, |r| r.uleb())? {
                Some(f) => (format!("resource (rep i32), dtor func {f}"), Vec::new()),
                None => ("resource (rep i32)".to_owned(), Vec::new()),
            }
        }
        0x3e => {
            if r.u8()? != 0x7f {
                return None;
            }
            let f = r.uleb()?;
            let mut s = format!("resource (rep i32), async dtor func {f}");
            if let Some(cb) = optional(r, |r| r.uleb())? {
                s.push_str(&format!(", callback func {cb}"));
            }
            (s, Vec::new())
        }
        _ => (defvaltype(r, b)?, Vec::new()),
    })
}

/// A `componentdecl` (with `component`) or `instancedecl`.
fn decl(r: &mut Reader<'_>, depth: u32, component: bool) -> Option<Node> {
    Some(match r.u8()? {
        0x03 if component => {
            let n = extern_name(r)?;
            Node::new(format!("import {n}")).value(text(extern_desc(r)?))
        }
        0x00 => {
            let (s, children) = core_deftype(r)?;
            with_children(Node::new("core type").value(text(s)), children)
        }
        0x01 => {
            let (s, children) = deftype(r, depth)?;
            with_children(Node::new("type").value(text(clip(&s, 200))), children)
        }
        0x02 => {
            let (what, target) = alias(r)?;
            Node::new("alias").value(text(what)).summary(target)
        }
        0x04 => {
            let n = extern_name(r)?;
            Node::new(format!("export {n}")).value(text(extern_desc(r)?))
        }
        _ => return None,
    })
}

/// An alias: the sort and the target.
pub(super) fn alias(r: &mut Reader<'_>) -> Option<(String, String)> {
    let what = sort(r)?;
    let target = match r.u8()? {
        0x00 => {
            let i = r.uleb()?;
            format!("export {:?} of instance {i}", name(r)?)
        }
        0x01 => {
            let i = r.uleb()?;
            format!("export {:?} of core instance {i}", name(r)?)
        }
        0x02 => {
            let up = r.uleb()?;
            format!("outer {up} index {}", r.uleb()?)
        }
        _ => return None,
    };
    Some((what, target))
}

const CORE_KIND: [&str; 5] = ["func", "table", "memory", "global", "tag"];

/// A core import or export descriptor: kind byte and descriptor.
fn core_desc(r: &mut Reader<'_>) -> Option<String> {
    let kind = r.u8()?;
    let what = CORE_KIND.get(usize::from(kind))?;
    Some(format!("{what} {}", import_desc(r, kind)?))
}

/// A `core:deftype`: a module type (0x50 and declarations) or a core
/// (GC) type.
fn core_deftype(r: &mut Reader<'_>) -> Option<(String, Vec<Node>)> {
    if r.peek()? != 0x50 {
        return Some((sub_type(r)?, Vec::new()));
    }
    r.u8()?;
    let decls = list(r, |r| {
        Some(match r.u8()? {
            0x00 => {
                let module = name(r)?;
                let field = name(r)?;
                Node::new(format!("import {module}.{field}")).value(text(core_desc(r)?))
            }
            0x01 => Node::new("type").value(text(sub_type(r)?)),
            0x02 => {
                let what = name_or(CORE_SORT, r.u8()?.into(), "core sort");
                if r.u8()? != 0x01 {
                    return None;
                }
                let up = r.uleb()?;
                let index = r.uleb()?;
                Node::new("alias")
                    .value(text(what))
                    .summary(format!("outer {up} index {index}"))
            }
            0x03 => {
                let n = name(r)?;
                Node::new(format!("export {n}")).value(text(core_desc(r)?))
            }
            _ => return None,
        })
    })?;
    Some((
        format!(
            "module type, {}",
            count(to_u64(decls.len()), "declaration", "declarations")
        ),
        decls,
    ))
}

/// A core type section entry.
pub(super) fn core_type(r: &mut Reader<'_>, i: u64) -> Option<Node> {
    let (s, children) = core_deftype(r)?;
    Some(with_children(
        Node::new(format!("[{i}]")).value(text(clip(&s, 200))),
        children,
    ))
}

/// A type section entry.
pub(super) fn component_type(r: &mut Reader<'_>, i: u64) -> Option<Node> {
    let (s, children) = deftype(r, 0)?;
    Some(with_children(
        Node::new(format!("[{i}]")).value(text(clip(&s, 200))),
        children,
    ))
}

/// A `core:sortidx`.
fn core_sort_index(r: &mut Reader<'_>) -> Option<String> {
    let what = name_or(CORE_SORT, r.u8()?.into(), "core sort");
    Some(format!("{what} {}", r.uleb()?))
}

/// A core instance section entry: an instantiation or inline exports.
pub(super) fn core_instance(r: &mut Reader<'_>, i: u64) -> Option<Node> {
    let node = Node::new(format!("[{i}]"));
    Some(match r.u8()? {
        0x00 => {
            let module = r.uleb()?;
            let args = list(r, |r| {
                let n = name(r)?;
                if r.u8()? != 0x12 {
                    return None;
                }
                Some(
                    Node::new(format!("with {n}"))
                        .value(text(format!("core instance {}", r.uleb()?))),
                )
            })?;
            with_children(
                node.value(text(format!("instantiate core module {module}")))
                    .summary(count(to_u64(args.len()), "argument", "arguments")),
                args,
            )
        }
        0x01 => {
            let exports = list(r, |r| {
                let n = name(r)?;
                Some(Node::new(n).value(text(core_sort_index(r)?)))
            })?;
            with_children(
                node.value(text("inline exports")).summary(count(
                    to_u64(exports.len()),
                    "export",
                    "exports",
                )),
                exports,
            )
        }
        _ => return None,
    })
}

/// An instance section entry: an instantiation or inline exports.
pub(super) fn instance(r: &mut Reader<'_>, i: u64) -> Option<Node> {
    let node = Node::new(format!("[{i}]"));
    Some(match r.u8()? {
        0x00 => {
            let component = r.uleb()?;
            let args = list(r, |r| {
                let n = name(r)?;
                Some(Node::new(format!("with {n}")).value(text(sort_index(r)?)))
            })?;
            with_children(
                node.value(text(format!("instantiate component {component}")))
                    .summary(count(to_u64(args.len()), "argument", "arguments")),
                args,
            )
        }
        0x01 => {
            let exports = list(r, |r| {
                let n = extern_name(r)?;
                Some(Node::new(n).value(text(sort_index(r)?)))
            })?;
            with_children(
                node.value(text("inline exports")).summary(count(
                    to_u64(exports.len()),
                    "export",
                    "exports",
                )),
                exports,
            )
        }
        _ => return None,
    })
}

/// `canonopt`s, rendered.
fn canon_opts(r: &mut Reader<'_>) -> Option<Vec<String>> {
    list(r, |r| {
        Some(match r.u8()? {
            0x00 => "string-encoding=utf8".to_owned(),
            0x01 => "string-encoding=utf16".to_owned(),
            0x02 => "string-encoding=latin1+utf16".to_owned(),
            0x03 => format!("core memory {}", r.uleb()?),
            0x04 => format!("realloc core func {}", r.uleb()?),
            0x05 => format!("post-return core func {}", r.uleb()?),
            0x06 => "async".to_owned(),
            0x07 => format!("callback core func {}", r.uleb()?),
            _ => return None,
        })
    })
}

/// A canon section entry: lift, lower or a resource built-in. (The
/// asynchronous built-ins, still changing, are not decoded.)
pub(super) fn canon(r: &mut Reader<'_>, i: u64) -> Option<Node> {
    let node = Node::new(format!("[{i}]"));
    let opts = |node: Node, opts: Vec<String>| {
        if opts.is_empty() {
            node
        } else {
            node.summary(clip(&opts.join(", "), 200))
        }
    };
    Some(match r.u8()? {
        0x00 => {
            if r.u8()? != 0x00 {
                return None;
            }
            let f = r.uleb()?;
            let o = canon_opts(r)?;
            let t = r.uleb()?;
            opts(
                node.value(text(format!("lift core func {f} as type {t}"))),
                o,
            )
        }
        0x01 => {
            if r.u8()? != 0x00 {
                return None;
            }
            let f = r.uleb()?;
            let o = canon_opts(r)?;
            opts(node.value(text(format!("lower func {f}"))), o)
        }
        0x02 => node.value(text(format!("resource.new type {}", r.uleb()?))),
        0x03 => node.value(text(format!("resource.drop type {}", r.uleb()?))),
        0x07 => node.value(text(format!("resource.drop async type {}", r.uleb()?))),
        0x04 => node.value(text(format!("resource.rep type {}", r.uleb()?))),
        _ => return None,
    })
}

/// The start section: the function, its argument values and the number
/// of results.
pub(super) fn start(r: &mut Reader<'_>) -> Option<Node> {
    let f = r.uleb()?;
    let args = list(r, |r| r.uleb())?;
    let results = r.uleb()?;
    let args: Vec<String> = args.iter().map(|a| format!("value {a}")).collect();
    Some(
        Node::new("start")
            .value(text(format!("func {f}")))
            .summary(format!(
                "({}) -> {}",
                clip(&args.join(", "), 200),
                count(results, "result", "results")
            )),
    )
}
