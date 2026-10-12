//! Expanders for the structured attributes beyond the basic ones:
//! `StackMapTable` (JVMS 4.7.4), the annotation family (4.7.16-4.7.22),
//! `Record` (4.7.30) and `Module` (4.7.25).

use super::{Attribute, BE, Class, ClassInfo, MAX_DEPTH, Owner, attribute_node, name_or};
use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::error::Result;
use crate::fields::Fields;
use crate::formats::util::binutil::{NodeExt, Reader};
use crate::formats::util::fmt::clip;
use crate::formats::util::val::text;
use crate::node::Node;
use crate::value::{EnumTable, FlagTable, flag};

/// Annotation values nest (arrays of annotations of arrays ...).
const MAX_NEST: u32 = 16;
/// Characters kept of a rendered value.
const SHOWN: usize = 160;

const VERIFICATION_TYPE: EnumTable = &[
    (0, "top"),
    (1, "int"),
    (2, "float"),
    (3, "double"),
    (4, "long"),
    (5, "null"),
    (6, "uninitializedThis"),
    (7, "Object"),
    (8, "Uninitialized"),
];

const TARGET_TYPE: EnumTable = &[
    (0x00, "class type parameter"),
    (0x01, "method type parameter"),
    (0x10, "supertype"),
    (0x11, "class type parameter bound"),
    (0x12, "method type parameter bound"),
    (0x13, "field or record component"),
    (0x14, "method return or new object"),
    (0x15, "method receiver"),
    (0x16, "formal parameter"),
    (0x17, "throws"),
    (0x40, "local variable"),
    (0x41, "resource variable"),
    (0x42, "exception parameter"),
    (0x43, "instanceof"),
    (0x44, "new"),
    (0x45, "constructor reference"),
    (0x46, "method reference"),
    (0x47, "cast"),
    (0x48, "constructor invocation type argument"),
    (0x49, "method invocation type argument"),
    (0x4a, "constructor reference type argument"),
    (0x4b, "method reference type argument"),
];

const MODULE_FLAGS: FlagTable = &[
    flag(0x0020, "OPEN"),
    flag(0x1000, "SYNTHETIC"),
    flag(0x8000, "MANDATED"),
];

const REQUIRES_FLAGS: FlagTable = &[
    flag(0x0020, "TRANSITIVE"),
    flag(0x0040, "STATIC_PHASE"),
    flag(0x1000, "SYNTHETIC"),
    flag(0x8000, "MANDATED"),
];

const EXPORTS_FLAGS: FlagTable = &[flag(0x1000, "SYNTHETIC"), flag(0x8000, "MANDATED")];

/// A string that stops growing at `SHOWN` characters.
/// Elements decoded for one rendering: annotation values are walked in
/// one step, so a hostile one cannot make that step unbounded.
const MAX_ELEMENTS: u32 = 1 << 16;

/// A rendering that stops growing at `SHOWN` characters, and the elements
/// left to decode.
struct Out(String, u32);

impl Out {
    fn new() -> Self {
        Out(String::new(), MAX_ELEMENTS)
    }
    fn push(&mut self, s: &str) {
        if self.0.len() < SHOWN {
            self.0.push_str(s);
        }
    }
    fn done(self) -> String {
        clip(&self.0, SHOWN)
    }
}

/// A type descriptor in source form (`Ljava/lang/String;` → `java.lang.String`).
fn type_name(descriptor: &str) -> String {
    let mut chars = descriptor.chars();
    super::field_type(&mut chars).unwrap_or_else(|| descriptor.replace('/', "."))
}

impl ClassInfo {
    fn utf8_or(&self, index: u16) -> String {
        self.utf8(index)
            .map_or_else(|| format!("#{index}?"), ToOwned::to_owned)
    }
}

/// Renders the `element_value` at `r`, advancing past it; `false` if it is
/// malformed, nests too deeply or has more than `MAX_ELEMENTS` elements.
fn element_value(c: &ClassInfo, r: &mut Reader<'_>, depth: u32, out: &mut Out) -> bool {
    if depth > MAX_NEST {
        return false;
    }
    let Some(left) = out.1.checked_sub(1) else {
        return false;
    };
    out.1 = left;
    let Some(tag) = r.u8() else { return false };
    match tag {
        b'B' | b'C' | b'D' | b'F' | b'I' | b'J' | b'S' | b'Z' => {
            let Some(i) = r.int::<u16>(BE) else {
                return false;
            };
            let v = c.resolve(i);
            match tag {
                b'Z' => out.push(if v == "0" { "false" } else { "true" }),
                b'C' => match v.parse::<u32>().ok().and_then(char::from_u32) {
                    Some(ch) => out.push(&format!("{ch:?}")),
                    None => out.push(&v),
                },
                _ => out.push(&v),
            }
            true
        }
        b's' => {
            let Some(i) = r.int::<u16>(BE) else {
                return false;
            };
            out.push(&format!("{:?}", c.utf8_or(i)));
            true
        }
        b'e' => {
            let (Some(t), Some(n)) = (r.int::<u16>(BE), r.int::<u16>(BE)) else {
                return false;
            };
            out.push(&type_name(&c.utf8_or(t)));
            out.push(".");
            out.push(&c.utf8_or(n));
            true
        }
        b'c' => {
            let Some(i) = r.int::<u16>(BE) else {
                return false;
            };
            out.push(&type_name(&c.utf8_or(i)));
            out.push(".class");
            true
        }
        b'@' => annotation(c, r, depth.saturating_add(1), out),
        b'[' => {
            let Some(n) = r.int::<u16>(BE) else {
                return false;
            };
            out.push("{");
            for i in 0..n {
                if i > 0 {
                    out.push(", ");
                }
                if !element_value(c, r, depth.saturating_add(1), out) {
                    return false;
                }
            }
            out.push("}");
            true
        }
        _ => false,
    }
}

/// Renders the `annotation` at `r` as `@Type(name=value, ...)`.
fn annotation(c: &ClassInfo, r: &mut Reader<'_>, depth: u32, out: &mut Out) -> bool {
    let (Some(kind), Some(pairs)) = (r.int::<u16>(BE), r.int::<u16>(BE)) else {
        return false;
    };
    out.push("@");
    out.push(&type_name(&c.utf8_or(kind)));
    if pairs > 0 {
        out.push("(");
        for i in 0..pairs {
            if i > 0 {
                out.push(", ");
            }
            let Some(name) = r.int::<u16>(BE) else {
                return false;
            };
            out.push(&c.utf8_or(name));
            out.push("=");
            if !element_value(c, r, depth, out) {
                return false;
            }
        }
        out.push(")");
    }
    true
}

/// A node for the annotation at absolute offset `at`; `None` if malformed.
/// Returns the node and the offset after the annotation.
fn annotation_node(c: &Class, at: usize, depth: u32) -> Option<(Node, usize)> {
    let mut r = Reader::at(&c.data, at);
    let kind = crate::bytes::u16_be(&c.data, at)?;
    let mut out = Out::new();
    if !annotation(c, &mut r, depth, &mut out) {
        return None;
    }
    let end = r.pos();
    let node = Node::new(format!("@{}", type_name(&c.utf8_or(kind))))
        .span(c.span(at, end.saturating_sub(at)))
        .value(text(out.done()));
    let pairs = crate::bytes::u16_be(&c.data, at.saturating_add(2)).unwrap_or(0);
    let node = if pairs > 0 && depth < MAX_NEST {
        node.lazy(
            crate::expander!(self::annotation_pairs: (Class, usize, u32)),
            (c.clone(), at, depth),
        )
    } else {
        node
    };
    Some((node, end))
}

/// A node for the element value at absolute offset `at`.
fn element_node(c: &Class, name: String, at: usize, depth: u32) -> Option<(Node, usize)> {
    let mut r = Reader::at(&c.data, at);
    let mut out = Out::new();
    if !element_value(c, &mut r, depth, &mut out) {
        return None;
    }
    let end = r.pos();
    let tag = c.data.get(at).copied().unwrap_or(0);
    let node = Node::new(name)
        .span(c.span(at, end.saturating_sub(at)))
        .value(text(out.done()));
    let node = match tag {
        b'@' if depth < MAX_NEST => node.lazy(
            crate::expander!(self::annotation_pairs: (Class, usize, u32)),
            (c.clone(), at.saturating_add(1), depth.saturating_add(1)),
        ),
        b'[' if depth < MAX_NEST
            && crate::bytes::u16_be(&c.data, at.saturating_add(1)).unwrap_or(0) > 0 =>
        {
            node.lazy(
                crate::expander!(self::array_elements: (Class, usize, u32)),
                (c.clone(), at, depth.saturating_add(1)),
            )
        }
        _ => node,
    };
    Some((node, end))
}

/// The `element_value_pairs` of the annotation at `at`.
async fn annotation_pairs(cx: Cx, (c, at, depth): (Class, usize, u32)) -> Result<()> {
    let pairs = crate::bytes::u16_be(&c.data, at.saturating_add(2)).unwrap_or(0);
    let mut pos = at.saturating_add(4);
    for i in 0..pairs {
        if i % 256 == 255 {
            cx.checkpoint().await;
        }
        let Some(name) = crate::bytes::u16_be(&c.data, pos) else {
            break;
        };
        let Some((node, end)) = element_node(&c, c.utf8_or(name), pos.saturating_add(2), depth)
        else {
            cx.diag(super::malformed("element value", pos, c.file));
            break;
        };
        cx.push(node.span(c.span(pos, end.saturating_sub(pos))))
            .await;
        pos = end;
    }
    Ok(())
}

/// The values of the array element value at `at`.
async fn array_elements(cx: Cx, (c, at, depth): (Class, usize, u32)) -> Result<()> {
    let n = crate::bytes::u16_be(&c.data, at.saturating_add(1)).unwrap_or(0);
    let mut pos = at.saturating_add(3);
    for i in 0..n {
        if i % 256 == 255 {
            cx.checkpoint().await;
        }
        let Some((node, end)) = element_node(&c, format!("[{i}]"), pos, depth) else {
            cx.diag(super::malformed("element value", pos, c.file));
            break;
        };
        cx.push(node).await;
        pos = end;
    }
    Ok(())
}

/// Emits `count` annotations starting at block position `f.pos()`, as
/// nodes; leaves `f` after them. `false` if one is malformed.
async fn annotations(cx: &Cx, c: &Class, a: Attribute, f: &mut Fields<'_>, count: u16) -> bool {
    let mut at = a.offset.saturating_add(crate::bytes::to_usize(f.pos()));
    for i in 0..count {
        if i % 256 == 255 {
            cx.checkpoint().await;
        }
        let Some((node, end)) = annotation_node(c, at, 0) else {
            cx.diag(super::malformed("annotation", at, c.file));
            return false;
        };
        f.node(node);
        f.skip(to_u64(end.saturating_sub(at)));
        at = end;
    }
    true
}

/// The value of an `AnnotationDefault` body (for its summary).
pub(super) fn default_value(c: &ClassInfo, b: &[u8]) -> String {
    let mut out = Out::new();
    if element_value(c, &mut Reader::new(b), 0, &mut out) {
        clip(&out.done(), 80)
    } else {
        String::new()
    }
}

/// The annotation types of a `Runtime*Annotations` body (for summaries).
pub(super) fn annotation_types(c: &ClassInfo, b: &[u8]) -> Vec<String> {
    let mut r = Reader::new(b);
    let mut out = Vec::new();
    let Some(n) = r.int::<u16>(BE) else {
        return out;
    };
    for _ in 0..n.min(64) {
        let Some(kind) = r.int::<u16>(BE) else { break };
        out.push(type_name(&c.utf8_or(kind)));
        let mut sink = Out::new();
        // Re-read from the type index to skip the whole annotation.
        let back = r.pos().saturating_sub(2);
        let mut r2 = Reader::at(b, back);
        if !annotation(c, &mut r2, 0, &mut sink) {
            break;
        }
        r = Reader::at(b, r2.pos());
    }
    out
}

/// Expands the attributes this module knows; `false` for any other name.
pub(super) async fn expand(
    cx: &Cx,
    c: &Class,
    f: &mut Fields<'_>,
    name: &str,
    a: Attribute,
    depth: u32,
) -> Result<bool> {
    match name {
        "StackMapTable" => stack_map_table(cx, c, f).await?,
        "RuntimeVisibleAnnotations" | "RuntimeInvisibleAnnotations" => {
            let n = f.u16("num_annotations").emit()?;
            annotations(cx, c, a, f, n).await;
        }
        "RuntimeVisibleParameterAnnotations" | "RuntimeInvisibleParameterAnnotations" => {
            let n = f.u8("num_parameters").emit()?;
            for p in 0..n {
                let start = f.pos();
                let count = f.u16("num_annotations").get()?;
                let at = a.offset.saturating_add(crate::bytes::to_usize(f.pos()));
                let mut end = at;
                let mut types = Vec::new();
                for _ in 0..count {
                    let mut r = Reader::at(&c.data, end);
                    let mut out = Out::new();
                    if !annotation(c, &mut r, 0, &mut out) {
                        cx.diag(super::malformed("annotation", end, c.file));
                        return Ok(true);
                    }
                    if types.len() < 16 {
                        let kind = crate::bytes::u16_be(&c.data, end).unwrap_or(0);
                        types.push(format!("@{}", type_name(&c.utf8_or(kind))));
                    }
                    end = r.pos();
                }
                f.skip(to_u64(end.saturating_sub(at)));
                let span = f.block().span.sub(start, f.pos().saturating_sub(start));
                let node =
                    Node::new(format!("parameter {p}"))
                        .span(span)
                        .summary(if types.is_empty() {
                            "no annotations".to_owned()
                        } else {
                            types.join(" ")
                        });
                f.node(if count > 0 {
                    node.lazy(
                        crate::expander!(self::parameter_annotations: (Class, usize, u16)),
                        (c.clone(), at, count),
                    )
                } else {
                    node
                });
            }
        }
        "AnnotationDefault" => {
            let at = a.offset.saturating_add(6);
            match element_node(c, "default_value".to_owned(), at, 0) {
                Some((node, _)) => f.node(node),
                None => cx.diag(super::malformed("element value", at, c.file)),
            }
        }
        "RuntimeVisibleTypeAnnotations" | "RuntimeInvisibleTypeAnnotations" => {
            let n = f.u16("num_annotations").emit()?;
            for i in 0..n {
                if i % 256 == 255 {
                    cx.checkpoint().await;
                }
                if !type_annotation(cx, c, a, f)? {
                    break;
                }
            }
        }
        "Record" => {
            let n = f.u16("components_count").emit()?;
            for i in 0..n {
                if i % 256 == 255 {
                    cx.checkpoint().await;
                }
                let start = f.pos();
                let name = f.u16("name_index").get()?;
                let desc = f.u16("descriptor_index").get()?;
                let count = f.u16("attributes_count").get()?;
                for _ in 0..count {
                    f.u16("attribute_name_index").get()?;
                    let len = f.u32("attribute_length").get()?;
                    f.skip(len.into());
                }
                if f.pos() > f.block().data.len() as u64 {
                    cx.diag(super::malformed("record component", a.offset, c.file));
                    break;
                }
                let span = f.block().span.sub(start, f.pos().saturating_sub(start));
                let decl = super::declaration(&c.utf8_or(name), &c.utf8_or(desc));
                let node = Node::new(c.utf8_or(name))
                    .span(span)
                    .value(text(decl))
                    .summary(format!("{count} attributes"));
                f.node(if count > 0 && depth < MAX_DEPTH {
                    node.lazy(
                        crate::expander!(self::component: (Class, usize, usize, u32)),
                        (c.clone(), a.offset, usize::from(i), depth),
                    )
                } else {
                    node
                });
            }
        }
        "Module" => module(cx, c, f).await?,
        _ => return Ok(false),
    }
    Ok(true)
}

/// The annotations of one parameter.
async fn parameter_annotations(cx: Cx, (c, at, count): (Class, usize, u16)) -> Result<()> {
    let mut at = at;
    for i in 0..count {
        if i % 256 == 255 {
            cx.checkpoint().await;
        }
        let Some((node, end)) = annotation_node(&c, at, 0) else {
            cx.diag(super::malformed("annotation", at, c.file));
            break;
        };
        cx.push(node).await;
        at = end;
    }
    Ok(())
}

/// The attributes of record component `index` of the `Record` attribute at
/// `offset`.
async fn component(cx: Cx, (c, offset, index, depth): (Class, usize, usize, u32)) -> Result<()> {
    let owner = Owner::Component(offset, index);
    for (i, attr) in super::attributes_of(&c, owner).iter().enumerate() {
        cx.push(attribute_node(&c, attr, owner, depth.saturating_add(1), i))
            .await;
    }
    Ok(())
}

/// The attributes of record component `index` in the `Record` attribute at
/// `offset`.
pub(super) fn component_attributes(c: &ClassInfo, offset: usize, index: usize) -> Vec<Attribute> {
    let mut r = Reader::at(&c.data, offset.saturating_add(6));
    let Some(n) = r.int::<u16>(BE) else {
        return Vec::new();
    };
    for i in 0..usize::from(n) {
        if r.int::<u16>(BE).is_none() || r.int::<u16>(BE).is_none() {
            break;
        }
        let Ok(list) = super::read_attributes(&mut r, c.file) else {
            break;
        };
        if i == index {
            return list;
        }
    }
    Vec::new()
}

/// One verification_type_info, rendered; `None` if truncated.
fn verification_type(c: &ClassInfo, f: &mut Fields<'_>) -> Result<String> {
    let tag = f.u8("tag").get()?;
    Ok(match tag {
        7 => {
            let i = f.u16("cpool_index").get()?;
            c.class_name(i)
        }
        8 => {
            let pc = f.u16("offset").get()?;
            format!("uninitialized(new at {pc})")
        }
        t => name_or(VERIFICATION_TYPE, t.into(), "type"),
    })
}

fn types(c: &ClassInfo, f: &mut Fields<'_>, n: u16) -> Result<String> {
    let mut v = Vec::new();
    for _ in 0..n {
        let t = verification_type(c, f)?;
        if v.len() < 32 {
            v.push(t);
        }
    }
    Ok(v.join(", "))
}

async fn stack_map_table(cx: &Cx, c: &Class, f: &mut Fields<'_>) -> Result<()> {
    let n = f.u16("number_of_entries").emit()?;
    let mut pc: Option<u32> = None;
    for i in 0..n {
        if i % 256 == 255 {
            cx.checkpoint().await;
        }
        let start = f.pos();
        let kind = f.u8("frame_type").get()?;
        let (label, delta, detail) = match kind {
            0..=63 => ("same", u16::from(kind), String::new()),
            64..=127 => {
                let s = types(c, f, 1)?;
                (
                    "same_locals_1_stack_item",
                    u16::from(kind.saturating_sub(64)),
                    format!("stack [{s}]"),
                )
            }
            247 => {
                let d = f.u16("offset_delta").get()?;
                let s = types(c, f, 1)?;
                (
                    "same_locals_1_stack_item_extended",
                    d,
                    format!("stack [{s}]"),
                )
            }
            248..=250 => {
                let d = f.u16("offset_delta").get()?;
                (
                    "chop",
                    d,
                    format!("{} locals removed", 251u8.saturating_sub(kind)),
                )
            }
            251 => ("same_extended", f.u16("offset_delta").get()?, String::new()),
            252..=254 => {
                let d = f.u16("offset_delta").get()?;
                let s = types(c, f, u16::from(kind.saturating_sub(251)))?;
                ("append", d, format!("locals + [{s}]"))
            }
            255 => {
                let d = f.u16("offset_delta").get()?;
                let nl = f.u16("number_of_locals").get()?;
                let l = types(c, f, nl)?;
                let ns = f.u16("number_of_stack_items").get()?;
                let s = types(c, f, ns)?;
                ("full", d, format!("locals [{l}], stack [{s}]"))
            }
            _ => {
                f.node(
                    Node::new(format!("frame {i}"))
                        .span(f.block().span.sub(start, 1))
                        .value(text("reserved"))
                        .diag(crate::error::Diagnostic::malformed(format!(
                            "reserved frame type {kind}"
                        ))),
                );
                break;
            }
        };
        let at = match pc {
            None => u32::from(delta),
            Some(p) => p.saturating_add(u32::from(delta)).saturating_add(1),
        };
        pc = Some(at);
        let summary = if detail.is_empty() {
            format!("pc {at}")
        } else {
            format!("pc {at}, {detail}")
        };
        f.node(
            Node::new(format!("frame {i}"))
                .span(f.block().span.sub(start, f.pos().saturating_sub(start)))
                .value(text(label))
                .summary(clip(&summary, SHOWN)),
        );
    }
    Ok(())
}

/// One `type_annotation`; `false` if malformed.
fn type_annotation(cx: &Cx, c: &Class, a: Attribute, f: &mut Fields<'_>) -> Result<bool> {
    let start = f.pos();
    let target = f.u8("target_type").get()?;
    let info = match target {
        0x00 | 0x01 => format!("type parameter {}", f.u8("type_parameter_index").get()?),
        0x10 => match f.u16("supertype_index").get()? {
            0xffff => "superclass".to_owned(),
            i => format!("interface {i}"),
        },
        0x11 | 0x12 => {
            let p = f.u8("type_parameter_index").get()?;
            let b = f.u8("bound_index").get()?;
            format!("type parameter {p}, bound {b}")
        }
        0x13..=0x15 => String::new(),
        0x16 => format!("parameter {}", f.u8("formal_parameter_index").get()?),
        0x17 => format!("throws {}", f.u16("throws_type_index").get()?),
        0x40 | 0x41 => {
            let n = f.u16("table_length").get()?;
            let mut slots = Vec::new();
            for _ in 0..n {
                let pc = f.u16("start_pc").get()?;
                let len = f.u16("length").get()?;
                let slot = f.u16("index").get()?;
                if slots.len() < 8 {
                    slots.push(format!(
                        "slot {slot} pc {pc}..{}",
                        u32::from(pc).saturating_add(len.into())
                    ));
                }
            }
            slots.join(", ")
        }
        0x42 => format!("exception table {}", f.u16("exception_table_index").get()?),
        0x43..=0x46 => format!("pc {}", f.u16("offset").get()?),
        0x47..=0x4b => {
            let pc = f.u16("offset").get()?;
            let i = f.u8("type_argument_index").get()?;
            format!("pc {pc}, type argument {i}")
        }
        _ => {
            cx.diag(
                crate::error::Diagnostic::malformed(format!("unknown target type 0x{target:02x}"))
                    .at(f.block().span.sub(start, 1)),
            );
            return Ok(false);
        }
    };
    let len = f.u8("path_length").get()?;
    let mut steps = Vec::new();
    for _ in 0..len {
        let kind = f.u8("type_path_kind").get()?;
        let arg = f.u8("type_argument_index").get()?;
        steps.push(match kind {
            0 => "array".to_owned(),
            1 => "nested".to_owned(),
            2 => "wildcard bound".to_owned(),
            3 => format!("type argument {arg}"),
            k => format!("kind {k}"),
        });
    }
    let path = steps.join(" / ");
    let at = a.offset.saturating_add(crate::bytes::to_usize(f.pos()));
    let Some((node, end)) = annotation_node(c, at, 0) else {
        cx.diag(super::malformed("annotation", at, c.file));
        return Ok(false);
    };
    f.skip(to_u64(end.saturating_sub(at)));
    let mut summary = name_or(TARGET_TYPE, target.into(), "target");
    if !info.is_empty() {
        summary.push_str(", ");
        summary.push_str(&info);
    }
    if !path.is_empty() {
        summary.push_str(", path ");
        summary.push_str(&path);
    }
    f.node(
        node.span(f.block().span.sub(start, f.pos().saturating_sub(start)))
            .summary(summary),
    );
    Ok(true)
}

async fn module(cx: &Cx, c: &Class, f: &mut Fields<'_>) -> Result<()> {
    let reference = |f: &mut Fields<'_>, label: &'static str| -> Result<u16> {
        f.u16(label).with(|&v, n| n.summary(c.resolve(v))).emit()
    };
    reference(f, "module_name_index")?;
    f.u16("module_flags").flags(MODULE_FLAGS).emit()?;
    f.u16("module_version_index")
        .with(|&v, n| {
            if v == 0 {
                n.summary("none")
            } else {
                n.summary(c.resolve(v))
            }
        })
        .emit()?;
    let flags_text = |table: FlagTable, v: u16| {
        let (set, _) = crate::value::decode_flags(table, v.into());
        set.join(" ")
    };
    let n = f.u16("requires_count").emit()?;
    for _ in 0..n {
        let start = f.pos();
        let m = f.u16("requires_index").get()?;
        let flags = f.u16("requires_flags").get()?;
        let v = f.u16("requires_version_index").get()?;
        let mut summary = flags_text(REQUIRES_FLAGS, flags);
        if v != 0 {
            if !summary.is_empty() {
                summary.push_str(", ");
            }
            summary.push_str(&format!("version {}", c.resolve(v)));
        }
        f.node(
            Node::new(format!("requires {}", c.resolve(m)))
                .span(f.block().span.sub(start, 6))
                .maybe_summary(summary),
        );
    }
    for (count, verb) in [("exports_count", "exports"), ("opens_count", "opens")] {
        let n = f.u16(count).emit()?;
        for i in 0..n {
            if i % 256 == 255 {
                cx.checkpoint().await;
            }
            let start = f.pos();
            let p = f.u16("index").get()?;
            let flags = f.u16("flags").get()?;
            let to = f.u16("to_count").get()?;
            let mut targets = Vec::new();
            for _ in 0..to {
                let m = f.u16("to_index").get()?;
                if targets.len() < 16 {
                    targets.push(c.resolve(m));
                }
            }
            let mut summary = flags_text(EXPORTS_FLAGS, flags);
            if !targets.is_empty() {
                if !summary.is_empty() {
                    summary.push_str(", ");
                }
                summary.push_str("to ");
                summary.push_str(&targets.join(", "));
            }
            f.node(
                Node::new(format!("{verb} {}", c.resolve(p).replace('/', ".")))
                    .span(f.block().span.sub(start, f.pos().saturating_sub(start)))
                    .maybe_summary(summary),
            );
        }
    }
    let n = f.u16("uses_count").emit()?;
    for _ in 0..n {
        let start = f.pos();
        let s = f.u16("uses_index").get()?;
        f.node(Node::new(format!("uses {}", c.class_name(s))).span(f.block().span.sub(start, 2)));
    }
    let n = f.u16("provides_count").emit()?;
    for i in 0..n {
        if i % 256 == 255 {
            cx.checkpoint().await;
        }
        let start = f.pos();
        let s = f.u16("provides_index").get()?;
        let with = f.u16("provides_with_count").get()?;
        let mut impls = Vec::new();
        for _ in 0..with {
            let k = f.u16("provides_with_index").get()?;
            if impls.len() < 16 {
                impls.push(c.class_name(k));
            }
        }
        f.node(
            Node::new(format!("provides {}", c.class_name(s)))
                .span(f.block().span.sub(start, f.pos().saturating_sub(start)))
                .maybe_summary(format!("with {}", impls.join(", "))),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use crate::span::{SourceId, Span};

    fn class() -> ClassInfo {
        ClassInfo {
            file: Span::new(SourceId(0), 0, 0),
            data: Vec::new(),
            minor: 0,
            major: 65,
            pool: Vec::new(),
            pool_span: (0, 0),
            access_offset: 0,
            access: 0,
            this_class: 0,
            super_class: 0,
            interfaces: (0, Vec::new()),
            fields: (0, 0, Vec::new()),
            methods: (0, 0, Vec::new()),
            attributes: (0, 0, Vec::new()),
        }
    }

    /// An array element value of `outer` arrays of `inner` empty arrays.
    fn nested(outer: u16, inner: u16) -> Vec<u8> {
        let mut b = vec![b'['];
        b.extend_from_slice(&outer.to_be_bytes());
        for _ in 0..outer {
            b.push(b'[');
            b.extend_from_slice(&inner.to_be_bytes());
            for _ in 0..inner {
                b.extend_from_slice(&[b'[', 0, 0]);
            }
        }
        b
    }

    #[test]
    fn element_walk_is_bounded() {
        let c = class();
        // 1 + 16 + 16 * 64 elements decode.
        let small = nested(16, 64);
        let mut out = Out::new();
        let mut r = Reader::new(&small);
        assert!(element_value(&c, &mut r, 0, &mut out));
        assert!(r.at_end());
        assert!(out.done().starts_with("{{{}, {}"));
        // 1 + 300 + 300 * 300 = 90301 elements: refused at MAX_ELEMENTS
        // rather than walked in one step.
        let big = nested(300, 300);
        let mut out = Out::new();
        let mut r = Reader::new(&big);
        assert!(!element_value(&c, &mut r, 0, &mut out));
        assert_eq!(out.1, 0);
    }
}
