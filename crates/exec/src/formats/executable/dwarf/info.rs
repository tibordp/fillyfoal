//! `.debug_info` and `.debug_types`: unit headers, DIE trees decoded
//! through their abbreviations (`.debug_abbrev`), and attribute values
//! resolved against the string, address and offset sections.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Fields, struct_node};
use crate::formats::util::binutil::Reader;
use crate::formats::util::fmt::plural;
use crate::formats::util::val::{hex, int, name_or, text, uint};
use crate::node::Node;
use crate::value::{Value, lookup};

use super::expr::{self, Sizes};
use super::line;
use super::tables::{
    ACCESSIBILITY, ATTRIBUTES, CALLING_CONVENTIONS, ENCODINGS, FORMS, INLINE, LANGUAGES, TAGS,
    UNIT_TYPES, VIRTUALITY,
};
use super::{Dwarf, Sec, initial_length, uint_of};

/// The first window read for DIEs; doubled while a DIE does not fit.
const WINDOW: u64 = 0x1000;
/// Most attribute references a DIE's expansion resolves (each a read).
const MAX_RESOLVED: usize = 64;
/// DIEs walked between checkpoints when skipping a subtree.
const SKIP_STEP: u32 = 32;

// ---------------------------------------------------------------------------
// Abbreviations

#[derive(Clone, Copy, Debug)]
pub(super) struct AttrSpec {
    pub at: u64,
    pub form: u64,
    pub implicit: i64,
}

#[derive(Debug)]
pub(super) struct Abbrev {
    pub tag: u64,
    pub children: bool,
    pub attrs: Vec<AttrSpec>,
}

/// One abbreviation table, by code.
#[derive(Debug, Default)]
pub(super) struct Abbrevs {
    map: BTreeMap<u64, Abbrev>,
}

/// Parses one declaration from `r`: `None` if the data runs out, `Some(None)`
/// for the table's terminating zero.
fn abbrev_decl(r: &mut Reader<'_>) -> Option<Option<(u64, Abbrev)>> {
    let code = r.uleb()?;
    if code == 0 {
        return Some(None);
    }
    let tag = r.uleb()?;
    let children = r.u8()? != 0;
    let mut attrs = Vec::new();
    loop {
        let at = r.uleb()?;
        let form = r.uleb()?;
        if at == 0 && form == 0 {
            break;
        }
        let implicit = if form == 0x21 { r.sleb()? } else { 0 };
        attrs.push(AttrSpec { at, form, implicit });
    }
    Some(Some((
        code,
        Abbrev {
            tag,
            children,
            attrs,
        },
    )))
}

/// The abbreviation table at `offset` in `.debug_abbrev`, parsed once and
/// cached (a table is read in windows and parsed with checkpoints).
pub(super) async fn abbrevs(cx: &Cx, dw: &Dwarf, offset: u64) -> Result<Arc<Abbrevs>> {
    let section = dw
        .span(Sec::Abbrev)
        .ok_or_else(|| Diagnostic::malformed("no .debug_abbrev section"))?;
    let key = section.sub(offset, 0);
    if let Some(found) = cx.cached::<Abbrevs>(key, "dwarf-abbrevs") {
        return Ok(found);
    }
    let mut table = Abbrevs::default();
    let mut pos = offset;
    let mut window = WINDOW;
    'read: while pos < section.len {
        let data = dw.read(cx, Sec::Abbrev, pos, window).await?;
        let at_end = pos.saturating_add(to_u64(data.len())) >= section.len;
        let mut r = Reader::new(&data);
        let mut parsed = 0u32;
        loop {
            let start = r.pos();
            match abbrev_decl(&mut r) {
                Some(None) => break 'read,
                Some(Some((code, abbrev))) => {
                    table.map.entry(code).or_insert(abbrev);
                    parsed = parsed.saturating_add(1);
                }
                None => {
                    if at_end {
                        break 'read;
                    }
                    if start == 0 {
                        // One declaration larger than the window.
                        window = window.saturating_mul(2);
                    } else {
                        pos = pos.saturating_add(to_u64(start));
                        window = WINDOW;
                    }
                    cx.charge(u64::from(parsed / 16)).await;
                    continue 'read;
                }
            }
        }
    }
    let table = Arc::new(table);
    cx.cache(key, "dwarf-abbrevs", table.clone());
    Ok(table)
}

/// Expander for `.debug_abbrev`: every declaration, in order, with its
/// attribute specifications; tables end with a zero code.
pub(super) async fn abbreviations(cx: &Cx, dw: &Arc<Dwarf>) -> Result<()> {
    let Some(section) = dw.span(Sec::Abbrev) else {
        return Ok(());
    };
    let (mut pos, mut index) = cx.resume::<(u64, u64)>().unwrap_or((0, 0));
    let mut window = WINDOW;
    while pos < section.len {
        let data = dw.read(cx, Sec::Abbrev, pos, window).await?;
        let base = pos;
        let at_end = base.saturating_add(to_u64(data.len())) >= section.len;
        let mut r = Reader::new(&data);
        let mut progressed = false;
        loop {
            let start = r.pos();
            let Some(decl) = abbrev_decl(&mut r) else {
                break;
            };
            progressed = true;
            let at = base.saturating_add(to_u64(start));
            let span = section.sub(at, to_u64(r.pos().saturating_sub(start)));
            let mark = (at, index);
            cx.mark(move || mark);
            let node = match decl {
                None => Node::new("Table end")
                    .span(span)
                    .value(uint(0u8, 8))
                    .desc("A zero code ends an abbreviation table"),
                Some((code, a)) => {
                    let tag = name_or(TAGS, a.tag, "DW_TAG");
                    let attrs = a
                        .attrs
                        .iter()
                        .map(|s| {
                            let mut n = Node::new(name_or(ATTRIBUTES, s.at, "DW_AT"))
                                .value(text(name_or(FORMS, s.form, "DW_FORM")));
                            if s.form == 0x21 {
                                n = n.summary(format!("{}", s.implicit));
                            }
                            n
                        })
                        .collect::<Vec<_>>();
                    let mut node = Node::new(format!("[{code}]"))
                        .span(span)
                        .value(text(tag))
                        .summary(format!(
                            "{}, {}",
                            if a.children {
                                "DW_CHILDREN_yes"
                            } else {
                                "DW_CHILDREN_no"
                            },
                            plural(attrs.len(), "attribute")
                        ));
                    if !attrs.is_empty() {
                        node =
                            node.lazy(crate::formats::util::arcutil::push_nodes, Arc::new(attrs));
                    }
                    node
                }
            };
            cx.push(node).await;
            index = index.saturating_add(1);
            pos = at.saturating_add(span.len);
            if r.at_end() {
                break;
            }
            // Re-read from the next declaration when the window runs low.
            if !at_end && r.rest().len() < 0x100 {
                break;
            }
        }
        if !progressed {
            if at_end || window >= 0x10_0000 {
                cx.diag(Diagnostic::truncated(section.tail(pos), 0));
                break;
            }
            window = window.saturating_mul(2);
        } else {
            window = WINDOW;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Units

/// A unit: its header and the bases its CU DIE declares.
#[derive(Clone, Debug, Default)]
pub(super) struct Unit {
    pub sec: Sec,
    /// Offset of the unit (its length field) in the section.
    pub offset: u64,
    /// Offset just past the unit.
    pub end: u64,
    /// Offset of the first DIE.
    pub first_die: u64,
    pub version: u16,
    pub unit_type: u8,
    pub offset_size: u8,
    pub address_size: u8,
    pub abbrev_offset: u64,
    pub str_offsets_base: Option<u64>,
    pub addr_base: Option<u64>,
    pub rnglists_base: Option<u64>,
    pub loclists_base: Option<u64>,
    pub low_pc: Option<u64>,
    /// `DW_AT_stmt_list`: the unit's line table, whose file list
    /// `DW_AT_decl_file` and `DW_AT_call_file` index.
    pub stmt_list: Option<u64>,
    pub comp_dir: Option<String>,
}

impl Unit {
    fn sizes(&self, dw: &Dwarf) -> Sizes {
        Sizes {
            address: self.address_size,
            offset: self.offset_size,
            endian: dw.endian,
            arch: dw.arch,
        }
    }

    fn kind(&self) -> &'static str {
        if self.sec == Sec::Types {
            return "type unit";
        }
        match self.unit_type {
            0x02 | 0x06 => "type unit",
            0x03 => "partial unit",
            0x04 => "skeleton unit",
            0x05 => "split compile unit",
            _ => "compile unit",
        }
    }
}

/// Parses a unit header from `data` (the unit from its length field).
fn unit_header(data: &[u8], dw: &Dwarf, sec: Sec, offset: u64) -> Option<Unit> {
    let e = dw.endian;
    let (length, offset_size, at) = initial_length(data, e)?;
    let mut r = Reader::at(data, to_usize(at));
    let version = u16::try_from(uint_of(r.bytes(2)?, 2, e)?).ok()?;
    let mut u = Unit {
        sec,
        offset,
        end: offset.saturating_add(at).saturating_add(length),
        version,
        offset_size,
        unit_type: 0x01,
        ..Unit::default()
    };
    if version >= 5 {
        u.unit_type = r.u8()?;
        u.address_size = r.u8()?;
        u.abbrev_offset = uint_of(r.bytes(offset_size.into())?, offset_size, e)?;
        match u.unit_type {
            0x04 | 0x05 => {
                r.bytes(8)?;
            }
            0x02 | 0x06 => {
                r.bytes(8)?;
                r.bytes(offset_size.into())?;
            }
            _ => {}
        }
    } else {
        u.abbrev_offset = uint_of(r.bytes(offset_size.into())?, offset_size, e)?;
        u.address_size = r.u8()?;
        if sec == Sec::Types {
            r.bytes(8)?;
            r.bytes(offset_size.into())?;
            u.unit_type = 0x02;
        }
    }
    u.first_die = offset.saturating_add(to_u64(r.pos()));
    Some(u)
}

/// The header fields, rendered.
fn header_fields(f: &mut Fields<'_>, u: &Unit) -> Result<()> {
    if u.offset_size == 8 {
        f.u32("unit_length (escape)").hex().emit()?;
        f.u64("unit_length").hex().emit()?;
    } else {
        f.u32("unit_length").hex().emit()?;
    }
    f.u16("version").emit()?;
    let offset = |f: &mut Fields<'_>, name: &'static str| -> Result<u64> {
        if u.offset_size == 8 {
            f.u64(name).hex().emit()
        } else {
            f.u32(name).hex().emit().map(u64::from)
        }
    };
    if u.version >= 5 {
        f.u8("unit_type").enumeration(UNIT_TYPES).emit()?;
        f.u8("address_size").emit()?;
        offset(f, "debug_abbrev_offset")?;
        match u.unit_type {
            0x04 | 0x05 => {
                f.u64("dwo_id").hex().emit()?;
            }
            0x02 | 0x06 => {
                f.u64("type_signature").hex().emit()?;
                offset(f, "type_offset")?;
            }
            _ => {}
        }
    } else {
        offset(f, "debug_abbrev_offset")?;
        f.u8("address_size").emit()?;
        if u.sec == Sec::Types {
            f.u64("type_signature").hex().emit()?;
            offset(f, "type_offset")?;
        }
    }
    Ok(())
}

/// Reads a unit's header and its CU DIE's bases (cached).
async fn load_unit(cx: &Cx, dw: &Dwarf, sec: Sec, offset: u64) -> Result<Arc<Unit>> {
    let section = dw
        .span(sec)
        .ok_or_else(|| Diagnostic::malformed("no unit section"))?;
    let key = section.sub(offset, 0);
    if let Some(found) = cx.cached::<Unit>(key, "dwarf-unit") {
        return Ok(found);
    }
    let head = dw.read(cx, sec, offset, 40).await?;
    let mut unit = unit_header(&head, dw, sec, offset)
        .ok_or_else(|| Diagnostic::truncated(section.sub(offset, 40), to_u64(head.len())))?;
    if !matches!(unit.address_size, 1 | 2 | 4 | 8) {
        return Err(Diagnostic::malformed(format!(
            "address size {}",
            unit.address_size
        )));
    }
    unit.end = unit.end.min(section.len);
    let abbrevs = abbrevs(cx, dw, unit.abbrev_offset).await?;
    if unit.first_die < unit.end {
        let mut win = Win::default();
        let die = die_at(cx, dw, &unit, &abbrevs, &mut win, unit.first_die).await?;
        let get = |at: u64| die.attrs.iter().find(|a| a.at == at);
        let base = |a: Option<&Attr>| a.and_then(|a| a.value.uint());
        unit.str_offsets_base = base(get(0x72));
        unit.addr_base = base(get(0x73).or_else(|| get(0x2133)));
        unit.rnglists_base = base(get(0x74));
        unit.loclists_base = base(get(0x8c));
        if let Some(a) = get(0x11) {
            unit.low_pc = address(cx, dw, &unit, a).await;
        }
        unit.stmt_list = base(get(0x10));
        if let Some(a) = get(0x1b) {
            unit.comp_dir = string_value(cx, dw, &unit, a).await;
        }
    }
    let unit = Arc::new(unit);
    cx.cache(key, "dwarf-unit", unit.clone());
    Ok(unit)
}

/// Expander for `.debug_info` / `.debug_types`: one node per unit.
pub(super) async fn units(cx: &Cx, dw: &Arc<Dwarf>, sec: Sec) -> Result<()> {
    let Some(section) = dw.span(sec) else {
        return Ok(());
    };
    let mut pos = cx.resume::<u64>().unwrap_or(0);
    while pos < section.len {
        cx.mark(move || pos);
        cx.progress_in(section, pos);
        let head = dw.read(cx, sec, pos, 40).await?;
        let Some(u) = unit_header(&head, dw, sec, pos) else {
            cx.diag(Diagnostic::malformed("unreadable unit header").at(section.sub(pos, 40)));
            break;
        };
        let span = section.sub(pos, u.end.saturating_sub(pos));
        let mut node = Node::new(format!("{} at {pos:#x}", capitalize(u.kind())))
            .span(span)
            .summary(format!("DWARF {}, {:#x} bytes", u.version, span.len));
        if !cx.skipping() {
            match load_unit(cx, dw, sec, pos).await {
                Ok(unit) => {
                    if let Some(name) = unit_name(cx, dw, &unit).await {
                        node = node.value(text(name));
                    }
                    node = node.lazy(unit_node, (dw.clone(), unit));
                }
                Err(e) => node = node.diag(e.at(span)),
            }
        }
        cx.push(node).await;
        if u.end <= pos {
            break;
        }
        pos = u.end;
    }
    Ok(())
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(first) => first.to_uppercase().chain(c).collect(),
        None => String::new(),
    }
}

/// The CU DIE's name.
async fn unit_name(cx: &Cx, dw: &Dwarf, unit: &Unit) -> Option<String> {
    let abbrevs = abbrevs(cx, dw, unit.abbrev_offset).await.ok()?;
    let mut win = Win::default();
    let die = die_at(cx, dw, unit, &abbrevs, &mut win, unit.first_die)
        .await
        .ok()?;
    die_name(cx, dw, unit, &die).await
}

/// A unit's expansion: its header, then its top-level DIEs.
async fn unit_node(cx: Cx, (dw, unit): (Arc<Dwarf>, Arc<Unit>)) -> Result<()> {
    let section = dw
        .span(unit.sec)
        .ok_or_else(|| Diagnostic::internal("no unit section"))?;
    let abbrevs = abbrevs(&cx, &dw, unit.abbrev_offset).await?;
    let mut pos = match cx.resume::<u64>() {
        Some(p) => p,
        None => {
            let header = section.sub(unit.offset, unit.first_die.saturating_sub(unit.offset));
            let data = dw.read(&cx, unit.sec, unit.offset, header.len).await?;
            let _ = data;
            cx.emit(
                struct_node("Header", header, dw.endian, (*unit).clone(), header_fields).summary(
                    format!(
                        "DWARF {}, {}-bit, address size {}",
                        unit.version,
                        u32::from(unit.offset_size).saturating_mul(8),
                        unit.address_size
                    ),
                ),
            );
            unit.first_die
        }
    };
    let mut win = Win::default();
    while pos < unit.end {
        cx.mark(move || pos);
        let die = die_at(&cx, &dw, &unit, &abbrevs, &mut win, pos).await?;
        let node = if cx.skipping() {
            Node::new("DIE")
        } else {
            die_node(&cx, &dw, &unit, &die).await
        };
        // Pushed before its subtree is skipped: the walk to the next
        // sibling happens only when the host asks for more children.
        cx.push(node).await;
        let next = if die.code == 0 {
            die.end
        } else {
            next_sibling(&cx, &dw, &unit, &abbrevs, &mut win, &die).await?
        };
        if next <= pos {
            break;
        }
        pos = next;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// DIEs

/// An attribute value as decoded from its form.
#[derive(Clone, Debug)]
pub(super) enum Val {
    U(u64),
    S(i64),
    Flag(bool),
    Str(String),
    /// A block or expression: offset of its bytes in the section, length.
    Block(u64, u64),
}

impl Val {
    fn uint(&self) -> Option<u64> {
        match self {
            Val::U(v) => Some(*v),
            Val::S(v) => u64::try_from(*v).ok(),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct Attr {
    pub at: u64,
    pub form: u64,
    pub value: Val,
    /// The value's bytes in the section.
    pub start: u64,
    pub len: u64,
}

#[derive(Clone, Debug)]
pub(super) struct Die {
    pub offset: u64,
    pub code: u64,
    pub tag: u64,
    pub children: bool,
    pub attrs: Vec<Attr>,
    /// Offset just past the DIE's attributes.
    pub end: u64,
}

/// A window of a unit's bytes, refilled as DIEs are read.
#[derive(Default)]
struct Win {
    base: u64,
    data: Vec<u8>,
}

enum Short {
    /// The window ended inside the DIE.
    More,
    Bad(Diagnostic),
}

/// Decodes one attribute value of `form` from `r` (`base` is the section
/// offset of the reader's data).
fn form_value(
    r: &mut Reader<'_>,
    form: u64,
    spec: AttrSpec,
    unit: &Unit,
    dw: &Dwarf,
    base: u64,
    depth: u8,
) -> std::result::Result<(u64, Val), Short> {
    let e = dw.endian;
    let need = |v: Option<u64>| v.ok_or(Short::More);
    let fixed = |r: &mut Reader<'_>, n: u8| -> std::result::Result<u64, Short> {
        let b = r.bytes(usize::from(n)).ok_or(Short::More)?;
        uint_of(b, n, e).ok_or(Short::More)
    };
    let block = |r: &mut Reader<'_>, len: u64| -> std::result::Result<Val, Short> {
        let at = base.saturating_add(to_u64(r.pos()));
        if at.saturating_add(len) > unit.end {
            return Err(Short::Bad(Diagnostic::malformed(format!(
                "block of {len:#x} bytes runs past the unit"
            ))));
        }
        r.bytes(to_usize(len)).ok_or(Short::More)?;
        Ok(Val::Block(at, len))
    };
    let value = match form {
        0x01 => Val::U(fixed(r, unit.address_size)?),
        0x03 => {
            let n = fixed(r, 2)?;
            block(r, n)?
        }
        0x04 => {
            let n = fixed(r, 4)?;
            block(r, n)?
        }
        0x05 => Val::U(fixed(r, 2)?),
        0x06 => Val::U(fixed(r, 4)?),
        0x07 | 0x20 | 0x24 => Val::U(fixed(r, 8)?),
        0x08 => {
            let s = r.cstr().ok_or(Short::More)?;
            Val::Str(String::from_utf8_lossy(s).into_owned())
        }
        0x09 | 0x18 => {
            let n = need(r.uleb())?;
            block(r, n)?
        }
        0x0a => {
            let n = fixed(r, 1)?;
            block(r, n)?
        }
        0x0b | 0x11 | 0x25 | 0x29 => Val::U(fixed(r, 1)?),
        0x0c => Val::Flag(fixed(r, 1)? != 0),
        0x0d => Val::S(r.sleb().ok_or(Short::More)?),
        0x0e | 0x17 | 0x1d | 0x1f | 0x1f20 | 0x1f21 => Val::U(fixed(r, unit.offset_size)?),
        0x0f | 0x15 | 0x1a | 0x1b | 0x22 | 0x23 | 0x1f01 | 0x1f02 => Val::U(need(r.uleb())?),
        0x10 => {
            let n = if unit.version <= 2 {
                unit.address_size
            } else {
                unit.offset_size
            };
            Val::U(fixed(r, n)?)
        }
        0x12 | 0x26 | 0x2a => Val::U(fixed(r, 2)?),
        0x13 | 0x1c | 0x28 | 0x2c => Val::U(fixed(r, 4)?),
        0x14 => Val::U(fixed(r, 8)?),
        0x27 | 0x2b => Val::U(fixed(r, 3)?),
        0x16 => {
            let actual = need(r.uleb())?;
            if depth >= 2 || actual == 0x16 {
                return Err(Short::Bad(Diagnostic::malformed("nested DW_FORM_indirect")));
            }
            return form_value(r, actual, spec, unit, dw, base, depth.saturating_add(1));
        }
        0x19 => Val::Flag(true),
        0x1e => block(r, 16)?,
        0x21 => Val::S(spec.implicit),
        _ => {
            return Err(Short::Bad(Diagnostic::unsupported(format!(
                "attribute form {form:#x}"
            ))));
        }
    };
    Ok((form, value))
}

/// Decodes the DIE at the start of `data` (at section offset `offset`).
fn parse_die(
    data: &[u8],
    offset: u64,
    unit: &Unit,
    abbrevs: &Abbrevs,
    dw: &Dwarf,
) -> std::result::Result<Die, Short> {
    let mut r = Reader::new(data);
    let code = r.uleb().ok_or(Short::More)?;
    let mut die = Die {
        offset,
        code,
        tag: 0,
        children: false,
        attrs: Vec::new(),
        end: 0,
    };
    if code != 0 {
        let abbrev = abbrevs.map.get(&code).ok_or_else(|| {
            Short::Bad(Diagnostic::malformed(format!(
                "abbreviation code {code} is not in the table"
            )))
        })?;
        die.tag = abbrev.tag;
        die.children = abbrev.children;
        for spec in &abbrev.attrs {
            let start = r.pos();
            let (form, value) = form_value(&mut r, spec.form, *spec, unit, dw, offset, 0)?;
            die.attrs.push(Attr {
                at: spec.at,
                form,
                value,
                start: offset.saturating_add(to_u64(start)),
                len: to_u64(r.pos().saturating_sub(start)),
            });
        }
    }
    die.end = offset.saturating_add(to_u64(r.pos()));
    Ok(die)
}

/// The DIE at section offset `off`, reading (and growing) the window as
/// needed.
async fn die_at(
    cx: &Cx,
    dw: &Dwarf,
    unit: &Unit,
    abbrevs: &Abbrevs,
    win: &mut Win,
    off: u64,
) -> Result<Die> {
    let section = dw
        .span(unit.sec)
        .ok_or_else(|| Diagnostic::internal("no unit section"))?;
    let mut want = WINDOW;
    loop {
        let rel = off.checked_sub(win.base).map(to_usize);
        if let Some(rel) = rel
            && let Some(data) = win.data.get(rel..)
            && !data.is_empty()
        {
            let complete = win.base.saturating_add(to_u64(win.data.len())) >= unit.end;
            match parse_die(data, off, unit, abbrevs, dw) {
                Ok(die) if die.end <= unit.end => return Ok(die),
                Ok(_) => {
                    return Err(Diagnostic::malformed("DIE runs past the end of its unit")
                        .at(section.sub(off, 1)));
                }
                Err(Short::Bad(d)) => return Err(d.at(section.sub(off, 1))),
                Err(Short::More) if complete => {
                    return Err(Diagnostic::truncated(
                        section.sub(off, unit.end.saturating_sub(off)),
                        to_u64(data.len()),
                    ));
                }
                Err(Short::More) => {
                    want = to_u64(data.len()).saturating_mul(2).max(want);
                }
            }
        }
        let len = want.min(unit.end.saturating_sub(off));
        if len == 0 {
            return Err(
                Diagnostic::malformed("DIE offset outside its unit").at(section.sub(off, 0))
            );
        }
        win.data = dw.read(cx, unit.sec, off, len).await?;
        win.base = off;
        if win.data.is_empty() {
            return Err(Diagnostic::truncated(section.sub(off, len), 0));
        }
    }
}

/// Where the DIE after `die`'s subtree starts.
async fn next_sibling(
    cx: &Cx,
    dw: &Dwarf,
    unit: &Unit,
    abbrevs: &Abbrevs,
    win: &mut Win,
    die: &Die,
) -> Result<u64> {
    if !die.children {
        return Ok(die.end);
    }
    if let Some(a) = die.attrs.iter().find(|a| a.at == 0x01)
        && let Some(target) = reference(unit, a)
        && target > die.end
        && target <= unit.end
    {
        return Ok(target);
    }
    let mut depth = 1u32;
    let mut pos = die.end;
    let mut steps = 0u32;
    while depth > 0 && pos < unit.end {
        let d = die_at(cx, dw, unit, abbrevs, win, pos).await?;
        if d.code == 0 {
            depth = depth.saturating_sub(1);
        } else if d.children {
            depth = depth.saturating_add(1);
        }
        pos = d.end;
        steps = steps.wrapping_add(1);
        if steps.is_multiple_of(SKIP_STEP) {
            cx.checkpoint().await;
        }
    }
    Ok(pos)
}

/// The section offset a reference attribute points at (in the same
/// section), if it is one.
fn reference(unit: &Unit, a: &Attr) -> Option<u64> {
    let v = a.value.uint()?;
    match a.form {
        0x11..=0x15 => unit.offset.checked_add(v),
        0x10 => Some(v),
        _ => None,
    }
}

/// The DIE's `DW_AT_name`.
async fn die_name(cx: &Cx, dw: &Dwarf, unit: &Unit, die: &Die) -> Option<String> {
    let a = die.attrs.iter().find(|a| a.at == 0x03)?;
    string_value(cx, dw, unit, a).await
}

/// A string attribute's text.
async fn string_value(cx: &Cx, dw: &Dwarf, unit: &Unit, a: &Attr) -> Option<String> {
    match (&a.value, a.form) {
        (Val::Str(s), _) => Some(s.clone()),
        (Val::U(off), 0x0e) => dw.string(cx, Sec::Str, *off).await,
        (Val::U(off), 0x1f) => dw.string(cx, Sec::LineStr, *off).await,
        (Val::U(index), 0x1a | 0x25..=0x28 | 0x1f02) => {
            let base = unit
                .str_offsets_base
                .unwrap_or(if unit.version >= 5 { 8 } else { 0 });
            let at = base.checked_add(index.checked_mul(unit.offset_size.into())?)?;
            let off = dw.uint(cx, Sec::StrOffsets, at, unit.offset_size).await?;
            dw.string(cx, Sec::Str, off).await
        }
        _ => None,
    }
}

/// An address attribute's address (`DW_FORM_addr` or an index into
/// `.debug_addr`).
async fn address(cx: &Cx, dw: &Dwarf, unit: &Unit, a: &Attr) -> Option<u64> {
    match (&a.value, a.form) {
        (Val::U(v), 0x01) => Some(*v),
        (Val::U(index), 0x1b | 0x29..=0x2c | 0x1f01) => {
            let base = unit.addr_base.unwrap_or(8);
            let at = base.checked_add(index.checked_mul(unit.address_size.into())?)?;
            dw.uint(cx, Sec::Addr, at, unit.address_size).await
        }
        _ => None,
    }
}

/// A DIE's node: its tag, named by `DW_AT_name`.
async fn die_node(cx: &Cx, dw: &Arc<Dwarf>, unit: &Arc<Unit>, die: &Die) -> Node {
    let span = dw
        .span_or_empty(unit.sec)
        .sub(die.offset, die.end.saturating_sub(die.offset));
    if die.code == 0 {
        return Node::new("NULL")
            .span(span)
            .summary(format!("{:#010x}", die.offset))
            .desc("Ends a list of sibling DIEs");
    }
    let mut node = Node::new(name_or(TAGS, die.tag, "DW_TAG"))
        .span(span)
        .summary(format!("{:#010x}", die.offset));
    if let Some(name) = die_name(cx, dw, unit, die).await {
        node = node.value(text(name));
    }
    if !die.attrs.is_empty() || die.children {
        node = node.lazy(
            crate::expander!(self::die_expand: (Arc<Dwarf>, Arc<Unit>, u64)),
            (dw.clone(), unit.clone(), die.offset),
        );
    }
    node
}

/// A DIE's expansion: its attributes, then its children (paged, with
/// resume marks at child offsets).
async fn die_expand(cx: Cx, (dw, unit, off): (Arc<Dwarf>, Arc<Unit>, u64)) -> Result<()> {
    let abbrevs = abbrevs(&cx, &dw, unit.abbrev_offset).await?;
    let mut win = Win::default();
    let die = die_at(&cx, &dw, &unit, &abbrevs, &mut win, off).await?;
    let mut pos = match cx.resume::<u64>() {
        Some(p) => p,
        None => {
            let low = match die.attrs.iter().find(|a| a.at == 0x11) {
                Some(a) => address(&cx, &dw, &unit, a).await,
                None => None,
            };
            for (i, a) in die.attrs.iter().enumerate() {
                let node = attr_node(&cx, &dw, &unit, a, low, i < MAX_RESOLVED).await;
                cx.emit(node);
            }
            die.end
        }
    };
    if !die.children {
        return Ok(());
    }
    let section = dw.span_or_empty(unit.sec);
    loop {
        if pos >= unit.end {
            cx.diag(
                Diagnostic::malformed("children run to the end of the unit without a NULL entry")
                    .at(section.sub(die.offset, 0)),
            );
            break;
        }
        cx.mark(move || pos);
        let child = die_at(&cx, &dw, &unit, &abbrevs, &mut win, pos).await?;
        if child.code == 0 {
            cx.push(die_node(&cx, &dw, &unit, &child).await).await;
            break;
        }
        let node = if cx.skipping() {
            Node::new("DIE")
        } else {
            die_node(&cx, &dw, &unit, &child).await
        };
        cx.push(node).await;
        let next = next_sibling(&cx, &dw, &unit, &abbrevs, &mut win, &child).await?;
        if next <= pos {
            break;
        }
        pos = next;
    }
    Ok(())
}

/// The value's bytes, up to `max`.
async fn block_bytes(cx: &Cx, dw: &Dwarf, sec: Sec, at: u64, len: u64, max: u64) -> Vec<u8> {
    dw.read(cx, sec, at, len.min(max)).await.unwrap_or_default()
}

/// An attribute's node: the value decoded by form and interpreted by
/// attribute; `resolve` allows reads to name what it refers to.
async fn attr_node(
    cx: &Cx,
    dw: &Dwarf,
    unit: &Unit,
    a: &Attr,
    low: Option<u64>,
    resolve: bool,
) -> Node {
    let section = dw.span_or_empty(unit.sec);
    let form = name_or(FORMS, a.form, "DW_FORM");
    let mut node = Node::new(name_or(ATTRIBUTES, a.at, "DW_AT")).span(section.sub(a.start, a.len));
    let mut summary = form.clone();
    match &a.value {
        Val::Str(s) => node = node.value(text(s.clone())),
        Val::Flag(b) => node = node.value(Value::Bool(*b)),
        Val::Block(at, len) => {
            let bytes = block_bytes(cx, dw, unit.sec, *at, *len, 0x400).await;
            if a.form == 0x18 || matches!(a.at, 0x02 | 0x40 | 0x38 | 0x4d | 0x48 | 0x2a | 0x50) {
                node = node.value(text(expr::describe(&bytes, unit.sizes(dw))));
                summary = format!("{form}, {len} bytes");
            } else {
                node = node.value(Value::Bytes(bytes));
            }
        }
        Val::S(v) => {
            let file = match (a.at, resolve, u64::try_from(*v)) {
                (0x3a | 0x58, true, Ok(u)) => file_path(cx, dw, unit, u).await,
                _ => None,
            };
            node = node.value(match (u64::try_from(*v), file) {
                (_, Some(path)) => {
                    summary = format!("{form}, file {v}");
                    text(path)
                }
                (Ok(u), None) if has_table(a.at) => interpret(a.at, a.form, u),
                _ => int(*v, 64),
            });
        }
        Val::U(v) => {
            let v = *v;
            let strings = matches!(a.form, 0x0e | 0x1f | 0x1a | 0x25..=0x28 | 0x1f02);
            if strings {
                match string_value(cx, dw, unit, a).await {
                    Some(s) => node = node.value(text(s)),
                    None => node = node.value(hex(v, 64)),
                }
                summary = if matches!(a.form, 0x0e | 0x1f) {
                    format!("{form} at {v:#x}")
                } else {
                    format!("{form} [{v}]")
                };
            } else if matches!(a.form, 0x01 | 0x1b | 0x29..=0x2c | 0x1f01) {
                let addr = address(cx, dw, unit, a).await;
                node = node.value(hex(addr.unwrap_or(v), 64));
                if a.form != 0x01 {
                    summary = format!("{form} [{v}]");
                }
            } else if let Some(target) = reference(unit, a) {
                node = node.value(hex(target, 64)).target(section.sub(target, 0));
                if resolve && a.at != 0x01 {
                    summary = format!("{form}, {}", describe_die(cx, dw, unit, target).await);
                }
            } else if matches!(a.form, 0x22 | 0x23) {
                // An index into the unit's offset table of location or
                // range lists; the table's entries are relative to it.
                let (sec, base) = if a.form == 0x22 {
                    (Sec::Loclists, unit.loclists_base)
                } else {
                    (Sec::Rnglists, unit.rnglists_base)
                };
                let base = base.unwrap_or(12);
                let entry = v
                    .checked_mul(unit.offset_size.into())
                    .and_then(|o| base.checked_add(o));
                let list = match entry {
                    Some(at) => dw.uint(cx, sec, at, unit.offset_size).await,
                    None => None,
                };
                summary = format!("{form} [{v}]");
                match list.and_then(|o| o.checked_add(base)) {
                    Some(target) => {
                        node = node.value(hex(target, 64));
                        if let Some(span) = dw.span(sec) {
                            node = node.target(span.sub(target, 0));
                        }
                    }
                    None => node = node.value(uint(v, 64)),
                }
            } else if a.form == 0x17 {
                node = node.value(hex(v, 64));
                if let Some((sec, base)) = offset_target(a.at, unit)
                    && let Some(span) = dw.span(sec)
                {
                    node = node.target(span.sub(v.saturating_add(base), 0));
                }
            } else if let (0x3a | 0x58, true) = (a.at, resolve)
                && let Some(path) = file_path(cx, dw, unit, v).await
            {
                // A file number, named through the unit's line table.
                node = node.value(text(path));
                summary = format!("{form}, file {v}");
            } else {
                node = node.value(interpret(a.at, a.form, v));
                if a.at == 0x12
                    && let Some(low) = low
                {
                    summary = format!("{form}, ends at {:#x}", low.saturating_add(v));
                }
            }
        }
    }
    node.summary(summary)
}

/// The path of file `index` of the unit's line table.
async fn file_path(cx: &Cx, dw: &Dwarf, unit: &Unit, index: u64) -> Option<String> {
    let files = line::file_names(cx, dw, unit.stmt_list?).await?;
    files.path(index, unit.comp_dir.as_deref())
}

/// Which section a `DW_FORM_sec_offset` attribute points into, and the base
/// its offset is relative to.
fn offset_target(at: u64, unit: &Unit) -> Option<(Sec, u64)> {
    let v5 = unit.version >= 5;
    Some(match at {
        0x10 => (Sec::Line, 0),
        0x55 if v5 => (Sec::Rnglists, 0),
        0x55 => (Sec::Ranges, 0),
        0x02 | 0x40 | 0x19 | 0x4d | 0x48 if v5 => (Sec::Loclists, 0),
        0x02 | 0x40 | 0x19 | 0x4d | 0x48 => (Sec::Loc, 0),
        0x72 => (Sec::StrOffsets, 0),
        0x73 | 0x2133 => (Sec::Addr, 0),
        0x74 => (Sec::Rnglists, 0),
        0x8c => (Sec::Loclists, 0),
        _ => return None,
    })
}

/// Whether constants of attribute `at` are named from a table.
fn has_table(at: u64) -> bool {
    matches!(at, 0x13 | 0x3e | 0x20 | 0x32 | 0x36 | 0x4c)
}

/// A constant attribute's value, named where the attribute has a table.
fn interpret(at: u64, form: u64, v: u64) -> Value {
    let table = match at {
        0x13 => Some(LANGUAGES),
        0x3e => Some(ENCODINGS),
        0x20 => Some(INLINE),
        0x32 => Some(ACCESSIBILITY),
        0x36 => Some(CALLING_CONVENTIONS),
        0x4c => Some(VIRTUALITY),
        _ => None,
    };
    if let Some(table) = table {
        return Value::Enum {
            raw: v,
            bits: 16,
            name: lookup(table, v),
        };
    }
    match form {
        0x0f | 0x15 => uint(v, 64),
        0x0b => hex(v, 8),
        0x05 => hex(v, 16),
        0x06 => hex(v, 32),
        _ => hex(v, 64),
    }
}

/// "DW_TAG_base_type \"int\"" for the DIE at `off`.
async fn describe_die(cx: &Cx, dw: &Dwarf, unit: &Unit, off: u64) -> String {
    let Ok(abbrevs) = abbrevs(cx, dw, unit.abbrev_offset).await else {
        return format!("{off:#x}");
    };
    if off < unit.first_die || off >= unit.end {
        return format!("{off:#x}");
    }
    let mut win = Win::default();
    match die_at(cx, dw, unit, &abbrevs, &mut win, off).await {
        Ok(die) if die.code != 0 => {
            let tag = name_or(TAGS, die.tag, "DW_TAG");
            match die_name(cx, dw, unit, &die).await {
                Some(name) => format!("{tag} \"{name}\""),
                None => tag,
            }
        }
        _ => format!("{off:#x}"),
    }
}
