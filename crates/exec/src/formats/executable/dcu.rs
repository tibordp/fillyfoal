//! Delphi compiled units (`.dcu`): the per-unit object files of Borland /
//! CodeGear / Embarcadero Delphi (and C++Builder's Pascal compiler). A DCU
//! holds a unit's interface (for compiling units that use it) and its
//! machine code with fixups (for linking), so it sits with the native
//! objects (OMF, COFF) rather than with interpreted bytecode.
//!
//! The format is undocumented and changes with every compiler version. What
//! is decoded here is reconstructed from memory of Alexei Hmelnov's DCU32INT
//! decompiler and checked against a single Delphi 7 unit; nothing comes from
//! a specification. Field names that come from DCU32INT say so; values whose
//! meaning was not established are shown raw ("Value N").
//!
//! - **Header** (all versions): a 4-byte magic, the file size (which must
//!   equal the file length) and the compile time as a DOS date/time. The last
//!   byte of the file is the end tag `a`.
//! - **Version**: from Delphi 6 on, the magic's high byte equals the
//!   compiler's `CompilerVersion` (`0x0f` = 15 = Delphi 7); that is verified
//!   for Delphi 7 only, and the mapping of the other values to products is
//!   the public `CompilerVersion` table, not checked against files. The low
//!   three bytes (`0xdf 00 00` for Delphi 7) are shown raw: they are said to
//!   carry platform and edition bits, which are not established here. The
//!   pre-Delphi 6 magics are from memory and unverified.
//! - **Tag stream** (Delphi 7 only, magic `0x0f0000df`): after an 18-byte
//!   header comes a stream of records, each a one-byte tag and fields. Most
//!   numbers are *packed indices* (DCU32INT's `ReadUIndex`/`ReadIndex`: the
//!   low bits of the first byte give the length, 1 to 5 bytes, unsigned or
//!   signed). Some records open a list of nested records closed by `c`.
//!
//! Records decoded (layouts verified at exact offsets in the sample):
//!
//! | Tag | Record | Fields |
//! |---|---|---|
//! | `0x96` | unit flags | two packed values |
//! | `p`, `r` | source / resource file | name, DOS time, a byte |
//! | `d` (`e`) | used unit, opens its import list | name, two raw 32-bit values |
//! | `f`, `g` | imported type / value | name, 32-bit check value |
//! | `4` | unit reference, opens an (empty) list | name, flags, index of the unit's `d` record |
//! | `&`, ` ` | symbol / variable | name, flags, type, a signed value |
//! | `*` | type name | name, flags, definition index |
//! | `(` | procedure, opens parameters and locals | name, flags, four values (the second is the code size) |
//! | `!`, `"`, ` ` | value / var parameter, local (in a procedure) | name, flags, type, location |
//! | `0x9e` | not established | one signed packed value |
//! | `G` | type definition (class reference / VMT, per its use) | five values |
//! | `F` | class definition, opens its members | twelve values |
//! | `,`, `-` | field / method (in a class) | name, flags, type and offset / two values and the implementing procedure |
//!
//! "Flags" is a packed value; at unit level, when its bit `0x40` is set, a
//! 32-bit check value follows (as observed: every unit-level record with
//! that bit has one, none without it, and nested records never do).
//!
//! Cross-references, verified on the sample:
//!
//! - **Types** are numbered from 1 in the order of the imported-type (`f`)
//!   records, then by the unit's own definitions; a `*` record gives the
//!   number its name stands for. Field and parameter types resolve to the
//!   expected classes (the same equivalence classes as the published field
//!   table in the code block, and `Self` resolves to the form class).
//! - **Declarations** are numbered from 2 (1 is the unit itself) in stream
//!   order over the `d`, `f`, `g`, `4`, `&`, `*`, ` `, `(`, `!` and `"`
//!   records, nested ones included: the unit references point at their `d`
//!   records and the methods at their procedures. Whether `0x9e`, `G`, `F`
//!   and class members take numbers is not known; numbers after the first of
//!   them are unverified.
//! - The `G` and `F` layouts are fixed counts of packed values taken from one
//!   instance each; some of their values resolve (the class a `G` refers to;
//!   the declaration, parent class and VMT symbol of an `F`), the rest are
//!   raw. A `G` or `F` that is not followed by a recognised record ends the
//!   walk.
//!
//! The walk stops at the first record it does not know (in the sample the
//! range type definition `D` that precedes the code block); everything from
//! there (further type definitions, the code block, fixups, line numbers) is
//! an unparsed remainder.

use std::sync::Arc;

use crate::bytes::u32_le;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::fmt::count;
use crate::formats::util::val::{hex, text, uint};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, Value, lookup};

pub static FORMAT: Format = Format {
    name: "dcu",
    title: "Delphi compiled unit",
    extensions: &["dcu"],
    mime: "application/x-delphi-dcu",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

/// Delphi 7's magic, the only version whose tag stream is decoded.
const MAGIC_D7: u32 = 0x0f00_00df;
/// Header length for Delphi 7 (magic, size, time, a 32-bit value, 2 bytes).
const HEADER_D7: u64 = 18;
/// Header fields common to all versions.
const HEADER_COMMON: u64 = 12;
/// The end tag, the last byte of every unit.
const END_TAG: u8 = b'a';
/// Longest record decoded: tag, counted name, flags, check value and up to
/// twelve packed values of at most five bytes.
const MAX_RECORD: u64 = 1 + 256 + 5 + 4 + 12 * 5;
/// The tag that closes a list.
const CLOSE: u8 = b'c';

/// Magics of the versions before Delphi 6, which do not follow the
/// `CompilerVersion` pattern. From memory of DCU32INT; unverified.
const OLD_MAGIC: &[(u32, &str)] = &[
    (0x5050_5348, "Delphi 2"),
    (0x4451_8641, "Delphi 3"),
    (0x4768_a6d8, "Delphi 4"),
    (0xf21f_148b, "Delphi 5"),
];

/// `CompilerVersion` (the magic's high byte from Delphi 6 on) to product.
const COMPILER_VERSION: EnumTable = &[
    (14, "Delphi 6 / C++Builder 6 / Kylix"),
    (15, "Delphi 7"),
    (16, "Delphi 8 for .NET"),
    (17, "Delphi 2005"),
    (18, "Delphi / C++Builder 2006 or 2007"),
    (19, "Delphi 2007 for .NET"),
    (20, "Delphi / C++Builder 2009"),
    (21, "Delphi / C++Builder 2010"),
    (22, "Delphi / C++Builder XE"),
    (23, "Delphi / C++Builder XE2"),
    (24, "Delphi / C++Builder XE3"),
    (25, "Delphi / C++Builder XE4"),
    (26, "Delphi / C++Builder XE5"),
    (27, "Delphi / C++Builder XE6"),
    (28, "Delphi / C++Builder XE7"),
    (29, "Delphi / C++Builder XE8"),
    (30, "Delphi / C++Builder 10 Seattle"),
    (31, "Delphi / C++Builder 10.1 Berlin"),
    (32, "Delphi / C++Builder 10.2 Tokyo"),
    (33, "Delphi / C++Builder 10.3 Rio"),
    (34, "Delphi / C++Builder 10.4 Sydney"),
    (35, "Delphi / C++Builder 11 Alexandria"),
    (36, "Delphi / C++Builder 12 Athens"),
    (37, "Delphi / C++Builder 13 Florence"),
];

/// The product a magic stands for, if it is a known DCU magic.
fn version(magic: u32) -> Option<String> {
    if let Some((_, name)) = OLD_MAGIC.iter().find(|(m, _)| *m == magic) {
        return Some((*name).to_owned());
    }
    let cv = magic >> 24;
    lookup(COMPILER_VERSION, cv.into()).map(str::to_owned)
}

/// A DOS date/time (date in the high word) with every field in range.
fn valid_dos_time(v: u32) -> bool {
    let (date, time) = (v >> 16, v & 0xffff);
    let (month, day) = ((date >> 5) & 0xf, date & 0x1f);
    let (hour, minute, sec2) = (time >> 11, (time >> 5) & 0x3f, time & 0x1f);
    (1..=12).contains(&month) && (1..=31).contains(&day) && hour < 24 && minute < 60 && sec2 < 30
}

fn dos_time(v: u32) -> String {
    let date = u16::try_from(v >> 16).unwrap_or(0);
    let time = u16::try_from(v & 0xffff).unwrap_or(0);
    crate::text::dos_datetime(date, time)
}

fn probe(h: &Head<'_>) -> bool {
    let (Some(magic), Some(size), Some(time)) =
        (u32_le(h.data, 0), u32_le(h.data, 4), u32_le(h.data, 8))
    else {
        return false;
    };
    let shape = version(magic).is_some()
        && u64::from(size) == h.len
        && h.len > HEADER_D7
        && valid_dos_time(time)
        && h.tail.last() == Some(&END_TAG);
    // For the version whose stream is understood, the first tag too.
    shape && (magic != MAGIC_D7 || h.data.get(18) == Some(&0x96))
}

/// The `n` bytes at `at`, little-endian.
fn le(data: &[u8], at: usize, n: usize) -> Option<u64> {
    let bytes = data.get(at..at.checked_add(n)?)?;
    Some(
        bytes
            .iter()
            .rev()
            .fold(0u64, |acc, &b| (acc << 8) | u64::from(b)),
    )
}

/// The length of the packed index whose first byte is `b0`.
fn packed_len(b0: u8) -> usize {
    match b0.trailing_ones() {
        0 => 1,
        1 => 2,
        2 => 3,
        3 => 4,
        _ => 5,
    }
}

/// A DCU packed index (DCU32INT's `ReadUIndex`): the low bits of the first
/// byte say how many bytes follow. Returns the value and its length.
fn packed(data: &[u8], at: usize) -> Option<(u64, usize)> {
    let n = packed_len(*data.get(at)?);
    if n == 5 {
        let v = u32_le(data, at.checked_add(1)?)?;
        return Some((u64::from(v), 5));
    }
    Some((le(data, at, n)? >> n, n))
}

/// The signed variant (DCU32INT's `ReadIndex`): the same lengths, with the
/// value sign-extended from the bytes read before the shift.
fn signed(data: &[u8], at: usize) -> Option<(i64, usize)> {
    let n = packed_len(*data.get(at)?);
    if n == 5 {
        let v = u32_le(data, at.checked_add(1)?)?;
        return Some((i64::from(v as i32), 5));
    }
    let raw = le(data, at, n)?;
    let unused = 64u32.saturating_sub(u32::try_from(n.saturating_mul(8)).unwrap_or(64));
    let extended = ((raw << unused) as i64) >> unused;
    Some((extended >> n, n))
}

/// Where a record occurs: which tags are allowed and what they mean.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Ctx {
    /// The unit-level stream.
    Top,
    /// The imports of a used unit (`d`).
    Unit,
    /// The (empty) list after a unit reference (`4`).
    UnitRef,
    /// Parameters and locals of a procedure (`(`).
    Proc,
    /// Members of a class definition (`F`).
    Class,
}

/// How a field is decoded and shown.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Tag,
    Name,
    Flags,
    Check,
    Time,
    Byte,
    Raw32,
    /// Unsigned packed value.
    Packed,
    /// Signed packed value.
    Signed,
    /// Unsigned packed type number.
    TypeRef,
    /// Unsigned packed declaration number.
    DeclRef,
}

/// One layout step: kind, label, description.
type Step = (Kind, &'static str, &'static str);

const NAME: Step = (Kind::Name, "Name", "Length-prefixed (short) string");
const FLAGS: Step = (
    Kind::Flags,
    "Flags",
    "Packed value; at unit level, bit 0x40 means a check value follows",
);

const L_UNIT_FLAGS: &[Step] = &[
    (
        Kind::Packed,
        "Flags",
        "Packed value; called the unit flags in DCU32INT",
    ),
    (
        Kind::Packed,
        "Priority",
        "Packed value; called the unit priority in DCU32INT",
    ),
];
const L_SOURCE: &[Step] = &[
    NAME,
    (
        Kind::Time,
        "Time",
        "DOS date and time of the file when compiled",
    ),
    (Kind::Byte, "Value", "Meaning not established"),
];
const L_USED_UNIT: &[Step] = &[
    NAME,
    (
        Kind::Raw32,
        "Value 1",
        "Meaning not established (units compiled together tend to share it)",
    ),
    (Kind::Raw32, "Value 2", "Meaning not established"),
];
const L_IMPORT: &[Step] = &[
    NAME,
    (
        Kind::Raw32,
        "Check value",
        "Presumably a signature of the imported declaration; zero for some compiler intrinsics",
    ),
];
const L_UNIT_REF: &[Step] = &[
    NAME,
    FLAGS,
    (
        Kind::DeclRef,
        "Unit",
        "Number of the used-unit record this refers to (1: this unit)",
    ),
];
const L_SYMBOL: &[Step] = &[
    NAME,
    FLAGS,
    (Kind::TypeRef, "Type", "Type number"),
    (
        Kind::Signed,
        "Value",
        "Signed packed value; meaning not established at unit level",
    ),
];
const L_TYPE: &[Step] = &[
    NAME,
    FLAGS,
    (
        Kind::Packed,
        "Definition",
        "The type number this name stands for",
    ),
];
const L_PROC: &[Step] = &[
    NAME,
    FLAGS,
    (Kind::Packed, "Value 1", "Meaning not established"),
    (
        Kind::Packed,
        "Code size",
        "Bytes of code (with its literals) in the code block",
    ),
    (Kind::Packed, "Value 3", "Meaning not established"),
    (Kind::Packed, "Value 4", "Meaning not established"),
];
const L_LOCAL: &[Step] = &[
    NAME,
    FLAGS,
    (Kind::TypeRef, "Type", "Type number"),
    (
        Kind::Signed,
        "Location",
        "Signed packed value: negative for frame-based locals (an offset); otherwise not \
         established (register or parameter slot)",
    ),
];
const L_9E: &[Step] = &[(Kind::Signed, "Value", "Meaning not established")];
const L_G: &[Step] = &[
    (Kind::Packed, "Value 1", "Meaning not established"),
    (Kind::Packed, "Value 2", "Meaning not established"),
    (Kind::Packed, "Value 3", "Meaning not established"),
    (
        Kind::TypeRef,
        "Class",
        "Type number of the class it refers to",
    ),
    (Kind::Packed, "Value 5", "Meaning not established"),
];
const L_CLASS: &[Step] = &[
    (Kind::Packed, "Value 1", "Meaning not established"),
    (Kind::Packed, "Value 2", "Meaning not established"),
    (
        Kind::DeclRef,
        "Declaration",
        "Number of the type name (`*`) record",
    ),
    (Kind::TypeRef, "Parent", "Type number of the parent class"),
    (Kind::Packed, "Value 5", "Meaning not established"),
    (Kind::Packed, "Value 6", "Meaning not established"),
    (
        Kind::DeclRef,
        "Symbol",
        "Number of a related declaration (the `&` record named after the class)",
    ),
    (Kind::Packed, "Value 8", "Meaning not established"),
    (Kind::Signed, "Value 9", "Meaning not established"),
    (Kind::Signed, "Value 10", "Meaning not established"),
    (Kind::Packed, "Value 11", "Meaning not established"),
    (Kind::Packed, "Value 12", "Meaning not established"),
];
const L_FIELD: &[Step] = &[
    NAME,
    FLAGS,
    (Kind::TypeRef, "Type", "Type number"),
    (Kind::Signed, "Offset", "Offset of the field in an instance"),
];
const L_METHOD: &[Step] = &[
    NAME,
    FLAGS,
    (Kind::Signed, "Value 1", "Meaning not established"),
    (
        Kind::DeclRef,
        "Implementation",
        "Number of the procedure record implementing the method",
    ),
    (Kind::Packed, "Value 3", "Meaning not established"),
];

/// A record kind: layout, what it is called, the list it opens, and
/// whether it takes a declaration number.
struct Layout {
    steps: &'static [Step],
    what: &'static str,
    opens: Option<Ctx>,
    numbered: bool,
}

const fn lay(
    steps: &'static [Step],
    what: &'static str,
    opens: Option<Ctx>,
    numbered: bool,
) -> Layout {
    Layout {
        steps,
        what,
        opens,
        numbered,
    }
}

fn layout(ctx: Ctx, tag: u8) -> Option<Layout> {
    Some(match (ctx, tag) {
        (Ctx::Top, 0x96) => lay(L_UNIT_FLAGS, "unit flags", None, false),
        (Ctx::Top, b'p') => lay(L_SOURCE, "source file", None, false),
        (Ctx::Top, b'r') => lay(L_SOURCE, "resource file", None, false),
        (Ctx::Top, b'd') => lay(L_USED_UNIT, "used unit", Some(Ctx::Unit), true),
        (Ctx::Top, b'e') => lay(
            L_USED_UNIT,
            "used unit (implementation)",
            Some(Ctx::Unit),
            true,
        ),
        (Ctx::Unit, b'f') => lay(L_IMPORT, "imported type", None, true),
        (Ctx::Unit, b'g') => lay(L_IMPORT, "imported value", None, true),
        (Ctx::Top, b'4') => lay(L_UNIT_REF, "unit reference", Some(Ctx::UnitRef), true),
        (Ctx::Top, b'&') => lay(L_SYMBOL, "symbol", None, true),
        (Ctx::Top, b'*') => lay(L_TYPE, "type", None, true),
        (Ctx::Top, b' ') => lay(L_SYMBOL, "variable", None, true),
        (Ctx::Top, b'(') => lay(L_PROC, "procedure", Some(Ctx::Proc), true),
        (Ctx::Top, 0x9e) => lay(L_9E, "record 0x9e", None, false),
        (Ctx::Top, b'G') => lay(L_G, "type definition G", None, false),
        (Ctx::Top, b'F') => lay(L_CLASS, "class definition", Some(Ctx::Class), false),
        (Ctx::Proc, b'!') => lay(L_LOCAL, "parameter", None, true),
        (Ctx::Proc, b'"') => lay(L_LOCAL, "var parameter", None, true),
        (Ctx::Proc, b' ') => lay(L_LOCAL, "local variable", None, true),
        (Ctx::Class, b',') => lay(L_FIELD, "field", None, false),
        (Ctx::Class, b'-') => lay(L_METHOD, "method", None, false),
        (Ctx::Unit | Ctx::UnitRef | Ctx::Proc | Ctx::Class, CLOSE) => {
            lay(&[], "end of list", None, false)
        }
        _ => return None,
    })
}

/// One decoded field: offset and length in the record, and its number or
/// text.
struct Field {
    step: Step,
    at: usize,
    len: usize,
    num: i64,
    text: Option<String>,
}

struct Rec {
    tag: u8,
    len: usize,
    what: &'static str,
    name: Option<String>,
    opens: Option<Ctx>,
    numbered: bool,
    fields: Vec<Field>,
}

impl Rec {
    fn num(&self, label: &str) -> Option<i64> {
        self.fields
            .iter()
            .find(|f| f.step.1 == label)
            .map(|f| f.num)
    }
}

enum Stop {
    /// A tag outside the grammar (or one whose layout is not known).
    Unknown(u8),
    /// The record runs past the region.
    Truncated,
}

/// Decodes the record at the start of `data` (a window of at most
/// [`MAX_RECORD`] bytes, shorter where the region ends).
fn parse_record(data: &[u8], ctx: Ctx) -> std::result::Result<Rec, Stop> {
    let Some(&tag) = data.first() else {
        return Err(Stop::Truncated);
    };
    let lay = layout(ctx, tag).ok_or(Stop::Unknown(tag))?;
    let mut fields = vec![Field {
        step: (Kind::Tag, "Tag", ""),
        at: 0,
        len: 1,
        num: tag.into(),
        text: None,
    }];
    let mut name = None;
    let mut at = 1usize;
    for &step in lay.steps {
        let (num, len, txt) = match step.0 {
            Kind::Name => {
                let n = usize::from(*data.get(at).ok_or(Stop::Truncated)?);
                let start = at.saturating_add(1);
                let bytes = data
                    .get(start..start.saturating_add(n))
                    .ok_or(Stop::Truncated)?;
                let s = crate::text::latin1(bytes);
                name = Some(s.clone());
                (0, n.saturating_add(1), Some(s))
            }
            Kind::Time | Kind::Raw32 | Kind::Check => {
                (u32_le(data, at).ok_or(Stop::Truncated)?.into(), 4, None)
            }
            Kind::Byte => (
                data.get(at).copied().ok_or(Stop::Truncated)?.into(),
                1,
                None,
            ),
            Kind::Signed => {
                let (v, n) = signed(data, at).ok_or(Stop::Truncated)?;
                (v, n, None)
            }
            Kind::Tag | Kind::Packed | Kind::TypeRef | Kind::DeclRef | Kind::Flags => {
                let (v, n) = packed(data, at).ok_or(Stop::Truncated)?;
                (i64::try_from(v).unwrap_or(i64::MAX), n, None)
            }
        };
        fields.push(Field {
            step,
            at,
            len,
            num,
            text: txt,
        });
        at = at.saturating_add(len);
        if step.0 == Kind::Flags && ctx == Ctx::Top && num & 0x40 != 0 {
            let v = u32_le(data, at).ok_or(Stop::Truncated)?;
            fields.push(Field {
                step: (
                    Kind::Check,
                    "Check value",
                    "Present at unit level when flag bit 0x40 is set; meaning not established",
                ),
                at,
                len: 4,
                num: v.into(),
                text: None,
            });
            at = at.saturating_add(4);
        }
    }
    Ok(Rec {
        tag,
        len: at,
        what: lay.what,
        name,
        opens: lay.opens,
        numbered: lay.numbered,
        fields,
    })
}

/// Reads and decodes the record at `pos` in `region`.
async fn read_record(
    cx: &Cx,
    region: Span,
    pos: u64,
    ctx: Ctx,
) -> Result<(std::result::Result<Rec, Stop>, Span)> {
    let window = region.sub(pos, MAX_RECORD);
    let data = cx.read(window).await?;
    let rec = parse_record(&data, ctx);
    let len = rec.as_ref().map_or(0, |r| r.len as u64);
    Ok((rec, region.sub(pos, len)))
}

/// Names for cross-references, collected by the top-level walk.
#[derive(Default)]
struct Names {
    /// Names of the imported types, numbered from 1.
    types: Vec<String>,
    /// Type numbers named by the unit's own `*` records (the first name
    /// given to a number).
    local_types: std::collections::BTreeMap<i64, String>,
    /// Declaration names, numbered from 2 (index 0 is declaration 2).
    decls: Vec<String>,
    /// Declaration numbers of the imported-type records, in order.
    type_decls: Vec<i64>,
}

impl Names {
    fn type_name(&self, n: i64) -> Option<String> {
        let imported = usize::try_from(n)
            .ok()
            .and_then(|i| i.checked_sub(1))
            .and_then(|i| self.types.get(i));
        if let Some(s) = imported {
            return Some(s.clone());
        }
        self.local_types.get(&n).cloned()
    }

    /// The type number of the imported-type record with declaration
    /// number `decl`.
    fn type_of_import(&self, decl: i64) -> Option<usize> {
        self.type_decls
            .binary_search(&decl)
            .ok()
            .and_then(|i| i.checked_add(1))
    }

    fn decl_name(&self, n: i64) -> Option<String> {
        if n == 1 {
            return Some("(this unit)".to_owned());
        }
        usize::try_from(n)
            .ok()
            .and_then(|i| i.checked_sub(2))
            .and_then(|i| self.decls.get(i))
            .cloned()
    }

    /// The next declaration number.
    fn next_decl(&self) -> i64 {
        i64::try_from(self.decls.len())
            .unwrap_or(i64::MAX)
            .saturating_add(2)
    }

    fn note(&mut self, rec: &Rec) {
        let name = rec.name.clone().unwrap_or_default();
        if rec.tag == b'f' {
            self.types.push(name.clone());
            self.type_decls.push(self.next_decl());
        }
        if rec.tag == b'*'
            && let Some(n) = rec.num("Definition")
        {
            self.local_types.entry(n).or_insert_with(|| name.clone());
        }
        if rec.numbered {
            self.decls.push(name);
        }
    }
}

/// The sections the top-level records are grouped into.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Section {
    Flags,
    Sources,
    Units,
    UnitRefs,
    Decls,
    TypeDefs,
}

fn section(tag: u8) -> Section {
    match tag {
        0x96 => Section::Flags,
        b'p' | b'r' => Section::Sources,
        b'd' | b'e' => Section::Units,
        b'4' => Section::UnitRefs,
        b'G' | b'F' => Section::TypeDefs,
        _ => Section::Decls,
    }
}

/// A run of consecutive top-level records of one section.
#[derive(Clone, Copy)]
struct Run {
    section: Section,
    region: Span,
    count: u64,
    /// Declaration number of the first numbered record in the run.
    first_decl: i64,
}

/// An item: a top-level record and its nested list, if it opens one.
struct Item {
    rec: Rec,
    head: Span,
    span: Span,
    /// Number of nested records (without the closing `c`).
    nested: u64,
}

/// Reads the item at `pos` of `region`, noting names in `names` (if
/// given). `Err` with the reason if it cannot be decoded completely.
async fn read_item(
    cx: &Cx,
    region: Span,
    pos: u64,
    mut names: Option<&mut Names>,
) -> Result<std::result::Result<Item, String>> {
    let (rec, head) = read_record(cx, region, pos, Ctx::Top).await?;
    let rec = match rec {
        Ok(r) => r,
        Err(Stop::Unknown(t)) => return Ok(Err(format!("tag {t:#04x} not decoded"))),
        Err(Stop::Truncated) => return Ok(Err("truncated record".to_owned())),
    };
    if let Some(n) = names.as_deref_mut() {
        n.note(&rec);
    }
    let mut end = pos.saturating_add(head.len);
    let mut nested = 0u64;
    if let Some(ctx) = rec.opens {
        loop {
            if end >= region.len {
                return Ok(Err(format!("{} list not closed", rec.what)));
            }
            let (inner, span) = read_record(cx, region, end, ctx).await?;
            match inner {
                Ok(i) => {
                    end = end.saturating_add(span.len);
                    if i.tag == CLOSE {
                        break;
                    }
                    if let Some(n) = names.as_deref_mut() {
                        n.note(&i);
                    }
                    nested = nested.saturating_add(1);
                }
                Err(Stop::Unknown(t)) => {
                    return Ok(Err(format!(
                        "tag {t:#04x} not decoded inside a {}",
                        rec.what
                    )));
                }
                Err(Stop::Truncated) => return Ok(Err("truncated record".to_owned())),
            }
        }
    }
    let span = region.sub(pos, end.saturating_sub(pos));
    Ok(Ok(Item {
        rec,
        head,
        span,
        nested,
    }))
}

fn type_label(names: &Names, n: i64) -> String {
    names.type_name(n).unwrap_or_else(|| format!("type #{n}"))
}

/// Label and summary of a record.
fn describe(rec: &Rec, names: &Names, number: Option<i64>, nested: u64) -> (String, String) {
    let num = |label: &str| rec.num(label).unwrap_or(0);
    let mut label = rec.name.clone().unwrap_or_default();
    let mut summary = match rec.tag {
        0x96 => {
            label = "Unit flags".to_owned();
            String::new()
        }
        b'p' | b'r' => format!(
            "{}, {}",
            rec.what,
            dos_time(u32::try_from(num("Time")).unwrap_or(0))
        ),
        b'd' | b'e' => format!("{}, {}", rec.what, count(nested, "import", "imports")),
        b'f' => match number.and_then(|n| names.type_of_import(n)) {
            Some(t) => format!("{}, type #{t}", rec.what),
            None => rec.what.to_owned(),
        },
        b'4' => format!(
            "{} → {}",
            rec.what,
            names
                .decl_name(num("Unit"))
                .unwrap_or_else(|| format!("#{}", num("Unit")))
        ),
        b'&' | b' ' | b'!' | b'"' => format!("{}: {}", rec.what, type_label(names, num("Type"))),
        b'*' => format!("{}, names type #{}", rec.what, num("Definition")),
        b'(' => format!(
            "{}, {} of code, {}",
            rec.what,
            count(
                u64::try_from(num("Code size")).unwrap_or(0),
                "byte",
                "bytes"
            ),
            count(nested, "parameter or local", "parameters and locals")
        ),
        0x9e => {
            label = "Record 0x9e".to_owned();
            format!("value {}", num("Value"))
        }
        b'G' => {
            label = "Type definition G".to_owned();
            format!("refers to {}", type_label(names, num("Class")))
        }
        b'F' => {
            label = names
                .decl_name(num("Declaration"))
                .unwrap_or_else(|| "Class definition".to_owned());
            format!(
                "{} (parent {}), {}",
                rec.what,
                type_label(names, num("Parent")),
                count(nested, "member", "members")
            )
        }
        b',' => format!(
            "{}: {} at offset {}",
            rec.what,
            type_label(names, num("Type")),
            num("Offset")
        ),
        b'-' => format!(
            "{} → {}",
            rec.what,
            names
                .decl_name(num("Implementation"))
                .unwrap_or_else(|| format!("#{}", num("Implementation")))
        ),
        CLOSE => {
            label = "End".to_owned();
            rec.what.to_owned()
        }
        _ => rec.what.to_owned(),
    };
    if let Some(n) = number {
        summary = format!("#{n} {summary}");
    }
    (label, summary)
}

fn field_node(f: &Field, span: Span, rec: &Rec, names: &Names) -> Node {
    let (kind, label, desc) = f.step;
    let raw = u64::try_from(f.num).unwrap_or(0);
    let mut node = Node::new(label).span(span.sub(f.at as u64, f.len as u64));
    node = match kind {
        Kind::Tag => node.value(Value::Enum {
            raw,
            bits: 8,
            name: Some(rec.what),
        }),
        Kind::Name => node.value(text(f.text.clone().unwrap_or_default())),
        Kind::Time => node
            .value(text(dos_time(u32::try_from(raw).unwrap_or(0))))
            .summary(format!("{raw:#010x}")),
        Kind::Byte => node.value(hex(raw, 8)),
        Kind::Raw32 | Kind::Check => node.value(hex(raw, 32)),
        Kind::Flags => node.value(hex(raw, 32)),
        Kind::Packed => node.value(uint(raw, 32)),
        Kind::Signed => node.value(Value::Int {
            value: f.num,
            bits: 32,
        }),
        Kind::TypeRef => {
            let n = node.value(uint(raw, 32));
            match names.type_name(f.num) {
                Some(s) => n.summary(s),
                None => n,
            }
        }
        Kind::DeclRef => {
            let n = node.value(uint(raw, 32));
            match names.decl_name(f.num) {
                Some(s) => n.summary(s),
                None => n,
            }
        }
    };
    if desc.is_empty() {
        node
    } else {
        node.desc(desc)
    }
}

/// Expands a record: its fields.
async fn record_fields(cx: Cx, (span, ctx, names): (Span, Ctx, Arc<Names>)) -> Result<()> {
    let data = cx.read(span).await?;
    let rec = parse_record(&data, ctx).map_err(|_| Diagnostic::malformed("record").at(span))?;
    for f in &rec.fields {
        cx.emit(field_node(f, span, &rec, &names));
    }
    Ok(())
}

/// Expands an item: the fields of its record, then its nested records.
async fn item_children(
    cx: Cx,
    (span, head_len, ctx, first, names): (Span, u64, Ctx, i64, Arc<Names>),
) -> Result<()> {
    let head = span.sub(0, head_len);
    let data = cx.read(head).await?;
    let rec =
        parse_record(&data, Ctx::Top).map_err(|_| Diagnostic::malformed("record").at(head))?;
    for f in &rec.fields {
        cx.emit(field_node(f, head, &rec, &names));
    }
    let mut pos = head_len;
    let mut number = first;
    while pos < span.len {
        let (inner, at) = read_record(&cx, span, pos, ctx).await?;
        let Ok(inner) = inner else {
            return Err(Diagnostic::malformed("record").at(at));
        };
        let this = inner.numbered.then_some(number);
        if inner.numbered {
            number = number.saturating_add(1);
        }
        let node = if inner.tag == CLOSE {
            Node::new("End").span(at).value(Value::Enum {
                raw: CLOSE.into(),
                bits: 8,
                name: Some(inner.what),
            })
        } else {
            let (label, summary) = describe(&inner, &names, this, 0);
            Node::new(label)
                .span(at)
                .summary(summary)
                .lazy(record_fields, (at, ctx, names.clone()))
        };
        cx.push(node).await;
        pos = pos.saturating_add(at.len);
        if at.len == 0 {
            break;
        }
    }
    Ok(())
}

/// Pushes the items of a run.
async fn run_items(cx: Cx, (run, names): (Run, Arc<Names>)) -> Result<()> {
    cx.set_count(Count::Exact(run.count));
    let mut pos = 0u64;
    let mut number = run.first_decl;
    while pos < run.region.len {
        let item = match read_item(&cx, run.region, pos, None).await? {
            Ok(i) => i,
            Err(why) => return Err(Diagnostic::malformed(why).at(run.region.tail(pos))),
        };
        if item.span.len == 0 {
            break;
        }
        cx.push(item_node(&item, &names, &mut number)).await;
        pos = pos.saturating_add(item.span.len);
    }
    Ok(())
}

/// The node of an item; advances `number` past the declarations it holds.
fn item_node(item: &Item, names: &Arc<Names>, number: &mut i64) -> Node {
    let this = item.rec.numbered.then_some(*number);
    if item.rec.numbered {
        *number = number.saturating_add(1);
    }
    let (label, summary) = describe(&item.rec, names, this, item.nested);
    let node = Node::new(label).span(item.span);
    let node = if summary.is_empty() {
        node
    } else {
        node.summary(summary)
    };
    match item.rec.opens {
        Some(ctx) => {
            let first = *number;
            if matches!(ctx, Ctx::Unit | Ctx::Proc) {
                // Imports, parameters and locals are numbered.
                *number = number.saturating_add(i64::try_from(item.nested).unwrap_or(0));
            }
            node.lazy(
                item_children,
                (item.span, item.head.len, ctx, first, names.clone()),
            )
        }
        None => node.lazy(record_fields, (item.head, Ctx::Top, names.clone())),
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, HEADER_D7)).await?;
    let magic = u32_le(&head, 0).unwrap_or(0);
    let size = u32_le(&head, 4).unwrap_or(0);
    let time = u32_le(&head, 8).unwrap_or(0);
    let product = version(magic).unwrap_or_else(|| "unknown version".to_owned());
    let d7 = magic == MAGIC_D7;
    let header_len = if d7 { HEADER_D7 } else { HEADER_COMMON };
    let hspan = file.sub(0, header_len);
    cx.emit(
        Node::new("Header")
            .span(hspan)
            .summary(product.clone())
            .lazy(header_fields, (hspan, d7)),
    );
    if u64::from(size) != file.len {
        cx.diag(Diagnostic::warning(format!(
            "header says {size} bytes, the file has {}",
            file.len
        )));
    }
    // The end tag, if present, is shown on its own.
    let last = cx.read(file.sub(file.len.saturating_sub(1), 1)).await?;
    let has_end = file.len > header_len && last.first() == Some(&END_TAG);
    let body_end = if has_end {
        file.len.saturating_sub(1)
    } else {
        file.len
    };
    let body = file.sub(0, body_end);

    let mut pos = header_len;
    let mut stop: Option<String> = None;
    let mut names = Names::default();
    let mut runs: Vec<Run> = Vec::new();
    if d7 {
        while pos < body.len {
            let first_decl = names.next_decl();
            let item = match read_item(&cx, body, pos, Some(&mut names)).await? {
                Ok(i) => i,
                Err(why) => {
                    stop = Some(why);
                    break;
                }
            };
            let sec = section(item.rec.tag);
            match runs.last_mut() {
                Some(r) if r.section == sec => {
                    r.region = Span::new(
                        r.region.source,
                        r.region.offset,
                        r.region.len.saturating_add(item.span.len),
                    );
                    r.count = r.count.saturating_add(1);
                }
                _ => runs.push(Run {
                    section: sec,
                    region: item.span,
                    count: 1,
                    first_decl,
                }),
            }
            pos = pos.saturating_add(item.span.len);
            cx.progress_in(body, body.offset.saturating_add(pos));
        }
    } else {
        stop = Some(format!("the record layout of {product} is not decoded"));
    }

    let names = Arc::new(names);
    let mut units = 0u64;
    let mut sources = 0u64;
    let mut decls = 0u64;
    for run in &runs {
        cx.checkpoint().await;
        let (label, unit) = match run.section {
            Section::Flags => ("Unit flags", ("record", "records")),
            Section::Sources => {
                sources = sources.saturating_add(run.count);
                ("Source files", ("file", "files"))
            }
            Section::Units => {
                units = units.saturating_add(run.count);
                ("Used units", ("unit", "units"))
            }
            Section::UnitRefs => ("Unit references", ("unit", "units")),
            Section::Decls => {
                decls = decls.saturating_add(run.count);
                ("Declarations", ("declaration", "declarations"))
            }
            Section::TypeDefs => ("Type definitions", ("definition", "definitions")),
        };
        if run.section == Section::Flags && run.count == 1 {
            // A single record, shown as itself.
            if let Ok(Ok(item)) = read_item(&cx, run.region, 0, None).await {
                let mut n = run.first_decl;
                cx.emit(item_node(&item, &names, &mut n));
            }
            continue;
        }
        let mut node = Node::new(label)
            .span(run.region)
            .summary(count(run.count, unit.0, unit.1))
            .lazy(run_items, (*run, names.clone()));
        if run.section == Section::UnitRefs {
            node = node.desc(
                "One per unit named in the uses clauses, and one for the unit itself; each \
                 refers to the used-unit record",
            );
        }
        cx.emit(node);
    }

    if pos < body.len {
        let rest = body.tail(pos);
        let why = stop.unwrap_or_else(|| "not decoded".to_owned());
        cx.emit(
            Node::new("Unparsed remainder")
                .span(rest)
                .summary(format!("{} bytes; {why}", rest.len))
                .desc(
                    "Type definitions, code, fixups and debug records not decoded. Their \
                     layout varies by compiler version.",
                ),
        );
    }
    if has_end {
        cx.emit(
            Node::new("End tag")
                .span(file.sub(body_end, 1))
                .value(Value::Enum {
                    raw: END_TAG.into(),
                    bits: 8,
                    name: Some("end of unit"),
                }),
        );
    }

    let mut note = format!("{product} compiled unit");
    if units > 0 {
        note.push_str(&format!(", {}", count(units, "used unit", "used units")));
    }
    if decls > 0 {
        note.push_str(&format!(
            ", {}",
            count(decls, "declaration", "declarations")
        ));
    }
    if sources > 0 {
        note.push_str(&format!(
            ", {}",
            count(sources, "source file", "source files")
        ));
    }
    if valid_dos_time(time) {
        note.push_str(&format!(", compiled {}", dos_time(time)));
    }
    cx.annotate(note);
    Ok(())
}

async fn header_fields(cx: Cx, (span, d7): (Span, bool)) -> Result<()> {
    let data = cx.read(span).await?;
    let Some(magic) = u32_le(&data, 0) else {
        return Err(Diagnostic::truncated(span.sub(0, 4), span.len));
    };
    let old = OLD_MAGIC.iter().any(|(m, _)| *m == magic);
    let mut node = Node::new("Magic")
        .span(span.sub(0, 4))
        .value(hex(magic, 32));
    if let Some(v) = version(magic) {
        node = node.summary(v);
    }
    if old {
        node = node.desc("Pre-Delphi 6 magic, from memory of DCU32INT (unverified)");
    }
    cx.emit(node);
    if !old {
        let cv = magic >> 24;
        cx.emit(
            Node::new("Compiler version")
                .span(span.sub(3, 1))
                .value(Value::Enum {
                    raw: cv.into(),
                    bits: 8,
                    name: lookup(COMPILER_VERSION, cv.into()),
                })
                .desc(
                    "The magic's high byte, equal to CompilerVersion (verified for Delphi 7 \
                     only; the product names are the public CompilerVersion table)",
                ),
        );
        cx.emit(
            Node::new("Platform / flags")
                .span(span.sub(0, 3))
                .value(hex(magic & 0x00ff_ffff, 24))
                .desc("Low three bytes of the magic; meaning not established"),
        );
    }
    if let Some(size) = u32_le(&data, 4) {
        cx.emit(
            Node::new("File size")
                .span(span.sub(4, 4))
                .value(uint(size, 32)),
        );
    }
    if let Some(t) = u32_le(&data, 8) {
        cx.emit(
            Node::new("Compile time")
                .span(span.sub(8, 4))
                .value(text(dos_time(t)))
                .summary(format!("{t:#010x}"))
                .desc("DOS date and time"),
        );
    }
    if d7 {
        if let Some(v) = u32_le(&data, 12) {
            cx.emit(
                Node::new("Unknown")
                    .span(span.sub(12, 4))
                    .value(hex(v, 32))
                    .desc(
                        "Meaning not established; used-unit records carry values of the same \
                         shape",
                    ),
            );
        }
        for at in [16u64, 17] {
            if let Some(&b) = data.get(at as usize) {
                cx.emit(
                    Node::new("Unknown")
                        .span(span.sub(at, 1))
                        .value(hex(b, 8))
                        .desc("Meaning not established"),
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packed_index_lengths() {
        assert_eq!(packed(&[0x3c], 0), Some((30, 1)));
        assert_eq!(packed(&[0x59, 0x02], 0), Some((0x96, 2)));
        assert_eq!(packed(&[0x03, 0x00, 0x01], 0), Some((0x2000, 3)));
        assert_eq!(packed(&[0x0f, 1, 2, 3, 4], 0), Some((0x0403_0201, 5)));
        assert_eq!(packed(&[0x01], 0), None);
    }

    #[test]
    fn signed_index() {
        assert_eq!(signed(&[0xf8], 0), Some((-4, 1)));
        assert_eq!(signed(&[0x08], 0), Some((4, 1)));
        assert_eq!(signed(&[0xe1, 0x0b], 0), Some((760, 2)));
        assert_eq!(signed(&[0xa9, 0xfe], 0), Some((-86, 2)));
        assert_eq!(signed(&[0x0f, 0, 0, 0, 0x80], 0), Some((-0x8000_0000, 5)));
    }

    #[test]
    fn dos_time_validation() {
        assert!(valid_dos_time(0x3475_8f0d));
        assert!(!valid_dos_time(0));
        assert!(!valid_dos_time(0x3475_8f1e)); // 60 seconds
    }

    #[test]
    fn versions() {
        assert_eq!(version(MAGIC_D7).as_deref(), Some("Delphi 7"));
        assert_eq!(version(0x0d00_00df), None);
        assert_eq!(version(0x7f00_00df), None);
    }
}
