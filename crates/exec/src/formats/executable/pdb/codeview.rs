//! CodeView records in PDB streams: type records (`LF_*`, in the TPI and
//! IPI streams) and symbol records (`S_*`, in the symbol record stream and
//! the module streams), following LLVM's `CodeView` headers and the
//! "CodeView Type Records" / "CodeView Symbol Records" documents.
//!
//! Every record starts with a 16-bit length (not counting itself) and a
//! 16-bit kind. Record walkers push one node per record and keep resume
//! marks; each record's fields are decoded only when it is expanded.

use crate::bytes::{to_u64, to_usize, u16_le, u32_le};
use crate::cx::{Block, Cx};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::executable::pe::tables::SECTION_CHARACTERISTICS;
use crate::formats::util::binutil::NodeExt;
use crate::formats::util::fmt::clip;
use crate::formats::util::val::{hex, int, name_or, text, uint};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, field, flag};

const LE: Endian = Endian::Little;

/// The first type index of a type stream; lower ones are simple types.
pub(super) const FIRST_TYPE: u32 = 0x1000;

// ---------------------------------------------------------------------------
// Type indices

/// Simple (built-in) type kinds: the low byte of a type index below 0x1000.
const SIMPLE_TYPES: EnumTable = &[
    (0x00, "<no type>"),
    (0x03, "void"),
    (0x07, "<not translated>"),
    (0x08, "HRESULT"),
    (0x10, "signed char"),
    (0x11, "short"),
    (0x12, "long"),
    (0x13, "__int64"),
    (0x14, "__int128"),
    (0x20, "unsigned char"),
    (0x21, "unsigned short"),
    (0x22, "unsigned long"),
    (0x23, "unsigned __int64"),
    (0x24, "unsigned __int128"),
    (0x30, "bool"),
    (0x31, "__bool16"),
    (0x32, "__bool32"),
    (0x33, "__bool64"),
    (0x34, "__bool128"),
    (0x40, "float"),
    (0x41, "double"),
    (0x42, "long double"),
    (0x43, "__float128"),
    (0x44, "__float48"),
    (0x45, "float (partial precision)"),
    (0x46, "_Float16"),
    (0x50, "_Complex float"),
    (0x51, "_Complex double"),
    (0x52, "_Complex long double"),
    (0x53, "_Complex __float128"),
    (0x68, "__int8"),
    (0x69, "unsigned __int8"),
    (0x70, "char"),
    (0x71, "wchar_t"),
    (0x72, "__int16"),
    (0x73, "unsigned __int16"),
    (0x74, "int"),
    (0x75, "unsigned"),
    (0x76, "__int64"),
    (0x77, "unsigned __int64"),
    (0x78, "__int128"),
    (0x79, "unsigned __int128"),
    (0x7a, "char16_t"),
    (0x7b, "char32_t"),
    (0x7c, "char8_t"),
];

/// A type index as text: the built-in type it names, or `0x1004`.
pub(super) fn type_name(ti: u32) -> String {
    if ti >= FIRST_TYPE {
        return format!("{ti:#x}");
    }
    let base = name_or(SIMPLE_TYPES, (ti & 0xff).into(), "simple type");
    match (ti >> 8) & 0xf {
        0 => base,
        1..=3 => format!("{base} near/far*"),
        4 | 5 => format!("{base}* (32-bit)"),
        6 => format!("{base}*"),
        _ => format!("{base}* (128-bit)"),
    }
}

/// Reads a type index field, showing the simple type it names.
fn ti(f: &mut Fields<'_>, name: &'static str) -> Result<u32> {
    f.u32(name)
        .with(|&v, n| {
            let n = n.value(hex(v, 32));
            if v < FIRST_TYPE {
                n.summary(type_name(v))
            } else {
                n
            }
        })
        .emit()
}

/// Reads a numeric leaf: a value below 0x8000 in place, or a leaf kind
/// followed by the value.
pub(super) fn numeric(f: &mut Fields<'_>, name: &'static str) -> Result<i128> {
    let data: &[u8] = &f.block().data;
    let at = to_usize(f.pos());
    let truncated = || Diagnostic::truncated(f.peek_span(2), 0);
    let leaf = u16_le(data, at).ok_or_else(truncated)?;
    let get = |n: usize| -> Option<u64> {
        let bytes = data.get(at.checked_add(2)?..at.checked_add(2)?.checked_add(n)?)?;
        Some(
            bytes
                .iter()
                .rev()
                .fold(0u64, |acc, &b| acc.wrapping_shl(8) | u64::from(b)),
        )
    };
    let signed = |v: u64, bits: u32| -> i128 {
        let shift = 64u32.saturating_sub(bits);
        i128::from((v.wrapping_shl(shift) as i64).wrapping_shr(shift))
    };
    let (value, len): (Option<i128>, u64) = match leaf {
        0..0x8000 => (Some(i128::from(leaf)), 2),
        0x8000 => (get(1).map(|v| signed(v, 8)), 3),
        0x8001 => (get(2).map(|v| signed(v, 16)), 4),
        0x8002 => (get(2).map(i128::from), 4),
        0x8003 => (get(4).map(|v| signed(v, 32)), 6),
        0x8004 => (get(4).map(i128::from), 6),
        0x8009 => (get(8).map(|v| signed(v, 64)), 10),
        0x800a => (get(8).map(i128::from), 10),
        _ => {
            return Err(
                Diagnostic::unsupported(format!("numeric leaf {leaf:#06x}")).at(f.peek_span(2))
            );
        }
    };
    let span = f.peek_span(len);
    let value = value.ok_or_else(|| Diagnostic::truncated(span, 0))?;
    f.skip(len);
    let shown = match i64::try_from(value) {
        Ok(v) if v < 0 => int(v, 64),
        _ => uint(u64::try_from(value).unwrap_or(u64::MAX), 64),
    };
    f.node(Node::new(name).span(span).value(shown));
    Ok(value)
}

/// The record's trailing name.
fn name(f: &mut Fields<'_>) -> Result<String> {
    f.cstr("Name").emit()
}

/// Emits a record's length and kind.
fn prefix(f: &mut Fields<'_>, kinds: EnumTable) -> Result<u16> {
    f.u16("Length").desc("Bytes after this field").emit()?;
    f.u16("Kind").hex().enumeration(kinds).emit()
}

/// The rest of a record as bytes.
fn rest(f: &mut Fields<'_>) -> Result<()> {
    let n = f.remaining();
    if n > 0 {
        f.bytes("Data", n).emit()?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Type records

pub(super) const TYPE_KINDS: EnumTable = &[
    (0x000a, "LF_VTSHAPE"),
    (0x000e, "LF_LABEL"),
    (0x1001, "LF_MODIFIER"),
    (0x1002, "LF_POINTER"),
    (0x1008, "LF_PROCEDURE"),
    (0x1009, "LF_MFUNCTION"),
    (0x100a, "LF_COBOL0"),
    (0x100b, "LF_BARRAY"),
    (0x100c, "LF_DIMARRAY_ST"),
    (0x100d, "LF_VFTPATH"),
    (0x100e, "LF_PRECOMP_ST"),
    (0x100f, "LF_OEM"),
    (0x0014, "LF_ENDPRECOMP"),
    (0x1201, "LF_ARGLIST"),
    (0x1203, "LF_FIELDLIST"),
    (0x1204, "LF_DERIVED"),
    (0x1205, "LF_BITFIELD"),
    (0x1206, "LF_METHODLIST"),
    (0x1400, "LF_BCLASS"),
    (0x1401, "LF_VBCLASS"),
    (0x1402, "LF_IVBCLASS"),
    (0x1404, "LF_INDEX"),
    (0x1409, "LF_VFUNCTAB"),
    (0x140a, "LF_FRIENDCLS"),
    (0x140c, "LF_VFUNCOFF"),
    (0x1502, "LF_ENUMERATE"),
    (0x1503, "LF_ARRAY"),
    (0x1504, "LF_CLASS"),
    (0x1505, "LF_STRUCTURE"),
    (0x1506, "LF_UNION"),
    (0x1507, "LF_ENUM"),
    (0x1508, "LF_DIMARRAY"),
    (0x1509, "LF_PRECOMP"),
    (0x150a, "LF_ALIAS"),
    (0x150b, "LF_DEFARG"),
    (0x150c, "LF_FRIENDFCN"),
    (0x150d, "LF_MEMBER"),
    (0x150e, "LF_STMEMBER"),
    (0x150f, "LF_METHOD"),
    (0x1510, "LF_NESTTYPE"),
    (0x1511, "LF_ONEMETHOD"),
    (0x1512, "LF_NESTTYPEEX"),
    (0x1513, "LF_MEMBERMODIFY"),
    (0x1514, "LF_MANAGED"),
    (0x1515, "LF_TYPESERVER2"),
    (0x1516, "LF_STRIDED_ARRAY"),
    (0x1517, "LF_HLSL"),
    (0x1518, "LF_MODIFIER_EX"),
    (0x1519, "LF_INTERFACE"),
    (0x151a, "LF_BINTERFACE"),
    (0x151b, "LF_VECTOR"),
    (0x151c, "LF_MATRIX"),
    (0x151d, "LF_VFTABLE"),
    (0x1601, "LF_FUNC_ID"),
    (0x1602, "LF_MFUNC_ID"),
    (0x1603, "LF_BUILDINFO"),
    (0x1604, "LF_SUBSTR_LIST"),
    (0x1605, "LF_STRING_ID"),
    (0x1606, "LF_UDT_SRC_LINE"),
    (0x1607, "LF_UDT_MOD_SRC_LINE"),
    (0x1608, "LF_CLASS2"),
    (0x1609, "LF_STRUCTURE2"),
    (0x160a, "LF_UNION2"),
    (0x160b, "LF_INTERFACE2"),
];

const CLASS_OPTIONS: FlagTable = &[
    flag(0x1, "packed"),
    flag(0x2, "has ctor/dtor"),
    flag(0x4, "has overloaded operator"),
    flag(0x8, "nested"),
    flag(0x10, "contains nested class"),
    flag(0x20, "has overloaded assignment"),
    flag(0x40, "has conversion operator"),
    flag(0x80, "forward ref"),
    flag(0x100, "scoped"),
    flag(0x200, "has unique name"),
    flag(0x400, "sealed"),
    field(0x1800, 0x800, "HFA float"),
    field(0x1800, 0x1000, "HFA double"),
    field(0x1800, 0x1800, "HFA other"),
    flag(0x2000, "intrinsic"),
    field(0xc000, 0x4000, "ref class"),
    field(0xc000, 0x8000, "value class"),
    field(0xc000, 0xc000, "interface"),
];

const MODIFIERS: FlagTable = &[
    flag(0x1, "const"),
    flag(0x2, "volatile"),
    flag(0x4, "unaligned"),
];

const CALLING_CONVENTIONS: EnumTable = &[
    (0x00, "near C"),
    (0x01, "far C"),
    (0x02, "near Pascal"),
    (0x03, "far Pascal"),
    (0x04, "near fastcall"),
    (0x05, "far fastcall"),
    (0x07, "near stdcall"),
    (0x08, "far stdcall"),
    (0x09, "near syscall"),
    (0x0a, "far syscall"),
    (0x0b, "thiscall"),
    (0x0c, "MIPS"),
    (0x0d, "generic"),
    (0x0e, "Alpha"),
    (0x0f, "PowerPC"),
    (0x10, "SuperH"),
    (0x11, "ARM"),
    (0x12, "AM33"),
    (0x13, "TriCore"),
    (0x14, "SH5"),
    (0x15, "M32R"),
    (0x16, "CLR call"),
    (0x17, "inline"),
    (0x18, "near vectorcall"),
    (0x19, "swift"),
];

const FUNCTION_OPTIONS: FlagTable = &[
    flag(0x1, "C++ return UDT"),
    flag(0x2, "constructor"),
    flag(0x4, "constructor with virtual bases"),
];

const POINTER_KINDS: EnumTable = &[
    (0x00, "near16"),
    (0x01, "far16"),
    (0x02, "huge16"),
    (0x0a, "near32"),
    (0x0b, "far32"),
    (0x0c, "near64"),
];

const POINTER_MODES: EnumTable = &[
    (0, "pointer"),
    (1, "lvalue reference"),
    (2, "pointer to data member"),
    (3, "pointer to member function"),
    (4, "rvalue reference"),
];

/// Pointer attribute bits besides kind, mode and size.
const POINTER_FLAGS: &[(u32, &str)] = &[
    (0x100, "flat32"),
    (0x200, "volatile"),
    (0x400, "const"),
    (0x800, "unaligned"),
    (0x1000, "restrict"),
    (0x8_0000, "WinRT smart pointer"),
    (0x10_0000, "lvalue ref this"),
    (0x20_0000, "rvalue ref this"),
];

const MEMBER_ACCESS: EnumTable = &[(0, "none"), (1, "private"), (2, "protected"), (3, "public")];

/// Member attributes: access in bits 0-1, method kind in bits 2-4.
const MEMBER_ATTRIBUTES: FlagTable = &[
    field(0x3, 0x1, "private"),
    field(0x3, 0x2, "protected"),
    field(0x3, 0x3, "public"),
    field(0x1c, 0x4, "virtual"),
    field(0x1c, 0x8, "static"),
    field(0x1c, 0xc, "friend"),
    field(0x1c, 0x10, "intro virtual"),
    field(0x1c, 0x14, "pure virtual"),
    field(0x1c, 0x18, "pure intro virtual"),
    flag(0x20, "pseudo"),
    flag(0x40, "no inherit"),
    flag(0x80, "no construct"),
    flag(0x100, "compiler generated"),
    flag(0x200, "sealed"),
];

/// Whether member attributes introduce a virtual function (a vtable offset
/// follows).
fn introduces_virtual(attributes: u16) -> bool {
    matches!((attributes >> 2) & 7, 4 | 6)
}

/// Decodes one type record (the whole record, length and kind included)
/// and returns its summary.
pub(super) fn type_record(f: &mut Fields<'_>, _: &()) -> Result<String> {
    let kind = prefix(f, TYPE_KINDS)?;
    let summary = match kind {
        0x1001 => {
            let t = ti(f, "Modified type")?;
            let m = f.u16("Modifiers").flags(MODIFIERS).emit()?;
            let mut parts = Vec::new();
            for (bit, n) in [(1, "const"), (2, "volatile"), (4, "unaligned")] {
                if m & bit != 0 {
                    parts.push(n);
                }
            }
            format!("{} {}", parts.join(" "), type_name(t))
        }
        0x1002 => {
            let t = ti(f, "Referent type")?;
            let attrs = f
                .u32("Attributes")
                .hex()
                .with(|&v, n| {
                    let mut parts = vec![
                        name_or(POINTER_KINDS, (v & 0x1f).into(), "kind"),
                        name_or(POINTER_MODES, ((v >> 5) & 7).into(), "mode"),
                        format!("size {}", (v >> 13) & 0x3f),
                    ];
                    parts.extend(
                        POINTER_FLAGS
                            .iter()
                            .filter(|&&(bit, _)| v & bit != 0)
                            .map(|&(_, name)| name.to_owned()),
                    );
                    n.summary(parts.join(", "))
                })
                .emit()?;
            let mode = (attrs >> 5) & 7;
            if mode == 2 || mode == 3 {
                ti(f, "Containing class")?;
                f.u16("Representation").emit()?;
            }
            format!(
                "{} to {}",
                name_or(POINTER_MODES, mode.into(), "mode"),
                type_name(t)
            )
        }
        0x1008 => {
            let r = ti(f, "Return type")?;
            f.u8("Calling convention")
                .enumeration(CALLING_CONVENTIONS)
                .emit()?;
            f.u8("Options").flags(FUNCTION_OPTIONS).emit()?;
            let n = f.u16("Parameter count").emit()?;
            let a = ti(f, "Argument list")?;
            format!("{} ({n} parameters, {})", type_name(r), type_name(a))
        }
        0x1009 => {
            let r = ti(f, "Return type")?;
            let c = ti(f, "Class type")?;
            ti(f, "This type")?;
            f.u8("Calling convention")
                .enumeration(CALLING_CONVENTIONS)
                .emit()?;
            f.u8("Options").flags(FUNCTION_OPTIONS).emit()?;
            let n = f.u16("Parameter count").emit()?;
            ti(f, "Argument list")?;
            f.i32("This adjustment").emit()?;
            format!("{} {}::({n} parameters)", type_name(r), type_name(c))
        }
        0x1201 | 0x1604 => {
            let n = f.u32("Count").emit()?;
            let mut names = Vec::new();
            for _ in 0..n {
                if f.remaining() < 4 {
                    break;
                }
                let t = ti(f, "Type")?;
                if names.len() < 8 {
                    names.push(type_name(t));
                }
            }
            format!("({})", names.join(", "))
        }
        0x1203 => field_list(f)?,
        0x1205 => {
            let t = ti(f, "Type")?;
            let len = f.u8("Length").emit()?;
            let pos = f.u8("Position").emit()?;
            format!("{} : {len} at bit {pos}", type_name(t))
        }
        0x1206 => {
            let mut n = 0u32;
            while f.remaining() >= 8 {
                let attrs = f.u16("Attributes").flags(MEMBER_ATTRIBUTES).emit()?;
                f.u16("Padding").emit()?;
                ti(f, "Type")?;
                if introduces_virtual(attrs) {
                    f.u32("Vtable offset").emit()?;
                }
                n = n.saturating_add(1);
            }
            format!("{n} methods")
        }
        0x1503 => {
            let e = ti(f, "Element type")?;
            ti(f, "Index type")?;
            let size = numeric(f, "Size")?;
            name(f)?;
            format!("{}[], {size} bytes", type_name(e))
        }
        0x1504 | 0x1505 | 0x1519 | 0x1506 => {
            let n = f.u16("Member count").emit()?;
            let options = f.u16("Options").flags(CLASS_OPTIONS).emit()?;
            let fields = ti(f, "Field list")?;
            if kind != 0x1506 {
                ti(f, "Derivation list")?;
                ti(f, "Vtable shape")?;
            }
            let size = numeric(f, "Size")?;
            let s = name(f)?;
            if options & 0x200 != 0 {
                f.cstr("Unique name").emit()?;
            }
            if options & 0x80 != 0 {
                format!("{s:?}, forward reference")
            } else {
                format!("{s:?}, {size} bytes, {n} members in {}", type_name(fields))
            }
        }
        0x1507 => {
            let n = f.u16("Member count").emit()?;
            let options = f.u16("Options").flags(CLASS_OPTIONS).emit()?;
            let u = ti(f, "Underlying type")?;
            let fields = ti(f, "Field list")?;
            let s = name(f)?;
            if options & 0x200 != 0 {
                f.cstr("Unique name").emit()?;
            }
            if options & 0x80 != 0 {
                format!("{s:?}, forward reference")
            } else {
                format!(
                    "{s:?}: {}, {n} enumerators in {}",
                    type_name(u),
                    type_name(fields)
                )
            }
        }
        0x000a => {
            let n = f.u16("Count").emit()?;
            let bytes = u64::from(n).div_ceil(2);
            f.bytes("Descriptors", bytes)
                .desc("4 bits per vtable slot")
                .emit()?;
            format!("{n} slots")
        }
        0x000e => {
            f.u16("Mode").emit()?;
            String::new()
        }
        0x1515 => {
            let g = f.guid("Signature").emit()?;
            f.u32("Age").emit()?;
            let s = name(f)?;
            format!("{s:?} {g}")
        }
        0x1601 => {
            ti(f, "Parent scope")?;
            let t = ti(f, "Function type")?;
            let s = name(f)?;
            format!("{s:?}, type {}", type_name(t))
        }
        0x1602 => {
            let c = ti(f, "Class type")?;
            let t = ti(f, "Function type")?;
            let s = name(f)?;
            format!("{}::{s}, type {}", type_name(c), type_name(t))
        }
        0x1603 => {
            let n = f.u16("Count").emit()?;
            for i in 0..n {
                if f.remaining() < 4 {
                    break;
                }
                let label = BUILD_INFO_ARGS
                    .get(usize::from(i))
                    .copied()
                    .unwrap_or("Argument");
                ti(f, label)?;
            }
            format!("{n} arguments")
        }
        0x1605 => {
            ti(f, "Substrings")?;
            let s = f.cstr("String").emit()?;
            format!("{:?}", clip(&s, 100))
        }
        0x1606 => {
            let u = ti(f, "UDT")?;
            let file = f.u32("Source file").hex().desc("A string ID").emit()?;
            let line = f.u32("Line").emit()?;
            format!("{} at {file:#x}:{line}", type_name(u))
        }
        0x1607 => {
            let u = ti(f, "UDT")?;
            f.u32("Source file").hex().desc("Offset in /names").emit()?;
            let line = f.u32("Line").emit()?;
            let m = f.u16("Module").emit()?;
            format!("{} at line {line}, module {m}", type_name(u))
        }
        _ => {
            rest(f)?;
            String::new()
        }
    };
    Ok(summary)
}

/// What the arguments of an `LF_BUILDINFO` record are.
const BUILD_INFO_ARGS: [&str; 5] = [
    "Current directory",
    "Build tool",
    "Source file",
    "Program database",
    "Command line",
];

/// The members of an `LF_FIELDLIST`, each a lazy node; returns the count.
fn field_list(f: &mut Fields<'_>) -> Result<String> {
    let block = f.block();
    let mut n = 0u32;
    while f.remaining() > 0 {
        let start = f.pos();
        // Padding bytes (LF_PAD0..LF_PAD15) align the next member.
        if let Some(&b) = block.data.get(to_usize(start))
            && b >= 0xf0
        {
            f.skip(u64::from(b & 0xf).max(1));
            continue;
        }
        let mut probe = Fields::new(block, LE);
        probe.seek(start);
        let (label, summary) = match member(&mut probe, &()) {
            Ok(m) => m,
            Err(e) => {
                f.node(
                    Node::new("Members")
                        .span(f.peek_span(f.remaining()))
                        .diag(e),
                );
                break;
            }
        };
        let len = probe.pos().saturating_sub(start);
        if len == 0 {
            break;
        }
        f.node(struct_node(label, f.peek_span(len), LE, (), member_layout).maybe_summary(summary));
        f.skip(len);
        n = n.saturating_add(1);
    }
    Ok(format!("{n} members"))
}

fn member_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    member(f, &()).map(|_| ())
}

/// One field list member: its label and summary.
fn member(f: &mut Fields<'_>, _: &()) -> Result<(String, String)> {
    let kind = f.u16("Kind").hex().enumeration(TYPE_KINDS).emit()?;
    let kind_name = name_or(TYPE_KINDS, kind.into(), "member");
    let attributes = |f: &mut Fields<'_>| f.u16("Attributes").flags(MEMBER_ATTRIBUTES).emit();
    let access = |a: u16| name_or(MEMBER_ACCESS, (a & 3).into(), "access");
    Ok(match kind {
        0x150d => {
            let a = attributes(f)?;
            let t = ti(f, "Type")?;
            let offset = numeric(f, "Offset")?;
            let s = name(f)?;
            (
                format!("{kind_name} {s}"),
                format!("{}, offset {offset}, {}", type_name(t), access(a)),
            )
        }
        0x1502 => {
            let a = attributes(f)?;
            let v = numeric(f, "Value")?;
            let s = name(f)?;
            (format!("{kind_name} {s}"), format!("= {v}, {}", access(a)))
        }
        0x1400 => {
            let a = attributes(f)?;
            let t = ti(f, "Base class")?;
            let offset = numeric(f, "Offset")?;
            (
                kind_name,
                format!("{}, offset {offset}, {}", type_name(t), access(a)),
            )
        }
        0x1401 | 0x1402 => {
            let a = attributes(f)?;
            let t = ti(f, "Base class")?;
            ti(f, "Virtual base pointer type")?;
            numeric(f, "Virtual base pointer offset")?;
            numeric(f, "Virtual base table index")?;
            (kind_name, format!("{}, {}", type_name(t), access(a)))
        }
        0x1404 => {
            f.u16("Padding").emit()?;
            let t = ti(f, "Continuation")?;
            (kind_name, format!("continued in {}", type_name(t)))
        }
        0x1409 => {
            f.u16("Padding").emit()?;
            let t = ti(f, "Vtable pointer type")?;
            (kind_name, type_name(t))
        }
        0x150e => {
            let a = attributes(f)?;
            let t = ti(f, "Type")?;
            let s = name(f)?;
            (
                format!("{kind_name} {s}"),
                format!("{}, static, {}", type_name(t), access(a)),
            )
        }
        0x150f => {
            let n = f.u16("Overloads").emit()?;
            let l = ti(f, "Method list")?;
            let s = name(f)?;
            (
                format!("{kind_name} {s}"),
                format!("{n} overloads in {}", type_name(l)),
            )
        }
        0x1511 => {
            let a = attributes(f)?;
            let t = ti(f, "Type")?;
            if introduces_virtual(a) {
                f.u32("Vtable offset").emit()?;
            }
            let s = name(f)?;
            (
                format!("{kind_name} {s}"),
                format!("{}, {}", type_name(t), access(a)),
            )
        }
        0x1510 => {
            f.u16("Padding").emit()?;
            let t = ti(f, "Type")?;
            let s = name(f)?;
            (format!("{kind_name} {s}"), type_name(t))
        }
        _ => {
            return Err(Diagnostic::unsupported(format!(
                "field list member {kind:#06x}"
            )));
        }
    })
}

// ---------------------------------------------------------------------------
// Symbol records

pub(super) const SYMBOL_KINDS: EnumTable = &[
    (0x0006, "S_END"),
    (0x0007, "S_SKIP"),
    (0x0008, "S_CVRESERVE"),
    (0x0009, "S_OBJNAME_ST"),
    (0x000a, "S_ENDARG"),
    (0x000b, "S_COBOLUDT_ST"),
    (0x000c, "S_MANYREG_ST"),
    (0x000d, "S_RETURN"),
    (0x000e, "S_ENTRYTHIS"),
    (0x1012, "S_FRAMEPROC"),
    (0x1019, "S_ANNOTATION"),
    (0x1101, "S_OBJNAME"),
    (0x1102, "S_THUNK32"),
    (0x1103, "S_BLOCK32"),
    (0x1104, "S_WITH32"),
    (0x1105, "S_LABEL32"),
    (0x1106, "S_REGISTER"),
    (0x1107, "S_CONSTANT"),
    (0x1108, "S_UDT"),
    (0x1109, "S_COBOLUDT"),
    (0x110a, "S_MANYREG"),
    (0x110b, "S_BPREL32"),
    (0x110c, "S_LDATA32"),
    (0x110d, "S_GDATA32"),
    (0x110e, "S_PUB32"),
    (0x110f, "S_LPROC32"),
    (0x1110, "S_GPROC32"),
    (0x1111, "S_REGREL32"),
    (0x1112, "S_LTHREAD32"),
    (0x1113, "S_GTHREAD32"),
    (0x1114, "S_SLINK32"),
    (0x1115, "S_LPROCMIPS"),
    (0x1116, "S_COMPILE2"),
    (0x1117, "S_MANYREG2"),
    (0x1118, "S_LPROCIA64"),
    (0x1119, "S_GPROCIA64"),
    (0x111a, "S_LOCALSLOT"),
    (0x111b, "S_PARAMSLOT"),
    (0x111c, "S_LMANDATA"),
    (0x111d, "S_GMANDATA"),
    (0x111e, "S_MANFRAMEREL"),
    (0x111f, "S_MANREGISTER"),
    (0x1120, "S_MANSLOT"),
    (0x1121, "S_MANMANYREG"),
    (0x1122, "S_MANREGREL"),
    (0x1123, "S_MANMANYREG2"),
    (0x1124, "S_UNAMESPACE"),
    (0x1125, "S_PROCREF"),
    (0x1126, "S_DATAREF"),
    (0x1127, "S_LPROCREF"),
    (0x1128, "S_ANNOTATIONREF"),
    (0x1129, "S_TOKENREF"),
    (0x112a, "S_GMANPROC"),
    (0x112b, "S_LMANPROC"),
    (0x112c, "S_TRAMPOLINE"),
    (0x112d, "S_MANCONSTANT"),
    (0x112e, "S_ATTR_FRAMEREL"),
    (0x112f, "S_ATTR_REGISTER"),
    (0x1130, "S_ATTR_REGREL"),
    (0x1131, "S_ATTR_MANYREG"),
    (0x1132, "S_SEPCODE"),
    (0x1133, "S_LOCAL_2005"),
    (0x1134, "S_DEFRANGE_2005"),
    (0x1135, "S_DEFRANGE2_2005"),
    (0x1136, "S_SECTION"),
    (0x1137, "S_COFFGROUP"),
    (0x1138, "S_EXPORT"),
    (0x1139, "S_CALLSITEINFO"),
    (0x113a, "S_FRAMECOOKIE"),
    (0x113b, "S_DISCARDED"),
    (0x113c, "S_COMPILE3"),
    (0x113d, "S_ENVBLOCK"),
    (0x113e, "S_LOCAL"),
    (0x113f, "S_DEFRANGE"),
    (0x1140, "S_DEFRANGE_SUBFIELD"),
    (0x1141, "S_DEFRANGE_REGISTER"),
    (0x1142, "S_DEFRANGE_FRAMEPOINTER_REL"),
    (0x1143, "S_DEFRANGE_SUBFIELD_REGISTER"),
    (0x1144, "S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE"),
    (0x1145, "S_DEFRANGE_REGISTER_REL"),
    (0x1146, "S_LPROC32_ID"),
    (0x1147, "S_GPROC32_ID"),
    (0x1148, "S_LPROCMIPS_ID"),
    (0x1149, "S_GPROCMIPS_ID"),
    (0x114a, "S_LPROCIA64_ID"),
    (0x114b, "S_GPROCIA64_ID"),
    (0x114c, "S_BUILDINFO"),
    (0x114d, "S_INLINESITE"),
    (0x114e, "S_INLINESITE_END"),
    (0x114f, "S_PROC_ID_END"),
    (0x1150, "S_DEFRANGE_HLSL"),
    (0x1151, "S_GDATA_HLSL"),
    (0x1152, "S_LDATA_HLSL"),
    (0x1153, "S_FILESTATIC"),
    (0x1154, "S_LOCAL_DPC_GROUPSHARED"),
    (0x1155, "S_LPROC32_DPC"),
    (0x1156, "S_LPROC32_DPC_ID"),
    (0x1157, "S_DEFRANGE_DPC_PTR_TAG"),
    (0x1158, "S_DPC_SYM_TAG_MAP"),
    (0x1159, "S_ARMSWITCHTABLE"),
    (0x115a, "S_CALLEES"),
    (0x115b, "S_CALLERS"),
    (0x115c, "S_POGODATA"),
    (0x115d, "S_INLINESITE2"),
    (0x115e, "S_HEAPALLOCSITE"),
    (0x115f, "S_MOD_TYPEREF"),
    (0x1160, "S_REF_MINIPDB"),
    (0x1161, "S_PDBMAP"),
    (0x1162, "S_GDATA_HLSL32"),
    (0x1163, "S_LDATA_HLSL32"),
    (0x1164, "S_GDATA_HLSL32_EX"),
    (0x1165, "S_LDATA_HLSL32_EX"),
    (0x1167, "S_FASTLINK"),
    (0x1168, "S_INLINEES"),
    (0x1169, "S_HOTPATCHFUNC"),
];

const LANGUAGES: EnumTable = &[
    (0x00, "C"),
    (0x01, "C++"),
    (0x02, "Fortran"),
    (0x03, "MASM"),
    (0x04, "Pascal"),
    (0x05, "Basic"),
    (0x06, "COBOL"),
    (0x07, "link"),
    (0x08, "cvtres"),
    (0x09, "cvtpgd"),
    (0x0a, "C#"),
    (0x0b, "Visual Basic"),
    (0x0c, "ILASM"),
    (0x0d, "Java"),
    (0x0e, "JScript"),
    (0x0f, "MSIL"),
    (0x10, "HLSL"),
    (0x11, "Objective-C"),
    (0x12, "Objective-C++"),
    (0x13, "Swift"),
    (0x14, "ALIASOBJ"),
    (0x15, "Rust"),
    (0x16, "Go"),
    (0x44, "D"),
];

/// CodeView CPU types (`S_COMPILE*` machine).
const CPU_TYPES: EnumTable = &[
    (0x00, "Intel 8080"),
    (0x01, "Intel 8086"),
    (0x02, "Intel 80286"),
    (0x03, "Intel 80386"),
    (0x04, "Intel 80486"),
    (0x05, "Intel Pentium"),
    (0x06, "Intel Pentium Pro"),
    (0x07, "Intel Pentium III"),
    (0x10, "MIPS"),
    (0x60, "ARM3"),
    (0x61, "ARM4"),
    (0x62, "ARM4T"),
    (0x63, "ARM5"),
    (0x64, "ARM5T"),
    (0x65, "ARM6"),
    (0x66, "ARM (XMAC)"),
    (0x67, "ARM (WMMX)"),
    (0x68, "ARM7"),
    (0x80, "Itanium"),
    (0xd0, "x64"),
    (0xe0, "EBC"),
    (0xf0, "Thumb"),
    (0xf4, "ARMNT"),
    (0xf6, "ARM64"),
    (0xf7, "hybrid x86/ARM64"),
    (0xf8, "ARM64EC"),
    (0xf9, "ARM64X"),
];

const PROC_FLAGS: FlagTable = &[
    flag(0x1, "no FPO"),
    flag(0x2, "interrupt return"),
    flag(0x4, "far return"),
    flag(0x8, "never returns"),
    flag(0x10, "not reached"),
    flag(0x20, "custom calling convention"),
    flag(0x40, "no inline"),
    flag(0x80, "optimized debug info"),
];

const PUBLIC_FLAGS: FlagTable = &[
    flag(0x1, "code"),
    flag(0x2, "function"),
    flag(0x4, "managed"),
    flag(0x8, "MSIL"),
];

const FRAME_FLAGS: FlagTable = &[
    flag(0x1, "has alloca"),
    flag(0x2, "has setjmp"),
    flag(0x4, "has longjmp"),
    flag(0x8, "has inline asm"),
    flag(0x10, "has EH"),
    flag(0x20, "inline"),
    flag(0x40, "has SEH"),
    flag(0x80, "naked"),
    flag(0x100, "security checks"),
    flag(0x200, "async EH"),
    flag(0x400, "no stack ordering"),
    flag(0x800, "inlined"),
    flag(0x1000, "strict security checks"),
    flag(0x2000, "safe buffers"),
    field(0xc000, 0x4000, "local base: stack pointer"),
    field(0xc000, 0x8000, "local base: frame pointer"),
    field(0xc000, 0xc000, "local base: base pointer"),
    field(0x3_0000, 0x1_0000, "parameter base: stack pointer"),
    field(0x3_0000, 0x2_0000, "parameter base: frame pointer"),
    field(0x3_0000, 0x3_0000, "parameter base: base pointer"),
    flag(0x4_0000, "profile guided"),
    flag(0x8_0000, "valid profile counts"),
    flag(0x10_0000, "opt speed"),
    flag(0x20_0000, "guard CF"),
    flag(0x40_0000, "guard CFW"),
];

const LOCAL_FLAGS: FlagTable = &[
    flag(0x1, "parameter"),
    flag(0x2, "address taken"),
    flag(0x4, "compiler generated"),
    flag(0x8, "aggregate"),
    flag(0x10, "part of aggregate"),
    flag(0x20, "aliased"),
    flag(0x40, "alias"),
    flag(0x80, "return value"),
    flag(0x100, "optimized out"),
    flag(0x200, "enregistered global"),
    flag(0x400, "enregistered static"),
];

/// "0001:0000".
fn address(seg: u16, off: u32) -> String {
    format!("{seg:04x}:{off:08x}")
}

/// A `S_DEFRANGE_*` address range and the gaps after it; returns
/// "[0001:00000000,+0x68)" and the gap count.
fn address_range(f: &mut Fields<'_>) -> Result<String> {
    let off = f.u32("Range start").hex().emit()?;
    let seg = f.u16("Range section").emit()?;
    let len = f.u16("Range length").hex().emit()?;
    let mut gaps = 0u32;
    while f.remaining() >= 4 {
        f.u16("Gap start").hex().emit()?;
        f.u16("Gap length").hex().emit()?;
        gaps = gaps.saturating_add(1);
    }
    let mut out = format!("[{},+{len:#x})", address(seg, off));
    if gaps > 0 {
        out.push_str(&format!(", {gaps} gaps"));
    }
    Ok(out)
}

/// Decodes one symbol record (length and kind included); returns its
/// name (empty if it has none) and summary.
pub(super) fn symbol_record(f: &mut Fields<'_>, _: &()) -> Result<(String, String)> {
    let kind = prefix(f, SYMBOL_KINDS)?;
    let out = match kind {
        0x0006 | 0x114e | 0x114f => (String::new(), String::new()),
        0x1101 => {
            f.u32("Signature").hex().emit()?;
            (name(f)?, String::new())
        }
        0x113c | 0x1116 => {
            let flags = f
                .u32("Flags")
                .hex()
                .with(|&v, n| n.summary(name_or(LANGUAGES, (v & 0xff).into(), "language")))
                .emit()?;
            let machine = f.u16("Machine").enumeration(CPU_TYPES).emit()?;
            let parts = if kind == 0x113c { 4 } else { 3 };
            let mut versions = [Vec::new(), Vec::new()];
            for (end, labels) in [
                (
                    0,
                    [
                        "Front end major",
                        "Front end minor",
                        "Front end build",
                        "Front end QFE",
                    ],
                ),
                (
                    1,
                    [
                        "Back end major",
                        "Back end minor",
                        "Back end build",
                        "Back end QFE",
                    ],
                ),
            ] {
                let mut v = Vec::new();
                for label in labels.into_iter().take(parts) {
                    v.push(f.u16(label).emit()?.to_string());
                }
                if let Some(slot) = versions.get_mut(end) {
                    *slot = v;
                }
            }
            let version = f.cstr("Version").emit()?;
            let [_, back] = versions;
            (
                String::new(),
                format!(
                    "{}, {}, {}back end {}",
                    name_or(LANGUAGES, (flags & 0xff).into(), "language"),
                    name_or(CPU_TYPES, machine.into(), "CPU"),
                    if version.is_empty() {
                        String::new()
                    } else {
                        format!("{version}, ")
                    },
                    back.join(".")
                ),
            )
        }
        0x110f | 0x1110 | 0x1146 | 0x1147 => {
            f.u32("Parent").hex().emit()?;
            f.u32("End").hex().emit()?;
            f.u32("Next").hex().emit()?;
            let len = f.u32("Code size").hex().emit()?;
            f.u32("Debug start").hex().emit()?;
            f.u32("Debug end").hex().emit()?;
            if kind >= 0x1146 {
                f.u32("Function ID").hex().emit()?;
            } else {
                ti(f, "Type")?;
            }
            let off = f.u32("Offset").hex().emit()?;
            let seg = f.u16("Segment").emit()?;
            f.u8("Flags").flags(PROC_FLAGS).emit()?;
            (name(f)?, format!("{}, {len:#x} bytes", address(seg, off)))
        }
        0x1102 => {
            f.u32("Parent").hex().emit()?;
            f.u32("End").hex().emit()?;
            f.u32("Next").hex().emit()?;
            let off = f.u32("Offset").hex().emit()?;
            let seg = f.u16("Segment").emit()?;
            let len = f.u16("Length").hex().emit()?;
            f.u8("Ordinal").emit()?;
            (name(f)?, format!("{}, {len:#x} bytes", address(seg, off)))
        }
        0x1103 => {
            f.u32("Parent").hex().emit()?;
            f.u32("End").hex().emit()?;
            let len = f.u32("Code size").hex().emit()?;
            let off = f.u32("Offset").hex().emit()?;
            let seg = f.u16("Segment").emit()?;
            (name(f)?, format!("{}, {len:#x} bytes", address(seg, off)))
        }
        0x1105 => {
            let off = f.u32("Offset").hex().emit()?;
            let seg = f.u16("Segment").emit()?;
            f.u8("Flags").flags(PROC_FLAGS).emit()?;
            (name(f)?, address(seg, off))
        }
        0x1012 => {
            let size = f.u32("Frame size").hex().emit()?;
            f.u32("Padding size").hex().emit()?;
            f.u32("Padding offset").hex().emit()?;
            f.u32("Callee-saved register bytes").hex().emit()?;
            f.u32("Exception handler offset").hex().emit()?;
            f.u16("Exception handler section").emit()?;
            f.u32("Flags").flags(FRAME_FLAGS).emit()?;
            (String::new(), format!("frame {size:#x} bytes"))
        }
        0x1107 | 0x112d => {
            let t = ti(f, "Type")?;
            let v = numeric(f, "Value")?;
            (name(f)?, format!("{} = {v}", type_name(t)))
        }
        0x1108 => {
            let t = ti(f, "Type")?;
            (name(f)?, type_name(t))
        }
        0x110c | 0x110d | 0x1112 | 0x1113 | 0x111c | 0x111d => {
            let t = ti(f, "Type")?;
            let off = f.u32("Offset").hex().emit()?;
            let seg = f.u16("Segment").emit()?;
            (name(f)?, format!("{}, {}", type_name(t), address(seg, off)))
        }
        0x110e => {
            let flags = f.u32("Flags").flags(PUBLIC_FLAGS).emit()?;
            let off = f.u32("Offset").hex().emit()?;
            let seg = f.u16("Segment").emit()?;
            let what = if flags & 2 != 0 { ", function" } else { "" };
            (name(f)?, format!("{}{what}", address(seg, off)))
        }
        0x1125..=0x1127 => {
            f.u32("SUC of name").hex().emit()?;
            let off = f
                .u32("Symbol offset")
                .hex()
                .desc("In the module's symbol stream")
                .emit()?;
            let module = f.u16("Module").desc("1-based").emit()?;
            (name(f)?, format!("module {module}, offset {off:#x}"))
        }
        0x1111 => {
            let off = f.u32("Offset").hex().emit()?;
            let t = ti(f, "Type")?;
            let reg = f.u16("Register").emit()?;
            (
                name(f)?,
                format!("{}, register {reg} + {off:#x}", type_name(t)),
            )
        }
        0x110b => {
            let off = f.i32("Offset").emit()?;
            let t = ti(f, "Type")?;
            (name(f)?, format!("{}, frame {off:+}", type_name(t)))
        }
        0x1106 => {
            let t = ti(f, "Type")?;
            let reg = f.u16("Register").emit()?;
            (name(f)?, format!("{}, register {reg}", type_name(t)))
        }
        0x113e => {
            let t = ti(f, "Type")?;
            f.u16("Flags").flags(LOCAL_FLAGS).emit()?;
            (name(f)?, type_name(t))
        }
        0x114c => {
            let id = f.u32("Build info").hex().desc("An IPI record").emit()?;
            (String::new(), format!("{id:#x}"))
        }
        0x113d => {
            f.u8("Flags").emit()?;
            let mut pairs = 0u32;
            while f.remaining() > 0 {
                let s = f.cstr("String").emit()?;
                if s.is_empty() {
                    break;
                }
                pairs = pairs.saturating_add(1);
            }
            (String::new(), format!("{pairs} strings"))
        }
        0x1136 => {
            let n = f.u16("Section").emit()?;
            f.u8("Alignment").desc("A power of two").emit()?;
            f.u8("Reserved").emit()?;
            let rva = f.u32("RVA").hex().emit()?;
            let len = f.u32("Length").hex().emit()?;
            f.u32("Characteristics")
                .flags(SECTION_CHARACTERISTICS)
                .emit()?;
            (
                name(f)?,
                format!("section {n}, RVA {rva:#x}, {len:#x} bytes"),
            )
        }
        0x1137 => {
            let len = f.u32("Size").hex().emit()?;
            f.u32("Characteristics")
                .flags(SECTION_CHARACTERISTICS)
                .emit()?;
            let off = f.u32("Offset").hex().emit()?;
            let seg = f.u16("Segment").emit()?;
            (name(f)?, format!("{}, {len:#x} bytes", address(seg, off)))
        }
        0x1138 => {
            let ordinal = f.u16("Ordinal").emit()?;
            f.u16("Flags").hex().emit()?;
            (name(f)?, format!("ordinal {ordinal}"))
        }
        0x1139 | 0x115e => {
            let off = f.u32("Offset").hex().emit()?;
            let seg = f.u16("Segment").emit()?;
            if kind == 0x1139 {
                f.u16("Padding").emit()?;
            } else {
                f.u16("Call instruction length").emit()?;
            }
            let t = ti(f, "Type")?;
            (
                String::new(),
                format!("{}, {}", address(seg, off), type_name(t)),
            )
        }
        0x113a => {
            let off = f.i32("Offset").emit()?;
            f.u16("Register").emit()?;
            f.u8("Cookie kind").emit()?;
            f.u8("Flags").emit()?;
            (String::new(), format!("frame {off:+}"))
        }
        0x1124 => (name(f)?, String::new()),
        0x114d => {
            f.u32("Parent").hex().emit()?;
            f.u32("End").hex().emit()?;
            let id = f.u32("Inlinee").hex().desc("An IPI record").emit()?;
            rest(f)?;
            (String::new(), format!("inlinee {id:#x}"))
        }
        0x1141 | 0x1143 => {
            let reg = f.u16("Register").emit()?;
            f.u16("May have no name").emit()?;
            if kind == 0x1143 {
                f.u32("Offset in parent")
                    .with(|&v, n| n.summary(format!("{}", v & 0xfff)))
                    .emit()?;
            }
            let range = address_range(f)?;
            (String::new(), format!("register {reg}, {range}"))
        }
        0x1142 => {
            let off = f.i32("Frame pointer offset").emit()?;
            let range = address_range(f)?;
            (String::new(), format!("frame {off:+}, {range}"))
        }
        0x1144 => {
            let off = f.i32("Frame pointer offset").emit()?;
            (String::new(), format!("frame {off:+}, whole scope"))
        }
        0x1145 => {
            let reg = f.u16("Base register").emit()?;
            f.u16("Flags").hex().emit()?;
            let off = f.i32("Base offset").emit()?;
            let range = address_range(f)?;
            (String::new(), format!("register {reg} {off:+}, {range}"))
        }
        0x1168 | 0x115a | 0x115b => {
            let n = f.u32("Count").emit()?;
            for _ in 0..n {
                if f.remaining() < 4 {
                    break;
                }
                f.u32("Function ID").hex().emit()?;
            }
            (
                String::new(),
                crate::formats::util::arcutil::count(n.into(), "function", "functions"),
            )
        }
        0x112c => {
            f.u16("Type").emit()?;
            f.u16("Thunk size").emit()?;
            f.u32("Thunk offset").hex().emit()?;
            f.u32("Target offset").hex().emit()?;
            f.u16("Thunk section").emit()?;
            f.u16("Target section").emit()?;
            (String::new(), String::new())
        }
        _ => {
            rest(f)?;
            (String::new(), String::new())
        }
    };
    Ok(out)
}

/// The kind and name of the symbol record at `offset` in `stream` (for
/// references from hash tables and module global-reference lists).
pub(super) async fn symbol_at(cx: &Cx, stream: Span, offset: u64) -> Result<(String, String)> {
    let head = cx.read(stream.sub_exact(offset, 4)?).await?;
    let len = u16_le(&head, 0).unwrap_or(0);
    let kind = u16_le(&head, 2).unwrap_or(0);
    let span = stream.sub(offset, u64::from(len).saturating_add(2));
    let block = cx.block(span).await?;
    let (name, _) = symbol_record(&mut Fields::new(&block, LE), &()).unwrap_or_default();
    Ok((name_or(SYMBOL_KINDS, kind.into(), "symbol"), name))
}

// ---------------------------------------------------------------------------
// Record walkers

/// Which records a walker decodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Records {
    /// Type records, numbered from this type index.
    Types(u32),
    /// Symbol records, labelled with their offsets plus this base (module
    /// streams count the 4-byte signature before them).
    Symbols(u64),
}

/// Walks the records of `span`, pushing a node per record.
pub(super) async fn records(cx: Cx, (span, kind): (Span, Records)) -> Result<()> {
    let (mut pos, mut index) = cx.resume::<(u64, u32)>().unwrap_or((0, 0));
    while pos.saturating_add(4) <= span.len {
        let at = (pos, index);
        cx.mark(move || at);
        cx.progress_in(span, pos);
        let head = cx.read(span.sub_exact(pos, 4)?).await?;
        let len = u16_le(&head, 0).unwrap_or(0);
        if len < 2 {
            cx.diag(Diagnostic::malformed(format!("record length {len}")).at(span.sub(pos, 2)));
            break;
        }
        let rec = span.sub(pos, u64::from(len).saturating_add(2));
        let raw = u16_le(&head, 2).unwrap_or(0);
        let node = if cx.skipping() {
            Node::new("record").span(rec)
        } else {
            let data = cx.read(rec).await?;
            let block = Block { span: rec, data };
            match kind {
                Records::Types(first) => {
                    let ti = first.saturating_add(index);
                    let summary =
                        type_record(&mut Fields::new(&block, LE), &()).unwrap_or_default();
                    struct_node(
                        format!("{ti:#x} {}", name_or(TYPE_KINDS, raw.into(), "LF")),
                        rec,
                        LE,
                        (),
                        type_record,
                    )
                    .maybe_summary(summary)
                }
                Records::Symbols(base) => {
                    let (name, summary) =
                        symbol_record(&mut Fields::new(&block, LE), &()).unwrap_or_default();
                    let mut node = struct_node(
                        format!(
                            "{} {}",
                            pos.saturating_add(base),
                            name_or(SYMBOL_KINDS, raw.into(), "S")
                        ),
                        rec,
                        LE,
                        (),
                        symbol_record,
                    );
                    if !name.is_empty() {
                        node = node.value(text(name));
                    }
                    node.maybe_summary(summary)
                }
            }
        };
        cx.push(node).await;
        pos = pos.saturating_add(rec.len);
        index = index.saturating_add(1);
    }
    if pos < span.len && pos.saturating_add(4) > span.len {
        cx.diag(Diagnostic::malformed("trailing bytes after the last record").at(span.tail(pos)));
    }
    Ok(())
}

/// Counts the records of `span` for a summary, reading only their headers
/// (a few thousand at most; `None` beyond that).
pub(super) async fn count_records(cx: &Cx, span: Span) -> Option<u64> {
    let mut pos = 0u64;
    let mut n = 0u64;
    while pos.saturating_add(4) <= span.len {
        if n >= 4096 {
            return None;
        }
        let head = cx.read(span.sub_exact(pos, 4).ok()?).await.ok()?;
        let len = u16_le(&head, 0)?;
        if len < 2 {
            return None;
        }
        pos = pos.saturating_add(u64::from(len)).saturating_add(2);
        n = n.saturating_add(1);
    }
    Some(n)
}

/// "N records" when cheap to count.
pub(super) async fn records_summary(cx: &Cx, span: Span) -> String {
    match count_records(cx, span).await {
        Some(n) => crate::formats::util::arcutil::count(n, "record", "records"),
        None => format!("{} bytes", span.len),
    }
}

// ---------------------------------------------------------------------------
// TPI and IPI streams

/// The TPI/IPI stream header, as far as other streams need it.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct TypeHeader {
    pub header_size: u32,
    pub first: u32,
    pub end: u32,
    pub record_bytes: u32,
    pub hash_stream: u16,
    pub hash_key_size: u32,
    pub hash_values: (u32, u32),
    pub index_offsets: (u32, u32),
    pub hash_adjusters: (u32, u32),
}

const TPI_VERSIONS: EnumTable = &[
    (19_950_410, "V40"),
    (19_951_122, "V41"),
    (19_961_031, "V50"),
    (19_990_903, "V70"),
    (20_040_203, "V80"),
];

pub(super) fn type_header(f: &mut Fields<'_>, _: &()) -> Result<TypeHeader> {
    f.u32("Version").enumeration(TPI_VERSIONS).emit()?;
    let header_size = f.u32("Header size").emit()?;
    let first = f.u32("First type index").hex().emit()?;
    let end = f.u32("End type index").hex().emit()?;
    let record_bytes = f.u32("Type record bytes").emit()?;
    let hash_stream = f.u16("Hash stream").emit()?;
    f.u16("Auxiliary hash stream").emit()?;
    let hash_key_size = f.u32("Hash key size").emit()?;
    f.u32("Hash buckets").emit()?;
    let pair = |f: &mut Fields<'_>, off: &'static str, len: &'static str| -> Result<(u32, u32)> {
        let o = f.u32(off).hex().emit()?;
        let l = f.u32(len).emit()?;
        Ok((o, l))
    };
    let hash_values = pair(f, "Hash values offset", "Hash values size")?;
    let index_offsets = pair(f, "Index offsets offset", "Index offsets size")?;
    let hash_adjusters = pair(f, "Hash adjusters offset", "Hash adjusters size")?;
    Ok(TypeHeader {
        header_size,
        first,
        end,
        record_bytes,
        hash_stream,
        hash_key_size,
        hash_values,
        index_offsets,
        hash_adjusters,
    })
}

/// A TPI or IPI stream: the header and the type records.
pub(super) async fn type_stream(cx: Cx, span: Span) -> Result<()> {
    let header = span.sub(0, 56);
    cx.emit(struct_node("Header", header, LE, (), type_header));
    let block = cx.block(header).await?;
    let h = type_header(&mut Fields::new(&block, LE), &())?;
    let records = span.sub(h.header_size.into(), h.record_bytes.into());
    let count = h.end.saturating_sub(h.first);
    cx.emit(
        Node::new("Type records")
            .span(records)
            .summary(if count == 0 {
                "no records".to_owned()
            } else {
                format!(
                    "{}, {} to {}",
                    crate::formats::util::arcutil::count(count.into(), "record", "records"),
                    type_name(h.first),
                    type_name(h.end.saturating_sub(1))
                )
            })
            .lazy(self::records, (records, Records::Types(h.first))),
    );
    let end = u64::from(h.header_size).saturating_add(h.record_bytes.into());
    if end < span.len {
        cx.emit(Node::new("Trailing data").span(span.tail(end)));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Module streams

/// A module's sizes from its DBI module info.
#[derive(Clone, Debug)]
pub(super) struct ModuleLayout {
    pub symbols: u32,
    pub c11: u32,
    pub c13: u32,
}

const C13_KINDS: EnumTable = &[
    (0xf1, "DEBUG_S_SYMBOLS"),
    (0xf2, "DEBUG_S_LINES"),
    (0xf3, "DEBUG_S_STRINGTABLE"),
    (0xf4, "DEBUG_S_FILECHKSMS"),
    (0xf5, "DEBUG_S_FRAMEDATA"),
    (0xf6, "DEBUG_S_INLINEELINES"),
    (0xf7, "DEBUG_S_CROSSSCOPEIMPORTS"),
    (0xf8, "DEBUG_S_CROSSSCOPEEXPORTS"),
    (0xf9, "DEBUG_S_IL_LINES"),
    (0xfa, "DEBUG_S_FUNC_MDTOKEN_MAP"),
    (0xfb, "DEBUG_S_TYPE_MDTOKEN_MAP"),
    (0xfc, "DEBUG_S_MERGED_ASSEMBLYINPUT"),
    (0xfd, "DEBUG_S_COFF_SYMBOL_RVA"),
];

const CHECKSUM_KINDS: EnumTable = &[(0, "none"), (1, "MD5"), (2, "SHA1"), (3, "SHA256")];

/// What resolving names in a module stream needs.
#[derive(Clone, Copy, Debug)]
pub(super) struct NameTables {
    /// The string buffer of `/names`.
    pub names: Option<Span>,
    /// The symbol record stream (for global references).
    pub symbols: Option<Span>,
}

/// A module stream: signature, symbols, C11 and C13 line information and
/// global references.
pub(super) async fn module_stream(
    cx: Cx,
    (span, m, tables): (Span, ModuleLayout, NameTables),
) -> Result<()> {
    let sig = cx.read_avail(span.sub(0, 4)).await?;
    cx.emit(
        Node::new("Signature")
            .span(span.sub(0, 4))
            .value(uint(u32_le(&sig, 0).unwrap_or(0), 32))
            .desc("4: C13 line information"),
    );
    let symbols = span.sub(4, u64::from(m.symbols).saturating_sub(4));
    let summary = records_summary(&cx, symbols).await;
    cx.emit(
        Node::new("Symbols")
            .span(symbols)
            .summary(summary)
            .lazy(records, (symbols, Records::Symbols(4))),
    );
    let mut at = u64::from(m.symbols);
    if m.c11 > 0 {
        cx.emit(
            Node::new("C11 line information")
                .span(span.sub(at, m.c11.into()))
                .desc("Old-style line numbers (not decoded)"),
        );
    }
    at = at.saturating_add(m.c11.into());
    if m.c13 > 0 {
        let c13 = span.sub(at, m.c13.into());
        cx.emit(
            Node::new("C13 debug subsections")
                .span(c13)
                .lazy(subsections, (c13, tables)),
        );
    }
    at = at.saturating_add(m.c13.into());
    if at.saturating_add(4) <= span.len {
        let size = cx.read(span.sub_exact(at, 4)?).await?;
        let size = u32_le(&size, 0).unwrap_or(0);
        let refs = span.sub(at, u64::from(size).saturating_add(4));
        cx.emit(
            Node::new("Global references")
                .span(refs)
                .summary(format!("{} references", size / 4))
                .lazy(global_refs, (refs.tail(4), tables.symbols)),
        );
    }
    Ok(())
}

async fn global_refs(cx: Cx, (span, symbols): (Span, Option<Span>)) -> Result<()> {
    let n = span.len / 4;
    cx.set_count(Count::Exact(n));
    for i in 0..n {
        let at = span.sub(i.saturating_mul(4), 4);
        let data = cx.read(at).await?;
        let off = u32_le(&data, 0).unwrap_or(0);
        let mut node = Node::new(format!("Reference {i}"))
            .span(at)
            .value(hex(off, 32));
        if let Some(s) = symbols
            && !cx.skipping()
            && let Ok((kind, name)) = symbol_at(&cx, s, off.into()).await
        {
            node = node.summary(format!("{kind} {name}"));
        }
        cx.push(node).await;
    }
    Ok(())
}

/// The C13 subsections of a module: kind, length, data, 4-byte aligned.
async fn subsections(cx: Cx, (span, tables): (Span, NameTables)) -> Result<()> {
    // Line blocks name files by their offset in the checksum subsection.
    let mut checksums = None;
    let mut pos = 0u64;
    let mut list = Vec::new();
    while pos.saturating_add(8) <= span.len {
        cx.checkpoint().await;
        let head = cx.read(span.sub_exact(pos, 8)?).await?;
        let kind = u32_le(&head, 0).unwrap_or(0);
        let len = u32_le(&head, 4).unwrap_or(0);
        let body = span.sub(pos.saturating_add(8), len.into());
        if kind == 0xf4 {
            checksums = Some(body);
        }
        list.push((kind, span.sub(pos, body.len.saturating_add(8)), body));
        pos = pos
            .saturating_add(8)
            .saturating_add(u64::from(len).next_multiple_of(4));
        if list.len() >= 0x10000 {
            break;
        }
    }
    let tables = SubsectionTables {
        names: tables.names,
        checksums,
    };
    for (kind, whole, body) in list {
        let label = name_or(C13_KINDS, (kind & 0x7fff_ffff).into(), "subsection");
        let node = Node::new(label)
            .span(whole)
            .summary(format!("{} bytes", body.len));
        let node = match kind {
            0xf2 => node.lazy(lines, (body, tables)),
            0xf4 => node.lazy(file_checksums, (body, tables)),
            0xf6 => node.lazy(inlinee_lines, (body, tables)),
            0xf3 => node.lazy(crate::formats::util::binutil::cstrings, body),
            0xf1 => node.lazy(records, (body, Records::Symbols(0))),
            _ => node,
        };
        cx.push(node).await;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct SubsectionTables {
    names: Option<Span>,
    checksums: Option<Span>,
}

/// A string in `/names` by offset.
async fn name_at(cx: &Cx, names: Option<Span>, offset: u32) -> Option<String> {
    let (s, _) = crate::formats::util::binutil::string_at(cx, names?, offset.into())
        .await
        .ok()?;
    Some(s)
}

/// The file name a checksum entry (by its offset) refers to.
async fn checksum_file(cx: &Cx, t: SubsectionTables, offset: u32) -> Option<String> {
    let entry = cx
        .read(t.checksums?.sub_exact(offset.into(), 4).ok()?)
        .await
        .ok()?;
    name_at(cx, t.names, u32_le(&entry, 0)?).await
}

async fn file_checksums(cx: Cx, (span, t): (Span, SubsectionTables)) -> Result<()> {
    let mut pos = 0u64;
    while pos.saturating_add(6) <= span.len {
        let head = cx.read(span.sub_exact(pos, 6)?).await?;
        let name = u32_le(&head, 0).unwrap_or(0);
        let size = head.get(4).copied().unwrap_or(0);
        let kind = head.get(5).copied().unwrap_or(0);
        let len = 6u64.saturating_add(size.into());
        let entry = span.sub(pos, len);
        let sum = cx.read_avail(entry.tail(6)).await?;
        let file = name_at(&cx, t.names, name).await.unwrap_or_default();
        let hexsum: String = sum.iter().map(|b| format!("{b:02X}")).collect();
        let node = Node::new(format!("{pos:#x}"))
            .span(entry)
            .value(text(file))
            .summary(format!(
                "{}{}",
                name_or(CHECKSUM_KINDS, kind.into(), "checksum"),
                if hexsum.is_empty() {
                    String::new()
                } else {
                    format!(": {hexsum}")
                }
            ))
            .lazy(checksum_entry, entry);
        cx.push(node).await;
        pos = pos.saturating_add(len.next_multiple_of(4));
    }
    Ok(())
}

async fn checksum_entry(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u32("File name").hex().desc("Offset in /names").emit()?;
    let size = f.u8("Checksum size").emit()?;
    f.u8("Checksum kind").enumeration(CHECKSUM_KINDS).emit()?;
    if size > 0 {
        f.bytes("Checksum", size.into()).emit()?;
    }
    Ok(())
}

/// A `DEBUG_S_LINES` subsection: a header, then blocks of lines per file.
async fn lines(cx: Cx, (span, t): (Span, SubsectionTables)) -> Result<()> {
    let header = span.sub(0, 12);
    let block = cx.block(header).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    let off = f.u32("Offset").hex().emit()?;
    let seg = f.u16("Segment").emit()?;
    let flags = f.u16("Flags").flags(LINE_FLAGS).emit()?;
    let size = f.u32("Code size").hex().emit()?;
    let columns = flags & 1 != 0;
    let mut pos = 12u64;
    while pos.saturating_add(12) <= span.len {
        let head = cx.read(span.sub_exact(pos, 12)?).await?;
        let file = u32_le(&head, 0).unwrap_or(0);
        let n = u32_le(&head, 4).unwrap_or(0);
        let len = u32_le(&head, 8).unwrap_or(0);
        if len < 12 {
            cx.diag(Diagnostic::malformed(format!("line block size {len}")).at(span.sub(pos, 12)));
            break;
        }
        let blk = span.sub(pos, len.into());
        let name = checksum_file(&cx, t, file)
            .await
            .unwrap_or_else(|| format!("file {file:#x}"));
        cx.push(
            Node::new(name)
                .span(blk)
                .summary(format!(
                    "{} in {}+{size:#x}",
                    crate::formats::util::arcutil::count(n.into(), "line", "lines"),
                    address(seg, off)
                ))
                .lazy(line_block, (blk, n, columns)),
        )
        .await;
        pos = pos.saturating_add(len.into());
    }
    Ok(())
}

async fn line_block(cx: Cx, (span, n, columns): (Span, u32, bool)) -> Result<()> {
    let head = cx.block(span.sub(0, 12)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.u32("File")
        .hex()
        .desc("Offset in the checksum subsection")
        .emit()?;
    f.u32("Lines").emit()?;
    f.u32("Block size").emit()?;
    let lines = span.sub(12, u64::from(n).saturating_mul(8));
    let data = cx.read_avail(lines).await?;
    for i in 0..to_u64(data.len()) / 8 {
        let at = to_usize(i.saturating_mul(8));
        let off = u32_le(&data, at).unwrap_or(0);
        let word = u32_le(&data, at.saturating_add(4)).unwrap_or(0);
        let line = word & 0xff_ffff;
        let mut summary = format!("offset {off:#x}");
        if word & 0x8000_0000 == 0 {
            summary.push_str(", expression");
        }
        cx.push(
            Node::new(format!("Line {line}"))
                .span(lines.sub(i.saturating_mul(8), 8))
                .summary(summary),
        )
        .await;
    }
    if columns {
        let cols = span.sub(
            12u64.saturating_add(u64::from(n).saturating_mul(8)),
            u64::from(n).saturating_mul(4),
        );
        cx.push(
            Node::new("Columns")
                .span(cols)
                .summary(format!("{n} entries")),
        )
        .await;
    }
    Ok(())
}

/// A `DEBUG_S_INLINEELINES` subsection.
async fn inlinee_lines(cx: Cx, (span, t): (Span, SubsectionTables)) -> Result<()> {
    let sig = cx.read(span.sub_exact(0, 4)?).await?;
    let extra = u32_le(&sig, 0).unwrap_or(0) == 1;
    cx.push(
        Node::new("Signature")
            .span(span.sub(0, 4))
            .value(uint(u32_le(&sig, 0).unwrap_or(0), 32))
            .desc("1: entries list extra files"),
    )
    .await;
    let mut pos = 4u64;
    while pos.saturating_add(12) <= span.len {
        let head = cx.read(span.sub_exact(pos, 12)?).await?;
        let id = u32_le(&head, 0).unwrap_or(0);
        let file = u32_le(&head, 4).unwrap_or(0);
        let line = u32_le(&head, 8).unwrap_or(0);
        let mut len = 12u64;
        if extra {
            let n = cx.read(span.sub_exact(pos.saturating_add(12), 4)?).await?;
            let n = u32_le(&n, 0).unwrap_or(0);
            len = 16u64.saturating_add(u64::from(n).saturating_mul(4));
        }
        let name = checksum_file(&cx, t, file)
            .await
            .unwrap_or_else(|| format!("file {file:#x}"));
        cx.push(
            Node::new(format!("Inlinee {id:#x}"))
                .span(span.sub(pos, len))
                .summary(format!("{name}:{line}")),
        )
        .await;
        pos = pos.saturating_add(len);
    }
    Ok(())
}

const LINE_FLAGS: FlagTable = &[flag(0x1, "has columns")];
