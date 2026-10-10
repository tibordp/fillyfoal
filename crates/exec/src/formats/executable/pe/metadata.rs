//! ECMA-335 metadata (partition II, 22–24): the metadata root and its
//! streams, the `#~` table stream with every table's rows, and the
//! `#Strings`, `#US`, `#GUID` and `#Blob` heaps; the portable PDB tables
//! (0x30–0x37) and `#Pdb` stream are included (Portable PDB v1.0
//! specification).
//!
//! The model ([`Metadata`]) is parsed once per metadata root and cached:
//! the row counts give every table's row width and offset, from which any
//! row can be read with one small read.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::signature::{self, Piece, SigKind};
use super::{LE, Pe, PeInfo, padding_node};
use crate::bytes::{to_u64, to_usize, u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::Fields;
use crate::formats::util::binutil::{ellipsize, hex_string};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Radix, Value, decode_flags, field, flag, lookup};

const NONE: usize = usize::MAX;

/// A coded index: a tag in the low `bits` bits selecting one of `tables`.
#[derive(Clone, Copy, Debug)]
pub(super) struct CodedIndex {
    pub name: &'static str,
    pub tables: &'static [usize],
    pub bits: u32,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Col {
    U16,
    U32,
    Str,
    Guid,
    Blob(SigKind),
    /// Index into one table.
    Idx(usize),
    Coded(CodedIndex),
}

/// How a column's value is shown.
#[derive(Clone, Copy, Debug)]
pub(super) enum Show {
    Plain,
    Hex,
    Flags(FlagTable),
    Enum(EnumTable),
    Rva,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Column {
    pub name: &'static str,
    pub col: Col,
    pub show: Show,
}

const fn c(name: &'static str, col: Col) -> Column {
    Column {
        name,
        col,
        show: Show::Plain,
    }
}

const fn s(name: &'static str, col: Col, show: Show) -> Column {
    Column { name, col, show }
}

pub(super) const TYPE_DEF_OR_REF: CodedIndex = CodedIndex {
    name: "TypeDefOrRef",
    tables: &[0x02, 0x01, 0x1b],
    bits: 2,
};
const HAS_CONSTANT: CodedIndex = CodedIndex {
    name: "HasConstant",
    tables: &[0x04, 0x08, 0x17],
    bits: 2,
};
const HAS_CUSTOM_ATTRIBUTE: CodedIndex = CodedIndex {
    name: "HasCustomAttribute",
    tables: &[
        0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0a, 0x00, 0x0e, 0x17, 0x14, 0x11, 0x1a, 0x1b, 0x20,
        0x23, 0x26, 0x27, 0x28, 0x2a, 0x2c, 0x2b,
    ],
    bits: 5,
};
const HAS_FIELD_MARSHAL: CodedIndex = CodedIndex {
    name: "HasFieldMarshal",
    tables: &[0x04, 0x08],
    bits: 1,
};
const HAS_DECL_SECURITY: CodedIndex = CodedIndex {
    name: "HasDeclSecurity",
    tables: &[0x02, 0x06, 0x20],
    bits: 2,
};
const MEMBER_REF_PARENT: CodedIndex = CodedIndex {
    name: "MemberRefParent",
    tables: &[0x02, 0x01, 0x1a, 0x06, 0x1b],
    bits: 3,
};
const HAS_SEMANTICS: CodedIndex = CodedIndex {
    name: "HasSemantics",
    tables: &[0x14, 0x17],
    bits: 1,
};
const METHOD_DEF_OR_REF: CodedIndex = CodedIndex {
    name: "MethodDefOrRef",
    tables: &[0x06, 0x0a],
    bits: 1,
};
const MEMBER_FORWARDED: CodedIndex = CodedIndex {
    name: "MemberForwarded",
    tables: &[0x04, 0x06],
    bits: 1,
};
pub(super) const IMPLEMENTATION: CodedIndex = CodedIndex {
    name: "Implementation",
    tables: &[0x26, 0x23, 0x27],
    bits: 2,
};
const CUSTOM_ATTRIBUTE_TYPE: CodedIndex = CodedIndex {
    name: "CustomAttributeType",
    tables: &[NONE, NONE, 0x06, 0x0a, NONE],
    bits: 3,
};
const RESOLUTION_SCOPE: CodedIndex = CodedIndex {
    name: "ResolutionScope",
    tables: &[0x00, 0x1a, 0x23, 0x01],
    bits: 2,
};
const TYPE_OR_METHOD_DEF: CodedIndex = CodedIndex {
    name: "TypeOrMethodDef",
    tables: &[0x02, 0x06],
    bits: 1,
};
const HAS_CUSTOM_DEBUG_INFORMATION: CodedIndex = CodedIndex {
    name: "HasCustomDebugInformation",
    tables: &[
        0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0a, 0x00, 0x0e, 0x17, 0x14, 0x11, 0x1a, 0x1b, 0x20,
        0x23, 0x26, 0x27, 0x28, 0x2a, 0x2c, 0x2b, 0x30, 0x32, 0x33, 0x34, 0x35,
    ],
    bits: 5,
};

const TYPE_ATTRIBUTES: FlagTable = &[
    field(0x7, 0x1, "Public"),
    field(0x7, 0x2, "NestedPublic"),
    field(0x7, 0x3, "NestedPrivate"),
    field(0x7, 0x4, "NestedFamily"),
    field(0x7, 0x5, "NestedAssembly"),
    field(0x7, 0x6, "NestedFamANDAssem"),
    field(0x7, 0x7, "NestedFamORAssem"),
    field(0x18, 0x08, "SequentialLayout"),
    field(0x18, 0x10, "ExplicitLayout"),
    flag(0x20, "Interface"),
    flag(0x80, "Abstract"),
    flag(0x100, "Sealed"),
    flag(0x400, "SpecialName"),
    flag(0x800, "RTSpecialName"),
    flag(0x1000, "Import"),
    flag(0x2000, "Serializable"),
    flag(0x4000, "WindowsRuntime"),
    field(0x30000, 0x10000, "UnicodeClass"),
    field(0x30000, 0x20000, "AutoClass"),
    field(0x30000, 0x30000, "CustomFormatClass"),
    flag(0x40000, "HasSecurity"),
    flag(0x100000, "BeforeFieldInit"),
    flag(0x200000, "Forwarder"),
];

const METHOD_ATTRIBUTES: FlagTable = &[
    field(0x7, 0x1, "Private"),
    field(0x7, 0x2, "FamANDAssem"),
    field(0x7, 0x3, "Assembly"),
    field(0x7, 0x4, "Family"),
    field(0x7, 0x5, "FamORAssem"),
    field(0x7, 0x6, "Public"),
    flag(0x8, "UnmanagedExport"),
    flag(0x10, "Static"),
    flag(0x20, "Final"),
    flag(0x40, "Virtual"),
    flag(0x80, "HideBySig"),
    flag(0x100, "NewSlot"),
    flag(0x200, "Strict"),
    flag(0x400, "Abstract"),
    flag(0x800, "SpecialName"),
    flag(0x1000, "RTSpecialName"),
    flag(0x2000, "PinvokeImpl"),
    flag(0x4000, "HasSecurity"),
    flag(0x8000, "RequireSecObject"),
];

const METHOD_IMPL: FlagTable = &[
    field(0x3, 0x1, "Native"),
    field(0x3, 0x2, "OPTIL"),
    field(0x3, 0x3, "Runtime"),
    flag(0x4, "Unmanaged"),
    flag(0x8, "NoInlining"),
    flag(0x10, "ForwardRef"),
    flag(0x20, "Synchronized"),
    flag(0x40, "NoOptimization"),
    flag(0x80, "PreserveSig"),
    flag(0x100, "AggressiveInlining"),
    flag(0x200, "AggressiveOptimization"),
    flag(0x1000, "InternalCall"),
];

const FIELD_ATTRIBUTES: FlagTable = &[
    field(0x7, 0x1, "Private"),
    field(0x7, 0x2, "FamANDAssem"),
    field(0x7, 0x3, "Assembly"),
    field(0x7, 0x4, "Family"),
    field(0x7, 0x5, "FamORAssem"),
    field(0x7, 0x6, "Public"),
    flag(0x10, "Static"),
    flag(0x20, "InitOnly"),
    flag(0x40, "Literal"),
    flag(0x80, "NotSerialized"),
    flag(0x100, "HasFieldRVA"),
    flag(0x200, "SpecialName"),
    flag(0x400, "RTSpecialName"),
    flag(0x1000, "HasFieldMarshal"),
    flag(0x2000, "PinvokeImpl"),
    flag(0x8000, "HasDefault"),
];

const PARAM_ATTRIBUTES: FlagTable = &[
    flag(0x1, "In"),
    flag(0x2, "Out"),
    flag(0x10, "Optional"),
    flag(0x1000, "HasDefault"),
    flag(0x2000, "HasFieldMarshal"),
];

const SPECIAL_NAME: FlagTable = &[
    flag(0x200, "SpecialName"),
    flag(0x400, "RTSpecialName"),
    flag(0x1000, "HasDefault"),
];

const SEMANTICS: FlagTable = &[
    flag(0x1, "Setter"),
    flag(0x2, "Getter"),
    flag(0x4, "Other"),
    flag(0x8, "AddOn"),
    flag(0x10, "RemoveOn"),
    flag(0x20, "Fire"),
];

const PINVOKE: FlagTable = &[
    flag(0x1, "NoMangle"),
    field(0x6, 0x2, "CharSetAnsi"),
    field(0x6, 0x4, "CharSetUnicode"),
    field(0x6, 0x6, "CharSetAuto"),
    flag(0x40, "SupportsLastError"),
    field(0x700, 0x100, "CallConvWinapi"),
    field(0x700, 0x200, "CallConvCdecl"),
    field(0x700, 0x300, "CallConvStdcall"),
    field(0x700, 0x400, "CallConvThiscall"),
    field(0x700, 0x500, "CallConvFastcall"),
];

const ASSEMBLY_FLAGS: FlagTable = &[
    flag(0x1, "PublicKey"),
    field(0x70, 0x10, "MSIL"),
    field(0x70, 0x20, "x86"),
    field(0x70, 0x30, "IA64"),
    field(0x70, 0x40, "AMD64"),
    field(0x70, 0x50, "ARM"),
    field(0x70, 0x70, "NoPlatform"),
    flag(0x100, "Retargetable"),
    field(0xe00, 0x200, "WindowsRuntime"),
    flag(0x4000, "DisableJITcompileOptimizer"),
    flag(0x8000, "EnableJITcompileTracking"),
];

const HASH_ALGORITHM: EnumTable = &[
    (0, "None"),
    (0x8003, "MD5"),
    (0x8004, "SHA1"),
    (0x800c, "SHA256"),
    (0x800d, "SHA384"),
    (0x800e, "SHA512"),
];

const MANIFEST_RESOURCE_FLAGS: FlagTable = &[field(0x7, 0x1, "Public"), field(0x7, 0x2, "Private")];

const FILE_FLAGS: FlagTable = &[flag(0x1, "ContainsNoMetaData")];

const GENERIC_PARAM: FlagTable = &[
    field(0x3, 0x1, "Covariant"),
    field(0x3, 0x2, "Contravariant"),
    flag(0x4, "ReferenceTypeConstraint"),
    flag(0x8, "NotNullableValueTypeConstraint"),
    flag(0x10, "DefaultConstructorConstraint"),
];

const SECURITY_ACTION: EnumTable = &[
    (1, "Request"),
    (2, "Demand"),
    (3, "Assert"),
    (4, "Deny"),
    (5, "PermitOnly"),
    (6, "LinkDemand"),
    (7, "InheritanceDemand"),
    (8, "RequestMinimum"),
    (9, "RequestOptional"),
    (10, "RequestRefuse"),
    (11, "PrereqAssert"),
    (12, "PrereqDeny"),
    (13, "NonCasDemand"),
    (14, "NonCasLinkDemand"),
];

pub(super) const ELEMENT_TYPES: EnumTable = &[
    (0x01, "void"),
    (0x02, "bool"),
    (0x03, "char"),
    (0x04, "int8"),
    (0x05, "uint8"),
    (0x06, "int16"),
    (0x07, "uint16"),
    (0x08, "int32"),
    (0x09, "uint32"),
    (0x0a, "int64"),
    (0x0b, "uint64"),
    (0x0c, "float32"),
    (0x0d, "float64"),
    (0x0e, "string"),
    (0x12, "class"),
    (0x1c, "object"),
];

use Col::*;
use SigKind as K;

const MODULE: &[Column] = &[
    c("Generation", U16),
    c("Name", Str),
    c("Mvid", Guid),
    c("EncId", Guid),
    c("EncBaseId", Guid),
];
const TYPE_REF: &[Column] = &[
    c("ResolutionScope", Coded(RESOLUTION_SCOPE)),
    c("TypeName", Str),
    c("TypeNamespace", Str),
];
const TYPE_DEF: &[Column] = &[
    s("Flags", U32, Show::Flags(TYPE_ATTRIBUTES)),
    c("TypeName", Str),
    c("TypeNamespace", Str),
    c("Extends", Coded(TYPE_DEF_OR_REF)),
    c("FieldList", Idx(0x04)),
    c("MethodList", Idx(0x06)),
];
const FIELD: &[Column] = &[
    s("Flags", U16, Show::Flags(FIELD_ATTRIBUTES)),
    c("Name", Str),
    c("Signature", Blob(K::Field)),
];
const METHOD_DEF: &[Column] = &[
    s("RVA", U32, Show::Rva),
    s("ImplFlags", U16, Show::Flags(METHOD_IMPL)),
    s("Flags", U16, Show::Flags(METHOD_ATTRIBUTES)),
    c("Name", Str),
    c("Signature", Blob(K::Method)),
    c("ParamList", Idx(0x08)),
];
const PARAM: &[Column] = &[
    s("Flags", U16, Show::Flags(PARAM_ATTRIBUTES)),
    c("Sequence", U16),
    c("Name", Str),
];
const INTERFACE_IMPL: &[Column] = &[
    c("Class", Idx(0x02)),
    c("Interface", Coded(TYPE_DEF_OR_REF)),
];
const MEMBER_REF: &[Column] = &[
    c("Class", Coded(MEMBER_REF_PARENT)),
    c("Name", Str),
    c("Signature", Blob(K::MemberRef)),
];
const CONSTANT: &[Column] = &[
    s("Type", U16, Show::Enum(ELEMENT_TYPES)),
    c("Parent", Coded(HAS_CONSTANT)),
    c("Value", Blob(K::Constant)),
];
const CUSTOM_ATTRIBUTE: &[Column] = &[
    c("Parent", Coded(HAS_CUSTOM_ATTRIBUTE)),
    c("Type", Coded(CUSTOM_ATTRIBUTE_TYPE)),
    c("Value", Blob(K::CustomAttribute)),
];
const FIELD_MARSHAL: &[Column] = &[
    c("Parent", Coded(HAS_FIELD_MARSHAL)),
    c("NativeType", Blob(K::Marshal)),
];
const DECL_SECURITY: &[Column] = &[
    s("Action", U16, Show::Enum(SECURITY_ACTION)),
    c("Parent", Coded(HAS_DECL_SECURITY)),
    c("PermissionSet", Blob(K::Permission)),
];
const CLASS_LAYOUT: &[Column] = &[
    c("PackingSize", U16),
    c("ClassSize", U32),
    c("Parent", Idx(0x02)),
];
const FIELD_LAYOUT: &[Column] = &[c("Offset", U32), c("Field", Idx(0x04))];
const STAND_ALONE_SIG: &[Column] = &[c("Signature", Blob(K::StandAlone))];
const EVENT_MAP: &[Column] = &[c("Parent", Idx(0x02)), c("EventList", Idx(0x14))];
const EVENT_PTR: &[Column] = &[c("Event", Idx(0x14))];
const EVENT: &[Column] = &[
    s("EventFlags", U16, Show::Flags(SPECIAL_NAME)),
    c("Name", Str),
    c("EventType", Coded(TYPE_DEF_OR_REF)),
];
const PROPERTY_MAP: &[Column] = &[c("Parent", Idx(0x02)), c("PropertyList", Idx(0x17))];
const PROPERTY_PTR: &[Column] = &[c("Property", Idx(0x17))];
const PROPERTY: &[Column] = &[
    s("Flags", U16, Show::Flags(SPECIAL_NAME)),
    c("Name", Str),
    c("Type", Blob(K::Property)),
];
const METHOD_SEMANTICS: &[Column] = &[
    s("Semantics", U16, Show::Flags(SEMANTICS)),
    c("Method", Idx(0x06)),
    c("Association", Coded(HAS_SEMANTICS)),
];
const METHOD_IMPL_TABLE: &[Column] = &[
    c("Class", Idx(0x02)),
    c("MethodBody", Coded(METHOD_DEF_OR_REF)),
    c("MethodDeclaration", Coded(METHOD_DEF_OR_REF)),
];
const MODULE_REF: &[Column] = &[c("Name", Str)];
const TYPE_SPEC: &[Column] = &[c("Signature", Blob(K::TypeSpec))];
const IMPL_MAP: &[Column] = &[
    s("MappingFlags", U16, Show::Flags(PINVOKE)),
    c("MemberForwarded", Coded(MEMBER_FORWARDED)),
    c("ImportName", Str),
    c("ImportScope", Idx(0x1a)),
];
const FIELD_RVA: &[Column] = &[s("RVA", U32, Show::Rva), c("Field", Idx(0x04))];
const ENC_LOG: &[Column] = &[s("Token", U32, Show::Hex), c("FuncCode", U32)];
const ENC_MAP: &[Column] = &[s("Token", U32, Show::Hex)];
const ASSEMBLY: &[Column] = &[
    s("HashAlgId", U32, Show::Enum(HASH_ALGORITHM)),
    c("MajorVersion", U16),
    c("MinorVersion", U16),
    c("BuildNumber", U16),
    c("RevisionNumber", U16),
    s("Flags", U32, Show::Flags(ASSEMBLY_FLAGS)),
    c("PublicKey", Blob(K::Bytes)),
    c("Name", Str),
    c("Culture", Str),
];
const ASSEMBLY_PROCESSOR: &[Column] = &[c("Processor", U32)];
const ASSEMBLY_OS: &[Column] = &[
    c("OSPlatformID", U32),
    c("OSMajorVersion", U32),
    c("OSMinorVersion", U32),
];
const ASSEMBLY_REF: &[Column] = &[
    c("MajorVersion", U16),
    c("MinorVersion", U16),
    c("BuildNumber", U16),
    c("RevisionNumber", U16),
    s("Flags", U32, Show::Flags(ASSEMBLY_FLAGS)),
    c("PublicKeyOrToken", Blob(K::Bytes)),
    c("Name", Str),
    c("Culture", Str),
    c("HashValue", Blob(K::Bytes)),
];
const ASSEMBLY_REF_PROCESSOR: &[Column] = &[c("Processor", U32), c("AssemblyRef", Idx(0x23))];
const ASSEMBLY_REF_OS: &[Column] = &[
    c("OSPlatformId", U32),
    c("OSMajorVersion", U32),
    c("OSMinorVersion", U32),
    c("AssemblyRef", Idx(0x23)),
];
const FILE: &[Column] = &[
    s("Flags", U32, Show::Flags(FILE_FLAGS)),
    c("Name", Str),
    c("HashValue", Blob(K::Bytes)),
];
const EXPORTED_TYPE: &[Column] = &[
    s("Flags", U32, Show::Flags(TYPE_ATTRIBUTES)),
    s("TypeDefId", U32, Show::Hex),
    c("TypeName", Str),
    c("TypeNamespace", Str),
    c("Implementation", Coded(IMPLEMENTATION)),
];
const MANIFEST_RESOURCE: &[Column] = &[
    s("Offset", U32, Show::Hex),
    s("Flags", U32, Show::Flags(MANIFEST_RESOURCE_FLAGS)),
    c("Name", Str),
    c("Implementation", Coded(IMPLEMENTATION)),
];
const NESTED_CLASS: &[Column] = &[c("NestedClass", Idx(0x02)), c("EnclosingClass", Idx(0x02))];
const GENERIC_PARAM_TABLE: &[Column] = &[
    c("Number", U16),
    s("Flags", U16, Show::Flags(GENERIC_PARAM)),
    c("Owner", Coded(TYPE_OR_METHOD_DEF)),
    c("Name", Str),
];
const METHOD_SPEC: &[Column] = &[
    c("Method", Coded(METHOD_DEF_OR_REF)),
    c("Instantiation", Blob(K::MethodSpec)),
];
const GENERIC_PARAM_CONSTRAINT: &[Column] = &[
    c("Owner", Idx(0x2a)),
    c("Constraint", Coded(TYPE_DEF_OR_REF)),
];
const DOCUMENT: &[Column] = &[
    c("Name", Blob(K::DocumentName)),
    c("HashAlgorithm", Guid),
    c("Hash", Blob(K::Bytes)),
    c("Language", Guid),
];
const METHOD_DEBUG_INFORMATION: &[Column] = &[
    c("Document", Idx(0x30)),
    c("SequencePoints", Blob(K::Bytes)),
];
const LOCAL_SCOPE: &[Column] = &[
    c("Method", Idx(0x06)),
    c("ImportScope", Idx(0x35)),
    c("VariableList", Idx(0x33)),
    c("ConstantList", Idx(0x34)),
    s("StartOffset", U32, Show::Hex),
    c("Length", U32),
];
const LOCAL_VARIABLE: &[Column] = &[c("Attributes", U16), c("Index", U16), c("Name", Str)];
const LOCAL_CONSTANT: &[Column] = &[c("Name", Str), c("Signature", Blob(K::Bytes))];
const IMPORT_SCOPE: &[Column] = &[c("Parent", Idx(0x35)), c("Imports", Blob(K::Bytes))];
const STATE_MACHINE_METHOD: &[Column] = &[
    c("MoveNextMethod", Idx(0x06)),
    c("KickoffMethod", Idx(0x06)),
];
const CUSTOM_DEBUG_INFORMATION: &[Column] = &[
    c("Parent", Coded(HAS_CUSTOM_DEBUG_INFORMATION)),
    c("Kind", Guid),
    c("Value", Blob(K::Bytes)),
];

const FIELD_PTR: &[Column] = &[c("Field", Idx(0x04))];
const METHOD_PTR: &[Column] = &[c("Method", Idx(0x06))];
const PARAM_PTR: &[Column] = &[c("Param", Idx(0x08))];

/// Names and columns of the tables, by number.
pub(super) fn schema(table: usize) -> Option<(&'static str, &'static [Column])> {
    Some(match table {
        0x00 => ("Module", MODULE),
        0x01 => ("TypeRef", TYPE_REF),
        0x02 => ("TypeDef", TYPE_DEF),
        0x03 => ("FieldPtr", FIELD_PTR),
        0x04 => ("Field", FIELD),
        0x05 => ("MethodPtr", METHOD_PTR),
        0x06 => ("MethodDef", METHOD_DEF),
        0x07 => ("ParamPtr", PARAM_PTR),
        0x08 => ("Param", PARAM),
        0x09 => ("InterfaceImpl", INTERFACE_IMPL),
        0x0a => ("MemberRef", MEMBER_REF),
        0x0b => ("Constant", CONSTANT),
        0x0c => ("CustomAttribute", CUSTOM_ATTRIBUTE),
        0x0d => ("FieldMarshal", FIELD_MARSHAL),
        0x0e => ("DeclSecurity", DECL_SECURITY),
        0x0f => ("ClassLayout", CLASS_LAYOUT),
        0x10 => ("FieldLayout", FIELD_LAYOUT),
        0x11 => ("StandAloneSig", STAND_ALONE_SIG),
        0x12 => ("EventMap", EVENT_MAP),
        0x13 => ("EventPtr", EVENT_PTR),
        0x14 => ("Event", EVENT),
        0x15 => ("PropertyMap", PROPERTY_MAP),
        0x16 => ("PropertyPtr", PROPERTY_PTR),
        0x17 => ("Property", PROPERTY),
        0x18 => ("MethodSemantics", METHOD_SEMANTICS),
        0x19 => ("MethodImpl", METHOD_IMPL_TABLE),
        0x1a => ("ModuleRef", MODULE_REF),
        0x1b => ("TypeSpec", TYPE_SPEC),
        0x1c => ("ImplMap", IMPL_MAP),
        0x1d => ("FieldRVA", FIELD_RVA),
        0x1e => ("EncLog", ENC_LOG),
        0x1f => ("EncMap", ENC_MAP),
        0x20 => ("Assembly", ASSEMBLY),
        0x21 => ("AssemblyProcessor", ASSEMBLY_PROCESSOR),
        0x22 => ("AssemblyOS", ASSEMBLY_OS),
        0x23 => ("AssemblyRef", ASSEMBLY_REF),
        0x24 => ("AssemblyRefProcessor", ASSEMBLY_REF_PROCESSOR),
        0x25 => ("AssemblyRefOS", ASSEMBLY_REF_OS),
        0x26 => ("File", FILE),
        0x27 => ("ExportedType", EXPORTED_TYPE),
        0x28 => ("ManifestResource", MANIFEST_RESOURCE),
        0x29 => ("NestedClass", NESTED_CLASS),
        0x2a => ("GenericParam", GENERIC_PARAM_TABLE),
        0x2b => ("MethodSpec", METHOD_SPEC),
        0x2c => ("GenericParamConstraint", GENERIC_PARAM_CONSTRAINT),
        0x30 => ("Document", DOCUMENT),
        0x31 => ("MethodDebugInformation", METHOD_DEBUG_INFORMATION),
        0x32 => ("LocalScope", LOCAL_SCOPE),
        0x33 => ("LocalVariable", LOCAL_VARIABLE),
        0x34 => ("LocalConstant", LOCAL_CONSTANT),
        0x35 => ("ImportScope", IMPORT_SCOPE),
        0x36 => ("StateMachineMethod", STATE_MACHINE_METHOD),
        0x37 => ("CustomDebugInformation", CUSTOM_DEBUG_INFORMATION),
        _ => return None,
    })
}

pub(super) fn table_name(table: usize) -> String {
    schema(table).map_or_else(|| format!("Table {table:#04x}"), |(n, _)| n.to_owned())
}

// ---------------------------------------------------------------------------
// Model

#[derive(Clone, Debug)]
pub(super) struct Stream {
    pub name: String,
    /// The stream header in the metadata root.
    pub header: Span,
    pub data: Span,
}

pub(super) struct Metadata {
    pub version: String,
    /// Length of the fixed header including the padded version string.
    pub header_len: u64,
    pub streams: Vec<Stream>,
    pub tables: Option<Span>,
    pub strings: Option<Span>,
    pub guid: Option<Span>,
    pub blob: Option<Span>,
    pub pdb: Option<Span>,
    pub heaps: u8,
    pub valid: u64,
    pub sorted: u64,
    pub rows: [u32; 64],
    /// Row counts used for index sizes: our own, or the type system's
    /// (from `#Pdb`) in a portable PDB.
    pub size_rows: [u32; 64],
    /// Offset of each table in the table stream, if it could be sized.
    pub offsets: [Option<u64>; 64],
    pub widths: [u64; 64],
    /// Offset of the first table (after the row counts).
    pub data_start: u64,
}

impl Metadata {
    fn col_size(&self, col: Col) -> u64 {
        let wide = |b: bool| if b { 4u64 } else { 2 };
        let rows = |t: usize| self.size_rows.get(t).copied().unwrap_or(0);
        match col {
            U16 => 2,
            U32 => 4,
            Str => wide(self.heaps & 0x01 != 0),
            Guid => wide(self.heaps & 0x02 != 0),
            Blob(_) => wide(self.heaps & 0x04 != 0),
            Idx(t) => wide(rows(t) > 0xffff),
            Coded(coded) => {
                let max = coded
                    .tables
                    .iter()
                    .map(|&t| if t == NONE { 0 } else { rows(t) })
                    .max()
                    .unwrap_or(0);
                wide(u64::from(max) >= 1u64 << 16u32.saturating_sub(coded.bits))
            }
        }
    }

    pub fn row_count(&self, table: usize) -> u32 {
        self.rows.get(table).copied().unwrap_or(0)
    }

    /// The span of row `row` (1-based) of `table`.
    pub fn row_span(&self, table: usize, row: u32) -> Option<Span> {
        if row == 0 || row > self.row_count(table) {
            return None;
        }
        let offset = (*self.offsets.get(table)?)?;
        let width = *self.widths.get(table)?;
        let at = offset.saturating_add(u64::from(row.saturating_sub(1)).saturating_mul(width));
        self.tables?.sub_exact(at, width).ok()
    }

    /// The span of a whole table.
    pub fn table_span(&self, table: usize) -> Option<Span> {
        let offset = (*self.offsets.get(table)?)?;
        let width = *self.widths.get(table)?;
        self.tables?
            .sub_exact(
                offset,
                u64::from(self.row_count(table)).saturating_mul(width),
            )
            .ok()
    }

    /// `(offset in row, size)` of each column of `table`.
    pub fn layout(&self, table: usize) -> Vec<(Column, u64, u64)> {
        let mut out = Vec::new();
        let mut at = 0u64;
        if let Some((_, cols)) = schema(table) {
            for &col in cols {
                let size = self.col_size(col.col);
                out.push((col, at, size));
                at = at.saturating_add(size);
            }
        }
        out
    }

    /// The raw bytes of a row.
    pub async fn row(&self, cx: &Cx, table: usize, row: u32) -> Option<Vec<u8>> {
        cx.read(self.row_span(table, row)?).await.ok()
    }

    /// Column `index` of a row read with [`Metadata::row`].
    pub fn cell(&self, table: usize, data: &[u8], index: usize) -> u32 {
        let Some((_, at, size)) = self.layout(table).get(index).copied() else {
            return 0;
        };
        let at = to_usize(at);
        if size == 2 {
            u16_le(data, at).map_or(0, u32::from)
        } else {
            u32_le(data, at).unwrap_or(0)
        }
    }

    pub async fn string(&self, cx: &Cx, index: u32) -> String {
        let Some(heap) = self.strings else {
            return String::new();
        };
        if u64::from(index) >= heap.len {
            return format!("<string {index:#x}>");
        }
        cx.cstr(heap.tail(index.into()).sub(0, 1024))
            .await
            .map(|(s, _)| s)
            .unwrap_or_default()
    }

    /// A blob's span (without its length prefix) and the prefix's length.
    pub async fn blob(&self, cx: &Cx, index: u32) -> Option<(Span, u64)> {
        let heap = self.blob?;
        blob_at(cx, heap, index.into()).await
    }

    pub async fn blob_bytes(&self, cx: &Cx, index: u32, max: u64) -> Option<Vec<u8>> {
        let (span, _) = self.blob(cx, index).await?;
        cx.read(span.sub(0, max)).await.ok()
    }

    pub async fn guid(&self, cx: &Cx, index: u32) -> Option<crate::value::Guid> {
        if index == 0 {
            return None;
        }
        let heap = self.guid?;
        let span = heap
            .sub_exact(u64::from(index.saturating_sub(1)).saturating_mul(16), 16)
            .ok()?;
        let block = cx.block(span).await.ok()?;
        Fields::new(&block, LE).guid("Guid").get().ok()
    }

    /// "Namespace.Name" of a TypeDef or TypeRef row, or a decoded TypeSpec.
    pub async fn type_name(&self, cx: &Cx, table: usize, row: u32) -> String {
        match table {
            0x01 | 0x02 => self.def_ref_name(cx, table, row).await,
            0x1b => {
                let Some(data) = self.row(cx, table, row).await else {
                    return format!("TypeSpec #{row}");
                };
                let blob = self.cell(table, &data, 0);
                match self.blob_bytes(cx, blob, 4096).await {
                    Some(bytes) => {
                        let pieces = signature::decode(&bytes, K::TypeSpec);
                        self.render_shallow(cx, &pieces).await
                    }
                    None => format!("TypeSpec #{row}"),
                }
            }
            _ => format!("{} #{row}", table_name(table)),
        }
    }

    /// "Namespace.Name" of a TypeDef or TypeRef row.
    async fn def_ref_name(&self, cx: &Cx, table: usize, row: u32) -> String {
        match table {
            0x01 | 0x02 => {
                let Some(data) = self.row(cx, table, row).await else {
                    return format!("{} #{row}", table_name(table));
                };
                // TypeName and TypeNamespace are columns 1 and 2 of both.
                let (name, ns) = (self.cell(table, &data, 1), self.cell(table, &data, 2));
                let name = self.string(cx, name).await;
                let ns = self.string(cx, ns).await;
                if ns.is_empty() {
                    name
                } else {
                    format!("{ns}.{name}")
                }
            }
            0x1b => format!("TypeSpec #{row}"),
            _ => format!("{} #{row}", table_name(table)),
        }
    }

    /// Renders signature pieces, naming TypeDefs and TypeRefs (TypeSpecs
    /// nested in a signature are shown by number).
    async fn render_shallow(&self, cx: &Cx, pieces: &[Piece]) -> String {
        let mut out = String::new();
        for p in pieces {
            match p {
                Piece::Text(t) => out.push_str(t),
                Piece::Type(t, row) => out.push_str(&self.def_ref_name(cx, *t, *row).await),
            }
        }
        out
    }

    /// Renders signature pieces with every type named.
    pub async fn render(&self, cx: &Cx, pieces: &[Piece]) -> String {
        let mut out = String::new();
        for (i, p) in pieces.iter().enumerate() {
            if i.is_multiple_of(256) {
                cx.checkpoint().await;
            }
            match p {
                Piece::Text(t) => out.push_str(t),
                Piece::Type(t, row) => out.push_str(&self.type_name(cx, *t, *row).await),
            }
        }
        out
    }

    /// A short label for a row: its name, or what it relates.
    pub async fn row_label(&self, cx: &Cx, table: usize, row: u32) -> String {
        let Some(data) = self.row(cx, table, row).await else {
            return String::new();
        };
        let name_col = self
            .layout(table)
            .iter()
            .position(|(col, _, _)| matches!(col.col, Str) && col.name.ends_with("Name"));
        match table {
            0x01 | 0x02 | 0x1b => self.type_name(cx, table, row).await,
            0x06 | 0x04 | 0x0a => {
                let name = self
                    .string(
                        cx,
                        self.cell(table, &data, if table == 0x06 { 3 } else { 1 }),
                    )
                    .await;
                let parent = if table == 0x0a {
                    let class = self.cell(table, &data, 0);
                    match decode_coded(MEMBER_REF_PARENT, class) {
                        Some((t, r)) if matches!(t, 0x01 | 0x02) => {
                            format!("{}::", self.type_name(cx, t, r).await)
                        }
                        _ => String::new(),
                    }
                } else {
                    String::new()
                };
                format!("{parent}{name}")
            }
            0x0c => {
                let ty = self.cell(table, &data, 1);
                match decode_coded(CUSTOM_ATTRIBUTE_TYPE, ty) {
                    Some((0x0a, r)) => self.member_parent_name(cx, r).await,
                    Some((0x06, r)) => self.method_owner_name(cx, r).await,
                    _ => String::new(),
                }
            }
            0x20 | 0x23 => {
                let (major, minor, build, rev, name) = if table == 0x20 {
                    (
                        self.cell(table, &data, 1),
                        self.cell(table, &data, 2),
                        self.cell(table, &data, 3),
                        self.cell(table, &data, 4),
                        self.cell(table, &data, 7),
                    )
                } else {
                    (
                        self.cell(table, &data, 0),
                        self.cell(table, &data, 1),
                        self.cell(table, &data, 2),
                        self.cell(table, &data, 3),
                        self.cell(table, &data, 6),
                    )
                };
                format!(
                    "{} {major}.{minor}.{build}.{rev}",
                    self.string(cx, name).await
                )
            }
            _ => match name_col {
                Some(i) => self.string(cx, self.cell(table, &data, i)).await,
                None => String::new(),
            },
        }
    }

    /// The type that declares MemberRef `row` (for custom attribute
    /// constructors: the attribute's type).
    async fn member_parent_name(&self, cx: &Cx, row: u32) -> String {
        let Some(data) = self.row(cx, 0x0a, row).await else {
            return String::new();
        };
        match decode_coded(MEMBER_REF_PARENT, self.cell(0x0a, &data, 0)) {
            Some((t, r)) => self.type_name(cx, t, r).await,
            None => String::new(),
        }
    }

    /// The TypeDef that owns MethodDef `row` (by the MethodList ranges).
    async fn method_owner_name(&self, cx: &Cx, row: u32) -> String {
        let types = self.row_count(0x02);
        let mut owner = 0u32;
        for t in 1..=types.min(65536) {
            if t.is_multiple_of(256) {
                cx.checkpoint().await;
            }
            let Some(data) = self.row(cx, 0x02, t).await else {
                break;
            };
            if self.cell(0x02, &data, 5) <= row {
                owner = t;
            } else {
                break;
            }
        }
        if owner == 0 {
            String::new()
        } else {
            self.type_name(cx, 0x02, owner).await
        }
    }

    /// The name of the target of a coded or simple index value.
    pub async fn target_label(&self, cx: &Cx, table: usize, row: u32) -> String {
        if row == 0 {
            return "null".to_owned();
        }
        let label = self.row_label(cx, table, row).await;
        if label.is_empty() {
            format!("{} #{row}", table_name(table))
        } else {
            format!("{} #{row} ({label})", table_name(table))
        }
    }
}

/// Decodes a coded index into `(table, row)`.
pub(super) fn decode_coded(coded: CodedIndex, value: u32) -> Option<(usize, u32)> {
    let mask = (1u32 << coded.bits).saturating_sub(1);
    let tag = usize::try_from(value & mask).ok()?;
    let table = *coded.tables.get(tag)?;
    if table == NONE {
        return None;
    }
    Some((table, value >> coded.bits))
}

/// Decodes an ECMA-335 compressed unsigned integer: `(value, length)`.
pub(super) fn compressed(data: &[u8]) -> Option<(u32, usize)> {
    let b0 = u32::from(*data.first()?);
    if b0 & 0x80 == 0 {
        Some((b0, 1))
    } else if b0 & 0xc0 == 0x80 {
        Some((((b0 & 0x3f) << 8) | u32::from(*data.get(1)?), 2))
    } else if b0 & 0xe0 == 0xc0 {
        Some((
            ((b0 & 0x1f) << 24)
                | (u32::from(*data.get(1)?) << 16)
                | (u32::from(*data.get(2)?) << 8)
                | u32::from(*data.get(3)?),
            4,
        ))
    } else {
        None
    }
}

/// A blob in `heap` at `offset`: its data span and prefix length.
pub(super) async fn blob_at(cx: &Cx, heap: Span, offset: u64) -> Option<(Span, u64)> {
    if offset >= heap.len {
        return None;
    }
    let head = cx.read_avail(heap.sub(offset, 4)).await.ok()?;
    let (len, used) = compressed(&head)?;
    let used = to_u64(used);
    Some((heap.sub(offset.saturating_add(used), len.into()), used))
}

/// Parses the metadata root at `root` (cached per root).
pub(super) async fn load(cx: &Cx, root: Span) -> Result<Arc<Metadata>> {
    if let Some(m) = cx.cached::<Metadata>(root, "clr-metadata") {
        return Ok(m);
    }
    let head = cx.read(root.sub(0, 16)).await?;
    if head.get(..4) != Some(b"BSJB") {
        return Err(Diagnostic::malformed("metadata root signature is not BSJB").at(root.sub(0, 4)));
    }
    let version_len = u64::from(u32_le(&head, 12).unwrap_or(0)).min(256);
    let (version, _) = cx.cstr(root.sub(16, version_len)).await?;
    let at = 16u64.saturating_add(version_len);
    let counts = cx.read(root.sub(at, 4)).await?;
    let count = u16_le(&counts, 2).unwrap_or(0);
    let mut pos = at.saturating_add(4);
    let mut streams = Vec::new();
    for _ in 0..count.min(64) {
        let h = cx.read(root.sub(pos, 8)).await?;
        let offset = u64::from(u32_le(&h, 0).unwrap_or(0));
        let size = u64::from(u32_le(&h, 4).unwrap_or(0));
        let (name, name_span) = cx.cstr(root.sub(pos.saturating_add(8), 32)).await?;
        let header_len = 8u64.saturating_add(name_span.len.next_multiple_of(4));
        streams.push(Stream {
            name,
            header: root.sub(pos, header_len),
            data: root.sub(offset, size),
        });
        pos = pos.saturating_add(header_len);
    }
    let find = |names: &[&str]| {
        streams
            .iter()
            .find(|s| names.contains(&s.name.as_str()))
            .map(|s| s.data)
    };
    let mut md = Metadata {
        version,
        header_len: at.saturating_add(4),
        tables: find(&["#~", "#-"]),
        strings: find(&["#Strings"]),
        guid: find(&["#GUID"]),
        blob: find(&["#Blob"]),
        pdb: find(&["#Pdb"]),
        streams,
        heaps: 0,
        valid: 0,
        sorted: 0,
        rows: [0; 64],
        size_rows: [0; 64],
        offsets: [None; 64],
        widths: [0; 64],
        data_start: 0,
    };
    if let Some(tables) = md.tables {
        let header = cx.read(tables.sub(0, 24)).await?;
        md.heaps = header.get(6).copied().unwrap_or(0);
        md.valid = u64_le(&header, 8).unwrap_or(0);
        md.sorted = u64_le(&header, 16).unwrap_or(0);
        let present = u64::from(md.valid.count_ones());
        let counts = cx
            .read(tables.sub_exact(24, present.saturating_mul(4))?)
            .await?;
        let mut i = 0usize;
        for t in 0..64usize {
            if md.valid & (1u64 << t) != 0 {
                if let Some(slot) = md.rows.get_mut(t) {
                    *slot = u32_le(&counts, i.saturating_mul(4)).unwrap_or(0);
                }
                i = i.saturating_add(1);
            }
        }
        md.size_rows = md.rows;
        // A portable PDB sizes indices into the type system tables by the
        // row counts recorded in #Pdb.
        if let Some(pdb) = md.pdb {
            let head = cx.read_avail(pdb.sub(0, 32)).await?;
            let referenced = u64_le(&head, 24).unwrap_or(0);
            let n = u64::from(referenced.count_ones());
            let ext = cx.read_avail(pdb.sub(32, n.saturating_mul(4))).await?;
            let mut i = 0usize;
            for t in 0..64usize {
                if referenced & (1u64 << t) != 0 {
                    if let Some(slot) = md.size_rows.get_mut(t) {
                        *slot = u32_le(&ext, i.saturating_mul(4)).unwrap_or(0);
                    }
                    i = i.saturating_add(1);
                }
            }
        }
        let mut offset = 24u64.saturating_add(present.saturating_mul(4));
        if md.heaps & 0x40 != 0 {
            // Extra data after the row counts (seen in some obfuscated files).
            offset = offset.saturating_add(4);
        }
        md.data_start = offset;
        for t in 0..64usize {
            if md.valid & (1u64 << t) == 0 {
                continue;
            }
            let Some((_, cols)) = schema(t) else {
                // A table we cannot size hides everything after it.
                break;
            };
            let width: u64 = cols.iter().map(|col| md.col_size(col.col)).sum();
            if let Some(w) = md.widths.get_mut(t) {
                *w = width;
            }
            if let Some(o) = md.offsets.get_mut(t) {
                *o = Some(offset);
            }
            let rows = u64::from(md.rows.get(t).copied().unwrap_or(0));
            offset = offset.saturating_add(rows.saturating_mul(width));
        }
    }
    let md = Arc::new(md);
    cx.cache(root, "clr-metadata", md.clone());
    Ok(md)
}

// ---------------------------------------------------------------------------
// Display: the metadata root

const STREAM_DESC: &[(&str, &str)] = &[
    ("#~", "Compressed metadata tables"),
    ("#-", "Uncompressed (edit-and-continue) metadata tables"),
    ("#Strings", "Identifier strings (UTF-8, NUL-terminated)"),
    (
        "#US",
        "User strings: string literals (UTF-16, length-prefixed)",
    ),
    ("#GUID", "16-byte GUIDs, indexed from 1"),
    (
        "#Blob",
        "Signatures and other binary values, length-prefixed",
    ),
    (
        "#Pdb",
        "Portable PDB header: PDB ID, entry point and type system row counts",
    ),
];

pub(super) async fn root(cx: Cx, (pe, root): (Pe, Span)) -> Result<()> {
    let md = load(&cx, root).await?;
    let header = root.sub(0, md.header_len);
    let block = cx.block(header).await?;
    {
        let mut f = Fields::emitting(&cx, &block, LE);
        f.ascii("Signature", 4).desc("\"BSJB\"").emit()?;
        f.u16("MajorVersion").emit()?;
        f.u16("MinorVersion").emit()?;
        f.u32("Reserved").emit()?;
        let len = f
            .u32("Length")
            .desc("Length of the version string, padded to 4")
            .emit()?;
        f.ascii("Version", u64::from(len).min(256))
            .desc("Runtime version the assembly was built for")
            .emit()?;
        f.u16("Flags").emit()?;
        f.u16("Streams").emit()?;
    }
    for stream in &md.streams {
        cx.emit(
            Node::new(format!("Stream Header {}", stream.name))
                .span(stream.header)
                .summary(format!(
                    "offset {:#x}, {} bytes",
                    stream.data.offset.saturating_sub(root.offset),
                    stream.data.len
                ))
                .target(stream.data)
                .lazy(stream_header, (stream.header, root)),
        );
    }
    for stream in &md.streams {
        let desc = STREAM_DESC
            .iter()
            .find(|(n, _)| *n == stream.name)
            .map(|(_, d)| *d);
        let mut node = Node::new(stream.name.clone()).span(stream.data);
        if let Some(d) = desc {
            node = node.desc(d);
        }
        let st = (pe.clone(), root, stream.data);
        node = match stream.name.as_str() {
            "#~" | "#-" => {
                let n = md.valid.count_ones();
                node.summary(format!(
                    "{n} tables, {} rows",
                    md.rows.iter().map(|&r| u64::from(r)).sum::<u64>()
                ))
                .lazy(tables, st)
            }
            "#Strings" => node
                .summary(format!("{} bytes", stream.data.len))
                .lazy(strings_heap, st),
            "#US" => node
                .summary(format!("{} bytes", stream.data.len))
                .lazy(us_heap, st),
            "#GUID" => node
                .summary(format!("{} GUIDs", stream.data.len / 16))
                .lazy(guid_heap, st),
            "#Blob" => node
                .summary(format!("{} bytes", stream.data.len))
                .lazy(blob_heap, st),
            "#Pdb" => node.lazy(pdb_stream, st),
            _ => node,
        };
        cx.emit(node);
    }
    cx.annotate(format!("{}, {} streams", md.version, md.streams.len()));
    Ok(())
}

async fn stream_header(cx: Cx, (span, root): (Span, Span)) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    let offset = f
        .u32("Offset")
        .hex()
        .desc("From the start of the metadata root")
        .emit()?;
    f.u32("Size")
        .hex()
        .with(|&v, n| n.target(root.sub(offset.into(), v.into())))
        .emit()?;
    let len = span.len.saturating_sub(8);
    f.ascii("Name", len)
        .desc("NUL-terminated, padded to 4 bytes")
        .emit()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Display: tables

const HEAP_SIZES: FlagTable = &[
    flag(0x01, "#Strings uses 4-byte indices"),
    flag(0x02, "#GUID uses 4-byte indices"),
    flag(0x04, "#Blob uses 4-byte indices"),
    flag(0x20, "padding bit"),
    flag(0x40, "extra data after the row counts"),
    flag(0x80, "has deleted rows"),
];

async fn tables(cx: Cx, (pe, root, span): (Pe, Span, Span)) -> Result<()> {
    let md = load(&cx, root).await?;
    let present = u64::from(md.valid.count_ones());
    let header = span.sub(0, 24);
    let block = cx.block(header).await?;
    {
        let mut f = Fields::emitting(&cx, &block, LE);
        f.u32("Reserved").emit()?;
        f.u8("MajorVersion").emit()?;
        f.u8("MinorVersion").emit()?;
        f.u8("HeapSizes").flags(HEAP_SIZES).emit()?;
        f.u8("Reserved").emit()?;
        let valid = md.valid;
        f.u64("Valid")
            .hex()
            .desc("Bit vector of the tables present")
            .with(|_, n| n.summary(present_tables(valid)))
            .emit()?;
        f.u64("Sorted")
            .hex()
            .desc("Bit vector of the sorted tables")
            .emit()?;
    }
    let counts = span.sub(24, present.saturating_mul(4));
    cx.emit(
        Node::new("Rows")
            .span(counts)
            .summary(format!("{present} counts"))
            .lazy(row_counts, (root, counts)),
    );
    if md.heaps & 0x40 != 0 {
        cx.emit(
            Node::new("Extra Data").span(span.sub(counts.end().saturating_sub(span.offset), 4)),
        );
    }
    let mut end = md.data_start;
    for t in 0..64usize {
        if md.valid & (1u64 << t) == 0 {
            continue;
        }
        let Some(table) = md.table_span(t) else {
            cx.diag(Diagnostic::unsupported(format!(
                "table {t:#04x} has an unknown layout; it and the tables after it are not shown"
            )));
            break;
        };
        end = table.end().saturating_sub(span.offset);
        let rows = md.row_count(t);
        cx.emit(
            Node::new(table_name(t))
                .span(table)
                .summary(format!(
                    "{rows} row{}, {} bytes each{}",
                    if rows == 1 { "" } else { "s" },
                    md.widths.get(t).copied().unwrap_or(0),
                    if md.sorted & (1u64 << t) != 0 {
                        ", sorted"
                    } else {
                        ""
                    }
                ))
                .lazy(table_rows, (pe.clone(), root, t)),
        );
    }
    if end < span.len {
        cx.emit(padding_node(
            "Padding",
            span.tail(end),
            "Zero bytes up to the end of the stream (4-byte alignment)",
        ));
    }
    Ok(())
}

fn present_tables(valid: u64) -> String {
    let names: Vec<String> = (0..64usize)
        .filter(|t| valid & (1u64 << t) != 0)
        .map(table_name)
        .collect();
    ellipsize(&names.join(", "), 200)
}

async fn row_counts(cx: Cx, (root, span): (Span, Span)) -> Result<()> {
    let md = load(&cx, root).await?;
    let mut i = 0u64;
    for t in 0..64usize {
        if md.valid & (1u64 << t) == 0 {
            continue;
        }
        cx.push(
            Node::new(table_name(t))
                .span(span.sub(i.saturating_mul(4), 4))
                .value(Value::UInt {
                    value: md.row_count(t).into(),
                    bits: 32,
                    radix: Radix::Dec,
                }),
        )
        .await;
        i = i.saturating_add(1);
    }
    Ok(())
}

async fn table_rows(cx: Cx, (pe, root, table): (Pe, Span, usize)) -> Result<()> {
    let md = load(&cx, root).await?;
    let count = md.row_count(table);
    cx.set_count(Count::Exact(count.into()));
    for row in 1..=count {
        let Some(span) = md.row_span(table, row) else {
            break;
        };
        if cx.skipping() {
            cx.push(Node::new(format!("#{row}")).span(span)).await;
            continue;
        }
        let label = md.row_label(&cx, table, row).await;
        let name = if label.is_empty() {
            format!("#{row}")
        } else {
            format!("#{row} {}", ellipsize(&label, 100))
        };
        let summary = row_summary(&cx, &md, &pe, table, row).await;
        let node = Node::new(name)
            .span(span)
            .lazy(row_columns, (pe.clone(), root, table, row));
        cx.push(if summary.is_empty() {
            node
        } else {
            node.summary(summary)
        })
        .await;
    }
    Ok(())
}

/// The most useful columns of a row, rendered.
async fn row_summary(cx: &Cx, md: &Metadata, pe: &PeInfo, table: usize, row: u32) -> String {
    let Some(data) = md.row(cx, table, row).await else {
        return String::new();
    };
    let sig = |col: usize| md.cell(table, &data, col);
    match table {
        0x02 => {
            let (set, _) = decode_flags(TYPE_ATTRIBUTES, sig(0).into());
            let extends = match decode_coded(TYPE_DEF_OR_REF, sig(3)) {
                Some((t, r)) if r != 0 => format!(", extends {}", md.type_name(cx, t, r).await),
                _ => String::new(),
            };
            format!("{}{extends}", set.join(" "))
        }
        0x04 | 0x06 | 0x0a | 0x17 | 0x11 | 0x1b | 0x2b => {
            let (col, kind) = match table {
                0x04 => (2, K::Field),
                0x06 => (4, K::Method),
                0x0a => (2, K::MemberRef),
                0x17 => (2, K::Property),
                0x11 => (0, K::StandAlone),
                0x1b => (0, K::TypeSpec),
                _ => (1, K::MethodSpec),
            };
            let text = blob_text(cx, md, sig(col), kind).await;
            if table == 0x06 && sig(0) != 0 {
                format!("{text}, body at {}", pe.describe_rva(sig(0)))
            } else {
                text
            }
        }
        0x0c => {
            let value = ca_text(cx, md, &data).await;
            match decode_coded(HAS_CUSTOM_ATTRIBUTE, sig(0)) {
                Some((t, r)) => format!("on {}{value}", md.target_label(cx, t, r).await),
                None => value,
            }
        }
        0x28 => {
            let (set, _) = decode_flags(MANIFEST_RESOURCE_FLAGS, sig(1).into());
            format!("{}, offset {:#x}", set.join(" "), sig(0))
        }
        0x0b => {
            let ty = sig(0) & 0xff;
            let bytes = md.blob_bytes(cx, sig(2), 4096).await.unwrap_or_default();
            let value = signature::constant_value(u8::try_from(ty).unwrap_or(0), &bytes);
            format!(
                "{} {value}",
                lookup(ELEMENT_TYPES, ty.into()).unwrap_or("?")
            )
        }
        0x1d => format!("data at {}", pe.describe_rva(sig(0))),
        _ => String::new(),
    }
}

/// A CustomAttribute row's value, decoded with its constructor's signature.
async fn ca_text(cx: &Cx, md: &Metadata, row: &[u8]) -> String {
    let ctor = match decode_coded(CUSTOM_ATTRIBUTE_TYPE, md.cell(0x0c, row, 1)) {
        Some((t @ (0x06 | 0x0a), r)) => match md.row(cx, t, r).await {
            Some(data) => {
                let col = if t == 0x06 { 4 } else { 2 };
                md.blob_bytes(cx, md.cell(t, &data, col), 4096)
                    .await
                    .unwrap_or_default()
            }
            None => Vec::new(),
        },
        _ => Vec::new(),
    };
    let bytes = md
        .blob_bytes(cx, md.cell(0x0c, row, 2), 4096)
        .await
        .unwrap_or_default();
    md.render(cx, &signature::custom_attribute(&bytes, &ctor))
        .await
}

/// A blob decoded as `kind`, rendered with names.
async fn blob_text(cx: &Cx, md: &Metadata, index: u32, kind: SigKind) -> String {
    let Some(bytes) = md.blob_bytes(cx, index, 4096).await else {
        return String::new();
    };
    match kind {
        K::CustomAttribute => {
            let pieces = signature::custom_attribute(&bytes, &[]);
            md.render(cx, &pieces).await
        }
        K::Bytes | K::Marshal | K::Permission | K::DocumentName | K::Constant => {
            if bytes.is_empty() {
                String::new()
            } else {
                ellipsize(&hex_string(&bytes), 64)
            }
        }
        _ => {
            let pieces = signature::decode(&bytes, kind);
            md.render(cx, &pieces).await
        }
    }
}

async fn row_columns(cx: Cx, (pe, root, table, row): (Pe, Span, usize, u32)) -> Result<()> {
    let md = load(&cx, root).await?;
    let span = md
        .row_span(table, row)
        .ok_or_else(|| Diagnostic::internal("row out of range"))?;
    let data = cx.read(span).await?;
    for (index, (col, at, size)) in md.layout(table).into_iter().enumerate() {
        let value = md.cell(table, &data, index);
        let cell = span.sub(at, size);
        let bits = if size == 2 { 16 } else { 32 };
        let mut node = Node::new(col.name).span(cell);
        node = match col.show {
            Show::Flags(t) => node.value(crate::formats::util::lines::flags(t, value.into(), bits)),
            Show::Enum(t) => node.value(Value::Enum {
                raw: value.into(),
                bits,
                name: lookup(
                    t,
                    (value & if table == 0x0b { 0xff } else { u32::MAX }).into(),
                ),
            }),
            Show::Hex | Show::Rva => node.value(Value::UInt {
                value: value.into(),
                bits,
                radix: Radix::Hex,
            }),
            Show::Plain => node.value(Value::UInt {
                value: value.into(),
                bits,
                radix: Radix::Dec,
            }),
        };
        node = match col.col {
            Str => {
                let text = md.string(&cx, value).await;
                let node = node.summary(format!("{text:?}"));
                match md.strings {
                    Some(h) => node.target(
                        h.tail(value.into())
                            .sub(0, to_u64(text.len()).saturating_add(1)),
                    ),
                    None => node,
                }
            }
            Guid => match md.guid(&cx, value).await {
                Some(g) => node.summary(g.to_string()),
                None => node.summary("none"),
            },
            Blob(kind) => {
                let text = if table == 0x0c {
                    ca_text(&cx, &md, &data).await
                } else if table == 0x0b {
                    let bytes = md.blob_bytes(&cx, value, 4096).await.unwrap_or_default();
                    signature::constant_value(
                        u8::try_from(md.cell(table, &data, 0) & 0xff).unwrap_or(0),
                        &bytes,
                    )
                } else {
                    blob_text(&cx, &md, value, kind).await
                };
                let node = node.summary(if text.is_empty() {
                    "empty".to_owned()
                } else {
                    text
                });
                match md.blob(&cx, value).await {
                    Some((b, _)) => node.target(b),
                    None => node,
                }
            }
            Idx(t) => {
                let node = node.summary(md.target_label(&cx, t, value).await);
                match md.row_span(t, value) {
                    Some(s) => node.target(s),
                    None => node,
                }
            }
            Coded(coded) => match decode_coded(coded, value) {
                Some((t, r)) => {
                    let node = node.summary(md.target_label(&cx, t, r).await);
                    match md.row_span(t, r) {
                        Some(s) => node.target(s),
                        None => node,
                    }
                }
                None => node.summary(format!("{} {value:#x}", coded.name)),
            },
            U16 | U32 => match col.show {
                Show::Rva if value != 0 => {
                    let node = node.summary(pe.describe_rva(value));
                    match pe.rva_span(value, 0) {
                        Ok(s) => node.target(s),
                        Err(e) => node.diag(e),
                    }
                }
                _ => node,
            },
        };
        cx.emit(node);
    }
    if table == 0x06 {
        let rva = md.cell(table, &data, 0);
        if rva != 0
            && let Ok(at) = pe.rva_span(rva, 12)
        {
            cx.emit(super::clr::method_body_node(&cx, &pe, at).await);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Display: heaps

/// Window size for walking heaps.
const WINDOW: u64 = 1 << 16;

async fn strings_heap(cx: Cx, (_pe, _root, span): (Pe, Span, Span)) -> Result<()> {
    let (mut pos, mut index) = cx.resume::<(u64, u64)>().unwrap_or((0, 0));
    while pos < span.len {
        let window = cx.read(span.sub(pos, WINDOW)).await?;
        if window.is_empty() {
            break;
        }
        let mut at = 0usize;
        let mut progressed = false;
        while let Some(len) = window
            .get(at..)
            .and_then(|w| w.iter().position(|&b| b == 0))
        {
            let start = pos.saturating_add(to_u64(at));
            let text =
                String::from_utf8_lossy(window.get(at..at.saturating_add(len)).unwrap_or_default())
                    .into_owned();
            let state = (start, index);
            cx.mark(move || state);
            cx.push(
                Node::new(format!("{start:#x}"))
                    .span(span.sub(start, to_u64(len).saturating_add(1)))
                    .value(Value::Text(text)),
            )
            .await;
            index = index.saturating_add(1);
            at = at.saturating_add(len).saturating_add(1);
            progressed = true;
        }
        if !progressed {
            // An unterminated string longer than the window, or trailing
            // bytes without a terminator.
            cx.push(
                Node::new(format!("{pos:#x}"))
                    .span(span.tail(pos))
                    .diag(Diagnostic::malformed("unterminated string")),
            )
            .await;
            break;
        }
        pos = pos.saturating_add(to_u64(at));
        cx.progress_in(span, pos);
    }
    Ok(())
}

async fn guid_heap(cx: Cx, (_pe, _root, span): (Pe, Span, Span)) -> Result<()> {
    let count = span.len / 16;
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let at = span.sub(i.saturating_mul(16), 16);
        let block = cx.block(at).await?;
        let guid = Fields::new(&block, LE).guid("GUID").get()?;
        cx.push(
            Node::new(format!("#{}", i.saturating_add(1)))
                .span(at)
                .value(Value::Guid(guid)),
        )
        .await;
    }
    Ok(())
}

/// Walks a blob-format heap (`#US` as text, `#Blob` decoded by `kinds`).
async fn walk_blobs(
    cx: &Cx,
    span: Span,
    us: bool,
    kinds: &BTreeMap<u32, SigKind>,
    md: &Metadata,
) -> Result<()> {
    let (mut pos, mut index) = cx.resume::<(u64, u64)>().unwrap_or((0, 0));
    while pos < span.len {
        cx.progress_in(span, pos);
        let Some((data, used)) = blob_at(cx, span, pos).await else {
            cx.push(
                Node::new(format!("{pos:#x}"))
                    .span(span.tail(pos))
                    .diag(Diagnostic::malformed("bad blob length")),
            )
            .await;
            break;
        };
        let entry = span.sub(pos, used.saturating_add(data.len));
        let state = (pos, index);
        cx.mark(move || state);
        let name = format!("{pos:#x}");
        let node = if cx.skipping() {
            Node::new(name).span(entry)
        } else if us {
            let raw = cx.read(data).await?;
            let units = raw.len() / 2;
            let text =
                crate::text::utf16(raw.get(..units.saturating_mul(2)).unwrap_or_default(), LE);
            let mut node = Node::new(name).span(entry).value(Value::Text(text));
            if raw.len() % 2 == 1 {
                node = node.summary(match raw.last() {
                    Some(1) => "has special characters",
                    _ => "plain",
                });
            }
            node
        } else {
            let offset = u32::try_from(pos).unwrap_or(u32::MAX);
            let bytes = cx.read(data.sub(0, 4096)).await?;
            let kind = kinds.get(&offset).copied();
            let summary = match kind {
                Some(K::CustomAttribute) => {
                    md.render(cx, &signature::custom_attribute(&bytes, &[]))
                        .await
                }
                Some(
                    k @ (K::Field
                    | K::Method
                    | K::MemberRef
                    | K::Property
                    | K::StandAlone
                    | K::TypeSpec
                    | K::MethodSpec),
                ) => md.render(cx, &signature::decode(&bytes, k)).await,
                _ => String::new(),
            };
            let node = Node::new(name).span(entry).value(Value::Bytes(
                bytes
                    .get(..bytes.len().min(256))
                    .unwrap_or_default()
                    .to_vec(),
            ));
            let label = kind.map(SigKind::label).unwrap_or("");
            match (label.is_empty(), summary.is_empty()) {
                (true, true) => node,
                (false, true) => node.summary(label),
                (true, false) => node.summary(ellipsize(&summary, 200)),
                (false, false) => node.summary(format!("{label}: {}", ellipsize(&summary, 200))),
            }
        };
        cx.push(node).await;
        index = index.saturating_add(1);
        pos = pos.saturating_add(used).saturating_add(data.len);
        if used == 0 {
            break;
        }
    }
    Ok(())
}

async fn us_heap(cx: Cx, (_pe, root, span): (Pe, Span, Span)) -> Result<()> {
    let md = load(&cx, root).await?;
    walk_blobs(&cx, span, true, &BTreeMap::new(), &md).await
}

/// Which blob each table column refers to, so blobs can be decoded by kind.
async fn blob_kinds(cx: &Cx, md: &Metadata) -> BTreeMap<u32, SigKind> {
    let mut out = BTreeMap::new();
    for t in 0..64usize {
        if md.valid & (1u64 << t) == 0 {
            continue;
        }
        let layout = md.layout(t);
        let blob_cols: Vec<(usize, SigKind)> = layout
            .iter()
            .enumerate()
            .filter_map(|(i, (col, _, _))| match col.col {
                Blob(kind) => Some((i, kind)),
                _ => None,
            })
            .collect();
        if blob_cols.is_empty() {
            continue;
        }
        let Some(table) = md.table_span(t) else {
            continue;
        };
        let width = md.widths.get(t).copied().unwrap_or(0);
        // Read the table in windows of whole rows.
        let per = WINDOW.checked_div(width).unwrap_or(1).max(1);
        let rows = u64::from(md.row_count(t));
        let mut row = 0u64;
        while row < rows {
            let n = per.min(rows.saturating_sub(row));
            let Ok(data) = cx
                .read(table.sub(row.saturating_mul(width), n.saturating_mul(width)))
                .await
            else {
                break;
            };
            for r in 0..n {
                let base = to_usize(r.saturating_mul(width));
                let Some(rowdata) = data.get(base..base.saturating_add(to_usize(width))) else {
                    break;
                };
                for &(i, kind) in &blob_cols {
                    let v = md.cell(t, rowdata, i);
                    if v != 0 {
                        out.entry(v).or_insert(kind);
                    }
                }
            }
            cx.checkpoint().await;
            row = row.saturating_add(n);
        }
    }
    out
}

async fn blob_heap(cx: Cx, (_pe, root, span): (Pe, Span, Span)) -> Result<()> {
    let md = load(&cx, root).await?;
    let kinds = blob_kinds(&cx, &md).await;
    walk_blobs(&cx, span, false, &kinds, &md).await
}

async fn pdb_stream(cx: Cx, (_pe, _root, span): (Pe, Span, Span)) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.bytes("PdbId", 20)
        .desc("GUID and stamp matching the image's CodeView record")
        .emit()?;
    f.u32("EntryPoint")
        .hex()
        .desc("MethodDef token, or 0")
        .emit()?;
    let referenced = f
        .u64("ReferencedTypeSystemTables")
        .hex()
        .with(|&v, n| n.summary(present_tables(v)))
        .emit()?;
    for t in 0..64usize {
        if referenced & (1u64 << t) != 0 {
            let span = f.peek_span(4);
            let rows = f.u32("Rows").get()?;
            f.node(
                Node::new(format!("{} rows", table_name(t)))
                    .span(span)
                    .value(Value::UInt {
                        value: rows.into(),
                        bits: 32,
                        radix: Radix::Dec,
                    }),
            );
        }
    }
    Ok(())
}
