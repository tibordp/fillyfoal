//! Symbolic names for Mach-O constants.

use crate::value::{EnumTable, FlagTable, field, flag};

pub const CPU_TYPE_X86: u32 = 7;
pub const CPU_TYPE_X86_64: u32 = 0x0100_0007;
pub const CPU_TYPE_ARM: u32 = 12;
pub const CPU_TYPE_ARM64: u32 = 0x0100_000c;
pub const CPU_TYPE_ARM64_32: u32 = 0x0200_000c;
pub const CPU_TYPE_POWERPC: u32 = 18;
pub const CPU_TYPE_POWERPC64: u32 = 0x0100_0012;

pub const CPU_TYPE: EnumTable = &[
    (1, "VAX"),
    (6, "MC680x0"),
    (7, "X86"),
    (0x0100_0007, "X86_64"),
    (8, "MIPS"),
    (10, "MC98000"),
    (11, "HPPA"),
    (12, "ARM"),
    (0x0100_000c, "ARM64"),
    (0x0200_000c, "ARM64_32"),
    (13, "MC88000"),
    (14, "SPARC"),
    (15, "I860"),
    (18, "POWERPC"),
    (0x0100_0012, "POWERPC64"),
    (24, "RISCV"),
];

pub const FILE_TYPE: EnumTable = &[
    (1, "MH_OBJECT"),
    (2, "MH_EXECUTE"),
    (3, "MH_FVMLIB"),
    (4, "MH_CORE"),
    (5, "MH_PRELOAD"),
    (6, "MH_DYLIB"),
    (7, "MH_DYLINKER"),
    (8, "MH_BUNDLE"),
    (9, "MH_DYLIB_STUB"),
    (10, "MH_DSYM"),
    (11, "MH_KEXT_BUNDLE"),
    (12, "MH_FILESET"),
    (13, "MH_GPU_EXECUTE"),
    (14, "MH_GPU_DYLIB"),
];

/// Short words for each file type, for summaries.
pub const FILE_TYPE_WORDS: EnumTable = &[
    (1, "object"),
    (2, "executable"),
    (3, "fixed VM shared library"),
    (4, "core"),
    (5, "preload executable"),
    (6, "dylib"),
    (7, "dynamic linker"),
    (8, "bundle"),
    (9, "dylib stub"),
    (10, "dSYM companion"),
    (11, "kext bundle"),
    (12, "kernel collection"),
    (13, "GPU executable"),
    (14, "GPU dylib"),
];

pub const MH_OBJECT: u32 = 1;
pub const MH_EXECUTE: u32 = 2;

pub const HEADER_FLAGS: FlagTable = &[
    flag(0x1, "NOUNDEFS"),
    flag(0x2, "INCRLINK"),
    flag(0x4, "DYLDLINK"),
    flag(0x8, "BINDATLOAD"),
    flag(0x10, "PREBOUND"),
    flag(0x20, "SPLIT_SEGS"),
    flag(0x40, "LAZY_INIT"),
    flag(0x80, "TWOLEVEL"),
    flag(0x100, "FORCE_FLAT"),
    flag(0x200, "NOMULTIDEFS"),
    flag(0x400, "NOFIXPREBINDING"),
    flag(0x800, "PREBINDABLE"),
    flag(0x1000, "ALLMODSBOUND"),
    flag(0x2000, "SUBSECTIONS_VIA_SYMBOLS"),
    flag(0x4000, "CANONICAL"),
    flag(0x8000, "WEAK_DEFINES"),
    flag(0x1_0000, "BINDS_TO_WEAK"),
    flag(0x2_0000, "ALLOW_STACK_EXECUTION"),
    flag(0x4_0000, "ROOT_SAFE"),
    flag(0x8_0000, "SETUID_SAFE"),
    flag(0x10_0000, "NO_REEXPORTED_DYLIBS"),
    flag(0x20_0000, "PIE"),
    flag(0x40_0000, "DEAD_STRIPPABLE_DYLIB"),
    flag(0x80_0000, "HAS_TLV_DESCRIPTORS"),
    flag(0x100_0000, "NO_HEAP_EXECUTION"),
    flag(0x200_0000, "APP_EXTENSION_SAFE"),
    flag(0x400_0000, "NLIST_OUTOFSYNC_WITH_DYLDINFO"),
    flag(0x800_0000, "SIM_SUPPORT"),
    flag(0x1000_0000, "IMPLICIT_PAGEZERO"),
    flag(0x8000_0000, "DYLIB_IN_CACHE"),
];

pub const MH_PIE: u32 = 0x20_0000;
pub const MH_TWOLEVEL: u32 = 0x80;

pub const LC_SEGMENT: u32 = 0x1;
pub const LC_SYMTAB: u32 = 0x2;
pub const LC_SYMSEG: u32 = 0x3;
pub const LC_THREAD: u32 = 0x4;
pub const LC_UNIXTHREAD: u32 = 0x5;
pub const LC_LOADFVMLIB: u32 = 0x6;
pub const LC_IDFVMLIB: u32 = 0x7;
pub const LC_PREBOUND_DYLIB: u32 = 0x10;
pub const LC_ROUTINES: u32 = 0x11;
pub const LC_TWOLEVEL_HINTS: u32 = 0x16;
pub const LC_PREBIND_CKSUM: u32 = 0x17;
pub const LC_ROUTINES_64: u32 = 0x1a;
pub const LC_DYSYMTAB: u32 = 0xb;
pub const LC_LOAD_DYLIB: u32 = 0xc;
pub const LC_ID_DYLIB: u32 = 0xd;
pub const LC_LOAD_DYLINKER: u32 = 0xe;
pub const LC_ID_DYLINKER: u32 = 0xf;
pub const LC_SUB_FRAMEWORK: u32 = 0x12;
pub const LC_SUB_UMBRELLA: u32 = 0x13;
pub const LC_SUB_CLIENT: u32 = 0x14;
pub const LC_SUB_LIBRARY: u32 = 0x15;
pub const LC_LOAD_WEAK_DYLIB: u32 = 0x8000_0018;
pub const LC_SEGMENT_64: u32 = 0x19;
pub const LC_UUID: u32 = 0x1b;
pub const LC_RPATH: u32 = 0x8000_001c;
pub const LC_CODE_SIGNATURE: u32 = 0x1d;
pub const LC_SEGMENT_SPLIT_INFO: u32 = 0x1e;
pub const LC_REEXPORT_DYLIB: u32 = 0x8000_001f;
pub const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
pub const LC_ENCRYPTION_INFO: u32 = 0x21;
pub const LC_DYLD_INFO: u32 = 0x22;
pub const LC_DYLD_INFO_ONLY: u32 = 0x8000_0022;
pub const LC_LOAD_UPWARD_DYLIB: u32 = 0x8000_0023;
pub const LC_VERSION_MIN_MACOSX: u32 = 0x24;
pub const LC_VERSION_MIN_IPHONEOS: u32 = 0x25;
pub const LC_FUNCTION_STARTS: u32 = 0x26;
pub const LC_DYLD_ENVIRONMENT: u32 = 0x27;
pub const LC_MAIN: u32 = 0x8000_0028;
pub const LC_DATA_IN_CODE: u32 = 0x29;
pub const LC_SOURCE_VERSION: u32 = 0x2a;
pub const LC_DYLIB_CODE_SIGN_DRS: u32 = 0x2b;
pub const LC_ENCRYPTION_INFO_64: u32 = 0x2c;
pub const LC_LINKER_OPTION: u32 = 0x2d;
pub const LC_LINKER_OPTIMIZATION_HINT: u32 = 0x2e;
pub const LC_VERSION_MIN_TVOS: u32 = 0x2f;
pub const LC_VERSION_MIN_WATCHOS: u32 = 0x30;
pub const LC_NOTE: u32 = 0x31;
pub const LC_BUILD_VERSION: u32 = 0x32;
pub const LC_DYLD_EXPORTS_TRIE: u32 = 0x8000_0033;
pub const LC_DYLD_CHAINED_FIXUPS: u32 = 0x8000_0034;
pub const LC_FILESET_ENTRY: u32 = 0x8000_0035;
pub const LC_ATOM_INFO: u32 = 0x36;
pub const LC_FUNCTION_VARIANTS: u32 = 0x37;
pub const LC_FUNCTION_VARIANT_FIXUPS: u32 = 0x38;
pub const LC_TARGET_TRIPLE: u32 = 0x39;

pub const LOAD_COMMAND: EnumTable = &[
    (0x1, "LC_SEGMENT"),
    (0x2, "LC_SYMTAB"),
    (0x3, "LC_SYMSEG"),
    (0x4, "LC_THREAD"),
    (0x5, "LC_UNIXTHREAD"),
    (0x6, "LC_LOADFVMLIB"),
    (0x7, "LC_IDFVMLIB"),
    (0x8, "LC_IDENT"),
    (0x9, "LC_FVMFILE"),
    (0xa, "LC_PREPAGE"),
    (0xb, "LC_DYSYMTAB"),
    (0xc, "LC_LOAD_DYLIB"),
    (0xd, "LC_ID_DYLIB"),
    (0xe, "LC_LOAD_DYLINKER"),
    (0xf, "LC_ID_DYLINKER"),
    (0x10, "LC_PREBOUND_DYLIB"),
    (0x11, "LC_ROUTINES"),
    (0x12, "LC_SUB_FRAMEWORK"),
    (0x13, "LC_SUB_UMBRELLA"),
    (0x14, "LC_SUB_CLIENT"),
    (0x15, "LC_SUB_LIBRARY"),
    (0x16, "LC_TWOLEVEL_HINTS"),
    (0x17, "LC_PREBIND_CKSUM"),
    (0x8000_0018, "LC_LOAD_WEAK_DYLIB"),
    (0x19, "LC_SEGMENT_64"),
    (0x1a, "LC_ROUTINES_64"),
    (0x1b, "LC_UUID"),
    (0x8000_001c, "LC_RPATH"),
    (0x1d, "LC_CODE_SIGNATURE"),
    (0x1e, "LC_SEGMENT_SPLIT_INFO"),
    (0x8000_001f, "LC_REEXPORT_DYLIB"),
    (0x20, "LC_LAZY_LOAD_DYLIB"),
    (0x21, "LC_ENCRYPTION_INFO"),
    (0x22, "LC_DYLD_INFO"),
    (0x8000_0022, "LC_DYLD_INFO_ONLY"),
    (0x8000_0023, "LC_LOAD_UPWARD_DYLIB"),
    (0x24, "LC_VERSION_MIN_MACOSX"),
    (0x25, "LC_VERSION_MIN_IPHONEOS"),
    (0x26, "LC_FUNCTION_STARTS"),
    (0x27, "LC_DYLD_ENVIRONMENT"),
    (0x8000_0028, "LC_MAIN"),
    (0x29, "LC_DATA_IN_CODE"),
    (0x2a, "LC_SOURCE_VERSION"),
    (0x2b, "LC_DYLIB_CODE_SIGN_DRS"),
    (0x2c, "LC_ENCRYPTION_INFO_64"),
    (0x2d, "LC_LINKER_OPTION"),
    (0x2e, "LC_LINKER_OPTIMIZATION_HINT"),
    (0x2f, "LC_VERSION_MIN_TVOS"),
    (0x30, "LC_VERSION_MIN_WATCHOS"),
    (0x31, "LC_NOTE"),
    (0x32, "LC_BUILD_VERSION"),
    (0x8000_0033, "LC_DYLD_EXPORTS_TRIE"),
    (0x8000_0034, "LC_DYLD_CHAINED_FIXUPS"),
    (0x8000_0035, "LC_FILESET_ENTRY"),
    (0x36, "LC_ATOM_INFO"),
    (0x37, "LC_FUNCTION_VARIANTS"),
    (0x38, "LC_FUNCTION_VARIANT_FIXUPS"),
    (0x39, "LC_TARGET_TRIPLE"),
];

pub const VM_PROT: FlagTable = &[flag(1, "READ"), flag(2, "WRITE"), flag(4, "EXECUTE")];

pub const SEGMENT_FLAGS: FlagTable = &[
    flag(0x1, "HIGHVM"),
    flag(0x2, "FVMLIB"),
    flag(0x4, "NORELOC"),
    flag(0x8, "PROTECTED_VERSION_1"),
    flag(0x10, "READ_ONLY"),
];

pub const S_ZEROFILL: u32 = 1;
pub const S_CSTRING_LITERALS: u32 = 2;
pub const S_4BYTE_LITERALS: u32 = 3;
pub const S_8BYTE_LITERALS: u32 = 4;
pub const S_LITERAL_POINTERS: u32 = 5;
pub const S_NON_LAZY_SYMBOL_POINTERS: u32 = 6;
pub const S_LAZY_SYMBOL_POINTERS: u32 = 7;
pub const S_SYMBOL_STUBS: u32 = 8;
pub const S_MOD_INIT_FUNC_POINTERS: u32 = 9;
pub const S_MOD_TERM_FUNC_POINTERS: u32 = 10;
pub const S_GB_ZEROFILL: u32 = 12;
pub const S_INTERPOSING: u32 = 13;
pub const S_16BYTE_LITERALS: u32 = 14;
pub const S_LAZY_DYLIB_SYMBOL_POINTERS: u32 = 16;
pub const S_THREAD_LOCAL_ZEROFILL: u32 = 18;
pub const S_THREAD_LOCAL_VARIABLES: u32 = 19;
pub const S_THREAD_LOCAL_VARIABLE_POINTERS: u32 = 20;
pub const S_THREAD_LOCAL_INIT_FUNCTION_POINTERS: u32 = 21;
pub const S_INIT_FUNC_OFFSETS: u32 = 22;

pub const SECTION_TYPE: EnumTable = &[
    (0, "S_REGULAR"),
    (1, "S_ZEROFILL"),
    (2, "S_CSTRING_LITERALS"),
    (3, "S_4BYTE_LITERALS"),
    (4, "S_8BYTE_LITERALS"),
    (5, "S_LITERAL_POINTERS"),
    (6, "S_NON_LAZY_SYMBOL_POINTERS"),
    (7, "S_LAZY_SYMBOL_POINTERS"),
    (8, "S_SYMBOL_STUBS"),
    (9, "S_MOD_INIT_FUNC_POINTERS"),
    (10, "S_MOD_TERM_FUNC_POINTERS"),
    (11, "S_COALESCED"),
    (12, "S_GB_ZEROFILL"),
    (13, "S_INTERPOSING"),
    (14, "S_16BYTE_LITERALS"),
    (15, "S_DTRACE_DOF"),
    (16, "S_LAZY_DYLIB_SYMBOL_POINTERS"),
    (17, "S_THREAD_LOCAL_REGULAR"),
    (18, "S_THREAD_LOCAL_ZEROFILL"),
    (19, "S_THREAD_LOCAL_VARIABLES"),
    (20, "S_THREAD_LOCAL_VARIABLE_POINTERS"),
    (21, "S_THREAD_LOCAL_INIT_FUNCTION_POINTERS"),
    (22, "S_INIT_FUNC_OFFSETS"),
];

pub const SECTION_FLAGS: FlagTable = &[
    field(0xff, 0x01, "S_ZEROFILL"),
    field(0xff, 0x02, "S_CSTRING_LITERALS"),
    field(0xff, 0x03, "S_4BYTE_LITERALS"),
    field(0xff, 0x04, "S_8BYTE_LITERALS"),
    field(0xff, 0x05, "S_LITERAL_POINTERS"),
    field(0xff, 0x06, "S_NON_LAZY_SYMBOL_POINTERS"),
    field(0xff, 0x07, "S_LAZY_SYMBOL_POINTERS"),
    field(0xff, 0x08, "S_SYMBOL_STUBS"),
    field(0xff, 0x09, "S_MOD_INIT_FUNC_POINTERS"),
    field(0xff, 0x0a, "S_MOD_TERM_FUNC_POINTERS"),
    field(0xff, 0x0b, "S_COALESCED"),
    field(0xff, 0x0c, "S_GB_ZEROFILL"),
    field(0xff, 0x0d, "S_INTERPOSING"),
    field(0xff, 0x0e, "S_16BYTE_LITERALS"),
    field(0xff, 0x0f, "S_DTRACE_DOF"),
    field(0xff, 0x10, "S_LAZY_DYLIB_SYMBOL_POINTERS"),
    field(0xff, 0x11, "S_THREAD_LOCAL_REGULAR"),
    field(0xff, 0x12, "S_THREAD_LOCAL_ZEROFILL"),
    field(0xff, 0x13, "S_THREAD_LOCAL_VARIABLES"),
    field(0xff, 0x14, "S_THREAD_LOCAL_VARIABLE_POINTERS"),
    field(0xff, 0x15, "S_THREAD_LOCAL_INIT_FUNCTION_POINTERS"),
    field(0xff, 0x16, "S_INIT_FUNC_OFFSETS"),
    flag(0x8000_0000, "PURE_INSTRUCTIONS"),
    flag(0x4000_0000, "NO_TOC"),
    flag(0x2000_0000, "STRIP_STATIC_SYMS"),
    flag(0x1000_0000, "NO_DEAD_STRIP"),
    flag(0x0800_0000, "LIVE_SUPPORT"),
    flag(0x0400_0000, "SELF_MODIFYING_CODE"),
    flag(0x0200_0000, "DEBUG"),
    flag(0x0000_0400, "SOME_INSTRUCTIONS"),
    flag(0x0000_0200, "EXT_RELOC"),
    flag(0x0000_0100, "LOC_RELOC"),
];

pub const N_TYPE: EnumTable = &[
    (0x0, "N_UNDF"),
    (0x2, "N_ABS"),
    (0xa, "N_INDR"),
    (0xc, "N_PBUD"),
    (0xe, "N_SECT"),
];

pub const N_STAB: EnumTable = &[
    (0x20, "N_GSYM"),
    (0x22, "N_FNAME"),
    (0x24, "N_FUN"),
    (0x26, "N_STSYM"),
    (0x28, "N_LCSYM"),
    (0x2e, "N_BNSYM"),
    (0x30, "N_AST"),
    (0x3c, "N_OPT"),
    (0x40, "N_RSYM"),
    (0x44, "N_SLINE"),
    (0x4e, "N_ENSYM"),
    (0x60, "N_SSYM"),
    (0x64, "N_SO"),
    (0x66, "N_OSO"),
    (0x6c, "N_LIB"),
    (0x80, "N_LSYM"),
    (0x82, "N_BINCL"),
    (0x84, "N_SOL"),
    (0x86, "N_PARAMS"),
    (0x88, "N_VERSION"),
    (0x8a, "N_OLEVEL"),
    (0xa0, "N_PSYM"),
    (0xa2, "N_EINCL"),
    (0xa4, "N_ENTRY"),
    (0xc0, "N_LBRAC"),
    (0xc2, "N_EXCL"),
    (0xe0, "N_RBRAC"),
    (0xe2, "N_BCOMM"),
    (0xe4, "N_ECOMM"),
    (0xe8, "N_ECOML"),
    (0xfe, "N_LENG"),
];

pub const N_DESC: FlagTable = &[
    field(0x7, 0x1, "REFERENCE_FLAG_UNDEFINED_LAZY"),
    field(0x7, 0x2, "REFERENCE_FLAG_DEFINED"),
    field(0x7, 0x3, "REFERENCE_FLAG_PRIVATE_DEFINED"),
    field(0x7, 0x4, "REFERENCE_FLAG_PRIVATE_UNDEFINED_NON_LAZY"),
    field(0x7, 0x5, "REFERENCE_FLAG_PRIVATE_UNDEFINED_LAZY"),
    flag(0x8, "N_ARM_THUMB_DEF"),
    flag(0x10, "REFERENCED_DYNAMICALLY"),
    flag(0x20, "N_NO_DEAD_STRIP"),
    flag(0x40, "N_WEAK_REF"),
    flag(0x80, "N_WEAK_DEF"),
    flag(0x100, "N_SYMBOL_RESOLVER"),
    flag(0x200, "N_ALT_ENTRY"),
    flag(0x400, "N_COLD_FUNC"),
];

/// What the fields of a stab mean, by `n_type`: `(type, meaning of the
/// name, meaning of n_value)`.
pub const STAB_MEANING: &[(u8, &str, &str)] = &[
    (0x20, "global symbol", "unused"),
    (0x22, "procedure name", "unused"),
    (
        0x24,
        "function (an empty name ends it: n_value is its size)",
        "address",
    ),
    (0x26, "static symbol", "address"),
    (0x28, "local common symbol", "address"),
    (0x2e, "begin of a symbol's code", "address"),
    (0x30, "AST file path", "unused"),
    (0x3c, "options", "unused"),
    (0x40, "register variable", "register"),
    (0x44, "source line", "address"),
    (0x4e, "end of a symbol's code", "address"),
    (0x60, "structure element", "offset"),
    (
        0x64,
        "source file or directory (an empty name ends the unit)",
        "address",
    ),
    (0x66, "object file path", "modification time"),
    (0x6c, "dylib path", "unused"),
    (0x80, "local symbol", "unused"),
    (0x82, "include file begin", "unused"),
    (0x84, "included source file", "address"),
    (0x86, "compiler parameters", "unused"),
    (0x88, "compiler version", "unused"),
    (0x8a, "compiler optimization level", "unused"),
    (0xa0, "parameter", "offset"),
    (0xa2, "include file end", "unused"),
    (0xa4, "alternate entry point", "address"),
    (0xc0, "left bracket", "address"),
    (0xc2, "deleted include file", "unused"),
    (0xe0, "right bracket", "address"),
    (0xe2, "begin common", "unused"),
    (0xe4, "end common", "unused"),
    (0xe8, "end common (local name)", "address"),
    (0xfe, "second stab entry with length", "unused"),
];

pub const PLATFORM: EnumTable = &[
    (1, "macOS"),
    (2, "iOS"),
    (3, "tvOS"),
    (4, "watchOS"),
    (5, "bridgeOS"),
    (6, "Mac Catalyst"),
    (7, "iOS Simulator"),
    (8, "tvOS Simulator"),
    (9, "watchOS Simulator"),
    (10, "DriverKit"),
    (11, "visionOS"),
    (12, "visionOS Simulator"),
    (13, "firmware"),
    (14, "sepOS"),
];

pub const TOOL: EnumTable = &[
    (1, "clang"),
    (2, "swift"),
    (3, "ld"),
    (4, "lld"),
    (1024, "Metal"),
    (1025, "AIR LLD"),
    (1026, "AIR NT"),
    (1027, "AIR NT plugin"),
    (1028, "AIR PACK"),
    (1031, "GPU archiver"),
    (1032, "Metal framebuffer"),
];

pub const DICE_KIND: EnumTable = &[
    (1, "DATA"),
    (2, "JUMP_TABLE8"),
    (3, "JUMP_TABLE16"),
    (4, "JUMP_TABLE32"),
    (5, "ABS_JUMP_TABLE32"),
];

pub const RELOC_X86_64: EnumTable = &[
    (0, "X86_64_RELOC_UNSIGNED"),
    (1, "X86_64_RELOC_SIGNED"),
    (2, "X86_64_RELOC_BRANCH"),
    (3, "X86_64_RELOC_GOT_LOAD"),
    (4, "X86_64_RELOC_GOT"),
    (5, "X86_64_RELOC_SUBTRACTOR"),
    (6, "X86_64_RELOC_SIGNED_1"),
    (7, "X86_64_RELOC_SIGNED_2"),
    (8, "X86_64_RELOC_SIGNED_4"),
    (9, "X86_64_RELOC_TLV"),
];

pub const RELOC_ARM64: EnumTable = &[
    (0, "ARM64_RELOC_UNSIGNED"),
    (1, "ARM64_RELOC_SUBTRACTOR"),
    (2, "ARM64_RELOC_BRANCH26"),
    (3, "ARM64_RELOC_PAGE21"),
    (4, "ARM64_RELOC_PAGEOFF12"),
    (5, "ARM64_RELOC_GOT_LOAD_PAGE21"),
    (6, "ARM64_RELOC_GOT_LOAD_PAGEOFF12"),
    (7, "ARM64_RELOC_POINTER_TO_GOT"),
    (8, "ARM64_RELOC_TLVP_LOAD_PAGE21"),
    (9, "ARM64_RELOC_TLVP_LOAD_PAGEOFF12"),
    (10, "ARM64_RELOC_ADDEND"),
    (11, "ARM64_RELOC_AUTHENTICATED_POINTER"),
];

pub const RELOC_ARM: EnumTable = &[
    (0, "ARM_RELOC_VANILLA"),
    (1, "ARM_RELOC_PAIR"),
    (2, "ARM_RELOC_SECTDIFF"),
    (3, "ARM_RELOC_LOCAL_SECTDIFF"),
    (4, "ARM_RELOC_PB_LA_PTR"),
    (5, "ARM_RELOC_BR24"),
    (6, "ARM_THUMB_RELOC_BR22"),
    (7, "ARM_THUMB_32BIT_BRANCH"),
    (8, "ARM_RELOC_HALF"),
    (9, "ARM_RELOC_HALF_SECTDIFF"),
];

pub const RELOC_GENERIC: EnumTable = &[
    (0, "GENERIC_RELOC_VANILLA"),
    (1, "GENERIC_RELOC_PAIR"),
    (2, "GENERIC_RELOC_SECTDIFF"),
    (3, "GENERIC_RELOC_PB_LA_PTR"),
    (4, "GENERIC_RELOC_LOCAL_SECTDIFF"),
    (5, "GENERIC_RELOC_TLV"),
];

pub const RELOC_PPC: EnumTable = &[
    (0, "PPC_RELOC_VANILLA"),
    (1, "PPC_RELOC_PAIR"),
    (2, "PPC_RELOC_BR14"),
    (3, "PPC_RELOC_BR24"),
    (4, "PPC_RELOC_HI16"),
    (5, "PPC_RELOC_LO16"),
    (6, "PPC_RELOC_HA16"),
    (7, "PPC_RELOC_LO14"),
    (8, "PPC_RELOC_SECTDIFF"),
    (9, "PPC_RELOC_PB_LA_PTR"),
    (10, "PPC_RELOC_HI16_SECTDIFF"),
    (11, "PPC_RELOC_LO16_SECTDIFF"),
    (12, "PPC_RELOC_HA16_SECTDIFF"),
    (13, "PPC_RELOC_JBSR"),
    (14, "PPC_RELOC_LO14_SECTDIFF"),
    (15, "PPC_RELOC_LOCAL_SECTDIFF"),
];

pub fn relocation_types(cputype: u32) -> EnumTable {
    match cputype {
        CPU_TYPE_X86_64 => RELOC_X86_64,
        CPU_TYPE_ARM64 | CPU_TYPE_ARM64_32 => RELOC_ARM64,
        CPU_TYPE_ARM => RELOC_ARM,
        CPU_TYPE_POWERPC | CPU_TYPE_POWERPC64 => RELOC_PPC,
        _ => RELOC_GENERIC,
    }
}

pub const CHAINED_IMPORT_FORMAT: EnumTable = &[
    (1, "DYLD_CHAINED_IMPORT"),
    (2, "DYLD_CHAINED_IMPORT_ADDEND"),
    (3, "DYLD_CHAINED_IMPORT_ADDEND64"),
];

pub const CHAINED_POINTER_FORMAT: EnumTable = &[
    (1, "DYLD_CHAINED_PTR_ARM64E"),
    (2, "DYLD_CHAINED_PTR_64"),
    (3, "DYLD_CHAINED_PTR_32"),
    (4, "DYLD_CHAINED_PTR_32_CACHE"),
    (5, "DYLD_CHAINED_PTR_32_FIRMWARE"),
    (6, "DYLD_CHAINED_PTR_64_OFFSET"),
    (7, "DYLD_CHAINED_PTR_ARM64E_KERNEL"),
    (8, "DYLD_CHAINED_PTR_64_KERNEL_CACHE"),
    (9, "DYLD_CHAINED_PTR_ARM64E_USERLAND"),
    (10, "DYLD_CHAINED_PTR_ARM64E_FIRMWARE"),
    (11, "DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE"),
    (12, "DYLD_CHAINED_PTR_ARM64E_USERLAND24"),
    (13, "DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE"),
    (14, "DYLD_CHAINED_PTR_ARM64E_SEGMENTED"),
];

pub const BIND_SPECIAL_DYLIB: EnumTable = &[
    (0, "self"),
    (0xff, "main executable"),
    (0xfe, "flat lookup"),
    (0xfd, "weak lookup"),
];

/// The conventional architecture name (`arm64e`, `x86_64h`, ...). The
/// capability bits (the top byte of the subtype) are not part of it.
pub fn arch_name(cputype: u32, subtype: u32) -> String {
    let sub = subtype & 0x00ff_ffff;
    let name = match (cputype, sub) {
        (CPU_TYPE_X86, _) => "i386",
        (CPU_TYPE_X86_64, 8) => "x86_64h",
        (CPU_TYPE_X86_64, _) => "x86_64",
        (CPU_TYPE_ARM64, 2) => "arm64e",
        (CPU_TYPE_ARM64, 1) => "arm64v8",
        (CPU_TYPE_ARM64, _) => "arm64",
        (CPU_TYPE_ARM64_32, _) => "arm64_32",
        (CPU_TYPE_ARM, 5) => "armv4t",
        (CPU_TYPE_ARM, 6) => "armv6",
        (CPU_TYPE_ARM, 7) => "armv5tej",
        (CPU_TYPE_ARM, 8) => "xscale",
        (CPU_TYPE_ARM, 9) => "armv7",
        (CPU_TYPE_ARM, 10) => "armv7f",
        (CPU_TYPE_ARM, 11) => "armv7s",
        (CPU_TYPE_ARM, 12) => "armv7k",
        (CPU_TYPE_ARM, 13) => "armv8",
        (CPU_TYPE_ARM, 14) => "armv6m",
        (CPU_TYPE_ARM, 15) => "armv7m",
        (CPU_TYPE_ARM, 16) => "armv7em",
        (CPU_TYPE_ARM, _) => "arm",
        (CPU_TYPE_POWERPC, 100) => "ppc970",
        (CPU_TYPE_POWERPC, _) => "ppc",
        (CPU_TYPE_POWERPC64, _) => "ppc64",
        _ => {
            return crate::value::lookup(CPU_TYPE, cputype.into())
                .map_or_else(|| format!("cputype {cputype:#x}"), str::to_ascii_lowercase);
        }
    };
    name.to_owned()
}

/// The capability bits of a CPU subtype (its top byte), described:
/// pointer authentication ABI versions for arm64e, 64-bit libraries for
/// x86_64 and ppc64.
pub fn subtype_caps(cputype: u32, subtype: u32) -> Option<String> {
    let caps = subtype >> 24;
    if caps == 0 {
        return None;
    }
    Some(match cputype {
        CPU_TYPE_ARM64 | CPU_TYPE_ARM64_32 if caps & 0x80 != 0 => format!(
            "pointer authentication ABI v{}, {}",
            caps & 0x3f,
            if caps & 0x40 != 0 {
                "kernel"
            } else {
                "userspace"
            }
        ),
        CPU_TYPE_X86_64 | CPU_TYPE_POWERPC64 if caps == 0x80 => {
            "64-bit libraries (LIB64)".to_owned()
        }
        _ => format!("capabilities {caps:#04x}"),
    })
}

/// The subtype with its capabilities, for field summaries.
pub fn subtype_summary(cputype: u32, subtype: u32) -> String {
    let mut s = arch_name(cputype, subtype);
    if let Some(caps) = subtype_caps(cputype, subtype) {
        s.push_str(", ");
        s.push_str(&caps);
    }
    s
}

/// `X.Y.Z` from a nibble-packed version (`xxxx.yy.zz`).
pub fn version(v: u32) -> String {
    let (major, minor, patch) = (v >> 16, (v >> 8) & 0xff, v & 0xff);
    if patch == 0 {
        format!("{major}.{minor}")
    } else {
        format!("{major}.{minor}.{patch}")
    }
}

/// `A.B.C.D.E` from a source version (24.10.10.10.10 bits).
pub fn source_version(v: u64) -> String {
    format!(
        "{}.{}.{}.{}.{}",
        v >> 40,
        (v >> 30) & 0x3ff,
        (v >> 20) & 0x3ff,
        (v >> 10) & 0x3ff,
        v & 0x3ff
    )
}

/// A UUID in the conventional 8-4-4-4-12 layout.
pub fn uuid(b: &[u8]) -> String {
    let h = crate::formats::util::binutil::hex_string(b).to_ascii_uppercase();
    let part = |r: std::ops::Range<usize>| h.get(r).unwrap_or_default().to_owned();
    format!(
        "{}-{}-{}-{}-{}",
        part(0..8),
        part(8..12),
        part(12..16),
        part(16..20),
        part(20..32)
    )
}

/// What well-known sections hold, by section name (and segment where the
/// name alone is ambiguous).
pub fn section_description(segment: &str, section: &str) -> Option<&'static str> {
    Some(match (segment, section) {
        ("__TEXT", "__text") => "Machine code",
        ("__TEXT", "__stubs") => "Stubs: indirect jumps through the lazy or non-lazy pointers",
        ("__TEXT", "__auth_stubs") => "Stubs: authenticated indirect jumps through __auth_got",
        ("__TEXT", "__stub_helper") => "Code that binds lazy pointers on first call",
        ("__TEXT", "__const") => "Read-only constant data",
        ("__TEXT", "__cstring") => "C string literals",
        ("__TEXT", "__ustring") => "UTF-16 string literals",
        ("__TEXT", "__oslogstring") => "os_log format strings",
        ("__TEXT", "__unwind_info") => "Compact unwind information",
        ("__TEXT", "__eh_frame") => "DWARF call frame information",
        ("__TEXT", "__gcc_except_tab") => "Language-specific exception tables (LSDA)",
        ("__TEXT", "__info_plist") => "Embedded Info.plist",
        ("__TEXT", "__objc_methname") => "Objective-C selector names",
        ("__TEXT", "__objc_classname") => "Objective-C class names",
        ("__TEXT", "__objc_methtype") => "Objective-C method type encodings",
        ("__TEXT", "__objc_stubs") => "Objective-C message send stubs",
        ("__TEXT", "__constg_swiftt") => "Swift type context descriptors",
        ("__TEXT", "__swift5_typeref") => "Swift mangled type references",
        ("__TEXT", "__swift5_reflstr") => "Swift reflection strings (field names)",
        ("__TEXT", "__swift5_fieldmd") => "Swift field descriptors",
        ("__TEXT", "__swift5_assocty") => "Swift associated type descriptors",
        ("__TEXT", "__swift5_builtin") => "Swift builtin type descriptors",
        ("__TEXT", "__swift5_capture") => "Swift closure capture descriptors",
        ("__TEXT", "__swift5_mpenum") => "Swift multi-payload enum descriptors",
        ("__TEXT", "__swift5_types") => "Swift type metadata records (relative pointers)",
        ("__TEXT", "__swift5_types2") => "Swift type metadata records (relative pointers)",
        ("__TEXT", "__swift5_protos") => "Swift protocol descriptors (relative pointers)",
        ("__TEXT", "__swift5_proto") => "Swift protocol conformances (relative pointers)",
        ("__TEXT", "__swift5_entry") => "Swift entry point (relative pointer)",
        ("__TEXT", "__swift5_acfuncs") => "Swift accessible functions",
        ("__TEXT", "__swift_as_entry" | "__swift_as_ret" | "__swift_as_cont") => {
            "Swift async function records"
        }
        (_, "__got") => "Non-lazy symbol pointers (global offset table)",
        (_, "__auth_got") => "Authenticated non-lazy symbol pointers",
        (_, "__auth_ptr") => "Authenticated pointers",
        (_, "__la_symbol_ptr") => "Lazy symbol pointers, bound on first call",
        (_, "__nl_symbol_ptr") => "Non-lazy symbol pointers",
        (_, "__mod_init_func") => "Initializers run before main",
        (_, "__mod_term_func") => "Terminators run at exit",
        (_, "__init_offsets") => "Initializers, as offsets from the image start",
        (_, "__const") => "Constant data (written by the loader's fixups only)",
        (_, "__data") => "Initialized data",
        (_, "__bss") => "Zero-initialized data (no file contents)",
        (_, "__common") => "Common symbols (no file contents)",
        (_, "__cfstring") => "Constant CFString objects",
        (_, "__thread_vars") => "Thread-local variable descriptors",
        (_, "__thread_data") => "Initial values of thread-local variables",
        (_, "__thread_bss") => "Zero-initialized thread-local variables",
        (_, "__thread_ptrs") => "Pointers to thread-local variable descriptors",
        (_, "__objc_imageinfo") => "Objective-C image info (version and flags)",
        (_, "__objc_classlist") => "Objective-C classes defined here",
        (_, "__objc_nlclslist") => "Objective-C classes with +load",
        (_, "__objc_catlist") => "Objective-C categories defined here",
        (_, "__objc_nlcatlist") => "Objective-C categories with +load",
        (_, "__objc_protolist") => "Objective-C protocols defined here",
        (_, "__objc_classrefs") => "References to Objective-C classes",
        (_, "__objc_superrefs") => "References to Objective-C superclasses",
        (_, "__objc_protorefs") => "References to Objective-C protocols",
        (_, "__objc_selrefs") => "Selector references",
        (_, "__objc_const") => "Objective-C class metadata (read-only parts)",
        (_, "__objc_data") => "Objective-C class objects",
        (_, "__objc_ivar") => "Objective-C instance variable offsets",
        (_, "__objc_classname") => "Objective-C class names",
        (_, "__compact_unwind") => "Compact unwind entries for the linker",
        (_, "__llvm_addrsig") => "Symbols whose address is taken (for identical code folding)",
        (_, "__bitcode") => "Embedded LLVM bitcode",
        (_, "__cmdline") => "Compiler command line",
        (_, "__asm") => "Placeholder for embedded bitcode",
        ("__DWARF", "__debug_info") => "DWARF debugging information entries",
        ("__DWARF", "__debug_abbrev") => "DWARF abbreviations",
        ("__DWARF", "__debug_line") => "DWARF line number program",
        ("__DWARF", "__debug_str") => "DWARF strings",
        ("__DWARF", "__debug_str_offs") => "DWARF string offsets",
        ("__DWARF", "__debug_line_str") => "DWARF line table strings",
        ("__DWARF", "__debug_addr") => "DWARF addresses",
        ("__DWARF", "__debug_names") => "DWARF name index",
        ("__DWARF", "__debug_aranges") => "DWARF address ranges",
        ("__DWARF", "__debug_ranges" | "__debug_rnglists") => "DWARF range lists",
        ("__DWARF", "__debug_loc" | "__debug_loclists") => "DWARF location lists",
        ("__DWARF", "__apple_names") => "Apple accelerator table: names",
        ("__DWARF", "__apple_types") => "Apple accelerator table: types",
        ("__DWARF", "__apple_namespac") => "Apple accelerator table: namespaces",
        ("__DWARF", "__apple_objc") => "Apple accelerator table: Objective-C",
        _ => return None,
    })
}

pub const REBASE_TYPE: EnumTable = &[
    (1, "REBASE_TYPE_POINTER"),
    (2, "REBASE_TYPE_TEXT_ABSOLUTE32"),
    (3, "REBASE_TYPE_TEXT_PCREL32"),
];

pub const REBASE_OPCODE: EnumTable = &[
    (0x00, "REBASE_OPCODE_DONE"),
    (0x10, "REBASE_OPCODE_SET_TYPE_IMM"),
    (0x20, "REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB"),
    (0x30, "REBASE_OPCODE_ADD_ADDR_ULEB"),
    (0x40, "REBASE_OPCODE_ADD_ADDR_IMM_SCALED"),
    (0x50, "REBASE_OPCODE_DO_REBASE_IMM_TIMES"),
    (0x60, "REBASE_OPCODE_DO_REBASE_ULEB_TIMES"),
    (0x70, "REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB"),
    (0x80, "REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB"),
];

pub const BIND_TYPE: EnumTable = &[
    (1, "BIND_TYPE_POINTER"),
    (2, "BIND_TYPE_TEXT_ABSOLUTE32"),
    (3, "BIND_TYPE_TEXT_PCREL32"),
];

pub const BIND_OPCODE: EnumTable = &[
    (0x00, "BIND_OPCODE_DONE"),
    (0x10, "BIND_OPCODE_SET_DYLIB_ORDINAL_IMM"),
    (0x20, "BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB"),
    (0x30, "BIND_OPCODE_SET_DYLIB_SPECIAL_IMM"),
    (0x40, "BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM"),
    (0x50, "BIND_OPCODE_SET_TYPE_IMM"),
    (0x60, "BIND_OPCODE_SET_ADDEND_SLEB"),
    (0x70, "BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB"),
    (0x80, "BIND_OPCODE_ADD_ADDR_ULEB"),
    (0x90, "BIND_OPCODE_DO_BIND"),
    (0xa0, "BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB"),
    (0xb0, "BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED"),
    (0xc0, "BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB"),
    (0xd0, "BIND_OPCODE_THREADED"),
];

/// `LC_LINKER_OPTIMIZATION_HINT` kinds (arm64).
pub const LOH_KIND: EnumTable = &[
    (1, "AdrpAdrp"),
    (2, "AdrpLdr"),
    (3, "AdrpAddLdr"),
    (4, "AdrpLdrGotLdr"),
    (5, "AdrpAddStr"),
    (6, "AdrpLdrGotStr"),
    (7, "AdrpAdd"),
    (8, "AdrpLdrGot"),
];

/// `objc_image_info.flags`.
pub const OBJC_IMAGE_FLAGS: FlagTable = &[
    flag(0x1, "IsReplacement"),
    flag(0x2, "SupportsGC"),
    flag(0x4, "RequiresGC"),
    flag(0x8, "OptimizedByDyld"),
    flag(0x10, "SignedClassRO"),
    flag(0x20, "IsSimulated"),
    flag(0x40, "HasCategoryClassProperties"),
    flag(0x80, "OptimizedByDyldClosure"),
];

/// Pointer authentication keys (arm64e).
pub const PAC_KEY: EnumTable = &[(0, "IA"), (1, "IB"), (2, "DA"), (3, "DB")];

/// Library ordinal kinds of `LC_*_DYLIB` commands.
pub const DYLIB_KIND: EnumTable = &[
    (0xc, "load"),
    (0xd, "id"),
    (0x8000_0018, "weak"),
    (0x8000_001f, "re-export"),
    (0x20, "lazy"),
    (0x8000_0023, "upward"),
];

/// A count with thousands separators: `2,345`.
pub fn grouped(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len().saturating_add(digits.len() / 3));
    let len = digits.len();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (len.saturating_sub(i)).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// A count with a noun, singular or plural: `1 symbol`, `2,345 symbols`.
pub fn count(n: u64, one: &str, many: &str) -> String {
    format!("{} {}", grouped(n), if n == 1 { one } else { many })
}
