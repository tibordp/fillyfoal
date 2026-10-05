//! Symbolic names for Mach-O constants.

use crate::value::{EnumTable, FlagTable, field, flag};

pub const CPU_ARCH_ABI64: u32 = 0x0100_0000;
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

/// How `file` describes each file type.
pub const FILE_TYPE_WORDS: EnumTable = &[
    (1, "object"),
    (2, "executable"),
    (3, "fixed virtual memory shared library"),
    (4, "core"),
    (5, "preload executable"),
    (6, "dynamically linked shared library"),
    (7, "dynamic linker"),
    (8, "bundle"),
    (9, "shared library stub"),
    (10, "dSYM companion file"),
    (11, "kext bundle"),
    (12, "kernel collection"),
    (13, "GPU executable"),
    (14, "GPU dylib"),
];

pub const MH_EXECUTE: u32 = 2;
pub const MH_DYLIB: u32 = 6;

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

pub const LC_REQ_DYLD: u32 = 0x8000_0000;
pub const LC_SEGMENT: u32 = 0x1;
pub const LC_SYMTAB: u32 = 0x2;
pub const LC_THREAD: u32 = 0x4;
pub const LC_UNIXTHREAD: u32 = 0x5;
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
pub const S_NON_LAZY_SYMBOL_POINTERS: u32 = 6;
pub const S_LAZY_SYMBOL_POINTERS: u32 = 7;
pub const S_SYMBOL_STUBS: u32 = 8;
pub const S_MOD_INIT_FUNC_POINTERS: u32 = 9;
pub const S_GB_ZEROFILL: u32 = 12;
pub const S_THREAD_LOCAL_ZEROFILL: u32 = 18;

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

pub const N_TYPE_FLAGS: FlagTable = &[
    flag(0x01, "N_EXT"),
    flag(0x10, "N_PEXT"),
    field(0xee, 0x02, "N_ABS"),
    field(0xee, 0x0a, "N_INDR"),
    field(0xee, 0x0c, "N_PBUD"),
    field(0xee, 0x0e, "N_SECT"),
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

/// The conventional architecture name (`arm64e`, `x86_64h`, ...).
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
    let h = crate::formats::binutil::hex_string(b).to_ascii_uppercase();
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
