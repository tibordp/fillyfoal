//! Symbolic names for PE/COFF constants.

use crate::value::{EnumTable, FlagTable, field, flag};

pub const MACHINE: EnumTable = &[
    (0x0, "UNKNOWN"),
    (0x14c, "I386"),
    (0x162, "R3000"),
    (0x166, "R4000"),
    (0x168, "R10000"),
    (0x169, "WCEMIPSV2"),
    (0x184, "ALPHA"),
    (0x1a2, "SH3"),
    (0x1a3, "SH3DSP"),
    (0x1a6, "SH4"),
    (0x1a8, "SH5"),
    (0x1c0, "ARM"),
    (0x1c2, "THUMB"),
    (0x1c4, "ARMNT"),
    (0x1d3, "AM33"),
    (0x1f0, "POWERPC"),
    (0x1f1, "POWERPCFP"),
    (0x200, "IA64"),
    (0x266, "MIPS16"),
    (0x284, "ALPHA64"),
    (0x366, "MIPSFPU"),
    (0x466, "MIPSFPU16"),
    (0xebc, "EBC"),
    (0x5032, "RISCV32"),
    (0x5064, "RISCV64"),
    (0x5128, "RISCV128"),
    (0x6232, "LOONGARCH32"),
    (0x6264, "LOONGARCH64"),
    (0x8664, "AMD64"),
    (0x9041, "M32R"),
    (0xa641, "ARM64EC"),
    (0xa64e, "ARM64X"),
    (0xaa64, "ARM64"),
];

pub const FILE_CHARACTERISTICS: FlagTable = &[
    flag(0x0001, "RELOCS_STRIPPED"),
    flag(0x0002, "EXECUTABLE_IMAGE"),
    flag(0x0004, "LINE_NUMS_STRIPPED"),
    flag(0x0008, "LOCAL_SYMS_STRIPPED"),
    flag(0x0010, "AGGRESSIVE_WS_TRIM"),
    flag(0x0020, "LARGE_ADDRESS_AWARE"),
    flag(0x0080, "BYTES_REVERSED_LO"),
    flag(0x0100, "32BIT_MACHINE"),
    flag(0x0200, "DEBUG_STRIPPED"),
    flag(0x0400, "REMOVABLE_RUN_FROM_SWAP"),
    flag(0x0800, "NET_RUN_FROM_SWAP"),
    flag(0x1000, "SYSTEM"),
    flag(0x2000, "DLL"),
    flag(0x4000, "UP_SYSTEM_ONLY"),
    flag(0x8000, "BYTES_REVERSED_HI"),
];

pub const OPTIONAL_MAGIC: EnumTable = &[(0x10b, "PE32"), (0x20b, "PE32+"), (0x107, "ROM")];

pub const SUBSYSTEM: EnumTable = &[
    (0, "UNKNOWN"),
    (1, "NATIVE"),
    (2, "WINDOWS_GUI"),
    (3, "WINDOWS_CUI"),
    (5, "OS2_CUI"),
    (7, "POSIX_CUI"),
    (8, "NATIVE_WINDOWS"),
    (9, "WINDOWS_CE_GUI"),
    (10, "EFI_APPLICATION"),
    (11, "EFI_BOOT_SERVICE_DRIVER"),
    (12, "EFI_RUNTIME_DRIVER"),
    (13, "EFI_ROM"),
    (14, "XBOX"),
    (16, "WINDOWS_BOOT_APPLICATION"),
];

pub const DLL_CHARACTERISTICS: FlagTable = &[
    flag(0x0020, "HIGH_ENTROPY_VA"),
    flag(0x0040, "DYNAMIC_BASE"),
    flag(0x0080, "FORCE_INTEGRITY"),
    flag(0x0100, "NX_COMPAT"),
    flag(0x0200, "NO_ISOLATION"),
    flag(0x0400, "NO_SEH"),
    flag(0x0800, "NO_BIND"),
    flag(0x1000, "APPCONTAINER"),
    flag(0x2000, "WDM_DRIVER"),
    flag(0x4000, "GUARD_CF"),
    flag(0x8000, "TERMINAL_SERVER_AWARE"),
];

const ALIGN: u64 = 0x00f0_0000;

pub const SECTION_CHARACTERISTICS: FlagTable = &[
    flag(0x0000_0008, "TYPE_NO_PAD"),
    flag(0x0000_0020, "CNT_CODE"),
    flag(0x0000_0040, "CNT_INITIALIZED_DATA"),
    flag(0x0000_0080, "CNT_UNINITIALIZED_DATA"),
    flag(0x0000_0100, "LNK_OTHER"),
    flag(0x0000_0200, "LNK_INFO"),
    flag(0x0000_0800, "LNK_REMOVE"),
    flag(0x0000_1000, "LNK_COMDAT"),
    flag(0x0000_8000, "GPREL"),
    flag(0x0002_0000, "MEM_PURGEABLE"),
    flag(0x0004_0000, "MEM_LOCKED"),
    flag(0x0008_0000, "MEM_PRELOAD"),
    field(ALIGN, 0x0010_0000, "ALIGN_1BYTES"),
    field(ALIGN, 0x0020_0000, "ALIGN_2BYTES"),
    field(ALIGN, 0x0030_0000, "ALIGN_4BYTES"),
    field(ALIGN, 0x0040_0000, "ALIGN_8BYTES"),
    field(ALIGN, 0x0050_0000, "ALIGN_16BYTES"),
    field(ALIGN, 0x0060_0000, "ALIGN_32BYTES"),
    field(ALIGN, 0x0070_0000, "ALIGN_64BYTES"),
    field(ALIGN, 0x0080_0000, "ALIGN_128BYTES"),
    field(ALIGN, 0x0090_0000, "ALIGN_256BYTES"),
    field(ALIGN, 0x00a0_0000, "ALIGN_512BYTES"),
    field(ALIGN, 0x00b0_0000, "ALIGN_1024BYTES"),
    field(ALIGN, 0x00c0_0000, "ALIGN_2048BYTES"),
    field(ALIGN, 0x00d0_0000, "ALIGN_4096BYTES"),
    field(ALIGN, 0x00e0_0000, "ALIGN_8192BYTES"),
    flag(0x0100_0000, "LNK_NRELOC_OVFL"),
    flag(0x0200_0000, "MEM_DISCARDABLE"),
    flag(0x0400_0000, "MEM_NOT_CACHED"),
    flag(0x0800_0000, "MEM_NOT_PAGED"),
    flag(0x1000_0000, "MEM_SHARED"),
    flag(0x2000_0000, "MEM_EXECUTE"),
    flag(0x4000_0000, "MEM_READ"),
    flag(0x8000_0000, "MEM_WRITE"),
];

pub const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const SCN_MEM_READ: u32 = 0x4000_0000;
pub const SCN_MEM_WRITE: u32 = 0x8000_0000;

pub const DATA_DIRECTORIES: [&str; 16] = [
    "Export Table",
    "Import Table",
    "Resource Table",
    "Exception Table",
    "Certificate Table",
    "Base Relocation Table",
    "Debug Directory",
    "Architecture",
    "Global Pointer",
    "TLS Table",
    "Load Config Table",
    "Bound Import",
    "Import Address Table",
    "Delay Import Descriptor",
    "CLR Runtime Header",
    "Reserved",
];

pub const DIR_EXPORT: usize = 0;
pub const DIR_IMPORT: usize = 1;
pub const DIR_RESOURCE: usize = 2;
pub const DIR_SECURITY: usize = 4;
pub const DIR_DEBUG: usize = 6;

pub const DEBUG_TYPE: EnumTable = &[
    (0, "UNKNOWN"),
    (1, "COFF"),
    (2, "CODEVIEW"),
    (3, "FPO"),
    (4, "MISC"),
    (5, "EXCEPTION"),
    (6, "FIXUP"),
    (7, "OMAP_TO_SRC"),
    (8, "OMAP_FROM_SRC"),
    (9, "BORLAND"),
    (10, "RESERVED10"),
    (11, "CLSID"),
    (12, "VC_FEATURE"),
    (13, "POGO"),
    (14, "ILTCG"),
    (15, "MPX"),
    (16, "REPRO"),
    (17, "EMBEDDED_PORTABLE_PDB"),
    (19, "PDBCHECKSUM"),
    (20, "EX_DLLCHARACTERISTICS"),
];

pub const DEBUG_TYPE_CODEVIEW: u32 = 2;

pub const RESOURCE_TYPE: EnumTable = &[
    (1, "RT_CURSOR"),
    (2, "RT_BITMAP"),
    (3, "RT_ICON"),
    (4, "RT_MENU"),
    (5, "RT_DIALOG"),
    (6, "RT_STRING"),
    (7, "RT_FONTDIR"),
    (8, "RT_FONT"),
    (9, "RT_ACCELERATOR"),
    (10, "RT_RCDATA"),
    (11, "RT_MESSAGETABLE"),
    (12, "RT_GROUP_CURSOR"),
    (14, "RT_GROUP_ICON"),
    (16, "RT_VERSION"),
    (17, "RT_DLGINCLUDE"),
    (19, "RT_PLUGPLAY"),
    (20, "RT_VXD"),
    (21, "RT_ANICURSOR"),
    (22, "RT_ANIICON"),
    (23, "RT_HTML"),
    (24, "RT_MANIFEST"),
];

pub const CERTIFICATE_REVISION: EnumTable = &[(0x100, "REVISION_1_0"), (0x200, "REVISION_2_0")];

pub const CERTIFICATE_TYPE: EnumTable = &[
    (1, "X509"),
    (2, "PKCS_SIGNED_DATA"),
    (3, "RESERVED_1"),
    (4, "TS_STACK_SIGNED"),
];
