//! Symbolic names for ELF constants.

use crate::value::{EnumTable, FlagTable, field, flag};

pub const CLASS: EnumTable = &[(0, "ELFCLASSNONE"), (1, "ELFCLASS32"), (2, "ELFCLASS64")];

pub const DATA: EnumTable = &[
    (0, "ELFDATANONE"),
    (1, "ELFDATA2LSB (little-endian)"),
    (2, "ELFDATA2MSB (big-endian)"),
];

pub const OSABI: EnumTable = &[
    (0, "UNIX System V"),
    (1, "HP-UX"),
    (2, "NetBSD"),
    (3, "GNU/Linux"),
    (4, "GNU Hurd"),
    (6, "Solaris"),
    (7, "AIX"),
    (8, "IRIX"),
    (9, "FreeBSD"),
    (10, "Tru64"),
    (11, "Novell Modesto"),
    (12, "OpenBSD"),
    (13, "OpenVMS"),
    (14, "HP NonStop Kernel"),
    (15, "AROS"),
    (16, "FenixOS"),
    (17, "Nuxi CloudABI"),
    (18, "Stratus OpenVOS"),
    (64, "ARM EABI"),
    (97, "ARM"),
    (255, "Standalone"),
];

pub const ET_REL: u16 = 1;
pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;
pub const ET_CORE: u16 = 4;

pub const TYPE: EnumTable = &[
    (0, "ET_NONE"),
    (1, "ET_REL (relocatable)"),
    (2, "ET_EXEC (executable)"),
    (3, "ET_DYN (shared object)"),
    (4, "ET_CORE (core dump)"),
];

pub const EM_386: u16 = 3;
pub const EM_MIPS: u16 = 8;
pub const EM_ARM: u16 = 40;
pub const EM_X86_64: u16 = 62;
pub const EM_AARCH64: u16 = 183;
pub const EM_RISCV: u16 = 243;
pub const EM_LOONGARCH: u16 = 258;

pub const MACHINE: EnumTable = &[
    (0, "none"),
    (1, "AT&T WE 32100"),
    (2, "SPARC"),
    (3, "Intel 80386"),
    (4, "Motorola 68000"),
    (5, "Motorola 88000"),
    (6, "Intel MCU"),
    (7, "Intel 80860"),
    (8, "MIPS"),
    (9, "IBM System/370"),
    (10, "MIPS RS3000 little-endian"),
    (15, "HP PA-RISC"),
    (17, "Fujitsu VPP500"),
    (18, "SPARC32PLUS"),
    (19, "Intel 80960"),
    (20, "PowerPC"),
    (21, "64-bit PowerPC"),
    (22, "IBM S/390"),
    (23, "Cell SPU"),
    (36, "NEC V800"),
    (37, "Fujitsu FR20"),
    (38, "TRW RH-32"),
    (39, "Motorola RCE"),
    (40, "ARM"),
    (41, "Digital Alpha (old)"),
    (42, "Renesas SuperH"),
    (43, "SPARC V9"),
    (44, "Siemens TriCore"),
    (45, "Argonaut RISC Core"),
    (46, "Renesas H8/300"),
    (47, "Renesas H8/300H"),
    (48, "Renesas H8S"),
    (49, "Renesas H8/500"),
    (50, "Intel IA-64"),
    (51, "Stanford MIPS-X"),
    (52, "Motorola ColdFire"),
    (53, "Motorola M68HC12"),
    (54, "Fujitsu MMA"),
    (55, "Siemens PCP"),
    (56, "Sony nCPU"),
    (57, "Denso NDR1"),
    (58, "Motorola StarCore"),
    (59, "Toyota ME16"),
    (60, "STMicroelectronics ST100"),
    (61, "Advanced Logic TinyJ"),
    (62, "x86-64"),
    (63, "Sony DSP"),
    (64, "DEC PDP-10"),
    (65, "DEC PDP-11"),
    (66, "Siemens FX66"),
    (67, "STMicroelectronics ST9+"),
    (68, "STMicroelectronics ST7"),
    (69, "Motorola MC68HC16"),
    (70, "Motorola MC68HC11"),
    (71, "Motorola MC68HC08"),
    (72, "Motorola MC68HC05"),
    (73, "Silicon Graphics SVx"),
    (74, "STMicroelectronics ST19"),
    (75, "DEC VAX"),
    (76, "Axis CRIS"),
    (77, "Infineon JAVELIN"),
    (78, "Element 14 FirePath"),
    (79, "LSI ZSP"),
    (80, "Knuth MMIX"),
    (81, "Harvard HUANY"),
    (82, "SiTera Prism"),
    (83, "Atmel AVR"),
    (84, "Fujitsu FR30"),
    (85, "Mitsubishi D10V"),
    (86, "Mitsubishi D30V"),
    (87, "NEC V850"),
    (88, "Renesas M32R"),
    (89, "Matsushita MN10300"),
    (90, "Matsushita MN10200"),
    (91, "picoJava"),
    (92, "OpenRISC"),
    (93, "ARC Compact"),
    (94, "Tensilica Xtensa"),
    (95, "Alphamosaic VideoCore"),
    (96, "Thompson GPP"),
    (97, "National Semiconductor 32000"),
    (98, "Tenor TPC"),
    (99, "Trebia SNP 1000"),
    (100, "STMicroelectronics ST200"),
    (101, "Ubicom IP2xxx"),
    (102, "MAX"),
    (103, "National Semiconductor CompactRISC"),
    (104, "Fujitsu F2MC16"),
    (105, "TI MSP430"),
    (106, "Analog Devices Blackfin"),
    (107, "Seiko Epson S1C33"),
    (108, "Sharp embedded"),
    (109, "Arca RISC"),
    (110, "Unicore"),
    (113, "Altera Nios II"),
    (117, "ARM AArch32"),
    (138, "Lattice Mico32"),
    (140, "TI C6000"),
    (164, "Qualcomm Hexagon"),
    (183, "ARM aarch64"),
    (185, "Atmel AVR32"),
    (186, "STMicroelectronics STM8"),
    (188, "Tilera TILE64"),
    (189, "Xilinx MicroBlaze"),
    (190, "NVIDIA CUDA"),
    (191, "Tilera TILE-Gx"),
    (195, "ARC Compact V2"),
    (220, "Zilog Z80"),
    (224, "AMD GPU"),
    (243, "RISC-V"),
    (247, "Linux BPF"),
    (252, "C-SKY"),
    (258, "LoongArch"),
    (0x9026, "Digital Alpha"),
    (0x9041, "Renesas M32R (old)"),
    (0x9080, "Renesas V850 (old)"),
    (0xa390, "IBM S/390 (old)"),
];

pub const EF_ARM: FlagTable = &[
    field(0xff00_0000, 0x0100_0000, "EABI_VER1"),
    field(0xff00_0000, 0x0200_0000, "EABI_VER2"),
    field(0xff00_0000, 0x0300_0000, "EABI_VER3"),
    field(0xff00_0000, 0x0400_0000, "EABI_VER4"),
    field(0xff00_0000, 0x0500_0000, "EABI_VER5"),
    flag(0x0080_0000, "BE8"),
    flag(0x0000_0400, "ABI_FLOAT_HARD"),
    flag(0x0000_0200, "ABI_FLOAT_SOFT"),
];

pub const EF_RISCV: FlagTable = &[
    flag(0x1, "RVC"),
    field(0x6, 0x2, "FLOAT_ABI_SINGLE"),
    field(0x6, 0x4, "FLOAT_ABI_DOUBLE"),
    field(0x6, 0x6, "FLOAT_ABI_QUAD"),
    flag(0x8, "RVE"),
    flag(0x10, "TSO"),
];

pub const EF_MIPS: FlagTable = &[
    flag(0x1, "NOREORDER"),
    flag(0x2, "PIC"),
    flag(0x4, "CPIC"),
    flag(0x20, "ABI2"),
    flag(0x400, "NAN2008"),
    field(0xf000_0000, 0x0000_0000, "ARCH_1"),
    field(0xf000_0000, 0x1000_0000, "ARCH_2"),
    field(0xf000_0000, 0x2000_0000, "ARCH_3"),
    field(0xf000_0000, 0x3000_0000, "ARCH_4"),
    field(0xf000_0000, 0x4000_0000, "ARCH_5"),
    field(0xf000_0000, 0x5000_0000, "ARCH_32"),
    field(0xf000_0000, 0x6000_0000, "ARCH_64"),
    field(0xf000_0000, 0x7000_0000, "ARCH_32R2"),
    field(0xf000_0000, 0x8000_0000, "ARCH_64R2"),
    field(0xf000_0000, 0x9000_0000, "ARCH_32R6"),
    field(0xf000_0000, 0xa000_0000, "ARCH_64R6"),
    field(0x0000_f000, 0x0000_1000, "ABI_O32"),
    field(0x0000_f000, 0x0000_2000, "ABI_O64"),
    field(0x0000_f000, 0x0000_3000, "ABI_EABI32"),
    field(0x0000_f000, 0x0000_4000, "ABI_EABI64"),
];

pub const EF_LOONGARCH: FlagTable = &[
    field(0x7, 0x1, "ABI_SOFT_FLOAT"),
    field(0x7, 0x2, "ABI_SINGLE_FLOAT"),
    field(0x7, 0x3, "ABI_DOUBLE_FLOAT"),
    field(0xc0, 0x40, "OBJABI_V1"),
];

pub const EF_NONE: FlagTable = &[];

pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_NOTE: u32 = 4;

pub const SEGMENT_TYPE: EnumTable = &[
    (0, "NULL"),
    (1, "LOAD"),
    (2, "DYNAMIC"),
    (3, "INTERP"),
    (4, "NOTE"),
    (5, "SHLIB"),
    (6, "PHDR"),
    (7, "TLS"),
    (0x6474_e550, "GNU_EH_FRAME"),
    (0x6474_e551, "GNU_STACK"),
    (0x6474_e552, "GNU_RELRO"),
    (0x6474_e553, "GNU_PROPERTY"),
    (0x6474_e554, "GNU_SFRAME"),
    (0x65a3_dbe6, "OPENBSD_RANDOMIZE"),
    (0x65a3_dbe7, "OPENBSD_WXNEEDED"),
    (0x65a3_dbe8, "OPENBSD_NOBTCFI"),
    (0x65a4_1be6, "OPENBSD_BOOTDATA"),
    (0x6fff_fffa, "SUNWBSS"),
    (0x6fff_fffb, "SUNWSTACK"),
    (0x7000_0000, "PROC_0 (ARM_ARCHEXT / MIPS_REGINFO)"),
    (0x7000_0001, "PROC_1 (ARM_EXIDX / MIPS_RTPROC)"),
    (0x7000_0002, "PROC_2 (MIPS_OPTIONS / AARCH64_MEMTAG_MTE)"),
    (0x7000_0003, "PROC_3 (MIPS_ABIFLAGS / RISCV_ATTRIBUTES)"),
];

pub const SEGMENT_FLAGS: FlagTable = &[flag(4, "R"), flag(2, "W"), flag(1, "X")];

pub const SHT_SYMTAB: u32 = 2;
pub const SHT_STRTAB: u32 = 3;
pub const SHT_RELA: u32 = 4;
pub const SHT_HASH: u32 = 5;
pub const SHT_DYNAMIC: u32 = 6;
pub const SHT_NOTE: u32 = 7;
pub const SHT_NOBITS: u32 = 8;
pub const SHT_REL: u32 = 9;
pub const SHT_DYNSYM: u32 = 11;
pub const SHT_INIT_ARRAY: u32 = 14;
pub const SHT_FINI_ARRAY: u32 = 15;
pub const SHT_PREINIT_ARRAY: u32 = 16;
pub const SHT_GROUP: u32 = 17;
pub const SHT_RELR: u32 = 19;
pub const SHT_GNU_VERDEF: u32 = 0x6fff_fffd;
pub const SHT_GNU_VERNEED: u32 = 0x6fff_fffe;
pub const SHT_GNU_VERSYM: u32 = 0x6fff_ffff;

pub const SECTION_TYPE: EnumTable = &[
    (0, "NULL"),
    (1, "PROGBITS"),
    (2, "SYMTAB"),
    (3, "STRTAB"),
    (4, "RELA"),
    (5, "HASH"),
    (6, "DYNAMIC"),
    (7, "NOTE"),
    (8, "NOBITS"),
    (9, "REL"),
    (10, "SHLIB"),
    (11, "DYNSYM"),
    (14, "INIT_ARRAY"),
    (15, "FINI_ARRAY"),
    (16, "PREINIT_ARRAY"),
    (17, "GROUP"),
    (18, "SYMTAB_SHNDX"),
    (19, "RELR"),
    (0x6000_0001, "ANDROID_REL"),
    (0x6000_0002, "ANDROID_RELA"),
    (0x6fff_4c00, "LLVM_ODRTAB"),
    (0x6fff_4c01, "LLVM_LINKER_OPTIONS"),
    (0x6fff_4c02, "LLVM_CALL_GRAPH_PROFILE (old)"),
    (0x6fff_4c03, "LLVM_ADDRSIG"),
    (0x6fff_4c04, "LLVM_DEPENDENT_LIBRARIES"),
    (0x6fff_4c05, "LLVM_SYMPART"),
    (0x6fff_4c06, "LLVM_PART_EHDR"),
    (0x6fff_4c07, "LLVM_PART_PHDR"),
    (0x6fff_4c08, "LLVM_BB_ADDR_MAP (old)"),
    (0x6fff_4c09, "LLVM_CALL_GRAPH_PROFILE"),
    (0x6fff_4c0a, "LLVM_BB_ADDR_MAP"),
    (0x6fff_4c0b, "LLVM_OFFLOADING"),
    (0x6fff_4c0c, "LLVM_LTO"),
    (0x6fff_fff5, "GNU_ATTRIBUTES"),
    (0x6fff_fff6, "GNU_HASH"),
    (0x6fff_fff7, "GNU_LIBLIST"),
    (0x6fff_fff8, "CHECKSUM"),
    (0x6fff_fffd, "GNU_verdef"),
    (0x6fff_fffe, "GNU_verneed"),
    (0x6fff_ffff, "GNU_versym"),
    (0x7000_0001, "PROC_1 (ARM_EXIDX / X86_64_UNWIND)"),
    (0x7000_0002, "ARM_PREEMPTMAP"),
    (0x7000_0003, "PROC_3 (ARM_ATTRIBUTES / RISCV_ATTRIBUTES)"),
    (0x7000_0006, "MIPS_REGINFO"),
    (0x7000_000d, "MIPS_OPTIONS"),
    (0x7000_001e, "MIPS_DWARF"),
    (0x7000_002a, "MIPS_ABIFLAGS"),
];

pub const SHF_COMPRESSED: u64 = 0x800;

pub const SECTION_FLAGS: FlagTable = &[
    flag(0x1, "WRITE"),
    flag(0x2, "ALLOC"),
    flag(0x4, "EXECINSTR"),
    flag(0x10, "MERGE"),
    flag(0x20, "STRINGS"),
    flag(0x40, "INFO_LINK"),
    flag(0x80, "LINK_ORDER"),
    flag(0x100, "OS_NONCONFORMING"),
    flag(0x200, "GROUP"),
    flag(0x400, "TLS"),
    flag(0x800, "COMPRESSED"),
    flag(0x20_0000, "GNU_RETAIN"),
    flag(0x1000_0000, "X86_64_LARGE / ARM_PURECODE"),
    flag(0x4000_0000, "ORDERED"),
    flag(0x8000_0000, "EXCLUDE"),
];

pub const SHN_LORESERVE: u16 = 0xff00;
pub const SHN_XINDEX: u16 = 0xffff;

pub const COMPRESSION: EnumTable = &[(1, "ZLIB"), (2, "ZSTD")];

pub const GROUP_FLAGS: FlagTable = &[flag(1, "GRP_COMDAT")];

pub const SYMBOL_BIND: EnumTable = &[(0, "LOCAL"), (1, "GLOBAL"), (2, "WEAK"), (10, "GNU_UNIQUE")];

pub const SYMBOL_TYPE: EnumTable = &[
    (0, "NOTYPE"),
    (1, "OBJECT"),
    (2, "FUNC"),
    (3, "SECTION"),
    (4, "FILE"),
    (5, "COMMON"),
    (6, "TLS"),
    (10, "GNU_IFUNC"),
];

pub const STT_SECTION: u8 = 3;

pub const SYMBOL_VISIBILITY: EnumTable = &[
    (0, "DEFAULT"),
    (1, "INTERNAL"),
    (2, "HIDDEN"),
    (3, "PROTECTED"),
];

pub const DT_NULL: u64 = 0;
pub const DT_NEEDED: u64 = 1;
pub const DT_STRTAB: u64 = 5;
pub const DT_STRSZ: u64 = 10;
pub const DT_SONAME: u64 = 14;
pub const DT_RPATH: u64 = 15;
pub const DT_RUNPATH: u64 = 29;
pub const DT_FLAGS: u64 = 30;
pub const DT_FLAGS_1: u64 = 0x6fff_fffb;
pub const DT_POSFLAG_1: u64 = 0x6fff_fdfd;

/// Tags whose value is an offset into the dynamic string table.
pub const DT_STRINGS: &[u64] = &[
    DT_NEEDED,
    DT_SONAME,
    DT_RPATH,
    DT_RUNPATH,
    0x6fff_fdfe, // DT_DEPAUDIT
    0x6fff_fefa, // DT_CONFIG
    0x6fff_fefb, // DT_DEPAUDIT
    0x6fff_fefc, // DT_AUDIT
    0x7fff_fffd, // DT_AUXILIARY
    0x7fff_ffff, // DT_FILTER
];

/// Tags whose value is an address.
pub const DT_ADDRESSES: &[u64] = &[
    3,
    4,
    5,
    6,
    7,
    12,
    13,
    17,
    21,
    23,
    25,
    26,
    32,
    34,
    36,
    0x6fff_fef5,
    0x6fff_fef6,
    0x6fff_fef7,
    0x6fff_fef8,
    0x6fff_fef9,
    0x6fff_fefa,
    0x6fff_fefb,
    0x6fff_fefc,
    0x6fff_fefd,
    0x6fff_fefe,
    0x6fff_feff,
    0x6fff_fff0,
    0x6fff_fffc,
    0x6fff_fffe,
    0x7000_0016,
];

pub const DYNAMIC_TAG: EnumTable = &[
    (0, "NULL"),
    (1, "NEEDED"),
    (2, "PLTRELSZ"),
    (3, "PLTGOT"),
    (4, "HASH"),
    (5, "STRTAB"),
    (6, "SYMTAB"),
    (7, "RELA"),
    (8, "RELASZ"),
    (9, "RELAENT"),
    (10, "STRSZ"),
    (11, "SYMENT"),
    (12, "INIT"),
    (13, "FINI"),
    (14, "SONAME"),
    (15, "RPATH"),
    (16, "SYMBOLIC"),
    (17, "REL"),
    (18, "RELSZ"),
    (19, "RELENT"),
    (20, "PLTREL"),
    (21, "DEBUG"),
    (22, "TEXTREL"),
    (23, "JMPREL"),
    (24, "BIND_NOW"),
    (25, "INIT_ARRAY"),
    (26, "FINI_ARRAY"),
    (27, "INIT_ARRAYSZ"),
    (28, "FINI_ARRAYSZ"),
    (29, "RUNPATH"),
    (30, "FLAGS"),
    (32, "PREINIT_ARRAY"),
    (33, "PREINIT_ARRAYSZ"),
    (34, "SYMTAB_SHNDX"),
    (35, "RELRSZ"),
    (36, "RELR"),
    (37, "RELRENT"),
    (0x6000_000d, "ANDROID_REL"),
    (0x6000_000e, "ANDROID_RELSZ"),
    (0x6000_000f, "ANDROID_RELA"),
    (0x6000_0010, "ANDROID_RELASZ"),
    (0x6fff_e000, "ANDROID_RELR"),
    (0x6fff_e001, "ANDROID_RELRSZ"),
    (0x6fff_e003, "ANDROID_RELRENT"),
    (0x6fff_fdf5, "GNU_PRELINKED"),
    (0x6fff_fdf6, "GNU_CONFLICTSZ"),
    (0x6fff_fdf7, "GNU_LIBLISTSZ"),
    (0x6fff_fdf8, "CHECKSUM"),
    (0x6fff_fdf9, "PLTPADSZ"),
    (0x6fff_fdfa, "MOVEENT"),
    (0x6fff_fdfb, "MOVESZ"),
    (0x6fff_fdfc, "FEATURE_1"),
    (0x6fff_fdfd, "POSFLAG_1"),
    (0x6fff_fdfe, "SYMINSZ"),
    (0x6fff_fdff, "SYMINENT"),
    (0x6fff_fef5, "GNU_HASH"),
    (0x6fff_fef6, "TLSDESC_PLT"),
    (0x6fff_fef7, "TLSDESC_GOT"),
    (0x6fff_fef8, "GNU_CONFLICT"),
    (0x6fff_fef9, "GNU_LIBLIST"),
    (0x6fff_fefa, "CONFIG"),
    (0x6fff_fefb, "DEPAUDIT"),
    (0x6fff_fefc, "AUDIT"),
    (0x6fff_fefd, "PLTPAD"),
    (0x6fff_fefe, "MOVETAB"),
    (0x6fff_feff, "SYMINFO"),
    (0x6fff_fff0, "VERSYM"),
    (0x6fff_fff9, "RELACOUNT"),
    (0x6fff_fffa, "RELCOUNT"),
    (0x6fff_fffb, "FLAGS_1"),
    (0x6fff_fffc, "VERDEF"),
    (0x6fff_fffd, "VERDEFNUM"),
    (0x6fff_fffe, "VERNEED"),
    (0x6fff_ffff, "VERNEEDNUM"),
    (0x7000_0001, "PROC_1 (MIPS_RLD_VERSION / AARCH64_BTI_PLT)"),
    (0x7000_0016, "MIPS_RLD_MAP"),
    (0x7fff_fffd, "AUXILIARY"),
    (0x7fff_ffff, "FILTER"),
];

pub const DYNAMIC_FLAGS: FlagTable = &[
    flag(0x1, "ORIGIN"),
    flag(0x2, "SYMBOLIC"),
    flag(0x4, "TEXTREL"),
    flag(0x8, "BIND_NOW"),
    flag(0x10, "STATIC_TLS"),
];

pub const DF_1_PIE: u64 = 0x0800_0000;

pub const DYNAMIC_FLAGS_1: FlagTable = &[
    flag(0x1, "NOW"),
    flag(0x2, "GLOBAL"),
    flag(0x4, "GROUP"),
    flag(0x8, "NODELETE"),
    flag(0x10, "LOADFLTR"),
    flag(0x20, "INITFIRST"),
    flag(0x40, "NOOPEN"),
    flag(0x80, "ORIGIN"),
    flag(0x100, "DIRECT"),
    flag(0x200, "TRANS"),
    flag(0x400, "INTERPOSE"),
    flag(0x800, "NODEFLIB"),
    flag(0x1000, "NODUMP"),
    flag(0x2000, "CONFALT"),
    flag(0x4000, "ENDFILTEE"),
    flag(0x8000, "DISPRELDNE"),
    flag(0x1_0000, "DISPRELPND"),
    flag(0x2_0000, "NODIRECT"),
    flag(0x4_0000, "IGNMULDEF"),
    flag(0x8_0000, "NOKSYMS"),
    flag(0x10_0000, "NOHDR"),
    flag(0x20_0000, "EDITED"),
    flag(0x40_0000, "NORELOC"),
    flag(0x80_0000, "SYMINTPOSE"),
    flag(0x100_0000, "GLOBAUDIT"),
    flag(0x200_0000, "SINGLETON"),
    flag(0x400_0000, "STUB"),
    flag(0x800_0000, "PIE"),
];

pub const POSFLAGS_1: FlagTable = &[flag(0x1, "LAZYLOAD"), flag(0x2, "GROUPPERM")];

pub const GNU_ABI_TAG_OS: EnumTable = &[
    (0, "Linux"),
    (1, "GNU Hurd"),
    (2, "Solaris"),
    (3, "FreeBSD"),
    (4, "NetBSD"),
    (5, "Syllable"),
    (6, "NaCl"),
];

/// Note types for notes named "GNU".
pub const NOTE_GNU: EnumTable = &[
    (1, "NT_GNU_ABI_TAG"),
    (2, "NT_GNU_HWCAP"),
    (3, "NT_GNU_BUILD_ID"),
    (4, "NT_GNU_GOLD_VERSION"),
    (5, "NT_GNU_PROPERTY_TYPE_0"),
    (0x100, "NT_GNU_BUILD_ATTRIBUTE_OPEN"),
    (0x101, "NT_GNU_BUILD_ATTRIBUTE_FUNC"),
];

/// Note types in core files ("CORE" and "LINUX" notes).
pub const NOTE_CORE: EnumTable = &[
    (1, "NT_PRSTATUS"),
    (2, "NT_PRFPREG"),
    (3, "NT_PRPSINFO"),
    (4, "NT_TASKSTRUCT"),
    (6, "NT_AUXV"),
    (10, "NT_PSTATUS"),
    (12, "NT_FPREGS"),
    (13, "NT_PSINFO"),
    (16, "NT_LWPSTATUS"),
    (17, "NT_LWPSINFO"),
    (18, "NT_WIN32PSTATUS"),
    (0x100, "NT_PPC_VMX"),
    (0x102, "NT_PPC_VSX"),
    (0x200, "NT_386_TLS"),
    (0x201, "NT_386_IOPERM"),
    (0x202, "NT_X86_XSTATE"),
    (0x203, "NT_X86_SHSTK"),
    (0x204, "NT_X86_XSAVE_LAYOUT"),
    (0x300, "NT_S390_HIGH_GPRS"),
    (0x400, "NT_ARM_VFP"),
    (0x401, "NT_ARM_TLS"),
    (0x402, "NT_ARM_HW_BREAK"),
    (0x403, "NT_ARM_HW_WATCH"),
    (0x404, "NT_ARM_SYSTEM_CALL"),
    (0x405, "NT_ARM_SVE"),
    (0x406, "NT_ARM_PAC_MASK"),
    (0x407, "NT_ARM_PACA_KEYS"),
    (0x408, "NT_ARM_PACG_KEYS"),
    (0x409, "NT_ARM_TAGGED_ADDR_CTRL"),
    (0x40a, "NT_ARM_PAC_ENABLED_KEYS"),
    (0x40b, "NT_ARM_SSVE"),
    (0x40c, "NT_ARM_ZA"),
    (0x40d, "NT_ARM_ZT"),
    (0x40e, "NT_ARM_FPMR"),
    (0x40f, "NT_ARM_POE"),
    (0x410, "NT_ARM_GCS"),
    (0x900, "NT_RISCV_CSR"),
    (0x901, "NT_RISCV_VECTOR"),
    (0xa00, "NT_LOONGARCH_CPUCFG"),
    (0x4649_4c45, "NT_FILE"),
    (0x5349_4749, "NT_SIGINFO"),
];

pub const NT_PRSTATUS: u32 = 1;
pub const NT_PRPSINFO: u32 = 3;
pub const NT_AUXV: u32 = 6;
pub const NT_FILE: u32 = 0x4649_4c45;

pub const NOTE_FREEBSD: EnumTable = &[
    (1, "NT_FREEBSD_ABI_TAG"),
    (2, "NT_FREEBSD_NOINIT_TAG"),
    (3, "NT_FREEBSD_ARCH_TAG"),
    (4, "NT_FREEBSD_FEATURE_CTL"),
];

pub const NOTE_STAPSDT: EnumTable = &[(3, "NT_STAPSDT")];
pub const NOTE_GO: EnumTable = &[(4, "NT_GO_BUILD_ID")];
pub const NOTE_ANDROID: EnumTable = &[
    (1, "NT_ANDROID_TYPE_IDENT"),
    (3, "NT_ANDROID_TYPE_KUSER"),
    (4, "NT_ANDROID_TYPE_MEMTAG"),
    (5, "NT_ANDROID_TYPE_PAD_SEGMENT"),
];
pub const NOTE_FDO: EnumTable = &[(0xcafe_1a7e, "NT_FDO_PACKAGING_METADATA")];
pub const NOTE_XEN: EnumTable = &[
    (1, "XEN_ELFNOTE_INFO"),
    (2, "XEN_ELFNOTE_ENTRY"),
    (3, "XEN_ELFNOTE_HYPERCALL_PAGE"),
    (5, "XEN_ELFNOTE_GUEST_OS"),
    (6, "XEN_ELFNOTE_GUEST_VERSION"),
    (7, "XEN_ELFNOTE_LOADER"),
    (18, "XEN_ELFNOTE_PHYS32_ENTRY"),
];

pub const GNU_PROPERTY: EnumTable = &[
    (1, "GNU_PROPERTY_STACK_SIZE"),
    (2, "GNU_PROPERTY_NO_COPY_ON_PROTECTED"),
    (3, "GNU_PROPERTY_MEMORY_SEAL"),
    (0xb000_8000, "GNU_PROPERTY_1_NEEDED"),
    (0xc000_0000, "GNU_PROPERTY_AARCH64_FEATURE_1_AND"),
    (0xc000_0001, "GNU_PROPERTY_AARCH64_FEATURE_PAUTH"),
    (0xc000_0002, "GNU_PROPERTY_X86_FEATURE_1_AND"),
    (0xc000_8001, "GNU_PROPERTY_X86_FEATURE_2_NEEDED"),
    (0xc000_8002, "GNU_PROPERTY_X86_ISA_1_NEEDED"),
    (0xc001_0001, "GNU_PROPERTY_X86_FEATURE_2_USED"),
    (0xc001_0002, "GNU_PROPERTY_X86_ISA_1_USED"),
];

pub const GNU_PROPERTY_AARCH64_FEATURE_1_AND: u32 = 0xc000_0000;
pub const GNU_PROPERTY_X86_FEATURE_1_AND: u32 = 0xc000_0002;
pub const GNU_PROPERTY_X86_ISA_1_NEEDED: u32 = 0xc000_8002;
pub const GNU_PROPERTY_X86_ISA_1_USED: u32 = 0xc001_0002;

pub const X86_FEATURE_1: FlagTable = &[
    flag(1, "IBT"),
    flag(2, "SHSTK"),
    flag(4, "LAM_U48"),
    flag(8, "LAM_U57"),
];
pub const AARCH64_FEATURE_1: FlagTable = &[flag(1, "BTI"), flag(2, "PAC"), flag(4, "GCS")];
pub const X86_ISA_1: FlagTable = &[
    flag(1, "x86-64-baseline"),
    flag(2, "x86-64-v2"),
    flag(4, "x86-64-v3"),
    flag(8, "x86-64-v4"),
];

pub const AUXV: EnumTable = &[
    (0, "AT_NULL"),
    (3, "AT_PHDR"),
    (4, "AT_PHENT"),
    (5, "AT_PHNUM"),
    (6, "AT_PAGESZ"),
    (7, "AT_BASE"),
    (8, "AT_FLAGS"),
    (9, "AT_ENTRY"),
    (11, "AT_UID"),
    (12, "AT_EUID"),
    (13, "AT_GID"),
    (14, "AT_EGID"),
    (15, "AT_PLATFORM"),
    (16, "AT_HWCAP"),
    (17, "AT_CLKTCK"),
    (23, "AT_SECURE"),
    (24, "AT_BASE_PLATFORM"),
    (25, "AT_RANDOM"),
    (26, "AT_HWCAP2"),
    (27, "AT_RSEQ_FEATURE_SIZE"),
    (28, "AT_RSEQ_ALIGN"),
    (29, "AT_HWCAP3"),
    (30, "AT_HWCAP4"),
    (31, "AT_EXECFN"),
    (32, "AT_SYSINFO"),
    (33, "AT_SYSINFO_EHDR"),
    (51, "AT_MINSIGSTKSZ"),
];

pub const SIGNAL: EnumTable = &[
    (1, "SIGHUP"),
    (2, "SIGINT"),
    (3, "SIGQUIT"),
    (4, "SIGILL"),
    (5, "SIGTRAP"),
    (6, "SIGABRT"),
    (7, "SIGBUS"),
    (8, "SIGFPE"),
    (9, "SIGKILL"),
    (10, "SIGUSR1"),
    (11, "SIGSEGV"),
    (12, "SIGUSR2"),
    (13, "SIGPIPE"),
    (14, "SIGALRM"),
    (15, "SIGTERM"),
];

pub const VERSION_FLAGS: FlagTable = &[flag(1, "BASE"), flag(2, "WEAK"), flag(4, "INFO")];

// --- Relocation types, per machine

pub const R_X86_64: EnumTable = &[
    (0, "R_X86_64_NONE"),
    (1, "R_X86_64_64"),
    (2, "R_X86_64_PC32"),
    (3, "R_X86_64_GOT32"),
    (4, "R_X86_64_PLT32"),
    (5, "R_X86_64_COPY"),
    (6, "R_X86_64_GLOB_DAT"),
    (7, "R_X86_64_JUMP_SLOT"),
    (8, "R_X86_64_RELATIVE"),
    (9, "R_X86_64_GOTPCREL"),
    (10, "R_X86_64_32"),
    (11, "R_X86_64_32S"),
    (12, "R_X86_64_16"),
    (13, "R_X86_64_PC16"),
    (14, "R_X86_64_8"),
    (15, "R_X86_64_PC8"),
    (16, "R_X86_64_DTPMOD64"),
    (17, "R_X86_64_DTPOFF64"),
    (18, "R_X86_64_TPOFF64"),
    (19, "R_X86_64_TLSGD"),
    (20, "R_X86_64_TLSLD"),
    (21, "R_X86_64_DTPOFF32"),
    (22, "R_X86_64_GOTTPOFF"),
    (23, "R_X86_64_TPOFF32"),
    (24, "R_X86_64_PC64"),
    (25, "R_X86_64_GOTOFF64"),
    (26, "R_X86_64_GOTPC32"),
    (27, "R_X86_64_GOT64"),
    (28, "R_X86_64_GOTPCREL64"),
    (29, "R_X86_64_GOTPC64"),
    (30, "R_X86_64_GOTPLT64"),
    (31, "R_X86_64_PLTOFF64"),
    (32, "R_X86_64_SIZE32"),
    (33, "R_X86_64_SIZE64"),
    (34, "R_X86_64_GOTPC32_TLSDESC"),
    (35, "R_X86_64_TLSDESC_CALL"),
    (36, "R_X86_64_TLSDESC"),
    (37, "R_X86_64_IRELATIVE"),
    (38, "R_X86_64_RELATIVE64"),
    (41, "R_X86_64_GOTPCRELX"),
    (42, "R_X86_64_REX_GOTPCRELX"),
    (43, "R_X86_64_CODE_4_GOTPCRELX"),
    (44, "R_X86_64_CODE_4_GOTTPOFF"),
    (45, "R_X86_64_CODE_4_GOTPC32_TLSDESC"),
];

pub const R_386: EnumTable = &[
    (0, "R_386_NONE"),
    (1, "R_386_32"),
    (2, "R_386_PC32"),
    (3, "R_386_GOT32"),
    (4, "R_386_PLT32"),
    (5, "R_386_COPY"),
    (6, "R_386_GLOB_DAT"),
    (7, "R_386_JMP_SLOT"),
    (8, "R_386_RELATIVE"),
    (9, "R_386_GOTOFF"),
    (10, "R_386_GOTPC"),
    (11, "R_386_32PLT"),
    (14, "R_386_TLS_TPOFF"),
    (15, "R_386_TLS_IE"),
    (16, "R_386_TLS_GOTIE"),
    (17, "R_386_TLS_LE"),
    (18, "R_386_TLS_GD"),
    (19, "R_386_TLS_LDM"),
    (20, "R_386_16"),
    (21, "R_386_PC16"),
    (22, "R_386_8"),
    (23, "R_386_PC8"),
    (35, "R_386_TLS_DTPMOD32"),
    (36, "R_386_TLS_DTPOFF32"),
    (37, "R_386_TLS_TPOFF32"),
    (38, "R_386_SIZE32"),
    (39, "R_386_TLS_GOTDESC"),
    (40, "R_386_TLS_DESC_CALL"),
    (41, "R_386_TLS_DESC"),
    (42, "R_386_IRELATIVE"),
    (43, "R_386_GOT32X"),
];

pub const R_AARCH64: EnumTable = &[
    (0, "R_AARCH64_NONE"),
    (257, "R_AARCH64_ABS64"),
    (258, "R_AARCH64_ABS32"),
    (259, "R_AARCH64_ABS16"),
    (260, "R_AARCH64_PREL64"),
    (261, "R_AARCH64_PREL32"),
    (262, "R_AARCH64_PREL16"),
    (263, "R_AARCH64_MOVW_UABS_G0"),
    (264, "R_AARCH64_MOVW_UABS_G0_NC"),
    (265, "R_AARCH64_MOVW_UABS_G1"),
    (266, "R_AARCH64_MOVW_UABS_G1_NC"),
    (267, "R_AARCH64_MOVW_UABS_G2"),
    (268, "R_AARCH64_MOVW_UABS_G2_NC"),
    (269, "R_AARCH64_MOVW_UABS_G3"),
    (270, "R_AARCH64_MOVW_SABS_G0"),
    (271, "R_AARCH64_MOVW_SABS_G1"),
    (272, "R_AARCH64_MOVW_SABS_G2"),
    (273, "R_AARCH64_LD_PREL_LO19"),
    (274, "R_AARCH64_ADR_PREL_LO21"),
    (275, "R_AARCH64_ADR_PREL_PG_HI21"),
    (276, "R_AARCH64_ADR_PREL_PG_HI21_NC"),
    (277, "R_AARCH64_ADD_ABS_LO12_NC"),
    (278, "R_AARCH64_LDST8_ABS_LO12_NC"),
    (279, "R_AARCH64_TSTBR14"),
    (280, "R_AARCH64_CONDBR19"),
    (282, "R_AARCH64_JUMP26"),
    (283, "R_AARCH64_CALL26"),
    (284, "R_AARCH64_LDST16_ABS_LO12_NC"),
    (285, "R_AARCH64_LDST32_ABS_LO12_NC"),
    (286, "R_AARCH64_LDST64_ABS_LO12_NC"),
    (299, "R_AARCH64_LDST128_ABS_LO12_NC"),
    (311, "R_AARCH64_ADR_GOT_PAGE"),
    (312, "R_AARCH64_LD64_GOT_LO12_NC"),
    (1024, "R_AARCH64_COPY"),
    (1025, "R_AARCH64_GLOB_DAT"),
    (1026, "R_AARCH64_JUMP_SLOT"),
    (1027, "R_AARCH64_RELATIVE"),
    (1028, "R_AARCH64_TLS_DTPMOD"),
    (1029, "R_AARCH64_TLS_DTPREL"),
    (1030, "R_AARCH64_TLS_TPREL"),
    (1031, "R_AARCH64_TLSDESC"),
    (1032, "R_AARCH64_IRELATIVE"),
];

pub const R_ARM: EnumTable = &[
    (0, "R_ARM_NONE"),
    (1, "R_ARM_PC24"),
    (2, "R_ARM_ABS32"),
    (3, "R_ARM_REL32"),
    (10, "R_ARM_THM_CALL"),
    (17, "R_ARM_TLS_DTPMOD32"),
    (18, "R_ARM_TLS_DTPOFF32"),
    (19, "R_ARM_TLS_TPOFF32"),
    (20, "R_ARM_COPY"),
    (21, "R_ARM_GLOB_DAT"),
    (22, "R_ARM_JUMP_SLOT"),
    (23, "R_ARM_RELATIVE"),
    (24, "R_ARM_GOTOFF32"),
    (25, "R_ARM_BASE_PREL"),
    (26, "R_ARM_GOT_BREL"),
    (27, "R_ARM_PLT32"),
    (28, "R_ARM_CALL"),
    (29, "R_ARM_JUMP24"),
    (30, "R_ARM_THM_JUMP24"),
    (38, "R_ARM_TARGET1"),
    (40, "R_ARM_V4BX"),
    (42, "R_ARM_PREL31"),
    (43, "R_ARM_MOVW_ABS_NC"),
    (44, "R_ARM_MOVT_ABS"),
    (45, "R_ARM_MOVW_PREL_NC"),
    (46, "R_ARM_MOVT_PREL"),
    (47, "R_ARM_THM_MOVW_ABS_NC"),
    (48, "R_ARM_THM_MOVT_ABS"),
    (51, "R_ARM_THM_JUMP19"),
    (102, "R_ARM_THM_JUMP11"),
    (160, "R_ARM_IRELATIVE"),
];

pub const R_RISCV: EnumTable = &[
    (0, "R_RISCV_NONE"),
    (1, "R_RISCV_32"),
    (2, "R_RISCV_64"),
    (3, "R_RISCV_RELATIVE"),
    (4, "R_RISCV_COPY"),
    (5, "R_RISCV_JUMP_SLOT"),
    (6, "R_RISCV_TLS_DTPMOD32"),
    (7, "R_RISCV_TLS_DTPMOD64"),
    (8, "R_RISCV_TLS_DTPREL32"),
    (9, "R_RISCV_TLS_DTPREL64"),
    (10, "R_RISCV_TLS_TPREL32"),
    (11, "R_RISCV_TLS_TPREL64"),
    (12, "R_RISCV_TLSDESC"),
    (16, "R_RISCV_BRANCH"),
    (17, "R_RISCV_JAL"),
    (18, "R_RISCV_CALL"),
    (19, "R_RISCV_CALL_PLT"),
    (20, "R_RISCV_GOT_HI20"),
    (21, "R_RISCV_TLS_GOT_HI20"),
    (22, "R_RISCV_TLS_GD_HI20"),
    (23, "R_RISCV_PCREL_HI20"),
    (24, "R_RISCV_PCREL_LO12_I"),
    (25, "R_RISCV_PCREL_LO12_S"),
    (26, "R_RISCV_HI20"),
    (27, "R_RISCV_LO12_I"),
    (28, "R_RISCV_LO12_S"),
    (29, "R_RISCV_TPREL_HI20"),
    (30, "R_RISCV_TPREL_LO12_I"),
    (31, "R_RISCV_TPREL_LO12_S"),
    (32, "R_RISCV_TPREL_ADD"),
    (33, "R_RISCV_ADD8"),
    (34, "R_RISCV_ADD16"),
    (35, "R_RISCV_ADD32"),
    (36, "R_RISCV_ADD64"),
    (37, "R_RISCV_SUB8"),
    (38, "R_RISCV_SUB16"),
    (39, "R_RISCV_SUB32"),
    (40, "R_RISCV_SUB64"),
    (43, "R_RISCV_ALIGN"),
    (44, "R_RISCV_RVC_BRANCH"),
    (45, "R_RISCV_RVC_JUMP"),
    (51, "R_RISCV_RELAX"),
    (52, "R_RISCV_SUB6"),
    (53, "R_RISCV_SET6"),
    (54, "R_RISCV_SET8"),
    (55, "R_RISCV_SET16"),
    (56, "R_RISCV_SET32"),
    (57, "R_RISCV_32_PCREL"),
    (58, "R_RISCV_IRELATIVE"),
    (59, "R_RISCV_PLT32"),
    (60, "R_RISCV_SET_ULEB128"),
    (61, "R_RISCV_SUB_ULEB128"),
];

pub const R_PPC64: EnumTable = &[
    (0, "R_PPC64_NONE"),
    (1, "R_PPC64_ADDR32"),
    (10, "R_PPC64_REL24"),
    (20, "R_PPC64_COPY"),
    (21, "R_PPC64_GLOB_DAT"),
    (22, "R_PPC64_JMP_SLOT"),
    (26, "R_PPC64_REL32"),
    (38, "R_PPC64_ADDR64"),
    (51, "R_PPC64_TOC"),
    (68, "R_PPC64_DTPMOD64"),
    (73, "R_PPC64_TPREL64"),
    (78, "R_PPC64_DTPREL64"),
    (248, "R_PPC64_IRELATIVE"),
];

pub const R_PPC: EnumTable = &[
    (0, "R_PPC_NONE"),
    (1, "R_PPC_ADDR32"),
    (6, "R_PPC_ADDR16_HA"),
    (4, "R_PPC_ADDR16_LO"),
    (10, "R_PPC_REL24"),
    (18, "R_PPC_PLTREL24"),
    (19, "R_PPC_COPY"),
    (20, "R_PPC_GLOB_DAT"),
    (21, "R_PPC_JMP_SLOT"),
    (22, "R_PPC_RELATIVE"),
    (26, "R_PPC_REL32"),
];

pub const R_MIPS: EnumTable = &[
    (0, "R_MIPS_NONE"),
    (2, "R_MIPS_32"),
    (3, "R_MIPS_REL32"),
    (4, "R_MIPS_26"),
    (5, "R_MIPS_HI16"),
    (6, "R_MIPS_LO16"),
    (7, "R_MIPS_GPREL16"),
    (9, "R_MIPS_GOT16"),
    (10, "R_MIPS_PC16"),
    (11, "R_MIPS_CALL16"),
    (18, "R_MIPS_64"),
    (37, "R_MIPS_JALR"),
    (126, "R_MIPS_COPY"),
    (127, "R_MIPS_JUMP_SLOT"),
];

/// Relocation type names for a machine.
pub fn relocation_types(machine: u16) -> crate::value::EnumTable {
    match machine {
        EM_X86_64 => R_X86_64,
        EM_386 => R_386,
        EM_AARCH64 => R_AARCH64,
        EM_ARM => R_ARM,
        EM_RISCV => R_RISCV,
        EM_MIPS => R_MIPS,
        20 => R_PPC,
        21 => R_PPC64,
        _ => &[],
    }
}

/// `e_flags` interpretation for a machine.
pub fn machine_flags(machine: u16) -> FlagTable {
    match machine {
        EM_ARM => EF_ARM,
        EM_RISCV => EF_RISCV,
        EM_MIPS => EF_MIPS,
        EM_LOONGARCH => EF_LOONGARCH,
        _ => EF_NONE,
    }
}

/// A short machine name for summaries (as `file` prints them).
pub fn machine_name(machine: u16) -> String {
    crate::value::lookup(MACHINE, machine.into())
        .map_or_else(|| format!("machine {machine:#x}"), str::to_owned)
}
