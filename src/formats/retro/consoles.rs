//! Console ROM and executable headers.

use crate::bytes::{to_u64, u16_le, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Record, emit_record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::{Head, Input, Probe, embedded};
use crate::node::{Count, Node};
use crate::record;
use crate::span::{Origin, Span};
use crate::value::{EnumTable, FlagTable, Value, field, flag, lookup};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

fn kib(n: u64) -> String {
    if n >= 1024 * 1024 && n.is_multiple_of(1024 * 1024) {
        format!("{} MiB", n / (1024 * 1024))
    } else {
        format!("{} KiB", n / 1024)
    }
}

// ---------------------------------------------------------------------------
// NES (iNES / NES 2.0)

declare_format!(pub NES = "nes", "Nintendo Entertainment System ROM (iNES)", ["nes"],
    "application/x-nes-rom", Probe::Magic(&[(0, b"NES\x1a")]), nes);

const NES_FLAGS6: FlagTable = &[
    flag(0x01, "VERTICAL_MIRRORING"),
    flag(0x02, "BATTERY"),
    flag(0x04, "TRAINER"),
    flag(0x08, "FOUR_SCREEN"),
];

const NES_FLAGS7: FlagTable = &[
    flag(0x01, "VS_UNISYSTEM"),
    flag(0x02, "PLAYCHOICE_10"),
    field(0x0c, 0x08, "NES_2_0"),
];

const NES_MAPPERS: EnumTable = &[
    (0, "NROM"),
    (1, "MMC1"),
    (2, "UxROM"),
    (3, "CNROM"),
    (4, "MMC3"),
    (5, "MMC5"),
    (7, "AxROM"),
    (9, "MMC2"),
    (10, "MMC4"),
    (11, "Color Dreams"),
    (16, "Bandai FCG"),
    (19, "Namco 163"),
    (21, "VRC4"),
    (23, "VRC2/VRC4"),
    (24, "VRC6"),
    (66, "GxROM"),
    (69, "Sunsoft FME-7"),
    (71, "Camerica"),
    (85, "VRC7"),
];

record! {
    pub struct InesHeader {
        magic: bytes[4] "Magic",
        prg: u8 "PRG ROM size" .desc("In 16 KiB units"),
        chr: u8 "CHR ROM size" .desc("In 8 KiB units; 0 means CHR RAM"),
        flags6: u8 "Flags 6" .flags(NES_FLAGS6) .desc("High nibble: mapper bits 0-3"),
        flags7: u8 "Flags 7" .flags(NES_FLAGS7) .desc("High nibble: mapper bits 4-7"),
        flags8: u8 "Flags 8" .desc("PRG RAM size (iNES) or mapper bits 8-11 (NES 2.0)"),
        flags9: u8 "Flags 9",
        flags10: u8 "Flags 10",
        _padding: bytes[5] "Padding",
    }
}

async fn nes(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: InesHeader = emit_record(&cx, file.sub(0, InesHeader::SIZE), LE).await?;
    let nes2 = h.flags7 & 0x0c == 0x08;
    let mut mapper = u16::from(h.flags6 >> 4) | u16::from(h.flags7 & 0xf0);
    if nes2 {
        mapper |= u16::from(h.flags8 & 0x0f) << 8;
    }
    let prg = u64::from(h.prg).saturating_mul(16 * 1024);
    let chr = u64::from(h.chr).saturating_mul(8 * 1024);
    let mapper_name = lookup(NES_MAPPERS, mapper.into()).unwrap_or("unknown mapper");
    cx.annotate(format!(
        "{}, mapper {mapper} ({mapper_name}), {} PRG, {} CHR",
        if nes2 { "NES 2.0" } else { "iNES" },
        kib(prg),
        kib(chr)
    ));
    let mut at = InesHeader::SIZE;
    if h.flags6 & 0x04 != 0 {
        cx.emit(Node::new("Trainer").span(file.sub(at, 512)));
        at = at.saturating_add(512);
    }
    cx.emit(Node::new("PRG ROM").span(file.sub(at, prg)).summary(kib(prg)));
    at = at.saturating_add(prg);
    if chr > 0 {
        cx.emit(Node::new("CHR ROM").span(file.sub(at, chr)).summary(kib(chr)));
        at = at.saturating_add(chr);
    }
    if at < file.len {
        cx.emit(Node::new("Extra data").span(file.tail(at)));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Famicom Disk System

declare_format!(pub FDS = "fds", "Famicom Disk System image", ["fds"],
    "application/octet-stream", Probe::Magic(&[(0, b"FDS\x1a"), (0, b"\x01*NINTENDO-HVC*")]), fds);

record! {
    pub struct FdsDiskInfo {
        block: u8 "Block code" .desc("1 = disk info"),
        verification: ascii[14] "Verification" .desc("*NINTENDO-HVC*"),
        maker: u8 "Manufacturer code" .hex(),
        name: ascii[3] "Game name",
        game_type: u8 "Game type",
        revision: u8 "Revision",
        side: u8 "Side number",
        disk: u8 "Disk number",
        disk_type: u8 "Disk type",
        _unknown: u8 "Unknown",
        boot_file: u8 "Boot read file code",
        _unknown2: bytes[5] "Unknown",
        date: bytes[3] "Manufacturing date (BCD)",
    }
}

async fn fds(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 16)).await?;
    let (sides_start, sides) = if head.starts_with(b"FDS\x1a") {
        cx.emit(Node::new("fwNES header").span(file.sub(0, 16)));
        (16u64, u64::from(head.get(4).copied().unwrap_or(0)))
    } else {
        (0u64, file.len / 65500)
    };
    cx.annotate(format!("{sides} disk side(s)"));
    cx.set_count(Count::Exact(sides.saturating_add(1)));
    for i in 0..sides {
        let span = file.sub(sides_start.saturating_add(i.saturating_mul(65500)), 65500);
        let info: Result<FdsDiskInfo> = read_record(&cx, span.sub(0, FdsDiskInfo::SIZE), LE).await;
        let mut node = Node::new(format!("Side {}", i.saturating_add(1))).span(span);
        if let Ok(info) = info {
            node = node.summary(format!("{} rev {}", info.name, info.revision));
        }
        cx.push(node.lazy(fds_side, span)).await;
    }
    Ok(())
}

async fn fds_side(cx: Cx, span: Span) -> Result<()> {
    cx.emit(FdsDiskInfo::node("Disk info block", span.sub(0, FdsDiskInfo::SIZE), LE));
    cx.emit(Node::new("Remaining blocks").span(span.tail(FdsDiskInfo::SIZE)));
    Ok(())
}

// ---------------------------------------------------------------------------
// Game Boy / Game Boy Color

const GB_LOGO: &[u8] = b"\xce\xed\x66\x66\xcc\x0d\x00\x0b\x03\x73\x00\x83";

fn gb_probe(h: &Head<'_>) -> bool {
    h.at(0x104, GB_LOGO)
}

fn gbc_probe(h: &Head<'_>) -> bool {
    gb_probe(h) && h.data.get(0x143).is_some_and(|&f| f & 0x80 != 0)
}

declare_format!(pub GBC = "gbc", "Game Boy Color ROM", ["gbc", "cgb"],
    "application/x-gameboy-color-rom", Probe::Custom(gbc_probe), gameboy);
declare_format!(pub GB = "gb", "Game Boy ROM", ["gb", "sgb"],
    "application/x-gameboy-rom", Probe::Custom(gb_probe), gameboy);

const GB_CGB: EnumTable = &[(0x00, "DMG only"), (0x80, "CGB enhanced"), (0xc0, "CGB only")];
const GB_SGB: EnumTable = &[(0x00, "No SGB functions"), (0x03, "SGB functions")];
const GB_CART: EnumTable = &[
    (0x00, "ROM ONLY"),
    (0x01, "MBC1"),
    (0x02, "MBC1+RAM"),
    (0x03, "MBC1+RAM+BATTERY"),
    (0x05, "MBC2"),
    (0x06, "MBC2+BATTERY"),
    (0x08, "ROM+RAM"),
    (0x09, "ROM+RAM+BATTERY"),
    (0x0b, "MMM01"),
    (0x0c, "MMM01+RAM"),
    (0x0d, "MMM01+RAM+BATTERY"),
    (0x0f, "MBC3+TIMER+BATTERY"),
    (0x10, "MBC3+TIMER+RAM+BATTERY"),
    (0x11, "MBC3"),
    (0x12, "MBC3+RAM"),
    (0x13, "MBC3+RAM+BATTERY"),
    (0x19, "MBC5"),
    (0x1a, "MBC5+RAM"),
    (0x1b, "MBC5+RAM+BATTERY"),
    (0x1c, "MBC5+RUMBLE"),
    (0x1d, "MBC5+RUMBLE+RAM"),
    (0x1e, "MBC5+RUMBLE+RAM+BATTERY"),
    (0x20, "MBC6"),
    (0x22, "MBC7+SENSOR+RUMBLE+RAM+BATTERY"),
    (0xfc, "POCKET CAMERA"),
    (0xfd, "BANDAI TAMA5"),
    (0xfe, "HuC3"),
    (0xff, "HuC1+RAM+BATTERY"),
];
const GB_RAM: EnumTable = &[
    (0, "None"),
    (1, "2 KiB"),
    (2, "8 KiB"),
    (3, "32 KiB"),
    (4, "128 KiB"),
    (5, "64 KiB"),
];
const GB_DESTINATION: EnumTable = &[(0, "Japan"), (1, "Overseas")];

record! {
    pub struct GbHeader {
        entry: bytes[4] "Entry point" .desc("Usually NOP; JP 0x150"),
        logo: bytes[48] "Nintendo logo",
        title: ascii[15] "Title",
        cgb: u8 "CGB flag" .enumeration(GB_CGB),
        licensee: ascii[2] "New licensee code",
        sgb: u8 "SGB flag" .enumeration(GB_SGB),
        cart: u8 "Cartridge type" .enumeration(GB_CART),
        rom_size: u8 "ROM size" .with(|&v, n| n.summary(kib(32u64.checked_shl(v.into()).unwrap_or(0).saturating_mul(1024)))),
        ram_size: u8 "RAM size" .enumeration(GB_RAM),
        destination: u8 "Destination" .enumeration(GB_DESTINATION),
        old_licensee: u8 "Old licensee code" .hex(),
        version: u8 "Mask ROM version",
        header_checksum: u8 "Header checksum" .hex(),
        global_checksum: u16 "Global checksum" .hex(),
    }
}

async fn gameboy(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("Interrupt vectors and RST").span(file.sub(0, 0x100)));
    let span = file.sub(0x100, GbHeader::SIZE);
    let h: GbHeader = read_record(&cx, span, BE).await?;
    let mut node = GbHeader::node("Cartridge header", span, BE);
    let covered = cx.read(file.sub(0x134, 0x19)).await?;
    let computed = covered
        .iter()
        .fold(0u8, |x, &b| x.wrapping_sub(b).wrapping_sub(1));
    if computed != h.header_checksum {
        node = node.diag(Diagnostic::warning(format!(
            "header checksum mismatch: computed {computed:#04x}"
        )));
    }
    cx.emit(node);
    cx.emit(Node::new("Program").span(file.tail(0x150)));
    let cart = lookup(GB_CART, h.cart.into()).unwrap_or("unknown cartridge");
    cx.annotate(format!("{:?}, {cart}", h.title.trim_end()));
    Ok(())
}

// ---------------------------------------------------------------------------
// Game Boy Advance

const GBA_LOGO: &[u8] = b"\x24\xff\xae\x51\x69\x9a\xa2\x21";

fn gba_probe(h: &Head<'_>) -> bool {
    h.at(4, GBA_LOGO) && h.at(0xb2, b"\x96")
}

declare_format!(pub GBA = "gba", "Game Boy Advance ROM", ["gba", "agb"],
    "application/x-gba-rom", Probe::Custom(gba_probe), gba);

record! {
    pub struct GbaHeader {
        entry: u32 "Entry point (ARM branch)" .hex(),
        logo: bytes[156] "Nintendo logo",
        title: ascii[12] "Game title",
        code: ascii[4] "Game code",
        maker: ascii[2] "Maker code",
        fixed: u8 "Fixed value" .hex() .desc("Must be 0x96"),
        unit: u8 "Main unit code",
        device: u8 "Device type",
        _reserved: bytes[7] "Reserved",
        version: u8 "Software version",
        complement: u8 "Complement check" .hex(),
        _reserved2: bytes[2] "Reserved",
    }
}

async fn gba(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, GbaHeader::SIZE);
    let h: GbaHeader = read_record(&cx, span, LE).await?;
    let covered = cx.read(file.sub(0xa0, 0x1d)).await?;
    let computed = covered
        .iter()
        .fold(0u8, |x, &b| x.wrapping_sub(b))
        .wrapping_sub(0x19);
    let mut node = GbaHeader::node("Cartridge header", span, LE);
    if computed != h.complement {
        node = node.diag(Diagnostic::warning(format!(
            "complement check mismatch: computed {computed:#04x}"
        )));
    }
    cx.emit(node);
    cx.emit(Node::new("Program").span(file.tail(GbaHeader::SIZE)));
    cx.annotate(format!("{:?} ({}{})", h.title.trim_end(), h.code, h.maker));
    Ok(())
}

// ---------------------------------------------------------------------------
// Nintendo DS

fn nds_probe(h: &Head<'_>) -> bool {
    h.at(0xc0, GBA_LOGO) && h.data.len() >= 0x160
}

declare_format!(pub NDS = "nds", "Nintendo DS ROM", ["nds", "srl"],
    "application/x-nintendo-ds-rom", Probe::Custom(nds_probe), nds);

record! {
    pub struct NdsHeader {
        title: ascii[12] "Game title",
        code: ascii[4] "Game code",
        maker: ascii[2] "Maker code",
        unit: u8 "Unit code" .enumeration(&[(0, "NDS"), (2, "NDS + DSi"), (3, "DSi")]),
        seed: u8 "Encryption seed select",
        capacity: u8 "Device capacity" .with(|&v, n| n.summary(kib(128u64.checked_shl(v.into()).unwrap_or(0).saturating_mul(1024)))),
        _reserved: bytes[7] "Reserved",
        _reserved2: u8 "Reserved",
        region: u8 "Region",
        version: u8 "ROM version",
        autostart: u8 "Autostart",
        arm9_offset: u32 "ARM9 ROM offset" .hex(),
        arm9_entry: u32 "ARM9 entry address" .hex(),
        arm9_load: u32 "ARM9 load address" .hex(),
        arm9_size: u32 "ARM9 size" .hex(),
        arm7_offset: u32 "ARM7 ROM offset" .hex(),
        arm7_entry: u32 "ARM7 entry address" .hex(),
        arm7_load: u32 "ARM7 load address" .hex(),
        arm7_size: u32 "ARM7 size" .hex(),
        fnt_offset: u32 "File name table offset" .hex(),
        fnt_size: u32 "File name table size" .hex(),
        fat_offset: u32 "File allocation table offset" .hex(),
        fat_size: u32 "File allocation table size" .hex(),
        arm9_overlay_offset: u32 "ARM9 overlay offset" .hex(),
        arm9_overlay_size: u32 "ARM9 overlay size" .hex(),
        arm7_overlay_offset: u32 "ARM7 overlay offset" .hex(),
        arm7_overlay_size: u32 "ARM7 overlay size" .hex(),
        port_normal: u32 "Port 0x40001A4 setting (normal)" .hex(),
        port_key1: u32 "Port 0x40001A4 setting (KEY1)" .hex(),
        banner_offset: u32 "Icon/title offset" .hex(),
        secure_crc: u16 "Secure area CRC" .hex(),
        secure_timeout: u16 "Secure transfer timeout",
        arm9_autoload: u32 "ARM9 autoload" .hex(),
        arm7_autoload: u32 "ARM7 autoload" .hex(),
        secure_disable: u64 "Secure area disable" .hex(),
        used_size: u32 "Total used ROM size" .hex(),
        header_size: u32 "ROM header size" .hex(),
    }
}

/// CRC-16/MODBUS, as used by the DS header.
fn crc16(data: &[u8]) -> u16 {
    let mut crc = 0xffffu16;
    for &b in data {
        crc ^= u16::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 { crc >> 1 ^ 0xa001 } else { crc >> 1 };
        }
    }
    crc
}

async fn nds(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, NdsHeader::SIZE);
    let h: NdsHeader = read_record(&cx, span, LE).await?;
    cx.emit(NdsHeader::node("Header", span, LE));
    let header = cx.read(file.sub(0, 0x160)).await?;
    let stored = u16_le(&header, 0x15e).unwrap_or(0);
    let computed = crc16(header.get(..0x15e).unwrap_or_default());
    let mut crc = Node::new("Header CRC")
        .span(file.sub(0x15e, 2))
        .value(Value::UInt { value: stored.into(), bits: 16, radix: crate::value::Radix::Hex });
    crc = if stored == computed {
        crc.summary("valid")
    } else {
        crc.diag(Diagnostic::warning(format!("CRC mismatch: computed {computed:#06x}")))
    };
    cx.emit(Node::new("Nintendo logo").span(file.sub(0xc0, 156)));
    cx.emit(crc);
    let region = |offset: u32, size: u32| file.sub(offset.into(), size.into());
    cx.emit(Node::new("ARM9 binary").span(region(h.arm9_offset, h.arm9_size)));
    cx.emit(Node::new("ARM7 binary").span(region(h.arm7_offset, h.arm7_size)));
    if h.fnt_size > 0 {
        cx.emit(Node::new("File name table").span(region(h.fnt_offset, h.fnt_size)));
    }
    if h.fat_size > 0 {
        cx.emit(
            Node::new("File allocation table")
                .span(region(h.fat_offset, h.fat_size))
                .summary(format!("{} files", h.fat_size / 8)),
        );
    }
    let mut title = None;
    if h.banner_offset != 0 {
        let banner = file.sub(h.banner_offset.into(), 0x840);
        // English title: UTF-16LE at 0x340, up to 0x100 bytes.
        if let Ok(bytes) = cx.read(banner.sub(0x340, 0x100)).await {
            let text = crate::text::utf16z(&bytes, LE).0;
            title = Some(text.lines().next().unwrap_or_default().to_owned());
            cx.emit(
                Node::new("Icon and title")
                    .span(banner)
                    .summary(text.replace('\n', " / ")),
            );
        }
    }
    cx.annotate(format!(
        "{} ({}{})",
        title.unwrap_or_else(|| h.title.trim_end().to_owned()),
        h.code,
        h.maker
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Nintendo 64

declare_format!(pub N64 = "n64", "Nintendo 64 ROM", ["z64", "n64", "v64"],
    "application/x-n64-rom",
    Probe::Magic(&[(0, b"\x80\x37\x12\x40"), (0, b"\x37\x80\x40\x12"), (0, b"\x40\x12\x37\x80")]),
    n64);

const N64_COUNTRY: EnumTable = &[
    (0x37, "Beta"),
    (0x41, "Asia (NTSC)"),
    (0x42, "Brazil"),
    (0x43, "China"),
    (0x44, "Germany"),
    (0x45, "North America"),
    (0x46, "France"),
    (0x47, "Gateway 64 (NTSC)"),
    (0x48, "Netherlands"),
    (0x49, "Italy"),
    (0x4a, "Japan"),
    (0x4b, "Korea"),
    (0x4c, "Gateway 64 (PAL)"),
    (0x4e, "Canada"),
    (0x50, "Europe"),
    (0x53, "Spain"),
    (0x55, "Australia"),
    (0x57, "Scandinavia"),
    (0x58, "Europe"),
    (0x59, "Europe"),
];

record! {
    pub struct N64Header {
        pi: u32 "PI BSD domain 1 config" .hex(),
        clock: u32 "Clock rate" .hex(),
        boot: u32 "Boot address" .hex(),
        release: u32 "libultra version" .hex(),
        crc1: u32 "Checksum 1" .hex(),
        crc2: u32 "Checksum 2" .hex(),
        _reserved: bytes[8] "Reserved",
        name: ascii[20] "Image name",
        _reserved2: bytes[7] "Reserved",
        media: ascii[1] "Media format",
        cart_id: ascii[2] "Cartridge ID",
        country: u8 "Country" .enumeration(N64_COUNTRY),
        version: u8 "Version",
    }
}

async fn n64(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 0x40)).await?;
    // Byte-swapped dumps are normalised into a derived copy of the header.
    let (span, order) = match head.get(..4) {
        Some(b"\x80\x37\x12\x40") => (file.sub(0, 0x40), "big-endian (.z64)"),
        Some(magic) => {
            let swapped: Vec<u8> = if magic == b"\x37\x80\x40\x12" {
                head.chunks(2).flat_map(|c| c.iter().rev().copied()).collect()
            } else {
                head.chunks(4).flat_map(|c| c.iter().rev().copied()).collect()
            };
            let decoded = cx.add_derived(
                Origin { parent: file.sub(0, 0x40), transform: "n64-byteswap" },
                swapped,
                0x40,
                None,
            )?;
            let order = if magic == b"\x37\x80\x40\x12" {
                "byte-swapped (.v64)"
            } else {
                "little-endian (.n64)"
            };
            (decoded.span, order)
        }
        None => return Err(Diagnostic::truncated(file.sub(0, 4), 0)),
    };
    let h: N64Header = read_record(&cx, span, BE).await?;
    cx.emit(N64Header::node("Header", span, BE).summary(order));
    cx.emit(Node::new("Boot code (IPL3)").span(file.sub(0x40, 0xfc0)));
    cx.emit(Node::new("Program").span(file.tail(0x1000)));
    let country = lookup(N64_COUNTRY, h.country.into()).unwrap_or("unknown region");
    cx.annotate(format!("{:?}, {country}, {order}", h.name.trim_end()));
    Ok(())
}

// ---------------------------------------------------------------------------
// Sega Mega Drive / Genesis (and 32X)

fn genesis_probe(h: &Head<'_>) -> bool {
    h.at(0x100, b"SEGA") || h.at(0x101, b"SEGA")
}

declare_format!(pub GENESIS = "genesis", "Sega Mega Drive / Genesis ROM", ["md", "gen", "smd", "32x"],
    "application/x-genesis-rom", Probe::Custom(genesis_probe), genesis);

record! {
    pub struct GenesisHeader {
        system: ascii[16] "System type",
        copyright: ascii[16] "Copyright and release date",
        domestic: ascii[48] "Domestic title",
        overseas: ascii[48] "Overseas title",
        serial: ascii[14] "Serial number",
        checksum: u16 "Checksum" .hex(),
        io: ascii[16] "Device support",
        rom_start: u32 "ROM start" .hex(),
        rom_end: u32 "ROM end" .hex(),
        ram_start: u32 "RAM start" .hex(),
        ram_end: u32 "RAM end" .hex(),
        sram: bytes[12] "Extra memory",
        modem: ascii[12] "Modem support",
        notes: ascii[40] "Notes",
        region: ascii[3] "Region support",
        _reserved: bytes[13] "Reserved",
    }
}

async fn genesis(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("68000 vector table").span(file.sub(0, 0x100)));
    let span = file.sub(0x100, GenesisHeader::SIZE);
    let h: GenesisHeader = read_record(&cx, span, BE).await?;
    cx.emit(GenesisHeader::node("Header", span, BE));
    cx.emit(Node::new("Program").span(file.tail(0x200)));
    let title = if h.overseas.trim().is_empty() { &h.domestic } else { &h.overseas };
    let title: String = title.split_whitespace().collect::<Vec<_>>().join(" ");
    cx.annotate(format!("{title:?}, {}, region {}", h.system.trim(), h.region.trim()));
    Ok(())
}

// ---------------------------------------------------------------------------
// Super Nintendo (LoROM, optionally with a 512-byte copier header)

fn snes_header_at(h: &Head<'_>) -> Option<usize> {
    [0x7fc0usize, 0x81c0].into_iter().find(|&base| {
        let complement = h.data.get(base.saturating_add(0x1c)..base.saturating_add(0x1e));
        let checksum = h.data.get(base.saturating_add(0x1e)..base.saturating_add(0x20));
        let map = h.data.get(base.saturating_add(0x15)).copied().unwrap_or(0);
        match (complement, checksum) {
            (Some(c), Some(s)) => {
                let c = u16::from_le_bytes([c.first().copied().unwrap_or(0), c.get(1).copied().unwrap_or(0)]);
                let s = u16::from_le_bytes([s.first().copied().unwrap_or(0), s.get(1).copied().unwrap_or(0)]);
                c ^ s == 0xffff && matches!(map & 0xef, 0x20 | 0x21 | 0x23 | 0x25 | 0x2a)
            }
            _ => false,
        }
    })
}

declare_format!(pub SNES = "snes", "Super Nintendo ROM", ["sfc", "smc", "swc"],
    "application/x-snes-rom", Probe::Custom(|h| snes_header_at(h).is_some()), snes);

const SNES_MAP: EnumTable = &[
    (0x20, "LoROM"),
    (0x21, "HiROM"),
    (0x23, "SA-1"),
    (0x25, "ExHiROM"),
    (0x30, "LoROM + FastROM"),
    (0x31, "HiROM + FastROM"),
    (0x32, "ExLoROM + FastROM"),
    (0x35, "ExHiROM + FastROM"),
];

const SNES_COUNTRY: EnumTable = &[
    (0, "Japan"),
    (1, "North America"),
    (2, "Europe"),
    (3, "Sweden/Scandinavia"),
    (4, "Finland"),
    (5, "Denmark"),
    (6, "France"),
    (7, "Netherlands"),
    (8, "Spain"),
    (9, "Germany"),
    (10, "Italy"),
    (11, "China"),
    (12, "Indonesia"),
    (13, "Korea"),
    (15, "Canada"),
    (16, "Brazil"),
    (17, "Australia"),
];

record! {
    pub struct SnesHeader {
        title: ascii[21] "Title",
        map: u8 "Map mode" .enumeration(SNES_MAP),
        cart: u8 "Cartridge type" .hex(),
        rom_size: u8 "ROM size" .with(|&v, n| n.summary(kib(1024u64.checked_shl(v.into()).unwrap_or(0)))),
        ram_size: u8 "RAM size" .with(|&v, n| n.summary(if v == 0 { "none".to_owned() } else { kib(1024u64.checked_shl(v.into()).unwrap_or(0)) })),
        country: u8 "Country" .enumeration(SNES_COUNTRY),
        developer: u8 "Developer ID" .hex(),
        version: u8 "Version",
        complement: u16 "Checksum complement" .hex(),
        checksum: u16 "Checksum" .hex(),
    }
}

async fn snes(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let (head, tail) = crate::formats::head(&cx, file).await?;
    let probe = Head { data: &head, tail: &tail, len: file.len };
    let base = to_u64(snes_header_at(&probe).unwrap_or(0x7fc0));
    if base == 0x81c0 {
        cx.emit(Node::new("Copier header").span(file.sub(0, 0x200)));
    }
    let span = file.sub(base, SnesHeader::SIZE);
    let h: SnesHeader = read_record(&cx, span, LE).await?;
    cx.emit(SnesHeader::node("Internal header", span, LE));
    cx.emit(Node::new("Vectors").span(file.sub(base.saturating_add(0x20), 0x20)));
    let map = lookup(SNES_MAP, h.map.into()).unwrap_or("unknown mapping");
    let country = lookup(SNES_COUNTRY, h.country.into()).unwrap_or("unknown region");
    cx.annotate(format!("{:?}, {map}, {country}", h.title.trim_end()));
    Ok(())
}

// ---------------------------------------------------------------------------
// PlayStation executables, PSP containers

declare_format!(pub PSX_EXE = "psx-exe", "PlayStation executable", ["exe", "psx", "psexe"],
    "application/octet-stream", Probe::Magic(&[(0, b"PS-X EXE")]), psx_exe);

record! {
    pub struct PsxHeader {
        magic: ascii[8] "Magic",
        _zero: bytes[8] "Reserved",
        pc: u32 "Initial PC" .hex(),
        gp: u32 "Initial GP" .hex(),
        text_addr: u32 "Load address" .hex(),
        text_size: u32 "Text size" .hex(),
        data_addr: u32 "Data address" .hex(),
        data_size: u32 "Data size" .hex(),
        bss_addr: u32 "BSS address" .hex(),
        bss_size: u32 "BSS size" .hex(),
        stack: u32 "Stack base" .hex(),
        stack_offset: u32 "Stack offset" .hex(),
        _reserved: bytes[20] "Reserved",
        marker: ascii[60] "Region marker",
    }
}

async fn psx_exe(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: PsxHeader = emit_record(&cx, file.sub(0, PsxHeader::SIZE), LE).await?;
    cx.emit(Node::new("Text").span(file.sub(0x800, h.text_size.into())));
    cx.annotate(format!("entry {:#x}, {}", h.pc, h.marker.trim()));
    Ok(())
}

declare_format!(pub PBP = "pbp", "PSP package (EBOOT.PBP)", ["pbp"],
    "application/octet-stream", Probe::Magic(&[(0, b"\0PBP")]), pbp);

const PBP_ENTRIES: [&str; 8] = [
    "PARAM.SFO", "ICON0.PNG", "ICON1.PMF", "PIC0.PNG", "PIC1.PNG", "SND0.AT3", "DATA.PSP", "DATA.PSAR",
];

async fn pbp(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let header = cx.read(file.sub(0, 0x28)).await?;
    cx.emit(Node::new("Header").span(file.sub(0, 0x28)).summary(format!(
        "version {:#x}",
        u32_le(&header, 4).unwrap_or(0)
    )));
    let offsets: Vec<u64> = (0..8)
        .map(|i: usize| u64::from(u32_le(&header, 8usize.saturating_add(i.saturating_mul(4))).unwrap_or(0)))
        .collect();
    for (i, name) in PBP_ENTRIES.iter().enumerate() {
        let start = offsets.get(i).copied().unwrap_or(0);
        let end = offsets.get(i.saturating_add(1)).copied().unwrap_or(file.len);
        if end <= start {
            continue;
        }
        cx.emit(embedded(*name, input.nested(file.sub(start, end.saturating_sub(start)))));
    }
    Ok(())
}

declare_format!(pub SFO = "sfo", "PlayStation system file object (PARAM.SFO)", ["sfo"],
    "application/octet-stream", Probe::Magic(&[(0, b"\0PSF")]), sfo);

record! {
    pub struct SfoHeader {
        magic: bytes[4] "Magic",
        version: u32 "Version" .hex(),
        keys: u32 "Key table offset" .hex(),
        data: u32 "Data table offset" .hex(),
        count: u32 "Entries",
    }
}

async fn sfo(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: SfoHeader = read_record(&cx, file.sub(0, SfoHeader::SIZE), LE).await?;
    cx.emit(SfoHeader::node("Header", file.sub(0, SfoHeader::SIZE), LE));
    let table = file.sub_exact(SfoHeader::SIZE, u64::from(h.count).saturating_mul(16))?;
    let entries = cx.read(table).await?;
    cx.set_count(Count::Exact(u64::from(h.count).saturating_add(1)));
    let mut title = None;
    for i in 0..usize::try_from(h.count).unwrap_or(0) {
        let at = i.saturating_mul(16);
        let key_offset = u16_le(&entries, at).unwrap_or(0);
        let fmt = u16_le(&entries, at.saturating_add(2)).unwrap_or(0);
        let len = u32_le(&entries, at.saturating_add(4)).unwrap_or(0);
        let data_offset = u32_le(&entries, at.saturating_add(12)).unwrap_or(0);
        let key_span = file.tail(u64::from(h.keys).saturating_add(key_offset.into()));
        let (key, _) = cx.cstr(key_span.sub(0, 64)).await?;
        let value_span = file.sub(
            u64::from(h.data).saturating_add(data_offset.into()),
            len.into(),
        );
        let bytes = cx.read_avail(value_span).await?;
        let value = if fmt == 0x0404 {
            Value::UInt { value: u32_le(&bytes, 0).unwrap_or(0).into(), bits: 32, radix: crate::value::Radix::Dec }
        } else {
            Value::Text(crate::text::until_nul(&bytes))
        };
        if key == "TITLE"
            && let Value::Text(t) = &value
        {
            title = Some(t.clone());
        }
        cx.push(Node::new(key).span(value_span).value(value)).await;
    }
    if let Some(title) = title {
        cx.annotate(title);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Xbox executable

declare_format!(pub XBE = "xbe", "Xbox executable", ["xbe"],
    "application/octet-stream", Probe::Magic(&[(0, b"XBEH")]), xbe);

record! {
    pub struct XbeHeader {
        magic: ascii[4] "Magic",
        signature: bytes[256] "Signature",
        base: u32 "Base address" .hex(),
        headers_size: u32 "Size of headers" .hex(),
        image_size: u32 "Size of image" .hex(),
        image_header_size: u32 "Size of image header" .hex(),
        timestamp: u32 "Time/date stamp" .timestamp(),
        certificate: u32 "Certificate address" .hex(),
        sections: u32 "Number of sections",
        section_headers: u32 "Section headers address" .hex(),
        init_flags: u32 "Initialisation flags" .hex(),
        entry: u32 "Entry point (encoded)" .hex(),
        tls: u32 "TLS address" .hex(),
    }
}

const XBE_SECTION_FLAGS: FlagTable = &[
    flag(1, "WRITABLE"),
    flag(2, "PRELOAD"),
    flag(4, "EXECUTABLE"),
    flag(8, "INSERTED_FILE"),
    flag(16, "HEAD_PAGE_READ_ONLY"),
    flag(32, "TAIL_PAGE_READ_ONLY"),
];

record! {
    pub struct XbeSection {
        flags: u32 "Flags" .flags(XBE_SECTION_FLAGS),
        virtual_address: u32 "Virtual address" .hex(),
        virtual_size: u32 "Virtual size" .hex(),
        raw_address: u32 "Raw address" .hex(),
        raw_size: u32 "Raw size" .hex(),
        name: u32 "Section name address" .hex(),
        refs: u32 "Section reference count",
        head_ref: u32 "Head shared page reference count address" .hex(),
        tail_ref: u32 "Tail shared page reference count address" .hex(),
        digest: bytes[20] "SHA-1 digest",
    }
}

async fn xbe(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, XbeHeader::SIZE);
    let h: XbeHeader = read_record(&cx, span, LE).await?;
    cx.emit(XbeHeader::node("Image header", span, LE));
    let at = |va: u32| u64::from(va.saturating_sub(h.base));
    // Certificate: title name is UTF-16LE at offset 0x0c, 40 characters.
    let cert = file.sub(at(h.certificate), 0x1d0);
    if let Ok(name) = cx.read(cert.sub(0x0c, 80)).await {
        let title = crate::text::utf16z(&name, LE).0;
        cx.emit(Node::new("Certificate").span(cert).summary(title.clone()));
        cx.annotate(format!("{title:?}"));
    }
    let table = file.sub_exact(at(h.section_headers), u64::from(h.sections).saturating_mul(XbeSection::SIZE))?;
    cx.emit(
        Node::new("Sections")
            .span(table)
            .summary(format!("{} sections", h.sections))
            .lazy(xbe_sections, (file, table, h.base)),
    );
    Ok(())
}

async fn xbe_sections(cx: Cx, (file, table, base): (Span, Span, u32)) -> Result<()> {
    let count = table.len / XbeSection::SIZE;
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let span = table.sub(i.saturating_mul(XbeSection::SIZE), XbeSection::SIZE);
        let s: XbeSection = read_record(&cx, span, LE).await?;
        let name = cx
            .cstr(file.sub(u64::from(s.name.saturating_sub(base)), 64))
            .await
            .map_or_else(|_| format!("#{i}"), |(n, _)| n);
        let data = file.sub(s.raw_address.into(), s.raw_size.into());
        cx.push(
            XbeSection::node(name, span, LE)
                .summary(format!("VA {:#x}+{:#x}", s.virtual_address, s.virtual_size))
                .target(data),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// GameCube / Wii discs

fn gamecube_probe(h: &Head<'_>) -> bool {
    h.at(0x1c, b"\xc2\x33\x9f\x3d")
}

fn wii_probe(h: &Head<'_>) -> bool {
    h.at(0x18, b"\x5d\x1c\x9e\xa3")
}

declare_format!(pub WII = "wii", "Wii disc image", ["iso", "wbfs"],
    "application/x-wii-rom", Probe::Custom(wii_probe), disc);
declare_format!(pub GAMECUBE = "gamecube", "GameCube disc image", ["iso", "gcm"],
    "application/x-gamecube-rom", Probe::Custom(gamecube_probe), disc);

record! {
    pub struct DiscHeader {
        id: ascii[6] "Game ID" .desc("System, game, region and maker codes"),
        disc: u8 "Disc number",
        version: u8 "Version",
        streaming: u8 "Audio streaming",
        buffer: u8 "Stream buffer size",
        _unused: bytes[14] "Unused",
        wii_magic: u32 "Wii magic" .hex(),
        gc_magic: u32 "GameCube magic" .hex(),
        title: ascii[64] "Title",
    }
}

async fn disc(cx: Cx, input: Input) -> Result<()> {
    let h: DiscHeader = emit_record(&cx, input.span.sub(0, DiscHeader::SIZE), BE).await?;
    cx.annotate(format!("{:?} ({})", h.title.trim_end(), h.id));
    Ok(())
}

// ---------------------------------------------------------------------------
// Nintendo Switch homebrew and system modules

fn nro_probe(h: &Head<'_>) -> bool {
    h.at(0x10, b"NRO0")
}

declare_format!(pub NRO = "nro", "Nintendo Switch relocatable object (NRO)", ["nro"],
    "application/octet-stream", Probe::Custom(nro_probe), nro);

record! {
    pub struct NroHeader {
        branch: u32 "Entry branch" .hex(),
        mod_offset: u32 "MOD0 offset" .hex(),
        _padding: bytes[8] "Padding",
        magic: ascii[4] "Magic",
        version: u32 "Version",
        size: u32 "Size" .hex(),
        flags: u32 "Flags" .hex(),
        text_offset: u32 ".text offset" .hex(),
        text_size: u32 ".text size" .hex(),
        ro_offset: u32 ".rodata offset" .hex(),
        ro_size: u32 ".rodata size" .hex(),
        data_offset: u32 ".data offset" .hex(),
        data_size: u32 ".data size" .hex(),
        bss_size: u32 ".bss size" .hex(),
        _reserved: u32 "Reserved",
        build_id: bytes[32] "Build ID",
    }
}

async fn nro(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: NroHeader = read_record(&cx, file.sub(0, NroHeader::SIZE), LE).await?;
    cx.emit(NroHeader::node("Header", file.sub(0, NroHeader::SIZE), LE));
    for (name, offset, size) in [
        (".text", h.text_offset, h.text_size),
        (".rodata", h.ro_offset, h.ro_size),
        (".data", h.data_offset, h.data_size),
    ] {
        cx.emit(Node::new(name).span(file.sub(offset.into(), size.into())));
    }
    let asset = file.tail(h.size.into());
    let magic = cx.read_avail(asset.sub(0, 4)).await?;
    if magic == b"ASET" {
        cx.emit(Node::new("Assets").span(asset).lazy(nro_assets, (input, asset)));
    }
    cx.annotate(format!("NRO, {:#x} bytes of code and data", h.size));
    Ok(())
}

async fn nro_assets(cx: Cx, (input, assets): (Input, Span)) -> Result<()> {
    let header = cx.read(assets.sub(0, 0x38)).await?;
    cx.emit(Node::new("Header").span(assets.sub(0, 0x38)));
    for (i, name) in ["Icon", "NACP", "RomFS"].iter().enumerate() {
        let at = 8usize.saturating_add(i.saturating_mul(16));
        let offset = crate::bytes::u64_le(&header, at).unwrap_or(0);
        let size = crate::bytes::u64_le(&header, at.saturating_add(8)).unwrap_or(0);
        if size > 0 {
            let span = assets.sub(offset, size);
            cx.emit(embedded(*name, input.nested(span)));
        }
    }
    Ok(())
}

declare_format!(pub NSO = "nso", "Nintendo Switch shared object (NSO)", ["nso"],
    "application/octet-stream", Probe::Magic(&[(0, b"NSO0")]), nso);

const NSO_FLAGS: FlagTable = &[
    flag(1, "TEXT_COMPRESSED"),
    flag(2, "RO_COMPRESSED"),
    flag(4, "DATA_COMPRESSED"),
    flag(8, "TEXT_HASH"),
    flag(16, "RO_HASH"),
    flag(32, "DATA_HASH"),
];

record! {
    pub struct NsoHeader {
        magic: ascii[4] "Magic",
        version: u32 "Version",
        _reserved: u32 "Reserved",
        flags: u32 "Flags" .flags(NSO_FLAGS),
        text_file: u32 ".text file offset" .hex(),
        text_memory: u32 ".text memory offset" .hex(),
        text_size: u32 ".text size" .hex(),
        module_name_offset: u32 "Module name offset" .hex(),
        ro_file: u32 ".rodata file offset" .hex(),
        ro_memory: u32 ".rodata memory offset" .hex(),
        ro_size: u32 ".rodata size" .hex(),
        module_name_size: u32 "Module name size",
        data_file: u32 ".data file offset" .hex(),
        data_memory: u32 ".data memory offset" .hex(),
        data_size: u32 ".data size" .hex(),
        bss_size: u32 ".bss size" .hex(),
        build_id: bytes[32] "Build ID",
        text_file_size: u32 ".text file size" .hex(),
        ro_file_size: u32 ".rodata file size" .hex(),
        data_file_size: u32 ".data file size" .hex(),
    }
}

async fn nso(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: NsoHeader = read_record(&cx, file.sub(0, NsoHeader::SIZE), LE).await?;
    cx.emit(NsoHeader::node("Header", file.sub(0, NsoHeader::SIZE), LE));
    for (i, (name, offset, size)) in [
        (".text", h.text_file, h.text_file_size),
        (".rodata", h.ro_file, h.ro_file_size),
        (".data", h.data_file, h.data_file_size),
    ]
    .into_iter()
    .enumerate()
    {
        let mut node = Node::new(name).span(file.sub(offset.into(), size.into()));
        if h.flags & (1u32 << i) != 0 {
            node = node.diag(Diagnostic::unsupported("LZ4-compressed segment"));
        }
        cx.emit(node);
    }
    cx.annotate("NSO module");
    Ok(())
}

// ---------------------------------------------------------------------------
// Nintendo 3DS

declare_format!(pub THREEDSX = "3dsx", "Nintendo 3DS homebrew executable", ["3dsx"],
    "application/octet-stream", Probe::Magic(&[(0, b"3DSX")]), threedsx);

record! {
    pub struct ThreeDsxHeader {
        magic: ascii[4] "Magic",
        header_size: u16 "Header size",
        reloc_header_size: u16 "Relocation header size",
        version: u32 "Version",
        flags: u32 "Flags" .hex(),
        code_size: u32 "Code segment size" .hex(),
        rodata_size: u32 "Rodata segment size" .hex(),
        data_size: u32 "Data segment size (incl. BSS)" .hex(),
        bss_size: u32 "BSS size" .hex(),
    }
}

async fn threedsx(cx: Cx, input: Input) -> Result<()> {
    let h: ThreeDsxHeader = emit_record(&cx, input.span.sub(0, ThreeDsxHeader::SIZE), LE).await?;
    cx.annotate(format!(
        "3DSX, code {:#x}, rodata {:#x}, data {:#x}",
        h.code_size, h.rodata_size, h.data_size
    ));
    Ok(())
}

fn ncsd_probe(h: &Head<'_>) -> bool {
    h.at(0x100, b"NCSD")
}

fn ncch_probe(h: &Head<'_>) -> bool {
    h.at(0x100, b"NCCH")
}

declare_format!(pub NCSD = "ncsd", "Nintendo 3DS cartridge image (NCSD)", ["3ds", "cci"],
    "application/octet-stream", Probe::Custom(ncsd_probe), ncsd);
declare_format!(pub NCCH = "ncch", "Nintendo 3DS content container (NCCH)", ["cxi", "cfa", "app"],
    "application/octet-stream", Probe::Custom(ncch_probe), ncch);

const MEDIA_UNIT: u64 = 0x200;

async fn ncsd(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let header = cx.read(file.sub(0, 0x200)).await?;
    cx.emit(Node::new("Signature").span(file.sub(0, 0x100)));
    cx.emit(Node::new("Header").span(file.sub(0x100, 0x100)));
    let names = ["Game (CXI)", "Manual (CFA)", "Download Play (CFA)", "Partition 3", "Partition 4", "Partition 5", "N3DS update (CFA)", "O3DS update (CFA)"];
    let mut partitions = 0u32;
    for (i, name) in names.iter().enumerate() {
        let at = 0x120usize.saturating_add(i.saturating_mul(8));
        let offset = u64::from(u32_le(&header, at).unwrap_or(0)).saturating_mul(MEDIA_UNIT);
        let size = u64::from(u32_le(&header, at.saturating_add(4)).unwrap_or(0)).saturating_mul(MEDIA_UNIT);
        if size == 0 {
            continue;
        }
        partitions = partitions.saturating_add(1);
        cx.emit(embedded(*name, input.nested(file.sub(offset, size))).summary(kib(size)));
    }
    let media_id = crate::bytes::u64_le(&header, 0x108).unwrap_or(0);
    cx.annotate(format!("media ID {media_id:016x}, {partitions} partition(s)"));
    Ok(())
}

record! {
    pub struct NcchHeader {
        signature: bytes[256] "RSA-2048 signature",
        magic: ascii[4] "Magic",
        content_size: u32 "Content size (media units)",
        partition_id: u64 "Partition ID" .hex(),
        maker: ascii[2] "Maker code",
        version: u16 "Version",
        hash: u32 "Seed check hash" .hex(),
        program_id: u64 "Program ID" .hex(),
        _reserved: bytes[16] "Reserved",
        logo_hash: bytes[32] "Logo region hash",
        product: ascii[16] "Product code",
        exheader_hash: bytes[32] "Extended header hash",
        exheader_size: u32 "Extended header size" .hex(),
        _reserved2: u32 "Reserved",
        flags: bytes[8] "Flags",
        plain_offset: u32 "Plain region offset (MU)",
        plain_size: u32 "Plain region size (MU)",
        logo_offset: u32 "Logo region offset (MU)",
        logo_size: u32 "Logo region size (MU)",
        exefs_offset: u32 "ExeFS offset (MU)",
        exefs_size: u32 "ExeFS size (MU)",
        exefs_hash_size: u32 "ExeFS hash region size (MU)",
        _reserved3: u32 "Reserved",
        romfs_offset: u32 "RomFS offset (MU)",
        romfs_size: u32 "RomFS size (MU)",
        romfs_hash_size: u32 "RomFS hash region size (MU)",
        _reserved4: u32 "Reserved",
        exefs_hash: bytes[32] "ExeFS superblock hash",
        romfs_hash: bytes[32] "RomFS superblock hash",
    }
}

async fn ncch(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, NcchHeader::SIZE);
    let h: NcchHeader = read_record(&cx, span, LE).await?;
    cx.emit(NcchHeader::node("Header", span, LE));
    let mu = |v: u32| u64::from(v).saturating_mul(MEDIA_UNIT);
    for (name, offset, size) in [
        ("Plain region", h.plain_offset, h.plain_size),
        ("Logo", h.logo_offset, h.logo_size),
        ("ExeFS", h.exefs_offset, h.exefs_size),
        ("RomFS", h.romfs_offset, h.romfs_size),
    ] {
        if size > 0 {
            cx.emit(Node::new(name).span(file.sub(mu(offset), mu(size))));
        }
    }
    cx.annotate(format!("{} (program {:016x})", h.product.trim_end(), h.program_id));
    Ok(())
}

// ---------------------------------------------------------------------------
// Atari Lynx and 7800

declare_format!(pub LYNX = "lynx", "Atari Lynx cartridge image", ["lnx"],
    "application/octet-stream", Probe::Magic(&[(0, b"LYNX\0")]), lynx);

record! {
    pub struct LynxHeader {
        magic: ascii[4] "Magic",
        bank0: u16 "Bank 0 page size",
        bank1: u16 "Bank 1 page size",
        version: u16 "Version",
        name: ascii[32] "Cartridge name",
        manufacturer: ascii[16] "Manufacturer",
        rotation: u8 "Rotation" .enumeration(&[(0, "none"), (1, "left"), (2, "right")]),
        _reserved: bytes[5] "Reserved",
    }
}

async fn lynx(cx: Cx, input: Input) -> Result<()> {
    let h: LynxHeader = emit_record(&cx, input.span.sub(0, LynxHeader::SIZE), LE).await?;
    cx.emit(Node::new("ROM").span(input.span.tail(LynxHeader::SIZE)));
    cx.annotate(format!("{:?} by {}", h.name.trim_end(), h.manufacturer.trim_end()));
    Ok(())
}

fn a7800_probe(h: &Head<'_>) -> bool {
    h.at(1, b"ATARI7800")
}

declare_format!(pub A7800 = "a78", "Atari 7800 cartridge image", ["a78"],
    "application/octet-stream", Probe::Custom(a7800_probe), a7800);

record! {
    pub struct A7800Header {
        version: u8 "Header version",
        magic: ascii[16] "Magic",
        title: ascii[32] "Title",
        size: u32 "ROM size" .hex(),
        cart_type: u16 "Cartridge type" .hex(),
        controller1: u8 "Controller 1",
        controller2: u8 "Controller 2",
        tv: u8 "TV type" .enumeration(&[(0, "NTSC"), (1, "PAL")]),
        save: u8 "Save device",
    }
}

async fn a7800(cx: Cx, input: Input) -> Result<()> {
    let h: A7800Header = emit_record(&cx, input.span.sub(0, A7800Header::SIZE), BE).await?;
    cx.emit(Node::new("ROM").span(input.span.tail(128)));
    cx.annotate(format!("{:?}, {}", h.title.trim_end(), kib(h.size.into())));
    Ok(())
}
