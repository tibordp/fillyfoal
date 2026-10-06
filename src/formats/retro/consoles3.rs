//! Console update and package containers and emulator recordings: Wii U WUX,
//! Switch NCZ and NPDM, PS3 PUP, PS4 PKG, PSP ~PSP modules, GBA SharkPort
//! saves, MAME input recordings and save states.

use super::util::{clean, hex, size, text};
use crate::bytes::{to_u64, u32_be, u32_le, u64_be, u64_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::{Codec, Head, Input, Probe, content, embedded, embedded_as};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// Wii U compressed disc image (WUX)

fn wux_probe(h: &Head<'_>) -> bool {
    h.at(0, b"WUX0") && u32_le(h.data, 4) == Some(0x1099_d02e)
}

declare_format!(pub WUX = "wux", "Wii U compressed disc image (WUX)", ["wux"],
    "application/x-wux", Probe::Custom(wux_probe), wux);

record! {
    pub struct WuxHeader {
        magic: ascii[4] "Magic",
        magic2: u32 "Magic 2" .hex(),
        sector_size: u32 "Sector size",
        _reserved: u32 "Reserved",
        size: u64 "Uncompressed size",
        flags: u32 "Flags" .hex(),
        _reserved2: u32 "Reserved",
    }
}

async fn wux(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, WuxHeader::SIZE);
    let h: WuxHeader = read_record(&cx, span, LE).await?;
    cx.emit(WuxHeader::node("Header", span, LE));
    let sector = u64::from(h.sector_size.max(1));
    let sectors = h.size.div_ceil(sector);
    let index = file.sub_exact(WuxHeader::SIZE, sectors.saturating_mul(4))?;
    let data_at = index.end().saturating_sub(file.offset).next_multiple_of(sector);
    let stored = file.len.saturating_sub(data_at).checked_div(sector).unwrap_or(0);
    cx.emit(Node::new("Sector index").span(index).summary(format!("{sectors} logical sectors")).lazy(wux_index, (file, index, data_at, sector)));
    cx.emit(Node::new("Unique sectors").span(file.tail(data_at)).summary(format!("{stored} stored")));
    cx.annotate(format!(
        "WUX image, {} in {sectors} sectors of {}, {stored} unique ({}% stored)",
        size(h.size),
        size(sector),
        stored.saturating_mul(100).checked_div(sectors).unwrap_or(0)
    ));
    Ok(())
}

async fn wux_index(cx: Cx, (file, index, data_at, sector): (Span, Span, u64, u64)) -> Result<()> {
    let count = index.len / 4;
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let entry = index.sub(i.saturating_mul(4), 4);
        let slot = u64::from(u32_le(&cx.read(entry).await?, 0).unwrap_or(0));
        cx.push(Node::new(format!("Sector {i}")).span(entry).value(hex(slot, 32)).target(file.sub(data_at.saturating_add(slot.saturating_mul(sector)), sector))).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Nintendo Switch NCZ (zstd-compressed NCA)

fn ncz_probe(h: &Head<'_>) -> bool {
    h.at(0x4000, b"NCZSECTN")
}

declare_format!(pub NCZ = "ncz", "Nintendo Switch compressed NCA (NCZ)", ["ncz"],
    "application/x-ncz", Probe::Custom(ncz_probe), ncz);

const NCZ_CRYPTO: EnumTable = &[(1, "none"), (2, "AES-XTS"), (3, "AES-CTR"), (4, "AES-CTR (BKTR)")];

async fn ncz(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("NCA header (encrypted)").span(file.sub(0, 0x4000)));
    let head = cx.read(file.sub(0x4000, 16)).await?;
    let count = u64_le(&head, 8).unwrap_or(0);
    let table = file.sub_exact(0x4010, count.saturating_mul(64))?;
    cx.emit(Node::new("Sections").span(file.sub(0x4000, table.len.saturating_add(16))).summary(format!("{count} sections")).lazy(ncz_sections, table));
    let mut at = table.end().saturating_sub(file.offset);
    let mut blocks = None;
    if cx.read_avail(file.sub(at, 8)).await? == b"NCZBLOCK" {
        let raw = cx.read(file.sub(at, 24)).await?;
        let n = u64::from(u32_le(&raw, 12).unwrap_or(0));
        let exp = raw.get(11).copied().unwrap_or(0);
        let total = u64_le(&raw, 16).unwrap_or(0);
        let span = file.sub(at, 24u64.saturating_add(n.saturating_mul(4)));
        cx.emit(Node::new("Block header").span(span).summary(format!("{n} blocks of {}, {} decompressed", size(1u64.checked_shl(exp.into()).unwrap_or(0)), size(total))));
        blocks = Some(n);
        at = span.end().saturating_sub(file.offset);
    }
    cx.emit(embedded("Compressed body (zstd)", input.nested(file.tail(at))));
    cx.annotate(format!("NCZ, {count} sections{}", blocks.map_or_else(|| ", solid zstd stream".to_owned(), |n| format!(", {n} zstd blocks"))));
    Ok(())
}

async fn ncz_sections(cx: Cx, table: Span) -> Result<()> {
    let count = table.len / 64;
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let span = table.sub(i.saturating_mul(64), 64);
        let raw = cx.read(span).await?;
        let offset = u64_le(&raw, 0).unwrap_or(0);
        let len = u64_le(&raw, 8).unwrap_or(0);
        let crypto = u64_le(&raw, 16).unwrap_or(0);
        cx.push(
            Node::new(format!("Section {i}"))
                .span(span)
                .value(Value::Enum { raw: crypto, bits: 64, name: lookup(NCZ_CRYPTO, crypto) })
                .summary(format!("{} at NCA offset {offset:#x}", size(len))),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Nintendo Switch program metadata (NPDM)

declare_format!(pub NPDM = "npdm", "Nintendo Switch program metadata (NPDM)", ["npdm"],
    "application/x-npdm", Probe::Magic(&[(0, b"META")]), npdm);

const NPDM_FLAGS: FlagTable = &[
    flag(0x01, "AARCH64"),
    crate::value::field(0x0e, 0x00, "ADDRESS_SPACE_32BIT"),
    crate::value::field(0x0e, 0x02, "ADDRESS_SPACE_64BIT_OLD"),
    crate::value::field(0x0e, 0x04, "ADDRESS_SPACE_32BIT_NO_RESERVED"),
    crate::value::field(0x0e, 0x06, "ADDRESS_SPACE_64BIT"),
    flag(0x10, "OPTIMIZE_MEMORY_ALLOCATION"),
];

record! {
    pub struct NpdmHeader {
        magic: ascii[4] "Magic",
        key_generation: u32 "Signature key generation",
        _reserved: u32 "Reserved",
        flags: u8 "Flags" .flags(NPDM_FLAGS),
        _reserved2: u8 "Reserved",
        priority: u8 "Main thread priority",
        core: u8 "Main thread core",
        _reserved3: u32 "Reserved",
        resource_size: u32 "System resource size",
        version: u32 "Version",
        stack: u32 "Main thread stack size" .hex(),
        name: ascii[16] "Name",
        product: ascii[16] "Product code",
        _reserved4: bytes[48] "Reserved",
        aci_offset: u32 "ACI0 offset" .hex(),
        aci_size: u32 "ACI0 size",
        acid_offset: u32 "ACID offset" .hex(),
        acid_size: u32 "ACID size",
    }
}

async fn npdm(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, NpdmHeader::SIZE);
    let h: NpdmHeader = read_record(&cx, span, LE).await?;
    cx.emit(NpdmHeader::node("Header", span, LE));
    let aci = file.sub(h.aci_offset.into(), h.aci_size.into());
    let raw = cx.read_avail(aci.sub(0, 0x40)).await?;
    let program = u64_le(&raw, 0x10).unwrap_or(0);
    let mut node = Node::new("ACI0 (access control info)").span(aci).summary(format!("program {program:016x}"));
    if raw.get(..4) != Some(b"ACI0") {
        node = node.diag(Diagnostic::malformed("missing ACI0 magic"));
    }
    cx.emit(node);
    let acid = file.sub(h.acid_offset.into(), h.acid_size.into());
    let raw = cx.read_avail(acid.sub(0, 0x240)).await?;
    let (lo, hi) = (u64_le(&raw, 0x210).unwrap_or(0), u64_le(&raw, 0x218).unwrap_or(0));
    cx.emit(Node::new("ACID (signed access control descriptor)").span(acid).summary(format!("programs {lo:016x}-{hi:016x}")));
    cx.annotate(format!("NPDM {:?}, program {program:016x}, {}, priority {}, core {}", clean(&h.name), if h.flags & 1 != 0 { "AArch64" } else { "AArch32" }, h.priority, h.core));
    Ok(())
}

// ---------------------------------------------------------------------------
// PlayStation 3 system update (PUP)

declare_format!(pub PS3_PUP = "ps3-pup", "PlayStation 3 system update (PUP)", ["pup"],
    "application/x-ps3-pup", Probe::Magic(&[(0, b"SCEUF\0\0\0")]), ps3_pup);

const PUP_ENTRIES: EnumTable = &[
    (0x100, "version.txt"),
    (0x101, "license.xml"),
    (0x102, "promo_flags.txt"),
    (0x103, "update_flags.txt"),
    (0x104, "patch_build.txt"),
    (0x200, "ps3swu.self"),
    (0x201, "vsh.tar"),
    (0x202, "dots.txt"),
    (0x203, "patch_data.pkg"),
    (0x300, "update_files.tar"),
    (0x501, "spkg_hdr.tar"),
    (0x601, "ps3swu2.self"),
];

async fn ps3_pup(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 0x30)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Magic", 8).emit()?;
    f.u64("Package version").emit()?;
    let image = f.u64("Image version").emit()?;
    let count = f.u64("File count").emit()?;
    f.u64("Header length").hex().emit()?;
    let data_len = f.u64("Data length").emit()?;
    let table = file.sub_exact(0x30, count.saturating_mul(32))?;
    let raw = cx.read(table).await?;
    let mut version = String::new();
    for (i, e) in raw.chunks(32).enumerate() {
        let id = u64_be(e, 0).unwrap_or(0);
        let offset = u64_be(e, 8).unwrap_or(0);
        let len = u64_be(e, 16).unwrap_or(0);
        let data = file.sub(offset, len);
        if id == 0x100 {
            version = String::from_utf8_lossy(&cx.read_avail(data.sub(0, 64)).await?).trim().to_owned();
        }
        let name = lookup(PUP_ENTRIES, id).map_or_else(|| format!("entry {id:#x}"), str::to_owned);
        cx.push(embedded(name, input.nested(data)).value(hex(id, 64)).summary(size(len)).target(table.sub(to_u64(i).saturating_mul(32), 32))).await;
    }
    let hashes = file.sub(table.end().saturating_sub(file.offset), count.saturating_mul(32));
    cx.emit(Node::new("SHA-1 HMAC table").span(hashes));
    cx.annotate(format!("PS3 update {}, image {image}, {count} files, {}", if version.is_empty() { "?" } else { &version }, size(data_len)));
    Ok(())
}

// ---------------------------------------------------------------------------
// PlayStation 4 package (PKG)

declare_format!(pub PS4_PKG = "ps4-pkg", "PlayStation 4 package (PKG)", ["pkg"],
    "application/x-ps4-pkg", Probe::Magic(&[(0, b"\x7fCNT")]), ps4_pkg);

const PS4_ENTRIES: EnumTable = &[
    (0x0001, "digests"),
    (0x0010, "entry_keys"),
    (0x0020, "image_key"),
    (0x0080, "general_digests"),
    (0x0100, "metas"),
    (0x0200, "entry_names"),
    (0x0400, "license.dat"),
    (0x0401, "license.info"),
    (0x0402, "nptitle.dat"),
    (0x0403, "npbind.dat"),
    (0x0409, "psreserved.dat"),
    (0x1000, "param.sfo"),
    (0x1001, "playgo-chunk.dat"),
    (0x1002, "playgo-chunk.sha"),
    (0x1003, "playgo-manifest.xml"),
    (0x1004, "pronunciation.xml"),
    (0x1005, "pronunciation.sig"),
    (0x1006, "pic1.png"),
    (0x1007, "pubtoolinfo.dat"),
    (0x1200, "icon0.png"),
    (0x1220, "pic0.png"),
    (0x1240, "snd0.at9"),
    (0x1260, "changeinfo/changeinfo.xml"),
];
const PS4_CONTENT: EnumTable = &[(0x1a, "game data (GD)"), (0x1b, "additional content (AC)"), (0x1c, "additional license (AL)"), (0x1e, "delta patch (DP)")];

async fn ps4_pkg(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 0x80)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.u32("Magic").hex().emit()?;
    f.u32("Package type").hex().emit()?;
    f.u32("Unknown").hex().emit()?;
    let files = f.u32("File count").emit()?;
    let count = f.u32("Entry count").emit()?;
    f.u16("SC entry count").emit()?;
    f.u16("Entry count (again)").emit()?;
    let table_at = f.u32("Entry table offset").hex().emit()?;
    f.u32("Entry data size").emit()?;
    let body_at = f.u64("Body offset").hex().emit()?;
    let body = f.u64("Body size").emit()?;
    f.u64("Content offset").hex().emit()?;
    f.u64("Content size").emit()?;
    let id = f.ascii("Content ID", 0x24).emit()?;
    f.bytes("Padding", 12).emit()?;
    f.u32("DRM type").hex().emit()?;
    let kind = f.u32("Content type").enumeration(PS4_CONTENT).emit()?;
    f.u32("Content flags").hex().emit()?;
    let table = file.sub_exact(table_at.into(), u64::from(count).saturating_mul(32))?;
    let raw = cx.read(table).await?;
    // File names live in the entry_names entry.
    let names_span = raw.chunks(32).find(|e| u32_be(e, 0) == Some(0x200)).map(|e| file.sub(u32_be(e, 16).unwrap_or(0).into(), u32_be(e, 20).unwrap_or(0).into()));
    let names = match names_span {
        Some(s) => cx.read_avail(s.sub(0, 0x10000)).await?,
        None => Vec::new(),
    };
    let mut title = None;
    for (i, e) in raw.chunks(32).enumerate() {
        let eid = u32_be(e, 0).unwrap_or(0);
        let name_at = usize::try_from(u32_be(e, 4).unwrap_or(0)).unwrap_or(usize::MAX);
        let encrypted = u32_be(e, 8).unwrap_or(0) & 0x8000_0000 != 0;
        let data = file.sub(u32_be(e, 16).unwrap_or(0).into(), u32_be(e, 20).unwrap_or(0).into());
        let name = lookup(PS4_ENTRIES, eid.into()).map(str::to_owned).or_else(|| (name_at > 0).then(|| crate::text::until_nul(names.get(name_at..).unwrap_or_default()))).unwrap_or_else(|| format!("entry {eid:#x}"));
        let node = if encrypted {
            Node::new(name).span(data).diag(Diagnostic::unsupported("encrypted entry"))
        } else if eid == 0x1000 {
            let sfo = embedded_as(name, input.nested(data), &super::consoles::SFO);
            let raw_sfo = cx.read_avail(data.sub(0, 0x4000)).await?;
            title = sfo_title(&raw_sfo);
            sfo
        } else {
            embedded(name, input.nested(data))
        };
        cx.push(node.value(hex(eid.into(), 32)).summary(size(data.len)).target(table.sub(to_u64(i).saturating_mul(32), 32))).await;
    }
    cx.emit(Node::new("Body").span(file.sub(body_at, body)).summary(size(body)));
    cx.annotate(format!(
        "PS4 package {id}{}, {}, {count} entries, {files} files",
        title.map_or_else(String::new, |t| format!(" {t:?}")),
        lookup(PS4_CONTENT, kind.into()).unwrap_or("unknown content")
    ));
    Ok(())
}

/// The TITLE value of a PARAM.SFO.
fn sfo_title(raw: &[u8]) -> Option<String> {
    let keys = usize::try_from(u32_le(raw, 8)?).ok()?;
    let data = usize::try_from(u32_le(raw, 12)?).ok()?;
    let count = usize::try_from(u32_le(raw, 16)?).ok()?;
    (0..count.min(256)).find_map(|i| {
        let at = 20usize.saturating_add(i.saturating_mul(16));
        let key_at = usize::from(crate::bytes::u16_le(raw, at)?);
        let key = crate::text::until_nul(raw.get(keys.saturating_add(key_at)..)?);
        let value_at = usize::try_from(u32_le(raw, at.saturating_add(12))?).ok()?;
        (key == "TITLE").then(|| crate::text::until_nul(raw.get(data.saturating_add(value_at)..).unwrap_or_default()))
    })
}

// ---------------------------------------------------------------------------
// PSP encrypted module (~PSP)

declare_format!(pub PSP_PRX = "psp-prx", "PSP encrypted module (~PSP)", ["prx", "bin"],
    "application/x-psp-prx", Probe::Magic(&[(0, b"~PSP")]), psp_prx);

const PSP_ATTR: FlagTable = &[flag(0x0001, "COMPRESSED"), flag(0x0200, "KL4E")];
const PSP_MOD: FlagTable = &[flag(0x0001, "CANT_STOP"), flag(0x0002, "EXCLUSIVE_LOAD"), flag(0x0004, "EXCLUSIVE_START"), flag(0x1000, "KERNEL"), flag(0x0800, "VSH"), flag(0x0400, "APP"), flag(0x0200, "USB_WLAN")];

record! {
    pub struct PspHeader {
        magic: ascii[4] "Magic",
        mod_attr: u16 "Module attributes" .flags(PSP_MOD),
        comp_attr: u16 "Compression attributes" .flags(PSP_ATTR),
        ver_lo: u8 "Module version (minor)",
        ver_hi: u8 "Module version (major)",
        name: ascii[28] "Module name",
        version: u8 "Header version",
        segments: u8 "Segments",
        elf_size: u32 "ELF size",
        psp_size: u32 "File size",
        entry: u32 "Entry point" .hex(),
        modinfo: u32 "Module info offset" .hex(),
        bss: u32 "BSS size",
        align: bytes[8] "Segment alignments",
        addresses: bytes[16] "Segment addresses",
        sizes: bytes[16] "Segment sizes",
        _reserved: bytes[20] "Reserved",
        devkit: u32 "Devkit version" .hex(),
        decrypt_mode: u8 "Decryption mode",
        _pad: u8 "Padding",
        overlap: u16 "Overlap size",
        aes_key: bytes[16] "AES key (encrypted)",
        cmac_key: bytes[16] "CMAC key (encrypted)",
        cmac_header: bytes[16] "CMAC header hash",
        comp_size: u32 "Compressed size",
        comp_offset: u32 "Compressed offset" .hex(),
        _unk1: u32 "Unknown",
        _unk2: u32 "Unknown",
        cmac_data: bytes[16] "CMAC data hash",
        tag: u32 "Tag" .hex(),
    }
}

async fn psp_prx(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, PspHeader::SIZE);
    let h: PspHeader = read_record(&cx, span, LE).await?;
    cx.emit(PspHeader::node("Header", span, LE));
    cx.emit(Node::new("Signature and key data").span(file.sub(PspHeader::SIZE, 0x150u64.saturating_sub(PspHeader::SIZE))));
    cx.emit(Node::new("Encrypted module").span(file.tail(0x150)).diag(Diagnostic::unsupported("PSP KIRK encryption")));
    cx.annotate(format!(
        "PSP module {:?} v{}.{}, tag {:#010x}, ELF {}, devkit {:#x}{}",
        clean(&h.name),
        h.ver_hi,
        h.ver_lo,
        h.tag,
        size(h.elf_size.into()),
        h.devkit,
        if h.comp_attr & 1 != 0 { ", compressed" } else { "" }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// GameShark / SharkPort GBA save

declare_format!(pub SHARKPORT = "gba-sharkport", "GameShark SharkPort GBA save", ["sps", "xps"],
    "application/x-sharkport", Probe::Magic(&[(0, b"\x0d\0\0\0SharkPortSave")]), sharkport);

async fn sharkport(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("Signature").span(file.sub(0, 17)).value(text("SharkPortSave")));
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(17);
    let at = cur.pos();
    let platform = cur.u32().await?;
    cx.emit(Node::new("Platform").span(cur.since(at)).value(hex(platform.into(), 32)));
    let mut strings = Vec::new();
    for name in ["Title", "Date", "Notes"] {
        let at = cur.pos();
        let len = u64::from(cur.u32().await?);
        let s = String::from_utf8_lossy(&cur.bytes(len.min(4096)).await?).into_owned();
        cx.emit(Node::new(name).span(cur.since(at)).value(text(s.clone())));
        strings.push(s);
    }
    let at = cur.pos();
    let len = u64::from(cur.u32().await?);
    let header = cur.span(0x1c);
    let rom = cx.read_avail(header.sub(0, 16)).await?;
    let game = String::from_utf8_lossy(rom.get(..12).unwrap_or_default()).trim_end_matches('\0').to_owned();
    cx.emit(Node::new("Save block").span(file.sub(at, len.saturating_add(4))).summary(format!("{} for {game:?}", size(len.saturating_sub(0x1c)))));
    cx.emit(Node::new("ROM header excerpt").span(header).value(text(game.clone())));
    cx.emit(Node::new("Save data").span(file.sub(header.end().saturating_sub(file.offset), len.saturating_sub(0x1c))));
    cx.annotate(format!(
        "SharkPort save {:?} for {game:?}, {}",
        strings.first().cloned().unwrap_or_default(),
        size(len.saturating_sub(0x1c))
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// MAME input recording (INP) and save state (STA)

declare_format!(pub MAME_INP = "mame-inp", "MAME input recording", ["inp"],
    "application/x-mame-inp", Probe::Magic(&[(0, b"MAMEINP\0")]), mame_inp);
declare_format!(pub MAME_STATE = "mame-state", "MAME save state", ["sta"],
    "application/x-mame-state", Probe::Magic(&[(0, b"MAMESAVE")]), mame_state);

async fn mame_inp(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 64)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Magic", 8).emit()?;
    f.u64("Recording time").timestamp().emit()?;
    let major = f.u8("Major version").emit()?;
    let minor = f.u8("Minor version").emit()?;
    f.bytes("Reserved", 2).emit()?;
    let game = f.ascii("Game", 12).emit()?;
    let version = f.ascii("MAME version", 32).emit()?;
    cx.emit(content("Input data", input, file.tail(64), Codec::Zlib, None));
    cx.annotate(format!("MAME input recording v{major}.{minor} of {:?}, {}", clean(&game), clean(&version)));
    Ok(())
}

const MAME_FLAGS: FlagTable = &[flag(0x02, "BIG_ENDIAN")];

async fn mame_state(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 32)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Magic", 8).emit()?;
    let version = f.u8("Version").emit()?;
    let flags = f.u8("Flags").flags(MAME_FLAGS).emit()?;
    let game = f.ascii("Game", 18).emit()?;
    f.u32("Signature").hex().emit()?;
    cx.emit(content("State data", input, file.tail(32), Codec::Zlib, None));
    cx.annotate(format!("MAME save state v{version} of {:?}{}", clean(&game), if flags & 2 != 0 { ", big-endian" } else { "" }));
    Ok(())
}
