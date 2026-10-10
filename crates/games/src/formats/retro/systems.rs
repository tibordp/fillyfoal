//! Console system files: GameCube DOL executables, Dreamcast VMI
//! descriptors, 3DS SMDH icons and FIRM firmware, Switch KIP1/INI1 kernel
//! processes, Xbox 360 STFS packages and Xbox XDVDFS (XISO) images.

use super::util::clean;
use crate::bytes::{to_u64, u16_le, u32_be, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Record, emit_record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::fmt::size;
use crate::formats::util::val::{hex, text};
use crate::formats::{Head, Input, Probe, embedded, embedded_as};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// GameCube / Wii DOL executable

fn gc_addr(a: u32) -> bool {
    (0x8000_0000..0x8180_0000).contains(&a)
}

fn dol_probe(h: &Head<'_>) -> bool {
    let off = |i: usize| u32_be(h.data, i.saturating_mul(4)).unwrap_or(0);
    let addr =
        |i: usize| u32_be(h.data, 0x48usize.saturating_add(i.saturating_mul(4))).unwrap_or(0);
    let len = |i: usize| u32_be(h.data, 0x90usize.saturating_add(i.saturating_mul(4))).unwrap_or(0);
    let sections_ok = (0..18).all(|i| {
        let (o, a, l) = (off(i), addr(i), len(i));
        (o == 0 && l == 0)
            || (o >= 0x100 && u64::from(o).saturating_add(l.into()) <= h.len && gc_addr(a))
    });
    h.data.len() >= 0x100
        && off(0) >= 0x100
        && len(0) > 0
        && sections_ok
        && u32_be(h.data, 0xe0).is_some_and(gc_addr)
}

declare_format!(pub DOL = "dol", "GameCube/Wii executable (DOL)", ["dol"],
    "application/x-dol", Probe::Custom(dol_probe), dol);

async fn dol(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let raw = cx.read(file.sub(0, 0x100)).await?;
    let word = |o: usize| u32_be(&raw, o).unwrap_or(0);
    let entry = word(0xe0);
    cx.emit(
        Node::new("Header")
            .span(file.sub(0, 0x100))
            .summary(format!("entry {entry:#010x}"))
            .lazy(dol_header, file.sub(0, 0x100)),
    );
    let (mut text, mut data) = (0u64, 0u64);
    for i in 0..18usize {
        let at = |base: usize| base.saturating_add(i.saturating_mul(4));
        let (offset, address, len) = (word(at(0)), word(at(0x48)), word(at(0x90)));
        if len == 0 {
            continue;
        }
        let (name, total) = if i < 7 {
            (format!("Text {i}"), &mut text)
        } else {
            (format!("Data {}", i.saturating_sub(7)), &mut data)
        };
        *total = total.saturating_add(len.into());
        cx.emit(
            Node::new(name)
                .span(file.sub(offset.into(), len.into()))
                .value(hex(address, 32))
                .summary(format!("{} at {address:#010x}", size(len.into()))),
        );
    }
    cx.annotate(format!(
        "GameCube/Wii DOL, {} text, {} data, {} BSS at {:#010x}, entry {entry:#010x}",
        size(text),
        size(data),
        size(word(0xdc).into()),
        word(0xd8)
    ));
    Ok(())
}

async fn dol_header(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    f.node(Node::new("Section file offsets").span(span.sub(0, 0x48)));
    f.node(Node::new("Section load addresses").span(span.sub(0x48, 0x48)));
    f.node(Node::new("Section sizes").span(span.sub(0x90, 0x48)));
    f.seek(0xd8);
    f.u32("BSS address").hex().emit()?;
    f.u32("BSS size").emit()?;
    f.u32("Entry point").hex().emit()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Dreamcast VMI (VMU file descriptor)

fn vmi_probe(h: &Head<'_>) -> bool {
    h.len == 108
        && h.data
            .get(..4)
            .zip(h.data.get(0x50..0x54))
            .is_some_and(|(sum, name)| {
                sum.iter()
                    .zip(name.iter().zip(b"SEGA"))
                    .all(|(&s, (&n, &k))| s == n & k)
            })
        && h.data
            .get(0x58..0x64)
            .is_some_and(|n| n.iter().all(|&b| b == 0 || (0x20..0x7f).contains(&b)))
}

declare_format!(pub VMI = "dreamcast-vmi", "Dreamcast VMU file descriptor (VMI)", ["vmi"],
    "application/x-dreamcast-vmi", Probe::Custom(vmi_probe), vmi);

const VMI_MODES: FlagTable = &[flag(0x01, "COPY_PROTECTED"), flag(0x02, "GAME")];

record! {
    pub struct VmiFile {
        checksum: bytes[4] "Checksum",
        description: ascii[32] "Description",
        copyright: ascii[32] "Copyright",
        year: u16 "Year",
        month: u8 "Month",
        day: u8 "Day",
        hour: u8 "Hour",
        minute: u8 "Minute",
        second: u8 "Second",
        weekday: u8 "Weekday",
        version: u16 "VMI version",
        number: u16 "File number",
        resource: ascii[8] "VMS resource name",
        filename: ascii[12] "File name on VMU",
        mode: u16 "File mode" .flags(VMI_MODES),
        _unknown: u16 "Unknown",
        size: u32 "File size",
    }
}

async fn vmi(cx: Cx, input: Input) -> Result<()> {
    let h: VmiFile = emit_record(&cx, input.span.sub(0, VmiFile::SIZE), LE).await?;
    cx.annotate(format!(
        "VMU {} {:?} ({}.VMS), {:?}, {}, {:04}-{:02}-{:02}",
        if h.mode & 2 != 0 { "game" } else { "save" },
        clean(&h.filename),
        clean(&h.resource),
        clean(&h.description),
        size(h.size.into()),
        h.year,
        h.month,
        h.day
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Nintendo 3DS SMDH (icon and titles)

declare_format!(pub SMDH = "smdh", "Nintendo 3DS icon and title data (SMDH)", ["smdh", "icn"],
    "application/x-smdh", Probe::Magic(&[(0, b"SMDH")]), smdh);

const SMDH_LANGUAGES: [&str; 12] = [
    "Japanese",
    "English",
    "French",
    "German",
    "Italian",
    "Spanish",
    "Simplified Chinese",
    "Korean",
    "Dutch",
    "Portuguese",
    "Russian",
    "Traditional Chinese",
];
const SMDH_REGIONS: FlagTable = &[
    flag(0x01, "JAPAN"),
    flag(0x02, "NORTH_AMERICA"),
    flag(0x04, "EUROPE"),
    flag(0x08, "AUSTRALIA"),
    flag(0x10, "CHINA"),
    flag(0x20, "KOREA"),
    flag(0x40, "TAIWAN"),
];
const SMDH_FLAGS: FlagTable = &[
    flag(0x0001, "VISIBLE"),
    flag(0x0002, "AUTOBOOT"),
    flag(0x0004, "ALLOW_3D"),
    flag(0x0008, "REQUIRE_EULA"),
    flag(0x0010, "AUTOSAVE"),
    flag(0x0020, "EXTENDED_BANNER"),
    flag(0x0040, "RATING_REQUIRED"),
    flag(0x0080, "SAVE_DATA"),
    flag(0x0100, "RECORD_USAGE"),
    flag(0x0400, "NO_SAVE_BACKUPS"),
    flag(0x1000, "NEW_3DS"),
];

async fn smdh(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 8)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Magic", 4).emit()?;
    f.u16("Version").emit()?;
    f.u16("Reserved").emit()?;
    let titles = file.sub(8, 16 * 0x200);
    let english = cx.read_avail(titles.sub(0x200, 0x200)).await?;
    let short = crate::text::utf16z(english.get(..0x80).unwrap_or_default(), LE).0;
    let publisher = crate::text::utf16z(english.get(0x180..).unwrap_or_default(), LE).0;
    cx.emit(
        Node::new("Application titles")
            .span(titles)
            .summary(format!("{short:?} by {publisher}"))
            .lazy(smdh_titles, titles),
    );
    let settings = cx.block(file.sub(0x2008, 0x30)).await?;
    let mut g = Fields::emitting(&cx, &settings, LE);
    g.bytes("Age ratings", 16).emit()?;
    let regions = g.u32("Region lockout").flags(SMDH_REGIONS).emit()?;
    g.u32("Match maker ID").hex().emit()?;
    g.u64("Match maker BIT ID").hex().emit()?;
    g.u32("Flags").flags(SMDH_FLAGS).emit()?;
    g.u16("EULA version").emit()?;
    g.u16("Reserved").emit()?;
    g.f32("Optimal animation default frame").emit()?;
    g.u32("CEC (StreetPass) ID").hex().emit()?;
    cx.emit(Node::new("Small icon (24×24 RGB565, tiled)").span(file.sub(0x2040, 0x480)));
    cx.emit(Node::new("Large icon (48×48 RGB565, tiled)").span(file.sub(0x24c0, 0x1200)));
    let all = (0..7).map(|i| 1u32 << i).fold(0, |a, b| a | b);
    cx.annotate(format!(
        "3DS SMDH {short:?} by {publisher}, {}",
        if regions & all == all || regions == 0x7fff_ffff {
            "region-free".to_owned()
        } else {
            format!("regions {regions:#x}")
        }
    ));
    Ok(())
}

async fn smdh_titles(cx: Cx, titles: Span) -> Result<()> {
    let raw = cx.read_avail(titles).await?;
    cx.set_count(Count::Exact(16));
    for i in 0..16usize {
        let at = i.saturating_mul(0x200);
        let one = raw.get(at..at.saturating_add(0x200)).unwrap_or_default();
        let short = crate::text::utf16z(one.get(..0x80).unwrap_or_default(), LE).0;
        let long = crate::text::utf16z(one.get(0x80..0x180).unwrap_or_default(), LE).0;
        let publisher = crate::text::utf16z(one.get(0x180..).unwrap_or_default(), LE).0;
        let name = SMDH_LANGUAGES
            .get(i)
            .map_or_else(|| format!("Language {i}"), |l| (*l).to_owned());
        cx.push(
            Node::new(name)
                .span(titles.sub(to_u64(at), 0x200))
                .value(text(short))
                .summary(format!("{} / {publisher}", long.replace('\n', " "))),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Nintendo 3DS FIRM

declare_format!(pub FIRM = "3ds-firm", "Nintendo 3DS firmware (FIRM)", ["firm", "bin"],
    "application/x-3ds-firm", Probe::Magic(&[(0, b"FIRM")]), firm);

const FIRM_COPY: EnumTable = &[(0, "NDMA"), (1, "XDMA"), (2, "CPU memcpy")];

async fn firm(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 0x40)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Magic", 4).emit()?;
    f.u32("Boot priority").emit()?;
    let arm11 = f.u32("ARM11 entry point").hex().emit()?;
    let arm9 = f.u32("ARM9 entry point").hex().emit()?;
    f.bytes("Reserved", 0x30).emit()?;
    let table = cx.read(file.sub(0x40, 0xc0)).await?;
    let mut sections = 0u32;
    for i in 0..4usize {
        let base = i.saturating_mul(0x30);
        let offset = u32_le(&table, base).unwrap_or(0);
        let address = u32_le(&table, base.saturating_add(4)).unwrap_or(0);
        let len = u32_le(&table, base.saturating_add(8)).unwrap_or(0);
        let copy = u32_le(&table, base.saturating_add(12)).unwrap_or(0);
        if len == 0 {
            continue;
        }
        sections = sections.saturating_add(1);
        cx.emit(
            Node::new(format!("Section {i}"))
                .span(file.sub(offset.into(), len.into()))
                .value(hex(address, 32))
                .summary(format!(
                    "{} at {address:#010x}, {}",
                    size(len.into()),
                    lookup(FIRM_COPY, copy.into()).unwrap_or("unknown copy method")
                ))
                .target(file.sub(0x40u64.saturating_add(to_u64(base)), 0x30)),
        );
    }
    cx.emit(Node::new("RSA-2048 signature").span(file.sub(0x100, 0x100)));
    cx.annotate(format!(
        "3DS FIRM, {sections} sections, ARM9 entry {arm9:#010x}, ARM11 entry {arm11:#010x}"
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Nintendo Switch KIP1 and INI1

declare_format!(pub KIP1 = "kip1", "Nintendo Switch kernel initial process (KIP1)", ["kip", "kip1"],
    "application/x-switch-kip", Probe::Magic(&[(0, b"KIP1")]), kip1);
declare_format!(pub INI1 = "ini1", "Nintendo Switch initial process bundle (INI1)", ["ini1", "bin"],
    "application/x-switch-ini1", Probe::Magic(&[(0, b"INI1")]), ini1);

const KIP_FLAGS: FlagTable = &[
    flag(0x01, "TEXT_COMPRESSED"),
    flag(0x02, "RO_COMPRESSED"),
    flag(0x04, "DATA_COMPRESSED"),
    flag(0x08, "AARCH64"),
    flag(0x10, "ADDRESS_SPACE_64BIT"),
    flag(0x20, "SECURE_MEMORY"),
];

record! {
    pub struct KipHeader {
        magic: ascii[4] "Magic",
        name: ascii[12] "Name",
        program: u64 "Program ID" .hex(),
        version: u32 "Version",
        priority: u8 "Main thread priority",
        core: u8 "Default core",
        _reserved: u8 "Reserved",
        flags: u8 "Flags" .flags(KIP_FLAGS),
        text_offset: u32 ".text memory offset" .hex(),
        text_size: u32 ".text size" .hex(),
        text_compressed: u32 ".text compressed size" .hex(),
        stack: u32 "Main thread stack size" .hex(),
        ro_offset: u32 ".rodata memory offset" .hex(),
        ro_size: u32 ".rodata size" .hex(),
        ro_compressed: u32 ".rodata compressed size" .hex(),
        _ro_attr: u32 ".rodata attribute",
        data_offset: u32 ".data memory offset" .hex(),
        data_size: u32 ".data size" .hex(),
        data_compressed: u32 ".data compressed size" .hex(),
        _data_attr: u32 ".data attribute",
        bss_offset: u32 ".bss memory offset" .hex(),
        bss_size: u32 ".bss size" .hex(),
        _reserved2: bytes[40] "Reserved",
        capabilities: bytes[128] "Kernel capabilities",
    }
}

fn kip_total(h: &KipHeader) -> u64 {
    KipHeader::SIZE
        .saturating_add(h.text_compressed.into())
        .saturating_add(h.ro_compressed.into())
        .saturating_add(h.data_compressed.into())
}

async fn kip1(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, KipHeader::SIZE);
    let h: KipHeader = read_record(&cx, span, LE).await?;
    cx.emit(KipHeader::node("Header", span, LE));
    let mut at = KipHeader::SIZE;
    for (i, (name, len)) in [
        (".text", h.text_compressed),
        (".rodata", h.ro_compressed),
        (".data", h.data_compressed),
    ]
    .into_iter()
    .enumerate()
    {
        let mut node = Node::new(name)
            .span(file.sub(at, len.into()))
            .summary(size(len.into()));
        if h.flags & (1u8 << i) != 0 {
            node = node.diag(Diagnostic::unsupported("BLZ (backwards LZ) compression"));
        }
        cx.emit(node);
        at = at.saturating_add(len.into());
    }
    cx.annotate(format!(
        "KIP1 {:?} ({:016x}) v{}, {}{}",
        clean(&h.name),
        h.program,
        h.version,
        size(
            u64::from(h.text_size)
                .saturating_add(h.ro_size.into())
                .saturating_add(h.data_size.into())
        ),
        if h.flags & 7 != 0 { ", compressed" } else { "" }
    ));
    Ok(())
}

async fn ini1(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 16)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Magic", 4).emit()?;
    let total = f.u32("Size").emit()?;
    let count = f.u32("Processes").emit()?;
    f.u32("Reserved").emit()?;
    let mut at = 16u64;
    let mut names = Vec::new();
    for _ in 0..count.min(256) {
        let span = file.sub(at, KipHeader::SIZE);
        let Ok(h) = read_record::<KipHeader>(&cx, span, LE).await else {
            break;
        };
        let len = kip_total(&h);
        names.push(clean(&h.name));
        cx.push(
            embedded_as(clean(&h.name), input.nested(file.sub(at, len)), &KIP1).summary(size(len)),
        )
        .await;
        at = at.saturating_add(len);
    }
    cx.annotate(format!(
        "INI1, {count} processes ({}), {}",
        names.join(", "),
        size(total.into())
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Xbox 360 STFS packages (CON, LIVE, PIRS)

declare_format!(pub STFS = "xbox360-stfs", "Xbox 360 package (STFS: CON/LIVE/PIRS)", ["con", "live", "pirs"],
    "application/x-xbox360-stfs", Probe::Magic(&[(0, b"CON "), (0, b"LIVE"), (0, b"PIRS")]), stfs);

const STFS_CONTENT: EnumTable = &[
    (0x0000_0001, "saved game"),
    (0x0000_0002, "marketplace content"),
    (0x0000_0003, "publisher"),
    (0x0000_1000, "Xbox 360 title"),
    (0x0000_2000, "IPTV pause buffer"),
    (0x0000_4000, "installed game"),
    (0x0000_5000, "original Xbox game"),
    (0x0000_7000, "Games on Demand"),
    (0x0000_9000, "avatar item"),
    (0x0001_0000, "profile"),
    (0x0002_0000, "gamer picture"),
    (0x0003_0000, "theme"),
    (0x0004_0000, "cache file"),
    (0x0005_0000, "storage download"),
    (0x0006_0000, "Xbox saved game"),
    (0x0007_0000, "Xbox download"),
    (0x0008_0000, "game demo"),
    (0x0009_0000, "video"),
    (0x000a_0000, "game title"),
    (0x000b_0000, "installer"),
    (0x000c_0000, "game trailer"),
    (0x000d_0000, "arcade title"),
    (0x000e_0000, "XNA"),
    (0x000f_0000, "license store"),
    (0x0010_0000, "movie"),
    (0x0020_0000, "TV"),
    (0x0030_0000, "music video"),
    (0x0040_0000, "game video"),
    (0x0050_0000, "podcast video"),
    (0x0060_0000, "viral video"),
    (0x0200_0000, "community game"),
];

fn utf16be(raw: &[u8]) -> String {
    crate::text::utf16z(raw, BE).0
}

async fn stfs(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let magic = cx.read(file.sub(0, 4)).await?;
    let magic = String::from_utf8_lossy(&magic).into_owned();
    cx.emit(
        Node::new("Magic")
            .span(file.sub(0, 4))
            .value(text(magic.clone())),
    );
    cx.emit(
        Node::new(if magic == "CON " {
            "Console certificate and signature"
        } else {
            "Package signature"
        })
        .span(file.sub(4, 0x228)),
    );
    cx.emit(Node::new("License entries").span(file.sub(0x22c, 0x100)));
    let meta = cx.block(file.sub(0x32c, 0x79)).await?;
    let mut f = Fields::emitting(&cx, &meta, BE);
    f.bytes("Header SHA-1", 20).emit()?;
    f.u32("Header size").hex().emit()?;
    let content = f.u32("Content type").enumeration(STFS_CONTENT).emit()?;
    f.u32("Metadata version").emit()?;
    let content_size = f.u64("Content size").emit()?;
    f.u32("Media ID").hex().emit()?;
    f.u32("Version").emit()?;
    f.u32("Base version").emit()?;
    let title_id = f.u32("Title ID").hex().emit()?;
    f.u8("Platform").emit()?;
    f.u8("Executable type").emit()?;
    f.u8("Disc number").emit()?;
    f.u8("Discs in set").emit()?;
    f.u32("Save game ID").hex().emit()?;
    f.bytes("Console ID", 5).emit()?;
    f.u64("Profile ID").hex().emit()?;
    cx.emit(Node::new("Volume descriptor").span(file.sub(0x379, 0x24)));
    let strings = cx.read_avail(file.sub(0x411, 0x1312)).await?;
    let display = utf16be(strings.get(..0x80).unwrap_or_default());
    let description = utf16be(strings.get(0x900..0x980).unwrap_or_default());
    let publisher = utf16be(strings.get(0x1200..0x1280).unwrap_or_default());
    let title = utf16be(strings.get(0x1280..0x1300).unwrap_or_default());
    cx.emit(
        Node::new("Display name")
            .span(file.sub(0x411, 0x80))
            .value(text(display.clone())),
    );
    cx.emit(
        Node::new("Display description")
            .span(file.sub(0xd11, 0x80))
            .value(text(description)),
    );
    cx.emit(
        Node::new("Publisher")
            .span(file.sub(0x1611, 0x80))
            .value(text(publisher.clone())),
    );
    cx.emit(
        Node::new("Title name")
            .span(file.sub(0x1691, 0x80))
            .value(text(title.clone())),
    );
    let sizes = cx.read_avail(file.sub(0x1712, 8)).await?;
    let thumb = u64::from(u32_be(&sizes, 0).unwrap_or(0));
    let title_thumb = u64::from(u32_be(&sizes, 4).unwrap_or(0));
    if thumb > 0 {
        cx.emit(embedded(
            "Thumbnail",
            input.nested(file.sub(0x171a, thumb.min(0x4000))),
        ));
    }
    if title_thumb > 0 {
        cx.emit(embedded(
            "Title thumbnail",
            input.nested(file.sub(0x571a, title_thumb.min(0x4000))),
        ));
    }
    cx.emit(Node::new("Hash tables and file data").span(file.tail(0xa000)));
    cx.annotate(format!(
        "Xbox 360 {} package, {} {display:?} for {title:?} ({title_id:08X}) by {publisher}, {}",
        magic.trim(),
        lookup(STFS_CONTENT, content.into()).unwrap_or("content"),
        size(content_size)
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Xbox XDVDFS (XISO)

const XISO_MAGIC: &[u8] = b"MICROSOFT*XBOX*MEDIA";
const XISO_SECTOR: u64 = 2048;

declare_format!(pub XISO = "xiso", "Xbox DVD file system image (XISO)", ["iso", "xiso"],
    "application/x-xiso", Probe::Magic(&[(0x10000, XISO_MAGIC)]), xiso);

const XISO_ATTRS: FlagTable = &[
    flag(0x01, "READ_ONLY"),
    flag(0x02, "HIDDEN"),
    flag(0x04, "SYSTEM"),
    flag(0x10, "DIRECTORY"),
    flag(0x20, "ARCHIVE"),
    flag(0x80, "NORMAL"),
];

async fn xiso(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let vd = cx.block(file.sub(0x10000, 0x24)).await?;
    let mut f = Fields::emitting(&cx, &vd, LE);
    f.ascii("Magic", 20).emit()?;
    let root = f.u32("Root directory sector").emit()?;
    let root_len = f.u32("Root directory size").emit()?;
    f.u64("Creation time").filetime().emit()?;
    let dir = file.sub(u64::from(root).saturating_mul(XISO_SECTOR), root_len.into());
    cx.emit(Node::new("/").span(dir).lazy(
        crate::expander!(self::xiso_dir: (Input, Span, u32)),
        (input, dir, 0u32),
    ));
    cx.annotate(format!(
        "Xbox XDVDFS image, root directory at sector {root} ({root_len} bytes), {}",
        size(file.len)
    ));
    Ok(())
}

async fn xiso_dir(cx: Cx, (input, dir, depth): (Input, Span, u32)) -> Result<()> {
    if depth > 32 {
        return Err(Diagnostic::limit("directories nested too deeply"));
    }
    let file = input.span;
    let raw = cx.read(dir).await?;
    let mut pos = 0usize;
    while pos.saturating_add(14) <= raw.len() {
        if u16_le(&raw, pos) == Some(0xffff) {
            pos = pos.saturating_add(1).next_multiple_of(2048);
            continue;
        }
        let sector = u64::from(u32_le(&raw, pos.saturating_add(4)).unwrap_or(0));
        let len = u64::from(u32_le(&raw, pos.saturating_add(8)).unwrap_or(0));
        let attrs = raw.get(pos.saturating_add(12)).copied().unwrap_or(0);
        let name_len = usize::from(raw.get(pos.saturating_add(13)).copied().unwrap_or(0));
        let name = String::from_utf8_lossy(
            raw.get(pos.saturating_add(14)..pos.saturating_add(14).saturating_add(name_len))
                .unwrap_or_default(),
        )
        .into_owned();
        let entry = dir.sub(to_u64(pos), to_u64(name_len).saturating_add(14));
        let data = file.sub(sector.saturating_mul(XISO_SECTOR), len);
        let (set, unknown) = crate::value::decode_flags(XISO_ATTRS, attrs.into());
        let node = if attrs & 0x10 != 0 {
            Node::new(format!("{name}/")).span(data).lazy(
                crate::expander!(self::xiso_dir: (Input, Span, u32)),
                (input, data, depth.saturating_add(1)),
            )
        } else {
            embedded(name.clone(), input.nested(data)).summary(size(len))
        };
        cx.push(
            node.value(Value::Flags {
                raw: attrs.into(),
                bits: 8,
                set,
                unknown,
            })
            .target(entry),
        )
        .await;
        pos = pos
            .saturating_add(14)
            .saturating_add(name_len)
            .next_multiple_of(4);
    }
    Ok(())
}
