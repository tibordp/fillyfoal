//! 8/16-bit computer graphics, icons, ROMs and file headers: Amiga Kickstart
//! ROMs and Workbench icons, Degas and NEOchrome pictures, Koala paintings,
//! MSX BSAVE files and Amstrad AMSDOS headers.

use super::util::{clean, dec, hex, size, text};
use crate::bytes::{to_u64, u16_be, u16_le, u32_be};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Record, emit_record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::{Head, Input, Probe, embedded};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// Amiga Kickstart ROM

fn kickstart_probe(h: &Head<'_>) -> bool {
    ((h.at(0, b"\x11\x14\x4e\xf9") || h.at(0, b"\x11\x11\x4e\xf9") || h.at(0, b"\x11\x16\x4e\xf9")) && matches!(h.len, 0x40000 | 0x80000 | 0x100000))
        || h.at(0, b"AMIROMTYPE1")
}

declare_format!(pub KICKSTART = "amiga-kickstart", "Amiga Kickstart ROM", ["rom", "kick"],
    "application/x-amiga-rom", Probe::Custom(kickstart_probe), kickstart);

const KICKSTART_VERSIONS: EnumTable = &[
    (30, "1.0"),
    (31, "1.1 (NTSC)"),
    (32, "1.1 (PAL)"),
    (33, "1.2"),
    (34, "1.3"),
    (35, "1.3 (A2024)"),
    (36, "2.0"),
    (37, "2.04/2.05"),
    (39, "3.0"),
    (40, "3.1"),
    (45, "3.x (OS 3.5+)"),
    (46, "3.1.4"),
    (47, "3.2"),
];

record! {
    pub struct KickHeader {
        magic: u16 "Magic" .hex(),
        jump: u16 "JMP opcode" .hex(),
        entry: u32 "Entry point" .hex(),
        diag: u32 "Diagnostic pattern" .hex(),
        version: u16 "Kickstart version" .enumeration(KICKSTART_VERSIONS),
        revision: u16 "Kickstart revision",
        exec_version: u16 "exec.library version",
        exec_revision: u16 "exec.library revision",
    }
}

async fn kickstart(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    if cx.read_avail(file.sub(0, 11)).await? == b"AMIROMTYPE1" {
        cx.emit(Node::new("Signature").span(file.sub(0, 11)).value(text("AMIROMTYPE1")));
        cx.emit(Node::new("Encrypted ROM").span(file.tail(11)).diag(Diagnostic::unsupported("Cloanto ROM encryption (needs rom.key)")));
        cx.annotate(format!("Cloanto-encrypted Amiga ROM, {}", size(file.len.saturating_sub(11))));
        return Ok(());
    }
    let h: KickHeader = emit_record(&cx, file.sub(0, KickHeader::SIZE), BE).await?;
    // The identification string follows the header.
    let ident = cx.read_avail(file.sub(0x18, 0x60)).await?;
    let ident: String = ident.iter().take_while(|&&b| b != 0 && b != b'\r' && b != b'\n').map(|&b| char::from(b)).collect();
    if !ident.is_empty() {
        cx.emit(Node::new("Identification").span(file.sub(0x18, to_u64(ident.len()))).value(text(ident.clone())));
    }
    let foot = file.len.saturating_sub(0x18);
    let tail = cx.read(file.sub(foot, 0x18)).await?;
    let stored = u32_be(&tail, 0).unwrap_or(0);
    let declared = u32_be(&tail, 4).unwrap_or(0);
    let mut verdict = "";
    let mut node = Node::new("Checksum").span(file.sub(foot, 4)).value(hex(stored.into(), 32));
    if file.len <= cx.limits().max_read {
        let all = cx.read(file).await?;
        // Sum of all longs with end-around carry must be 0xFFFFFFFF.
        let sum = all.chunks(4).fold(0u32, |acc, c| {
            let (s, carry) = acc.overflowing_add(u32_be(c, 0).unwrap_or(0));
            s.wrapping_add(u32::from(carry))
        });
        if sum == u32::MAX {
            verdict = ", checksum valid";
            node = node.summary("valid");
        } else {
            verdict = ", checksum mismatch";
            node = node.diag(Diagnostic::warning(format!("long sum is {sum:#010x}, expected 0xffffffff")));
        }
    }
    cx.emit(node);
    cx.emit(Node::new("ROM size").span(file.sub(foot.saturating_add(4), 4)).value(dec(declared.into(), 32)));
    cx.emit(Node::new("Autovectors").span(file.sub(foot.saturating_add(8), 16)));
    cx.emit(Node::new("Resident modules and libraries").span(file.sub(KickHeader::SIZE, foot.saturating_sub(KickHeader::SIZE))));
    cx.annotate(format!(
        "Amiga Kickstart {} ({}.{}), exec {}.{}, {}{verdict}",
        lookup(KICKSTART_VERSIONS, h.version.into()).unwrap_or("?"),
        h.version,
        h.revision,
        h.exec_version,
        h.exec_revision,
        size(file.len)
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Amiga Workbench icon (.info)

fn info_probe(h: &Head<'_>) -> bool {
    h.at(0, b"\xe3\x10\x00\x01") && h.data.get(0x30).is_some_and(|t| (1..=8).contains(t))
}

declare_format!(pub AMIGA_INFO = "amiga-info", "Amiga Workbench icon (.info)", ["info"],
    "application/x-amiga-icon", Probe::Custom(info_probe), amiga_info);

const ICON_TYPES: EnumTable = &[(1, "disk"), (2, "drawer"), (3, "tool"), (4, "project"), (5, "trashcan"), (6, "device"), (7, "Kickstart disk"), (8, "AppIcon")];
const GADGET_FLAGS: FlagTable = &[flag(0x0001, "GADGHBOX"), flag(0x0002, "GADGHIMAGE"), flag(0x0004, "GADGIMAGE"), flag(0x0080, "SELECTED"), flag(0x0100, "DISABLED")];

record! {
    pub struct DiskObject {
        magic: u16 "Magic" .hex(),
        version: u16 "Version",
        next: u32 "Gadget: next" .hex(),
        left: i16 "Gadget: left edge",
        top: i16 "Gadget: top edge",
        width: i16 "Gadget: width",
        height: i16 "Gadget: height",
        flags: u16 "Gadget: flags" .flags(GADGET_FLAGS),
        activation: u16 "Gadget: activation" .hex(),
        gadget_type: u16 "Gadget: type" .hex(),
        render: u32 "Gadget: render image" .hex(),
        select: u32 "Gadget: select image" .hex(),
        gadget_text: u32 "Gadget: text" .hex(),
        mutual: i32 "Gadget: mutual exclude",
        special: u32 "Gadget: special info" .hex(),
        id: u16 "Gadget: ID",
        user: u32 "Gadget: user data" .hex() .desc("Low byte: revision (1 = OS 2.x)"),
        kind: u8 "Icon type" .enumeration(ICON_TYPES),
        _pad: u8 "Padding",
        default_tool: u32 "Default tool" .hex(),
        tool_types: u32 "Tool types" .hex(),
        x: i32 "Current X",
        y: i32 "Current Y",
        drawer: u32 "Drawer data" .hex(),
        tool_window: u32 "Tool window" .hex(),
        stack: i32 "Stack size",
    }
}

record! {
    pub struct IconImage {
        left: i16 "Left edge",
        top: i16 "Top edge",
        width: i16 "Width",
        height: i16 "Height",
        depth: i16 "Depth",
        data: u32 "Image data" .hex(),
        pick: u8 "Plane pick" .hex(),
        on_off: u8 "Plane on/off" .hex(),
        next: u32 "Next image" .hex(),
    }
}

async fn amiga_info(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, DiskObject::SIZE);
    let h: DiskObject = read_record(&cx, span, BE).await?;
    cx.emit(DiskObject::node("Disk object", span, BE));
    let mut at = DiskObject::SIZE;
    if h.drawer != 0 {
        cx.emit(Node::new("Drawer data (NewWindow)").span(file.sub(at, 56)));
        at = at.saturating_add(56);
    }
    let mut dims = String::new();
    for (name, present) in [("Image", h.render != 0), ("Selected image", h.select != 0)] {
        if !present {
            continue;
        }
        let ispan = file.sub(at, IconImage::SIZE);
        let img: IconImage = read_record(&cx, ispan, BE).await?;
        let width = u64::try_from(img.width).unwrap_or(0);
        let height = u64::try_from(img.height).unwrap_or(0);
        let depth = u64::try_from(img.depth).unwrap_or(0);
        let planes = width.div_ceil(16).saturating_mul(2).saturating_mul(height).saturating_mul(depth);
        if dims.is_empty() {
            dims = format!("{width}×{height}, {depth} bitplanes");
        }
        let node = IconImage::node(name, ispan, BE).span(file.sub(at, IconImage::SIZE.saturating_add(planes))).summary(format!("{width}×{height}×{depth}"));
        cx.emit(node);
        at = at.saturating_add(IconImage::SIZE).saturating_add(planes);
    }
    let mut tool = String::new();
    if h.default_tool != 0 {
        let len = u64::from(u32_be(&cx.read(file.sub(at, 4)).await?, 0).unwrap_or(0));
        tool = crate::text::until_nul(&cx.read_avail(file.sub(at.saturating_add(4), len.min(1024))).await?);
        cx.emit(Node::new("Default tool").span(file.sub(at, len.saturating_add(4))).value(text(tool.clone())));
        at = at.saturating_add(4).saturating_add(len);
    }
    let mut types = Vec::new();
    if h.tool_types != 0 {
        let start = at;
        let n = u64::from(u32_be(&cx.read(file.sub(at, 4)).await?, 0).unwrap_or(0) / 4).saturating_sub(1);
        at = at.saturating_add(4);
        for _ in 0..n.min(256) {
            let len = u64::from(u32_be(&cx.read(file.sub(at, 4)).await?, 0).unwrap_or(0));
            types.push(crate::text::until_nul(&cx.read_avail(file.sub(at.saturating_add(4), len.min(1024))).await?));
            at = at.saturating_add(4).saturating_add(len);
        }
        cx.emit(Node::new("Tool types").span(file.sub(start, at.saturating_sub(start))).value(text(types.join("; "))));
    }
    if h.drawer != 0 && h.user & 0xff > 0 {
        cx.emit(Node::new("Drawer data (OS 2.x extension)").span(file.sub(at, 6)));
        at = at.saturating_add(6);
    }
    if at < file.len {
        cx.emit(embedded("Extended icon data (OS 3.5 / GlowIcons)", input.nested(file.tail(at))));
    }
    cx.annotate(format!(
        "Amiga {} icon, {dims}{}{}",
        lookup(ICON_TYPES, h.kind.into()).unwrap_or("unknown"),
        if tool.is_empty() { String::new() } else { format!(", default tool {tool:?}") },
        if types.is_empty() { String::new() } else { format!(", {} tool types", types.len()) }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Atari ST pictures: Degas and NEOchrome

fn st_palette_ok(data: &[u8], at: usize) -> bool {
    data.get(at..at.saturating_add(32)).is_some_and(|p| p.chunks(2).all(|c| c.first().is_some_and(|&hi| hi & 0xf0 == 0)))
}

fn degas_probe(h: &Head<'_>) -> bool {
    matches!(h.len, 32_034 | 32_066) && u16_be(h.data, 0).is_some_and(|r| r <= 2) && st_palette_ok(h.data, 2)
}

fn neo_probe(h: &Head<'_>) -> bool {
    h.len == 32_128 && u16_be(h.data, 0) == Some(0) && u16_be(h.data, 2).is_some_and(|r| r <= 2) && st_palette_ok(h.data, 4)
}

declare_format!(pub DEGAS = "degas", "Degas picture (Atari ST)", ["pi1", "pi2", "pi3"],
    "image/x-degas", Probe::Custom(degas_probe), degas);
declare_format!(pub NEOCHROME = "neochrome", "NEOchrome picture (Atari ST)", ["neo"],
    "image/x-neochrome", Probe::Custom(neo_probe), neochrome);

const ST_RESOLUTIONS: EnumTable = &[(0, "low (320×200, 16 colours)"), (1, "medium (640×200, 4 colours)"), (2, "high (640×400, mono)")];

/// An ST palette entry (0x0RGB, 3 or 4 bits per channel) as `#rrggbb`.
fn st_colour(v: u16) -> String {
    // STE puts the low bit of each channel in bit 3.
    let ch = |n: u16| {
        let n = n & 0xf;
        let v = (n & 7) << 1 | n >> 3;
        v.saturating_mul(17)
    };
    format!("#{:02x}{:02x}{:02x}", ch(v >> 8), ch(v >> 4), ch(v))
}

async fn st_palette(cx: Cx, span: Span) -> Result<()> {
    let raw = cx.read(span).await?;
    for (i, c) in raw.chunks(2).enumerate() {
        let v = u16_be(c, 0).unwrap_or(0);
        cx.emit(Node::new(format!("Colour {i}")).span(span.sub(to_u64(i).saturating_mul(2), 2)).value(hex(v.into(), 16)).summary(st_colour(v)));
    }
    Ok(())
}

async fn degas(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 2)).await?;
    let res = Fields::emitting(&cx, &head, BE).u16("Resolution").enumeration(ST_RESOLUTIONS).emit()?;
    cx.emit(Node::new("Palette").span(file.sub(2, 32)).lazy(st_palette, file.sub(2, 32)));
    cx.emit(Node::new("Bitmap (interleaved bitplanes)").span(file.sub(34, 32_000)));
    let elite = file.len == 32_066;
    if elite {
        cx.emit(Node::new("Colour animation (Degas Elite)").span(file.sub(32_034, 32)));
    }
    cx.annotate(format!("Degas{} picture, {}", if elite { " Elite" } else { "" }, lookup(ST_RESOLUTIONS, res.into()).unwrap_or("unknown resolution")));
    Ok(())
}

record! {
    pub struct NeoHeader {
        flag: u16 "Flag",
        resolution: u16 "Resolution" .enumeration(ST_RESOLUTIONS),
        palette: bytes[32] "Palette",
        filename: ascii[12] "File name",
        limits: u16 "Colour animation limits" .hex(),
        speed: u16 "Colour animation speed and direction" .hex(),
        steps: u16 "Colour animation steps",
        x: u16 "Image X offset",
        y: u16 "Image Y offset",
        width: u16 "Image width",
        height: u16 "Image height",
        _reserved: bytes[66] "Reserved",
    }
}

async fn neochrome(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: NeoHeader = emit_record(&cx, file.sub(0, NeoHeader::SIZE), BE).await?;
    cx.emit(Node::new("Palette colours").span(file.sub(4, 32)).lazy(st_palette, file.sub(4, 32)));
    cx.emit(Node::new("Bitmap (interleaved bitplanes)").span(file.sub(128, 32_000)));
    cx.annotate(format!("NEOchrome picture, {}{}", lookup(ST_RESOLUTIONS, h.resolution.into()).unwrap_or("unknown resolution"), if clean(&h.filename).is_empty() { String::new() } else { format!(", {:?}", clean(&h.filename)) }));
    Ok(())
}

// ---------------------------------------------------------------------------
// Koala Painter (C64 multicolour bitmap)

fn koala_probe(h: &Head<'_>) -> bool {
    h.len == 10_003 && h.at(0, b"\x00\x60")
}

declare_format!(pub KOALA = "koala", "Koala Painter picture (C64)", ["koa", "kla", "gg"],
    "image/x-koala", Probe::Custom(koala_probe), koala);

const C64_COLOURS: EnumTable = &[
    (0, "black"),
    (1, "white"),
    (2, "red"),
    (3, "cyan"),
    (4, "purple"),
    (5, "green"),
    (6, "blue"),
    (7, "yellow"),
    (8, "orange"),
    (9, "brown"),
    (10, "light red"),
    (11, "dark grey"),
    (12, "grey"),
    (13, "light green"),
    (14, "light blue"),
    (15, "light grey"),
];

async fn koala(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 2)).await?;
    Fields::emitting(&cx, &head, LE).u16("Load address").hex().emit()?;
    cx.emit(Node::new("Bitmap").span(file.sub(2, 8000)).summary("160×200 multicolour"));
    cx.emit(Node::new("Screen RAM (colours 1 and 2)").span(file.sub(8002, 1000)));
    cx.emit(Node::new("Colour RAM (colour 3)").span(file.sub(9002, 1000)));
    let bg = cx.read(file.sub(10_002, 1)).await?.first().copied().unwrap_or(0);
    cx.emit(Node::new("Background colour").span(file.sub(10_002, 1)).value(Value::Enum { raw: bg.into(), bits: 8, name: lookup(C64_COLOURS, u64::from(bg & 15)) }));
    cx.annotate(format!("Koala Painter picture, 160×200 multicolour, background {}", lookup(C64_COLOURS, u64::from(bg & 15)).unwrap_or("?")));
    Ok(())
}

// ---------------------------------------------------------------------------
// MSX BASIC BSAVE file

fn bsave_probe(h: &Head<'_>) -> bool {
    let start = u16_le(h.data, 1).unwrap_or(0);
    let end = u16_le(h.data, 3).unwrap_or(0);
    let need = u64::from(end.saturating_sub(start)).saturating_add(8);
    h.data.first() == Some(&0xfe) && end > start && h.len >= need && h.len.saturating_sub(need) < 128
}

declare_format!(pub MSX_BSAVE = "msx-bsave", "MSX BASIC BSAVE file", ["bin", "sc2", "sc5", "sc7", "sc8", "grp"],
    "application/x-msx-bsave", Probe::Custom(bsave_probe), bsave);

record! {
    pub struct BsaveHeader {
        id: u8 "ID" .hex(),
        start: u16 "Start address" .hex(),
        end: u16 "End address" .hex(),
        exec: u16 "Execution address" .hex(),
    }
}

async fn bsave(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: BsaveHeader = emit_record(&cx, file.sub(0, BsaveHeader::SIZE), LE).await?;
    let len = u64::from(h.end.saturating_sub(h.start)).saturating_add(1);
    cx.emit(Node::new("Data").span(file.sub(7, len)).summary(size(len)));
    // Screen dumps (BSAVE ...,S) load into VRAM starting at 0.
    let kind = if h.start == 0 && matches!(len, 0x3800 | 0x4000 | 0x6a00 | 0x7680 | 0xd400 | 0xfa00 | 0x10000) { "VRAM screen dump" } else { "memory image" };
    cx.annotate(format!("MSX BSAVE {kind}, ${:04x}-${:04x}, exec ${:04x}", h.start, h.end, h.exec));
    Ok(())
}

// ---------------------------------------------------------------------------
// Amstrad CPC AMSDOS file header

fn amsdos_probe(h: &Head<'_>) -> bool {
    let Some(header) = h.data.get(..0x45) else { return false };
    let sum = header.iter().take(0x43).fold(0u16, |s, &b| s.wrapping_add(b.into()));
    sum != 0
        && u16_le(header, 0x43) == Some(sum)
        && header.get(1..12).is_some_and(|n| n.iter().all(|&b| (0x20..0x7f).contains(&(b & 0x7f))))
        && header.get(0x12).is_some_and(|&t| t <= 0x16)
}

declare_format!(pub AMSDOS = "amsdos", "Amstrad CPC file with AMSDOS header", ["bin", "bas", "scr"],
    "application/x-amsdos", Probe::Custom(amsdos_probe), amsdos);

const AMSDOS_TYPES: EnumTable = &[(0, "BASIC"), (1, "protected BASIC"), (2, "binary"), (3, "protected binary"), (0x16, "ASCII")];

record! {
    pub struct AmsdosHeader {
        user: u8 "User number",
        name: ascii[8] "File name",
        ext: ascii[3] "Extension",
        _reserved: bytes[4] "Reserved",
        block: u8 "Block number",
        last: u8 "Last block",
        kind: u8 "File type" .enumeration(AMSDOS_TYPES),
        data_len: u16 "Data length",
        load: u16 "Load address" .hex(),
        first: u8 "First block",
        logical: u16 "Logical length",
        entry: u16 "Entry address" .hex(),
        _unused: bytes[36] "Unused",
        file_len: bytes[3] "File length (24-bit)",
        checksum: u16 "Checksum" .hex(),
    }
}

async fn amsdos(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, AmsdosHeader::SIZE);
    let h: AmsdosHeader = read_record(&cx, span, LE).await?;
    cx.emit(AmsdosHeader::node("AMSDOS header", file.sub(0, 128), LE).summary("checksum valid"));
    let len = u64::from(crate::bytes::u24_le(&h.file_len, 0).unwrap_or(0));
    let data = file.sub(128, len);
    let name = format!("{}.{}", clean(&h.name), clean(&h.ext));
    let node = if h.kind == 0x16 { embedded(name.clone(), input.nested(data)) } else { Node::new(name.clone()).span(data) };
    cx.emit(node.summary(size(len)));
    cx.annotate(format!(
        "AMSDOS file {name:?}, {}, {}, load ${:04x}{}",
        lookup(AMSDOS_TYPES, h.kind.into()).unwrap_or("unknown type"),
        size(len),
        h.load,
        if h.kind & 2 != 0 { format!(", entry ${:04x}", h.entry) } else { String::new() }
    ));
    Ok(())
}
