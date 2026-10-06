//! Assorted emulator and console files: GBX ROM footers, DeSmuME saves,
//! GameCube and Wii banners, TPL texture libraries, 3DO cels, HxC MFM and
//! FDI floppy images.

use super::util::{clean, dec, size, text};
use crate::bytes::{to_u64, u16_le, u32_be, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, emit_record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::{Head, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, flag, lookup};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// GBX (Game Boy ROM with a mapper footer)

fn gbx_probe(h: &Head<'_>) -> bool {
    let n = h.tail.len();
    h.tail.get(n.saturating_sub(4)..) == Some(b"GBX!")
        && u32_be(h.tail, n.saturating_sub(16)) == Some(64)
}

declare_format!(pub GBX = "gbx", "Game Boy ROM with GBX footer", ["gbx"],
    "application/x-gbx", Probe::Custom(gbx_probe), gbx);

record! {
    pub struct GbxFooter {
        mapper: ascii[4] "Mapper",
        battery: u8 "Battery" .enumeration(&[(0, "no"), (1, "yes")]),
        rumble: u8 "Rumble" .enumeration(&[(0, "no"), (1, "yes")]),
        timer: u8 "Timer" .enumeration(&[(0, "no"), (1, "yes")]),
        _unused: u8 "Unused",
        rom: u32 "ROM size",
        ram: u32 "RAM size",
        vars: bytes[32] "Mapper variables",
        footer: u32 "Footer size",
        major: u32 "Major version",
        minor: u32 "Minor version",
        magic: ascii[4] "Magic",
    }
}

async fn gbx(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let at = file.len.saturating_sub(GbxFooter::SIZE);
    let span = file.sub(at, GbxFooter::SIZE);
    let h: GbxFooter = read_record(&cx, span, BE).await?;
    cx.emit(crate::formats::embedded_as(
        "ROM",
        input.nested(file.sub(0, at)),
        &super::consoles::GB,
    ));
    cx.emit(GbxFooter::node("GBX footer", span, BE));
    let title = crate::text::until_nul(&cx.read_avail(file.sub(0x134, 16)).await?);
    cx.annotate(format!(
        "GBX v{}.{} {title:?}, mapper {}, {} ROM, {} RAM{}{}{}",
        h.major,
        h.minor,
        h.mapper.trim(),
        size(h.rom.into()),
        size(h.ram.into()),
        if h.battery != 0 { ", battery" } else { "" },
        if h.rumble != 0 { ", rumble" } else { "" },
        if h.timer != 0 { ", RTC" } else { "" }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// DeSmuME save (DSV)

const DSV_TEXT: &[u8] =
    b"|<--Snip above here to create a raw sav by excluding this DeSmuME savedata footer:";
const DSV_COOKIE: &[u8] = b"|-DESMUME SAVE-|";

fn dsv_probe(h: &Head<'_>) -> bool {
    h.tail.ends_with(DSV_COOKIE) && h.tail.windows(DSV_TEXT.len()).any(|w| w == DSV_TEXT)
}

declare_format!(pub DSV = "desmume-dsv", "DeSmuME Nintendo DS save", ["dsv"],
    "application/x-desmume-dsv", Probe::Custom(dsv_probe), dsv);

const DSV_TYPES: EnumTable = &[
    (0, "auto"),
    (1, "EEPROM 4 Kbit"),
    (2, "EEPROM 64 Kbit"),
    (3, "EEPROM 512 Kbit"),
    (4, "FRAM 256 Kbit"),
    (5, "flash 2 Mbit"),
    (6, "flash 4 Mbit"),
    (7, "flash 8 Mbit"),
    (8, "flash 16 Mbit"),
    (9, "flash 32 Mbit"),
    (10, "flash 64 Mbit"),
    (11, "flash 128 Mbit"),
    (12, "flash 256 Mbit"),
    (13, "flash 512 Mbit"),
];

async fn dsv(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let tail_at = file.len.saturating_sub(1024);
    let tail = cx.read(file.tail(tail_at)).await?;
    let text_at = tail
        .windows(DSV_TEXT.len())
        .rposition(|w| w == DSV_TEXT)
        .ok_or_else(|| Diagnostic::malformed("footer text not found"))?;
    let footer_at = tail_at.saturating_add(to_u64(text_at));
    cx.emit(
        Node::new("Save data")
            .span(file.sub(0, footer_at))
            .summary(size(footer_at)),
    );
    cx.emit(Node::new("Footer text").span(file.sub(footer_at, to_u64(DSV_TEXT.len()))));
    let info = cx
        .block(file.sub(footer_at.saturating_add(to_u64(DSV_TEXT.len())), 20))
        .await?;
    let mut f = Fields::emitting(&cx, &info, LE);
    let actual = f.u32("Actual size").emit()?;
    f.u32("Padded size").emit()?;
    let kind = f.u32("Type").enumeration(DSV_TYPES).emit()?;
    let addr = f.u32("Address size (bytes)").emit()?;
    f.u32("Memory size").emit()?;
    cx.emit(
        Node::new("Cookie")
            .span(file.sub(file.len.saturating_sub(16), 16))
            .value(text("|-DESMUME SAVE-|")),
    );
    cx.annotate(format!(
        "DeSmuME DS save, {} of data, {}, {addr}-byte addressing",
        size(actual.into()),
        lookup(DSV_TYPES, kind.into()).unwrap_or("unknown type")
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// GameCube banner (opening.bnr)

declare_format!(pub GC_BANNER = "gc-banner", "GameCube banner (opening.bnr)", ["bnr"],
    "application/x-gc-banner", Probe::Magic(&[(0, b"BNR1"), (0, b"BNR2")]), gc_banner);

const BNR2_LANGUAGES: [&str; 6] = ["English", "German", "French", "Spanish", "Italian", "Dutch"];

record! {
    pub struct BannerText {
        name: ascii[32] "Game name",
        company: ascii[32] "Company",
        full_name: ascii[64] "Full game name",
        full_company: ascii[64] "Full company",
        description: ascii[128] "Description",
    }
}

async fn gc_banner(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let magic = cx.read(file.sub(0, 4)).await?;
    let v2 = magic == b"BNR2";
    cx.emit(
        Node::new("Magic")
            .span(file.sub(0, 4))
            .value(text(String::from_utf8_lossy(&magic).into_owned())),
    );
    cx.emit(Node::new("Banner image (96×32 RGB5A3)").span(file.sub(0x20, 0x1800)));
    let count = if v2 { 6u64 } else { 1 };
    let mut first = None;
    for i in 0..count {
        let span = file.sub(
            0x1820u64.saturating_add(i.saturating_mul(BannerText::SIZE)),
            BannerText::SIZE,
        );
        let Ok(t) = read_record::<BannerText>(&cx, span, BE).await else {
            break;
        };
        let label = if v2 {
            BNR2_LANGUAGES
                .get(usize::try_from(i).unwrap_or(0))
                .copied()
                .unwrap_or("?")
        } else {
            "Text"
        };
        cx.emit(BannerText::node(label, span, BE).summary(format!(
            "{:?} by {}",
            clean(&t.full_name),
            clean(&t.full_company)
        )));
        if first.is_none() {
            first = Some(t);
        }
    }
    let t = first.ok_or_else(|| {
        Diagnostic::truncated(
            file.sub(0x1820, BannerText::SIZE),
            file.len.saturating_sub(0x1820),
        )
    })?;
    cx.annotate(format!(
        "GameCube banner {}, {:?} by {}",
        if v2 { "BNR2 (6 languages)" } else { "BNR1" },
        clean(&t.full_name),
        clean(&t.full_company)
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Wii save banner (banner.bin)

declare_format!(pub WII_BANNER = "wii-banner", "Wii save banner (WIBN)", ["bin"],
    "application/x-wii-banner", Probe::Magic(&[(0, b"WIBN")]), wii_banner);

const WIBN_FLAGS: FlagTable = &[flag(0x01, "NO_COPY"), flag(0x10, "ICON_BOUNCE")];

async fn wii_banner(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 0xa0)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Magic", 4).emit()?;
    f.u32("Flags").flags(WIBN_FLAGS).emit()?;
    f.u16("Animation speed").hex().emit()?;
    f.bytes("Reserved", 22).emit()?;
    let title = f
        .utf16("Title", 32)
        .map(|s| s.trim_end_matches('\0').to_owned())
        .emit()?;
    let subtitle = f
        .utf16("Subtitle", 32)
        .map(|s| s.trim_end_matches('\0').to_owned())
        .emit()?;
    cx.emit(Node::new("Banner image (192×64 RGB5A3)").span(file.sub(0xa0, 0x6000)));
    let icons = file.len.saturating_sub(0x60a0) / 0x1200;
    for i in 0..icons.min(8) {
        cx.emit(
            Node::new(format!("Icon frame {i} (48×48 RGB5A3)"))
                .span(file.sub(0x60a0u64.saturating_add(i.saturating_mul(0x1200)), 0x1200)),
        );
    }
    cx.annotate(format!(
        "Wii save banner {title:?} / {subtitle:?}, {icons} icon frame(s)"
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// GameCube/Wii texture palette library (TPL)

declare_format!(pub TPL = "tpl", "GameCube/Wii texture library (TPL)", ["tpl"],
    "image/x-tpl", Probe::Magic(&[(0, b"\x00\x20\xaf\x30")]), tpl);

const TPL_FORMATS: EnumTable = &[
    (0, "I4"),
    (1, "I8"),
    (2, "IA4"),
    (3, "IA8"),
    (4, "RGB565"),
    (5, "RGB5A3"),
    (6, "RGBA8"),
    (8, "C4"),
    (9, "C8"),
    (10, "C14X2"),
    (14, "CMPR"),
];
const TPL_WRAP: EnumTable = &[(0, "clamp"), (1, "repeat"), (2, "mirror")];
const TPL_FILTER: EnumTable = &[
    (0, "near"),
    (1, "linear"),
    (2, "near-mip-near"),
    (3, "lin-mip-near"),
    (4, "near-mip-lin"),
    (5, "lin-mip-lin"),
];

record! {
    pub struct TplImage {
        height: u16 "Height",
        width: u16 "Width",
        format: u32 "Format" .enumeration(TPL_FORMATS),
        data: u32 "Data offset" .hex(),
        wrap_s: u32 "Wrap S" .enumeration(TPL_WRAP),
        wrap_t: u32 "Wrap T" .enumeration(TPL_WRAP),
        min: u32 "Min filter" .enumeration(TPL_FILTER),
        mag: u32 "Mag filter" .enumeration(TPL_FILTER),
        lod_bias: f32 "LOD bias",
        edge_lod: u8 "Edge LOD",
        min_lod: u8 "Min LOD",
        max_lod: u8 "Max LOD",
        unpacked: u8 "Unpacked",
    }
}

/// Encoded size of one TPL image: tiles of `(w, h)` pixels at `bpp` bits.
fn tpl_size(format: u32, width: u64, height: u64) -> u64 {
    let (bw, bh, bpp) = match format {
        0 | 8 | 14 => (8u64, 8u64, 4u64),
        1 | 2 | 9 => (8, 4, 8),
        6 => (4, 4, 32),
        _ => (4, 4, 16),
    };
    width
        .next_multiple_of(bw)
        .saturating_mul(height.next_multiple_of(bh))
        .saturating_mul(bpp)
        / 8
}

async fn tpl(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 12)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.u32("Magic").hex().emit()?;
    let count = f.u32("Images").emit()?;
    let table_at = f.u32("Image table offset").hex().emit()?;
    let table = file.sub_exact(table_at.into(), u64::from(count).saturating_mul(8))?;
    let raw = cx.read(table).await?;
    cx.set_count(Count::Exact(u64::from(count).saturating_add(3)));
    let mut formats = Vec::new();
    for (i, e) in raw.chunks(8).enumerate() {
        let image_at = u64::from(u32_be(e, 0).unwrap_or(0));
        let palette_at = u64::from(u32_be(e, 4).unwrap_or(0));
        let span = file.sub(image_at, TplImage::SIZE);
        let img: TplImage = read_record(&cx, span, BE).await?;
        let name = lookup(TPL_FORMATS, img.format.into()).unwrap_or("?");
        if !formats.contains(&name) {
            formats.push(name);
        }
        let data = file.sub(
            img.data.into(),
            tpl_size(img.format, img.width.into(), img.height.into()),
        );
        cx.push(
            Node::new(format!("Image {i}"))
                .span(span)
                .summary(format!(
                    "{}×{} {name}{}",
                    img.width,
                    img.height,
                    if palette_at != 0 {
                        ", with palette"
                    } else {
                        ""
                    }
                ))
                .target(data)
                .lazy(tpl_image, (span, palette_at, file, data)),
        )
        .await;
    }
    cx.annotate(format!(
        "TPL texture library, {count} image(s) ({})",
        formats.join(", ")
    ));
    Ok(())
}

async fn tpl_image(cx: Cx, (span, palette_at, file, data): (Span, u64, Span, Span)) -> Result<()> {
    let block = cx.block(span).await?;
    TplImage::read(&mut Fields::emitting(&cx, &block, BE))?;
    if palette_at != 0 {
        let p = cx.block(file.sub(palette_at, 12)).await?;
        let mut f = Fields::emitting(&cx, &p, BE);
        f.u16("Palette entries").emit()?;
        f.u8("Palette unpacked").emit()?;
        f.u8("Padding").emit()?;
        f.u32("Palette format")
            .enumeration(&[(0, "IA8"), (1, "RGB565"), (2, "RGB5A3")])
            .emit()?;
        f.u32("Palette data offset").hex().emit()?;
    }
    cx.emit(
        Node::new("Pixel data (tiled)")
            .span(data)
            .summary(size(data.len)),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// 3DO cel (CCB, PLUT, PDAT chunks)

fn cel_probe(h: &Head<'_>) -> bool {
    h.at(0, b"CCB ") && u32_be(h.data, 4) == Some(0x50)
}

declare_format!(pub CEL_3DO = "3do-cel", "3DO cel image", ["cel", "3do"],
    "image/x-3do-cel", Probe::Custom(cel_probe), cel);

const CCB_FLAGS: FlagTable = &[
    flag(0x8000_0000, "SKIP"),
    flag(0x4000_0000, "LAST"),
    flag(0x2000_0000, "NPABS"),
    flag(0x1000_0000, "SPABS"),
    flag(0x0800_0000, "PPABS"),
    flag(0x0400_0000, "LDSIZE"),
    flag(0x0200_0000, "LDPRS"),
    flag(0x0100_0000, "LDPPMP"),
    flag(0x0080_0000, "LDPLUT"),
    flag(0x0040_0000, "CCBPRE"),
    flag(0x0020_0000, "YOXY"),
    flag(0x0000_0200, "PACKED"),
    flag(0x0000_0020, "BGND"),
    flag(0x0000_0010, "NOBLK"),
];

record! {
    pub struct CcbChunk {
        id: ascii[4] "Chunk ID",
        size: u32 "Chunk size",
        version: u32 "Version",
        flags: u32 "Flags" .flags(CCB_FLAGS),
        next: u32 "Next CCB" .hex(),
        source: u32 "Source data" .hex(),
        plut: u32 "PLUT" .hex(),
        x: i32 "X position (16.16)",
        y: i32 "Y position (16.16)",
        hdx: i32 "HDX",
        hdy: i32 "HDY",
        vdx: i32 "VDX",
        vdy: i32 "VDY",
        ddx: i32 "DDX",
        ddy: i32 "DDY",
        pixc: u32 "PIXC" .hex(),
        pre0: u32 "Preamble word 0" .hex(),
        pre1: u32 "Preamble word 1" .hex(),
        width: u32 "Width",
        height: u32 "Height",
    }
}

async fn cel(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, CcbChunk::SIZE);
    let h: CcbChunk = read_record(&cx, span, BE).await?;
    cx.emit(CcbChunk::node("CCB", span, BE));
    let bpp = match h.pre0 & 7 {
        1 => 1,
        2 => 2,
        3 => 4,
        4 => 6,
        5 => 8,
        6 => 16,
        _ => 0,
    };
    let mut cur = Cursor::new(&cx, file, BE);
    cur.seek(CcbChunk::SIZE);
    let mut chunks = Vec::new();
    while cur.remaining() >= 8 {
        let start = cur.pos();
        let id = String::from_utf8_lossy(&cur.bytes(4).await?).into_owned();
        let len = u64::from(cur.u32().await?);
        if len < 8 {
            break;
        }
        cur.seek(start.saturating_add(len));
        let mut node = Node::new(id.clone())
            .span(cur.since(start))
            .summary(format!("{len} bytes"));
        if id == "PLUT" {
            let n = u32_be(
                &cx.read_avail(file.sub(start.saturating_add(8), 4)).await?,
                0,
            )
            .unwrap_or(0);
            node = node.summary(format!("{n} colours"));
        }
        chunks.push(id);
        cx.push(node).await;
    }
    cx.annotate(format!(
        "3DO cel, {}×{}, {bpp} bpp{}, chunks {}",
        h.width,
        h.height,
        if h.flags & 0x200 != 0 { " packed" } else { "" },
        chunks.join(" ")
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// HxC MFM track image

declare_format!(pub HXC_MFM = "hxc-mfm", "HxC MFM floppy image", ["mfm"],
    "application/x-hxc-mfm", Probe::Magic(&[(0, b"HXCMFM\0")]), hxc_mfm);

async fn hxc_mfm(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 19)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 7).emit()?;
    let tracks = f.u16("Tracks").emit()?;
    let sides = f.u8("Sides").emit()?;
    let rpm = f.u16("RPM").emit()?;
    let rate = f.u16("Bit rate (kbit/s)").emit()?;
    f.u8("Interface type").emit()?;
    let list = f.u32("Track list offset").hex().emit()?;
    let n = u64::from(tracks).saturating_mul(sides.into());
    let table = file.sub_exact(list.into(), n.saturating_mul(11))?;
    let raw = cx.read(table).await?;
    for (i, e) in raw.chunks(11).enumerate() {
        let number = u16_le(e, 0).unwrap_or(0);
        let side = e.get(2).copied().unwrap_or(0);
        let len = u64::from(u32_le(e, 3).unwrap_or(0));
        let at = u64::from(u32_le(e, 7).unwrap_or(0));
        cx.push(
            Node::new(format!("Track {number} side {side}"))
                .span(table.sub(to_u64(i).saturating_mul(11), 11))
                .value(dec(len, 32))
                .summary(format!("{len} MFM bytes"))
                .target(file.sub(at, len)),
        )
        .await;
    }
    cx.annotate(format!(
        "HxC MFM image, {tracks} tracks × {sides} sides, {rpm} RPM, {rate} kbit/s"
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// FDI (Formatted Disk Image, Vincent Joguin)

declare_format!(pub FDI = "fdi", "Formatted Disk Image (FDI)", ["fdi"],
    "application/x-fdi", Probe::Magic(&[(0, b"Formatted Disk Image file\r\n")]), fdi);

const FDI_TYPES: EnumTable = &[(0, "8\""), (1, "5.25\""), (2, "3.5\""), (3, "3\"")];
const FDI_TPI: EnumTable = &[
    (0, "48"),
    (1, "67"),
    (2, "96"),
    (3, "100"),
    (4, "135"),
    (5, "192"),
];
const FDI_FLAGS: FlagTable = &[
    flag(0x01, "WRITE_PROTECTED"),
    flag(0x02, "INDEX_SYNCHRONISED"),
];

record! {
    pub struct FdiHeader {
        signature: ascii[27] "Signature",
        creator: ascii[30] "Creator",
        crlf: bytes[2] "Line break",
        comment: ascii[80] "Comment",
        eof: u8 "End of text" .hex(),
        version: u16 "Version" .hex(),
        last_track: u16 "Last track",
        last_head: u8 "Last head",
        kind: u8 "Disk type" .enumeration(FDI_TYPES),
        speed: u8 "Rotation speed (RPM - 128)",
        flags: u8 "Flags" .flags(FDI_FLAGS),
        tpi: u8 "Tracks per inch" .enumeration(FDI_TPI),
        head_width: u8 "Head width" .enumeration(FDI_TPI),
        _reserved: u16 "Reserved",
    }
}

async fn fdi(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: FdiHeader = emit_record(&cx, file.sub(0, FdiHeader::SIZE), BE).await?;
    let tracks = u64::from(h.last_track)
        .saturating_add(1)
        .saturating_mul(u64::from(h.last_head).saturating_add(1));
    let table = file.sub(FdiHeader::SIZE, tracks.saturating_mul(2));
    cx.emit(
        Node::new("Track descriptors")
            .span(table)
            .summary(format!("{tracks} tracks")),
    );
    cx.annotate(format!(
        "FDI v{}.{} {} disk, {} tracks × {} heads, {} RPM{}",
        h.version >> 8,
        h.version & 0xff,
        lookup(FDI_TYPES, h.kind.into()).unwrap_or("?"),
        u32::from(h.last_track).saturating_add(1),
        u32::from(h.last_head).saturating_add(1),
        u32::from(h.speed).saturating_add(128),
        if clean(&h.creator).is_empty() {
            String::new()
        } else {
            format!(", by {:?}", clean(&h.creator))
        }
    ));
    Ok(())
}
