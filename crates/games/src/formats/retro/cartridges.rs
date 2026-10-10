//! More console cartridge formats: Sega Master System / Game Gear, Super
//! Magic Drive dumps, Neo Geo Pocket, Pokémon mini, Neo Geo (.neo), UNIF,
//! Vectrex, Intellivision, ColecoVision, MSX, WonderSwan and Virtual Boy.

use super::util::clean;
use crate::bytes::{to_u64, u16_be, u16_le, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, emit_record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::fmt::size;
use crate::formats::util::val::{hex, text, uint};
use crate::formats::{Head, Input, Probe, embedded_as};
use crate::node::Node;
use crate::record;
use crate::span::{Origin, Span};
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// Sega Master System / Game Gear ("TMR SEGA" header)

const TMR_OFFSETS: [usize; 3] = [0x7ff0, 0x3ff0, 0x1ff0];

fn tmr_at(h: &Head<'_>) -> Option<usize> {
    TMR_OFFSETS.into_iter().find(|&o| h.at(o, b"TMR SEGA"))
}

fn tmr_region(h: &Head<'_>) -> Option<u8> {
    tmr_at(h)
        .and_then(|o| h.data.get(o.saturating_add(15)))
        .map(|b| b >> 4)
}

fn gg_probe(h: &Head<'_>) -> bool {
    tmr_region(h).is_some_and(|r| (5..=7).contains(&r))
}

fn sms_probe(h: &Head<'_>) -> bool {
    tmr_at(h).is_some()
}

declare_format!(pub GAME_GEAR = "game-gear", "Sega Game Gear ROM", ["gg"],
    "application/x-gamegear-rom", Probe::Custom(gg_probe), sms);
declare_format!(pub SMS = "sms", "Sega Master System ROM", ["sms", "sg"],
    "application/x-sms-rom", Probe::Custom(sms_probe), sms);

const TMR_REGIONS: EnumTable = &[
    (3, "SMS Japan"),
    (4, "SMS Export"),
    (5, "GG Japan"),
    (6, "GG Export"),
    (7, "GG International"),
];
const TMR_SIZES: [(u8, u64, &str); 9] = [
    (0xa, 0x2000, "8 KiB"),
    (0xb, 0x4000, "16 KiB"),
    (0xc, 0x8000, "32 KiB"),
    (0xd, 0xc000, "48 KiB"),
    (0xe, 0x10000, "64 KiB"),
    (0xf, 0x20000, "128 KiB"),
    (0x0, 0x40000, "256 KiB"),
    (0x1, 0x80000, "512 KiB"),
    (0x2, 0x100000, "1 MiB"),
];

fn bcd(b: u8) -> u32 {
    u32::from(b >> 4)
        .saturating_mul(10)
        .saturating_add(u32::from(b & 0xf))
}

async fn sms(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let (head, tail) = crate::formats::head(&cx, file).await?;
    let probe = Head {
        data: &head,
        tail: &tail,
        len: file.len,
        len_known: true,
    };
    let at = to_u64(tmr_at(&probe).unwrap_or(0x7ff0));
    let span = file.sub(at, 16);
    let raw = cx.read(span).await?;
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    let stored = {
        let mut g = Fields::new(&block, LE);
        g.skip(10);
        g.u16("Checksum").get()?
    };
    let [p0, p1, p2, last] = [12usize, 13, 14, 15].map(|i| raw.get(i).copied().unwrap_or(0));
    let product = u32::from(p2 >> 4)
        .saturating_mul(10000)
        .saturating_add(bcd(p1).saturating_mul(100))
        .saturating_add(bcd(p0));
    let region = last >> 4;
    let size_code = last & 0xf;
    let rom = TMR_SIZES.iter().find(|s| s.0 == size_code);
    // Checksum over the declared size, skipping the header itself.
    let mut computed = None;
    if let Some(&(_, len, _)) = rom
        && len <= file.len
        && at == 0x7ff0
    {
        let first = cx.read(file.sub(0, len.min(0x7ff0))).await?;
        let mut sum = first.iter().fold(0u16, |s, &b| s.wrapping_add(b.into()));
        if len > 0x8000 {
            let rest = cx
                .read(file.sub(0x8000, len.saturating_sub(0x8000)))
                .await?;
            sum = rest.iter().fold(sum, |s, &b| s.wrapping_add(b.into()));
        }
        computed = Some(sum);
    }
    f.ascii("Signature", 8).emit()?;
    f.bytes("Reserved", 2).emit()?;
    f.u16("Checksum")
        .hex()
        .check(|&v| {
            computed
                .filter(|&c| c != v)
                .map(|c| Diagnostic::warning(format!("checksum mismatch: computed {c:#06x}")))
        })
        .emit()?;
    f.node(
        Node::new("Product code")
            .span(file.sub(at.saturating_add(12), 3))
            .value(uint(product, 32)),
    );
    f.node(
        Node::new("Version")
            .span(file.sub(at.saturating_add(14), 1))
            .value(uint(p2 & 0xf, 8)),
    );
    f.node(
        Node::new("Region")
            .span(file.sub(at.saturating_add(15), 1))
            .value(Value::Enum {
                raw: region.into(),
                bits: 4,
                name: lookup(TMR_REGIONS, region.into()),
            }),
    );
    f.node(
        Node::new("ROM size")
            .span(file.sub(at.saturating_add(15), 1))
            .value(Value::Enum {
                raw: size_code.into(),
                bits: 4,
                name: rom.map(|r| r.2),
            }),
    );
    let sdsc = file.sub(at.saturating_sub(16), 16);
    if cx.read_avail(sdsc.sub(0, 4)).await? == b"SDSC" {
        let d = cx.read(sdsc).await?;
        cx.emit(
            Node::new("SDSC homebrew header")
                .span(sdsc)
                .summary(format!(
                    "v{}.{:02}, {:02x}{:02x}-{:02x}-{:02x}",
                    d.get(4).copied().unwrap_or(0),
                    bcd(d.get(5).copied().unwrap_or(0)),
                    d.get(9).copied().unwrap_or(0),
                    d.get(8).copied().unwrap_or(0),
                    d.get(7).copied().unwrap_or(0),
                    d.get(6).copied().unwrap_or(0)
                )),
        );
    }
    cx.annotate(format!(
        "{}, product {product}, {}{}",
        lookup(TMR_REGIONS, region.into()).unwrap_or("unknown region"),
        rom.map_or("unknown size", |r| r.2),
        match computed {
            Some(c) if c == stored => ", checksum valid",
            Some(_) => ", checksum mismatch",
            None => "",
        }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Super Magic Drive interleaved Mega Drive dumps

fn smd_probe(h: &Head<'_>) -> bool {
    h.at(8, b"\xaa\xbb") && h.data.get(10) == Some(&6) && h.len > 512 + 0x4000
}

declare_format!(pub SMD = "smd", "Super Magic Drive interleaved Mega Drive ROM", ["smd"],
    "application/x-genesis-rom", Probe::Custom(smd_probe), smd);

record! {
    pub struct SmdHeader {
        blocks: u8 "16 KiB blocks",
        mode: u8 "Mode",
        split: u8 "Split flag" .enumeration(&[(0x00, "last (or only) file"), (0x40, "more files follow")]),
        _reserved: bytes[5] "Reserved",
        id: u16 "Identifier" .hex(),
        kind: u8 "File type" .enumeration(&[(6, "Mega Drive program"), (7, "Mega Drive SRAM")]),
    }
}

async fn smd(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: SmdHeader = emit_record(&cx, file.sub(0, SmdHeader::SIZE), LE).await?;
    let blocks = (file.len.saturating_sub(512)) / 0x4000;
    // Each 16 KiB block stores the odd bytes first, then the even bytes.
    let first = cx.read(file.sub(512, 0x4000)).await?;
    let (odd, even) = first.split_at(0x2000);
    let plain: Vec<u8> = even.iter().zip(odd).flat_map(|(&e, &o)| [e, o]).collect();
    let decoded = cx.add_derived(
        Origin {
            parent: file.sub(512, 0x4000),
            transform: "smd-deinterleave",
        },
        plain,
        0x4000,
        None,
    )?;
    cx.emit(
        Node::new("Interleaved data")
            .span(file.tail(512))
            .summary(format!("{blocks} blocks of 16 KiB")),
    );
    cx.emit(embedded_as(
        "First block (de-interleaved)",
        input.nested(decoded.span),
        &super::consoles::GENESIS,
    ));
    let g: super::consoles::GenesisHeader = read_record(
        &cx,
        decoded
            .span
            .sub(0x100, super::consoles::GenesisHeader::SIZE),
        BE,
    )
    .await?;
    let title = if clean(&g.overseas).is_empty() {
        clean(&g.domestic)
    } else {
        clean(&g.overseas)
    };
    let title: String = title.split_whitespace().collect::<Vec<_>>().join(" ");
    cx.annotate(format!(
        "SMD dump of {title:?} ({}), {blocks} blocks{}",
        clean(&g.serial),
        if h.split == 0x40 { ", split" } else { "" }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Neo Geo Pocket (Color)

fn ngp_probe(h: &Head<'_>) -> bool {
    (h.at(0, b"COPYRIGHT BY SNK CORPORATION") || h.at(0, b" LICENSED BY SNK CORPORATION"))
        && h.data.len() >= 0x40
}

fn ngpc_probe(h: &Head<'_>) -> bool {
    ngp_probe(h) && h.data.get(0x23) == Some(&0x10)
}

declare_format!(pub NGPC = "ngpc", "Neo Geo Pocket Color ROM", ["ngc", "ngpc"],
    "application/x-ngpc-rom", Probe::Custom(ngpc_probe), ngp);
declare_format!(pub NGP = "ngp", "Neo Geo Pocket ROM", ["ngp"],
    "application/x-ngp-rom", Probe::Custom(ngp_probe), ngp);

record! {
    pub struct NgpHeader {
        copyright: ascii[28] "Licence",
        entry: u32 "Start address" .hex(),
        catalog: u16 "Catalogue number" .hex(),
        sub_catalog: u8 "Catalogue version",
        mode: u8 "System" .enumeration(&[(0x00, "monochrome"), (0x10, "colour")]),
        title: ascii[12] "Title",
        _reserved: bytes[16] "Reserved",
    }
}

async fn ngp(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: NgpHeader = emit_record(&cx, file.sub(0, NgpHeader::SIZE), LE).await?;
    cx.emit(Node::new("Program").span(file.tail(NgpHeader::SIZE)));
    cx.annotate(format!(
        "{:?}, catalogue {:04x}-{}, {}, entry {:#x}, {}",
        clean(&h.title),
        h.catalog,
        h.sub_catalog,
        if h.mode == 0x10 {
            "colour"
        } else {
            "monochrome"
        },
        h.entry,
        size(file.len)
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Pokémon mini

fn pokemini_probe(h: &Head<'_>) -> bool {
    h.at(0x2100, b"MN") && h.at(0x21a4, b"NINTENDO")
}

declare_format!(pub POKEMON_MINI = "pokemon-mini", "Pokémon mini ROM", ["min"],
    "application/x-pokemon-mini-rom", Probe::Custom(pokemini_probe), pokemini);

async fn pokemini(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("BIOS area (not in cartridge)").span(file.sub(0, 0x2100)));
    let block = cx.block(file.sub(0x2100, 0xc0)).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.ascii("Signature", 2).emit()?;
    f.bytes("Reset and interrupt vectors", 0xa2).emit()?;
    f.ascii("Nintendo", 8).emit()?;
    let code = f.ascii("Game code", 4).emit()?;
    let title = f.ascii("Title", 12).emit()?;
    f.ascii("Players marker", 2).emit()?;
    cx.emit(Node::new("Program").span(file.tail(0x21c0)));
    cx.annotate(format!(
        "Pokémon mini {:?} ({}), {}",
        clean(&title),
        clean(&code),
        size(file.len)
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Neo Geo (.neo, TerraOnion NeoSD)

declare_format!(pub NEO_GEO = "neo-geo", "Neo Geo cartridge image (.neo)", ["neo"],
    "application/x-neogeo-rom", Probe::Magic(&[(0, b"NEO\x01")]), neo);

const NEO_GENRES: EnumTable = &[
    (0, "other"),
    (1, "action"),
    (2, "beat 'em up"),
    (3, "sports"),
    (4, "driving"),
    (5, "platformer"),
    (6, "mahjong"),
    (7, "shooter"),
    (8, "quiz"),
    (9, "fighting"),
    (10, "puzzle"),
];

record! {
    pub struct NeoHeader {
        magic: ascii[3] "Magic",
        version: u8 "Version",
        p: u32 "P ROM size",
        s: u32 "S ROM size",
        m: u32 "M ROM size",
        v1: u32 "V1 ROM size",
        v2: u32 "V2 ROM size",
        c: u32 "C ROM size",
        year: u32 "Year",
        genre: u32 "Genre" .enumeration(NEO_GENRES),
        screenshot: u32 "Screenshot",
        ngh: u32 "NGH number" .hex(),
        name: ascii[33] "Name",
        manufacturer: ascii[17] "Manufacturer",
    }
}

async fn neo(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, NeoHeader::SIZE);
    let h: NeoHeader = read_record(&cx, span, LE).await?;
    cx.emit(NeoHeader::node("Header", span, LE));
    let mut at = 4096u64;
    for (name, len, desc) in [
        ("P ROM", h.p, "68000 program"),
        ("S ROM", h.s, "fix layer graphics"),
        ("M ROM", h.m, "Z80 sound program"),
        ("V1 ROM", h.v1, "ADPCM-A samples"),
        ("V2 ROM", h.v2, "ADPCM-B samples"),
        ("C ROM", h.c, "sprite graphics"),
    ] {
        if len > 0 {
            cx.emit(
                Node::new(name)
                    .span(file.sub(at, len.into()))
                    .summary(size(len.into()))
                    .desc(desc),
            );
        }
        at = at.saturating_add(len.into());
    }
    cx.annotate(format!(
        "{:?} by {}, {}, {}, NGH {:03x}",
        clean(&h.name),
        clean(&h.manufacturer),
        h.year,
        lookup(NEO_GENRES, h.genre.into()).unwrap_or("unknown genre"),
        h.ngh
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// UNIF (Universal NES Image Format)

declare_format!(pub UNIF = "unif", "Universal NES Image Format (UNIF)", ["unf", "unif"],
    "application/x-unif", Probe::Magic(&[(0, b"UNIF")]), unif);

const UNIF_CHUNKS: &[(&str, &str)] = &[
    ("MAPR", "board name"),
    ("READ", "comments"),
    ("NAME", "game name"),
    ("TVCI", "TV standard"),
    ("CTRL", "controllers"),
    ("BATR", "battery"),
    ("VROR", "CHR is RAM"),
    ("MIRR", "mirroring"),
    ("DINF", "dumper info"),
    ("WRTR", "writer"),
    ("PCK", "PRG CRC-32"),
    ("CCK", "CHR CRC-32"),
    ("PRG", "PRG ROM"),
    ("CHR", "CHR ROM"),
];

const UNIF_MIRRORING: EnumTable = &[
    (0, "horizontal"),
    (1, "vertical"),
    (2, "single-screen A"),
    (3, "single-screen B"),
    (4, "four-screen"),
    (5, "mapper-controlled"),
];

async fn unif(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 32)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Magic", 4).emit()?;
    let revision = f.u32("Revision").emit()?;
    f.bytes("Reserved", 24).emit()?;
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(32);
    let (mut board, mut name) = (None, None);
    let (mut prg, mut chr) = (0u64, 0u64);
    while cur.remaining() >= 8 {
        let start = cur.pos();
        let id = String::from_utf8_lossy(&cur.bytes(4).await?).into_owned();
        let len = u64::from(cur.u32().await?);
        let data = cur.span(len);
        cur.skip(len);
        let meaning = UNIF_CHUNKS
            .iter()
            .find(|c| id.starts_with(c.0))
            .map_or("unknown", |c| c.1);
        let mut node = Node::new(id.clone())
            .span(cur.since(start))
            .desc(meaning)
            .target(data);
        match id.get(..3).unwrap_or_default() {
            "MAP" | "NAM" | "REA" | "WRT" => {
                let s = crate::text::until_nul(&cx.read_avail(data.sub(0, 1024)).await?);
                if id == "MAPR" {
                    board = Some(s.clone());
                } else if id == "NAME" {
                    name = Some(s.clone());
                }
                node = node.value(text(s));
            }
            "MIR" => {
                let b = cx
                    .read_avail(data.sub(0, 1))
                    .await?
                    .first()
                    .copied()
                    .unwrap_or(0);
                node = node.value(Value::Enum {
                    raw: b.into(),
                    bits: 8,
                    name: lookup(UNIF_MIRRORING, b.into()),
                });
            }
            "TVC" => {
                let b = cx
                    .read_avail(data.sub(0, 1))
                    .await?
                    .first()
                    .copied()
                    .unwrap_or(0);
                node = node.value(Value::Enum {
                    raw: b.into(),
                    bits: 8,
                    name: lookup(&[(0, "NTSC"), (1, "PAL"), (2, "both")], b.into()),
                });
            }
            "PCK" | "CCK" => {
                let raw = cx.read_avail(data.sub(0, 4)).await?;
                node = node.value(hex(u32_le(&raw, 0).unwrap_or(0), 32));
            }
            "PRG" => {
                prg = prg.saturating_add(len);
                node = node.summary(size(len));
            }
            "CHR" => {
                chr = chr.saturating_add(len);
                node = node.summary(size(len));
            }
            _ => node = node.summary(format!("{len} bytes")),
        }
        cx.push(node).await;
    }
    cx.annotate(format!(
        "UNIF rev {revision}{}, board {}, {} PRG, {} CHR",
        name.map_or_else(String::new, |n| format!(" {n:?}")),
        board.unwrap_or_else(|| "?".to_owned()),
        size(prg),
        size(chr)
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Vectrex

declare_format!(pub VECTREX = "vectrex", "Vectrex cartridge ROM", ["vec", "gam"],
    "application/x-vectrex-rom", Probe::Magic(&[(0, b"g GCE")]), vectrex);

async fn vectrex(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let data = cx.read_avail(file.sub(0, 512)).await?;
    let copyright_end = data
        .iter()
        .position(|&b| b == 0x80)
        .ok_or_else(|| Diagnostic::malformed("copyright string not terminated"))?;
    let copyright =
        String::from_utf8_lossy(data.get(..copyright_end).unwrap_or_default()).into_owned();
    cx.emit(
        Node::new("Copyright")
            .span(file.sub(0, to_u64(copyright_end).saturating_add(1)))
            .value(text(copyright.clone())),
    );
    let music_at = copyright_end.saturating_add(1);
    let music = u16_be(&data, music_at).unwrap_or(0);
    cx.emit(
        Node::new("Music pointer")
            .span(file.sub(to_u64(music_at), 2))
            .value(hex(music, 16)),
    );
    let mut pos = music_at.saturating_add(2);
    let mut titles = Vec::new();
    while let Some(&height) = data.get(pos) {
        if height == 0 {
            cx.emit(Node::new("End of title").span(file.sub(to_u64(pos), 1)));
            pos = pos.saturating_add(1);
            break;
        }
        let Some(len) = data
            .get(pos.saturating_add(4)..)
            .and_then(|r| r.iter().position(|&b| b == 0x80))
        else {
            break;
        };
        let s = String::from_utf8_lossy(
            data.get(pos.saturating_add(4)..pos.saturating_add(4).saturating_add(len))
                .unwrap_or_default(),
        )
        .into_owned();
        let [h, w, y, x] = [0usize, 1, 2, 3].map(|i| {
            data.get(pos.saturating_add(i))
                .map_or(0, |&b| i8::from_le_bytes([b]))
        });
        cx.emit(
            Node::new("Title line")
                .span(file.sub(to_u64(pos), to_u64(len).saturating_add(5)))
                .value(text(s.clone()))
                .summary(format!("height {h}, width {w}, at ({x}, {y})")),
        );
        titles.push(s);
        pos = pos.saturating_add(len).saturating_add(5);
    }
    cx.emit(Node::new("Program").span(file.tail(to_u64(pos))));
    cx.annotate(format!(
        "Vectrex {:?}, {copyright}, {}",
        titles.join(" "),
        size(file.len)
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Intellivision (Intellicart .rom)

fn intv_probe(h: &Head<'_>) -> bool {
    let n = h.data.get(1).copied().unwrap_or(0);
    h.data.first() == Some(&0xa8) && n > 0 && h.data.get(2) == Some(&(n ^ 0xff))
}

declare_format!(pub INTELLIVISION = "intellivision", "Intellivision ROM (Intellicart)", ["rom", "int"],
    "application/x-intellivision-rom", Probe::Custom(intv_probe), intellivision);

async fn intellivision(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 3)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.u8("Magic").hex().emit()?;
    let segments = f.u8("Segments").emit()?;
    f.u8("Segments (complement)").hex().emit()?;
    let mut pos = 3u64;
    let mut words = 0u64;
    for i in 0..segments {
        let raw = cx.read(file.sub(pos, 2)).await?;
        let lo = u64::from(raw.first().copied().unwrap_or(0));
        let hi = u64::from(raw.get(1).copied().unwrap_or(0));
        let count = hi.saturating_add(1).saturating_sub(lo).saturating_mul(256);
        let len = 2u64
            .saturating_add(count.saturating_mul(2))
            .saturating_add(2);
        let span = file.sub(pos, len);
        words = words.saturating_add(count);
        cx.push(
            Node::new(format!("Segment {i}"))
                .span(span)
                .value(hex(lo << 8, 16))
                .summary(format!(
                    "${:04x}-${:04x}, {count} words",
                    lo << 8,
                    (hi << 8) | 0xff
                ))
                .lazy(intv_segment, span),
        )
        .await;
        pos = pos.saturating_add(len);
    }
    if pos < file.len {
        cx.emit(Node::new("Memory attribute table and CRC").span(file.tail(pos)));
    }
    cx.annotate(format!(
        "Intellivision ROM, {segments} segment(s), {words} decles"
    ));
    Ok(())
}

async fn intv_segment(cx: Cx, span: Span) -> Result<()> {
    let head = cx.block(span.sub(0, 2)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.u8("Start address (high byte)").hex().emit()?;
    f.u8("End address (high byte)").hex().emit()?;
    cx.emit(Node::new("Data (16-bit words)").span(span.sub(2, span.len.saturating_sub(4))));
    let crc = cx.block(span.sub(span.len.saturating_sub(2), 2)).await?;
    Fields::emitting(&cx, &crc, BE).u16("CRC-16").hex().emit()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// ColecoVision

fn coleco_probe(h: &Head<'_>) -> bool {
    let magic = h.at(0, b"\xaa\x55") || h.at(0, b"\x55\xaa");
    let start = u16_le(h.data, 10).unwrap_or(0);
    let jumps = [0x0cusize, 0x0f, 0x12, 0x15, 0x18, 0x1b, 0x1e, 0x21]
        .iter()
        .filter(|&&o| matches!(h.data.get(o), Some(0xc3 | 0xc9 | 0xed)))
        .count();
    magic && start >= 0x8000 && jumps >= 4 && (0x2000..=0x80000).contains(&h.len)
}

declare_format!(pub COLECOVISION = "colecovision", "ColecoVision cartridge ROM", ["col", "rom"],
    "application/x-colecovision-rom", Probe::Custom(coleco_probe), coleco);

record! {
    pub struct ColecoHeader {
        magic: u16 "Magic" .enumeration(&[(0x55aa, "show title screen"), (0xaa55, "skip title screen")]),
        sprite_names: u16 "Sprite name table" .hex(),
        sprite_order: u16 "Sprite order table" .hex(),
        work_buffer: u16 "Work buffer" .hex(),
        controller_map: u16 "Controller map" .hex(),
        start: u16 "Game start" .hex(),
        rst08: bytes[3] "RST 08h",
        rst10: bytes[3] "RST 10h",
        rst18: bytes[3] "RST 18h",
        rst20: bytes[3] "RST 20h",
        rst28: bytes[3] "RST 28h",
        rst30: bytes[3] "RST 30h",
        irq: bytes[3] "IRQ (RST 38h)",
        nmi: bytes[3] "NMI",
    }
}

async fn coleco(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: ColecoHeader = emit_record(&cx, file.sub(0, ColecoHeader::SIZE), LE).await?;
    let name = cx.read_avail(file.sub(ColecoHeader::SIZE, 96)).await?;
    let mut title = String::new();
    if h.magic == 0x55aa {
        let end = name
            .iter()
            .position(|&b| b == 0 || !(0x20..0x7f).contains(&b))
            .unwrap_or(name.len());
        let s = String::from_utf8_lossy(name.get(..end).unwrap_or_default()).into_owned();
        // "LINE 2/LINE 1/YEAR"
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() == 3 {
            title = format!(
                "{:?} ({}, {})",
                parts.get(1).copied().unwrap_or(""),
                parts.first().copied().unwrap_or(""),
                parts.get(2).copied().unwrap_or("")
            );
            cx.emit(
                Node::new("Title string")
                    .span(file.sub(ColecoHeader::SIZE, to_u64(end)))
                    .value(text(s)),
            );
        }
    }
    cx.emit(Node::new("Program").span(file.tail(ColecoHeader::SIZE)));
    cx.annotate(format!(
        "ColecoVision {}{}, start {:#06x}",
        if title.is_empty() {
            String::new()
        } else {
            format!("{title}, ")
        },
        size(file.len),
        h.start
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// MSX cartridge ROM

fn msx_ptr_ok(p: Option<u16>) -> bool {
    p.is_some_and(|p| p == 0 || (0x4000..0xc000).contains(&p))
}

fn msx_probe(h: &Head<'_>) -> bool {
    let init = u16_le(h.data, 2);
    let text = u16_le(h.data, 8);
    h.at(0, b"AB")
        && h.data
            .get(10..16)
            .is_some_and(|r| r.iter().all(|&b| b == 0))
        && msx_ptr_ok(init)
        && msx_ptr_ok(u16_le(h.data, 4))
        && msx_ptr_ok(u16_le(h.data, 6))
        && text.is_some_and(|t| t == 0 || (0x8000..0xc000).contains(&t))
        && (init.unwrap_or(0) != 0 || text.unwrap_or(0) != 0)
        && h.len.is_multiple_of(0x2000)
        && h.len <= 0x40_0000
}

declare_format!(pub MSX_ROM = "msx-rom", "MSX cartridge ROM", ["rom", "mx1", "mx2"],
    "application/x-msx-rom", Probe::Custom(msx_probe), msx);

record! {
    pub struct MsxHeader {
        id: ascii[2] "ID",
        init: u16 "INIT" .hex() .desc("Initialisation routine"),
        statement: u16 "STATEMENT" .hex() .desc("CALL statement handler"),
        device: u16 "DEVICE" .hex() .desc("Device handler"),
        text: u16 "TEXT" .hex() .desc("Tokenised BASIC program"),
        _reserved: bytes[6] "Reserved",
    }
}

async fn msx(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: MsxHeader = emit_record(&cx, file.sub(0, MsxHeader::SIZE), LE).await?;
    cx.emit(Node::new("Program").span(file.tail(MsxHeader::SIZE)));
    let kind = if h.text != 0 { "BASIC" } else { "machine code" };
    let mapper = match file.len {
        0..=0x8000 => "plain",
        0x8001..=0x10000 => "plain (64 KiB)",
        _ => "mapped (MegaROM)",
    };
    cx.annotate(format!(
        "MSX {kind} ROM, {}, {mapper}, INIT {:#06x}",
        size(file.len),
        h.init
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// WonderSwan (footer in the last 10 bytes)

fn ws_footer<'a>(h: &Head<'a>) -> Option<&'a [u8]> {
    let n = h.tail.len();
    let ok = h.len.is_power_of_two()
        && (0x2_0000..=0x100_0000).contains(&h.len)
        && h.tail.get(n.saturating_sub(16)) == Some(&0xea);
    let footer = h.tail.get(n.saturating_sub(10)..)?;
    let color = *footer.get(1)?;
    let rom = *footer.get(4)?;
    (ok && color <= 1 && rom <= 0x0a).then_some(footer)
}

fn wsc_probe(h: &Head<'_>) -> bool {
    ws_footer(h).is_some_and(|f| f.get(1) == Some(&1))
}

fn ws_probe(h: &Head<'_>) -> bool {
    ws_footer(h).is_some()
}

declare_format!(pub WONDERSWAN_COLOR = "wonderswan-color", "WonderSwan Color ROM", ["wsc"],
    "application/x-wonderswan-color-rom", Probe::Custom(wsc_probe), wonderswan);
declare_format!(pub WONDERSWAN = "wonderswan", "WonderSwan ROM", ["ws"],
    "application/x-wonderswan-rom", Probe::Custom(ws_probe), wonderswan);

const WS_ROM_SIZES: EnumTable = &[
    (0x00, "1 Mbit"),
    (0x01, "2 Mbit"),
    (0x02, "4 Mbit"),
    (0x03, "8 Mbit"),
    (0x04, "16 Mbit"),
    (0x05, "24 Mbit"),
    (0x06, "32 Mbit"),
    (0x07, "48 Mbit"),
    (0x08, "64 Mbit"),
    (0x09, "128 Mbit"),
];
const WS_SAVE: EnumTable = &[
    (0x00, "none"),
    (0x01, "SRAM 64 Kbit"),
    (0x02, "SRAM 256 Kbit"),
    (0x03, "SRAM 1 Mbit"),
    (0x04, "SRAM 2 Mbit"),
    (0x05, "SRAM 4 Mbit"),
    (0x10, "EEPROM 1 Kbit"),
    (0x20, "EEPROM 16 Kbit"),
    (0x50, "EEPROM 8 Kbit"),
];
const WS_FLAGS: FlagTable = &[
    flag(0x01, "VERTICAL"),
    flag(0x02, "BUS_8BIT"),
    flag(0x04, "ROM_1_CYCLE"),
];

record! {
    pub struct WsFooter {
        publisher: u8 "Publisher ID" .hex(),
        color: u8 "System" .enumeration(&[(0, "WonderSwan"), (1, "WonderSwan Color")]),
        game: u8 "Game ID" .hex(),
        version: u8 "Version",
        rom: u8 "ROM size" .enumeration(WS_ROM_SIZES),
        save: u8 "Save type" .enumeration(WS_SAVE),
        flags: u8 "Flags" .flags(WS_FLAGS),
        mapper: u8 "Mapper / RTC" .enumeration(&[(0, "none"), (1, "RTC")]),
        checksum: u16 "Checksum" .hex(),
    }
}

async fn wonderswan(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let at = file.len.saturating_sub(WsFooter::SIZE);
    cx.emit(Node::new("Program").span(file.sub(0, file.len.saturating_sub(16))));
    cx.emit(Node::new("Reset code (JMP FAR)").span(file.sub(file.len.saturating_sub(16), 6)));
    let span = file.sub(at, WsFooter::SIZE);
    let h: WsFooter = read_record(&cx, span, LE).await?;
    let mut node = WsFooter::node("Footer", span, LE);
    let mut verified = "";
    if at <= cx.limits().max_read {
        let data = cx.read(file.sub(0, at.saturating_add(8))).await?;
        let sum = data.iter().fold(0u16, |s, &b| s.wrapping_add(b.into()));
        if sum == h.checksum {
            verified = ", checksum valid";
        } else {
            node = node.diag(Diagnostic::warning(format!(
                "checksum mismatch: computed {sum:#06x}"
            )));
            verified = ", checksum mismatch";
        }
    }
    cx.emit(node);
    cx.annotate(format!(
        "{} game {:02x}-{:02x} v{}, {}, save {}{verified}",
        if h.color == 1 {
            "WonderSwan Color"
        } else {
            "WonderSwan"
        },
        h.publisher,
        h.game,
        h.version,
        size(file.len),
        lookup(WS_SAVE, h.save.into()).unwrap_or("unknown")
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Virtual Boy (header 0x220 bytes before the end)

fn vb_header<'a>(h: &Head<'a>) -> Option<&'a [u8]> {
    let n = h.tail.len();
    let header = h
        .tail
        .get(n.checked_sub(0x220)?..n.checked_sub(0x220 - 0x20)?)?;
    let alnum = |r: std::ops::Range<usize>| {
        header.get(r).is_some_and(|s| {
            s.iter()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        })
    };
    let ok = h.len.is_power_of_two()
        && (0x1_0000..=0x100_0000).contains(&h.len)
        && header
            .get(0x14..0x19)
            .is_some_and(|r| r.iter().all(|&b| b == 0))
        && alnum(0x19..0x1b)
        && alnum(0x1b..0x1f)
        && header.first().is_some_and(|&b| b >= 0x20);
    ok.then_some(header)
}

declare_format!(pub VIRTUAL_BOY = "virtual-boy", "Virtual Boy ROM", ["vb", "vboy"],
    "application/x-virtualboy-rom", Probe::Custom(|h| vb_header(h).is_some()), virtual_boy);

record! {
    pub struct VbHeader {
        title: bytes[20] "Title (Shift-JIS)",
        _reserved: bytes[5] "Reserved",
        maker: ascii[2] "Maker code",
        game: ascii[4] "Game code",
        version: u8 "Version",
    }
}

async fn virtual_boy(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let at = file.len.saturating_sub(0x220);
    cx.emit(Node::new("Program").span(file.sub(0, at)));
    let span = file.sub(at, VbHeader::SIZE);
    let h: VbHeader = read_record(&cx, span, LE).await?;
    cx.emit(VbHeader::node("Header", span, LE));
    cx.emit(
        Node::new("Interrupt and exception vectors")
            .span(file.tail(file.len.saturating_sub(0x200))),
    );
    // Titles are Shift-JIS; show the ASCII part.
    let title: String = h
        .title
        .iter()
        .take_while(|&&b| b != 0)
        .map(|&b| {
            if (0x20..0x7f).contains(&b) {
                char::from(b)
            } else {
                '?'
            }
        })
        .collect();
    cx.annotate(format!(
        "Virtual Boy {:?} ({}{}) v1.{}, {}",
        title.trim(),
        h.game,
        h.maker,
        h.version,
        size(file.len)
    ));
    Ok(())
}
