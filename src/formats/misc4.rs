//! Game assets (Blizzard, Bethesda, Rockstar, Build engine, EA, FromSoftware,
//! Nintendo audio and layouts, Minecraft NBT), trackers, bitmap fonts, Java
//! keystores, PuTTY keys and planetary/remote-sensing imagery.

use crate::bytes::{to_u64, to_usize, u16_be, u16_le, u32_be, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, emit_record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::text::decode::{Transform, decoded_node};
use crate::formats::{Head, Input, Probe, embedded, embedded_as};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{FlagTable, Radix, Value, flag};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

fn text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

fn uint(value: u64, bits: u8) -> Value {
    Value::UInt { value, bits, radix: Radix::Dec }
}

/// NUL-terminated (or padded) Latin-1 text.
fn zstr(b: &[u8]) -> String {
    crate::text::until_nul(b)
}

/// `KEY value` / `KEY=value` lines of a text header, up to `end` (exclusive)
/// or `max` bytes, with spans.
async fn header_lines(cx: &Cx, file: Span, max: u64) -> Result<Vec<(String, Span)>> {
    let head = cx.read_avail(file.sub(0, max)).await?;
    let mut out = Vec::new();
    let mut pos = 0u64;
    for line in head.split(|&b| b == b'\n') {
        let len = to_u64(line.len());
        out.push((String::from_utf8_lossy(line).trim_end_matches('\r').to_owned(), file.sub(pos, len)));
        pos = pos.saturating_add(len).saturating_add(1);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Blizzard: BLP textures, M2 models, Warcraft III maps

declare_format!(pub BLP = "blp", "Blizzard texture (BLP)", ["blp"], "image/x-blp",
    Probe::Magic(&[(0, b"BLP2"), (0, b"BLP1")]), blp);

async fn blp(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let v2 = cx.read(file.sub(0, 4)).await? == b"BLP2";
    let head_len = if v2 { 20 } else { 28 };
    let head = cx.block(file.sub(0, head_len)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 4).emit()?;
    let (width, height, kind) = if v2 {
        f.u32("Type").emit()?;
        let encoding = f.u8("Encoding").enumeration(&[(1, "palettized"), (2, "DXT"), (3, "uncompressed BGRA")]).emit()?;
        f.u8("Alpha depth").emit()?;
        f.u8("Alpha encoding").enumeration(&[(0, "DXT1"), (1, "DXT3"), (7, "DXT5")]).emit()?;
        f.u8("Has mipmaps").emit()?;
        let w = f.u32("Width").emit()?;
        let h = f.u32("Height").emit()?;
        (w, h, match encoding { 1 => "palettized", 2 => "DXT", 3 => "BGRA", _ => "unknown" })
    } else {
        let compression = f.u32("Compression").enumeration(&[(0, "JPEG"), (1, "palettized")]).emit()?;
        f.u32("Alpha bits").emit()?;
        let w = f.u32("Width").emit()?;
        let h = f.u32("Height").emit()?;
        f.u32("Extra").emit()?;
        f.u32("Has mipmaps").emit()?;
        (w, h, if compression == 0 { "JPEG" } else { "palettized" })
    };
    let table = cx.read(file.sub(head_len, 128)).await?;
    for level in 0..16usize {
        let offset = u64::from(u32_le(&table, level.saturating_mul(4)).unwrap_or(0));
        let size = u64::from(u32_le(&table, level.saturating_mul(4).saturating_add(64)).unwrap_or(0));
        if offset == 0 || size == 0 {
            break;
        }
        cx.push(
            Node::new(format!("Mipmap {level}"))
                .span(file.sub(offset, size))
                .summary(format!("{}×{}", (width >> level).max(1), (height >> level).max(1))),
        )
        .await;
    }
    cx.annotate(format!("BLP{} {kind} texture, {width}×{height}", if v2 { 2 } else { 1 }));
    Ok(())
}

declare_format!(pub M2 = "wow-m2", "World of Warcraft model (M2)", ["m2", "mdx"], "model/x-wow-m2",
    Probe::Magic(&[(0, b"MD20"), (0, b"MD21")]), m2);

async fn m2(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut body = file;
    if cx.read(file.sub(0, 4)).await? == b"MD21" {
        // Chunked (Legion+): MD21 wraps the classic header.
        let size = u64::from(u32_le(&cx.read(file.sub(4, 4)).await?, 0).unwrap_or(0));
        cx.emit(Node::new("MD21 chunk").span(file.sub(0, size.saturating_add(8))));
        body = file.sub(8, size);
    }
    let head = cx.block(body.sub(0, 16)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 4).emit()?;
    let version = f.u32("Version").emit()?;
    let name_len = f.u32("Name length").emit()?;
    let name_at = f.u32("Name offset").hex().emit()?;
    let name = zstr(&cx.read_avail(body.sub(name_at.into(), u64::from(name_len).min(256))).await?);
    cx.emit(Node::new("Name").span(body.sub(name_at.into(), name_len.into())).value(text(name.clone())));
    let era = match version {
        256..=257 => "Classic",
        260..=263 => "Burning Crusade",
        264 => "Wrath of the Lich King",
        265..=272 => "Cataclysm to Warlords",
        273.. => "Legion or later",
        _ => "unknown",
    };
    cx.annotate(format!("M2 model {name:?}, version {version} ({era})"));
    Ok(())
}

declare_format!(pub W3M = "w3m", "Warcraft III map", ["w3m", "w3x"], "application/x-w3m",
    Probe::Magic(&[(0, b"HM3W")]), w3m);

async fn w3m(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, LE);
    cur.skip(8);
    let (name, name_span) = cur.cstr(256).await?;
    let flags = cur.u32().await?;
    let players = cur.u32().await?;
    cx.emit(Node::new("Signature").span(file.sub(0, 4)));
    cx.emit(Node::new("Map name").span(name_span).value(text(name.clone())));
    cx.emit(Node::new("Flags").span(cur.since(cur.pos().saturating_sub(8)).sub(0, 4)).value(Value::UInt { value: flags.into(), bits: 32, radix: Radix::Hex }));
    cx.emit(Node::new("Maximum players").span(cur.since(cur.pos().saturating_sub(4))).value(uint(players.into(), 32)));
    let archive = file.tail(512);
    cx.emit(embedded("MPQ archive", input.nested(archive)));
    cx.annotate(format!("Warcraft III map {name:?}, {players} players"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Bethesda: TES3 / TES4+ plugins

fn tes_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"TES3") && h.at(16, b"HEDR")
        || h.starts_with(b"TES4") && (h.at(20, b"HEDR") || h.at(24, b"HEDR"))
}

declare_format!(pub TES = "tes-plugin", "Bethesda game plugin (ESM/ESP)", ["esm", "esp", "esl", "omwaddon"], "application/x-tes-plugin",
    Probe::Custom(tes_probe), tes);

async fn tes(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 28)).await?;
    let tes3 = head.starts_with(b"TES3");
    // TES3 records: 16-byte header, 8-byte subrecord headers. TES4 and later:
    // 20 (Oblivion) or 24-byte record headers, 6-byte subrecord headers.
    let rec_head: u64 = if tes3 { 16 } else if head.get(20..24) == Some(b"HEDR") { 20 } else { 24 };
    let mut pos = 0u64;
    let mut n = 0u32;
    let mut summary = String::new();
    while pos.saturating_add(rec_head) <= file.len {
        let h = cx.read(file.sub(pos, rec_head)).await?;
        let kind = String::from_utf8_lossy(h.get(..4).unwrap_or_default()).into_owned();
        let size = u64::from(u32_le(&h, 4).unwrap_or(0));
        // GRUP sizes include their header; record sizes do not.
        let total = if kind == "GRUP" { size } else { size.saturating_add(rec_head) };
        if total < rec_head {
            return Err(Diagnostic::malformed("record size smaller than its header").at(file.sub(pos, rec_head)));
        }
        let span = file.sub(pos, total);
        let mut node = Node::new(kind.clone()).span(span);
        if kind == "GRUP" {
            let label = h.get(8..12).unwrap_or_default();
            node = node.summary(format!("{} — {} bytes", String::from_utf8_lossy(label), size));
        } else if n == 0 {
            // The file header: HEDR, author, description, masters.
            let body = cx.read_avail(span.tail(rec_head).sub(0, 4096)).await?;
            let mut at = 0usize;
            let mut masters = Vec::new();
            while at.saturating_add(if tes3 { 8 } else { 6 }) <= body.len() {
                let id = String::from_utf8_lossy(body.get(at..at.saturating_add(4)).unwrap_or_default()).into_owned();
                let (len, hl) = if tes3 {
                    (to_usize(u32_le(&body, at.saturating_add(4)).unwrap_or(0).into()), 8)
                } else {
                    (usize::from(u16_le(&body, at.saturating_add(4)).unwrap_or(0)), 6)
                };
                let data = body.get(at.saturating_add(hl)..at.saturating_add(hl).saturating_add(len)).unwrap_or_default();
                match id.as_str() {
                    "HEDR" => {
                        let version = f32::from_le_bytes([
                            data.first().copied().unwrap_or(0),
                            data.get(1).copied().unwrap_or(0),
                            data.get(2).copied().unwrap_or(0),
                            data.get(3).copied().unwrap_or(0),
                        ]);
                        let records = if tes3 { u32_le(data, 296) } else { u32_le(data, 4) }.unwrap_or(0);
                        if tes3 {
                            summary = format!("{} ", zstr(data.get(8..40).unwrap_or_default()));
                        }
                        summary.push_str(&format!("v{version:.2}, {records} records"));
                    }
                    "CNAM" => summary = format!("{} by {}", summary, zstr(data)),
                    "MAST" => masters.push(zstr(data)),
                    _ => {}
                }
                at = at.saturating_add(hl).saturating_add(len);
            }
            if !masters.is_empty() {
                summary.push_str(&format!(", masters: {}", masters.join(", ")));
            }
            node = node.summary(summary.clone());
        } else {
            node = node.summary(format!("{size} bytes"));
        }
        cx.push(node).await;
        n = n.saturating_add(1);
        pos = pos.saturating_add(total);
    }
    cx.annotate(format!("{} plugin, {summary}", if tes3 { "Morrowind" } else { "Gamebryo/Creation engine" }));
    Ok(())
}

// ---------------------------------------------------------------------------
// Archives: GTA IMG v2, Descent HOG, Build GRP, EA BIG, Blood RFF,
// FromSoftware BND

declare_format!(pub GTA_IMG = "gta-img", "GTA San Andreas archive (IMG v2)", ["img"], "application/x-gta-img",
    Probe::Magic(&[(0, b"VER2")]), gta_img);

async fn gta_img(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let count = u32_le(&cx.read(file.sub(4, 4)).await?, 0).unwrap_or(0);
    cx.emit(Node::new("Entries").span(file.sub(4, 4)).value(uint(count.into(), 32)));
    for i in 0..count {
        let at = 8u64.saturating_add(u64::from(i).saturating_mul(32));
        let e = cx.read(file.sub_exact(at, 32)?).await?;
        let offset = u64::from(u32_le(&e, 0).unwrap_or(0)).saturating_mul(2048);
        let sectors = u64::from(u16_le(&e, 4).unwrap_or(0));
        let name = zstr(e.get(8..32).unwrap_or_default());
        let data = file.sub(offset, sectors.saturating_mul(2048));
        cx.push(embedded(name, input.nested(data)).target(file.sub(at, 32))).await;
    }
    cx.annotate(format!("GTA IMG v2 archive, {count} entries"));
    Ok(())
}

declare_format!(pub HOG = "descent-hog", "Descent archive (HOG)", ["hog"], "application/x-descent-hog",
    Probe::Magic(&[(0, b"DHF")]), hog);

async fn hog(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut pos = 3u64;
    let mut n = 0u32;
    while pos.saturating_add(17) <= file.len {
        let h = cx.read(file.sub(pos, 17)).await?;
        let name = zstr(h.get(..13).unwrap_or_default());
        let size = u64::from(u32_le(&h, 13).unwrap_or(0));
        let data = file.sub_exact(pos.saturating_add(17), size)?;
        cx.push(embedded(name, input.nested(data)).target(file.sub(pos, 17))).await;
        n = n.saturating_add(1);
        pos = data.end().saturating_sub(file.offset);
    }
    cx.annotate(format!("Descent HOG archive, {n} files"));
    Ok(())
}

declare_format!(pub GRP = "build-grp", "Build engine group file (GRP)", ["grp"], "application/x-build-grp",
    Probe::Magic(&[(0, b"KenSilverman")]), grp);

async fn grp(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let count = u32_le(&cx.read(file.sub(12, 4)).await?, 0).unwrap_or(0);
    let dir_len = u64::from(count).saturating_add(1).saturating_mul(16);
    let mut data_at = dir_len;
    for i in 0..count {
        let at = 16u64.saturating_add(u64::from(i).saturating_mul(16));
        let e = cx.read(file.sub_exact(at, 16)?).await?;
        let name = zstr(e.get(..12).unwrap_or_default());
        let size = u64::from(u32_le(&e, 12).unwrap_or(0));
        cx.push(embedded(name, input.nested(file.sub(data_at, size))).target(file.sub(at, 16))).await;
        data_at = data_at.saturating_add(size);
    }
    cx.annotate(format!("Build engine GRP, {count} files"));
    Ok(())
}

declare_format!(pub BIG = "ea-big", "EA BIG archive", ["big"], "application/x-ea-big",
    Probe::Magic(&[(0, b"BIGF"), (0, b"BIG4")]), big);

async fn big(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 16)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Signature", 4).emit()?;
    f.skip(4);
    let size = u32_le(&cx.read(file.sub(4, 4)).await?, 0).unwrap_or(0);
    cx.emit(Node::new("Archive size (little-endian)").span(file.sub(4, 4)).value(uint(size.into(), 32)));
    let count = f.u32("Entries").emit()?;
    f.u32("Header size").emit()?;
    let mut cur = Cursor::new(&cx, file, BE);
    cur.seek(16);
    for _ in 0..count {
        let start = cur.pos();
        let offset = u64::from(cur.u32().await?);
        let size = u64::from(cur.u32().await?);
        let (name, _) = cur.cstr(512).await?;
        cx.push(embedded(name, input.nested(file.sub(offset, size))).target(cur.since(start))).await;
    }
    cx.annotate(format!("EA BIG archive, {count} files"));
    Ok(())
}

declare_format!(pub RFF = "blood-rff", "Blood resource file (RFF)", ["rff"], "application/x-blood-rff",
    Probe::Magic(&[(0, b"RFF\x1a")]), rff);

async fn rff(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 16)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 4).emit()?;
    let version = f.u16("Version").hex().emit()?;
    f.u16("Padding").emit()?;
    let dir = f.u32("Directory offset").hex().emit()?;
    let count = f.u32("Entries").emit()?;
    let dir_span = file.sub(dir.into(), u64::from(count).saturating_mul(48));
    let mut node = Node::new("Directory").span(dir_span).summary(format!("{count} × 48-byte entries"));
    if version >= 0x301 {
        node = node.diag(Diagnostic::unsupported("directory is XOR-encrypted"));
    }
    cx.emit(node);
    cx.annotate(format!("Blood RFF v{}.{}, {count} entries", version >> 8, version & 0xff));
    Ok(())
}

declare_format!(pub BND = "fromsoft-bnd", "FromSoftware binder (BND3/BND4)", ["bnd", "chrbnd", "partsbnd", "objbnd", "mtdbnd", "anibnd"], "application/x-fromsoft-bnd",
    Probe::Magic(&[(0, b"BND3"), (0, b"BND4")]), bnd);

async fn bnd(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 0x40)).await?;
    let v4 = head.starts_with(b"BND4");
    let (count, version) = if v4 {
        let big = head.get(9).copied().unwrap_or(0) != 0;
        let count = if big { u32_be(&head, 0x0c) } else { u32_le(&head, 0x0c) }.unwrap_or(0);
        (count, zstr(head.get(0x18..0x20).unwrap_or_default()))
    } else {
        let big = head.get(0x0d).copied().unwrap_or(0) != 0;
        let count = if big { u32_be(&head, 0x10) } else { u32_le(&head, 0x10) }.unwrap_or(0);
        (count, zstr(head.get(4..12).unwrap_or_default()))
    };
    cx.emit(Node::new("Signature").span(file.sub(0, 4)));
    cx.emit(Node::new("Version").span(file.sub(if v4 { 0x18 } else { 4 }, 8)).value(text(version.clone())));
    cx.emit(Node::new("Files").span(file.sub(if v4 { 0x0c } else { 0x10 }, 4)).value(uint(count.into(), 32)));
    cx.emit(Node::new("Body").span(file.tail(if v4 { 0x40 } else { 0x20 })));
    cx.annotate(format!("{} binder {version:?}, {count} files", if v4 { "BND4" } else { "BND3" }));
    Ok(())
}

// ---------------------------------------------------------------------------
// Nintendo NW4R (Wii) and NW4C/NW4F (3DS, Wii U, Switch) binaries

fn nw_probe(h: &Head<'_>) -> bool {
    const MAGICS: &[&[u8; 4]] = &[b"CSTM", b"FSTM", b"CWAV", b"FWAV", b"CSAR", b"FSAR", b"CLYT", b"FLYT", b"CLAN", b"FLAN"];
    MAGICS.iter().any(|m| h.starts_with(*m)) && (h.at(4, b"\xff\xfe") || h.at(4, b"\xfe\xff"))
}

declare_format!(pub NW4 = "nw4-binary", "Nintendo NW4C/NW4F resource", ["bcstm", "bfstm", "bcwav", "bfwav", "bcsar", "bfsar", "bclyt", "bflyt", "bclan", "bflan"], "application/x-nintendo-nw4",
    Probe::Custom(nw_probe), nw4);

async fn nw4(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let bom = cx.read(file.sub(4, 2)).await?;
    let endian = if bom == b"\xfe\xff" { BE } else { LE };
    let head = cx.block(file.sub(0, 20)).await?;
    let mut f = Fields::emitting(&cx, &head, endian);
    let magic = f.ascii("Signature", 4).emit()?;
    f.u16("Byte-order mark").hex().emit()?;
    let header_len = f.u16("Header size").emit()?;
    let version = f.u32("Version").hex().emit()?;
    f.u32("File size").emit()?;
    let sections = f.u16("Sections").emit()?;
    f.u16("Reserved").emit()?;
    let layout = matches!(magic.as_str(), "CLYT" | "FLYT" | "CLAN" | "FLAN");
    let mut cur = Cursor::new(&cx, file, endian);
    if layout {
        // Blocks follow the header: magic, size.
        cur.seek(header_len.into());
        for _ in 0..sections {
            let start = cur.pos();
            let id = String::from_utf8_lossy(&cur.bytes(4).await?).into_owned();
            let size = u64::from(cur.u32().await?);
            if size < 8 {
                return Err(Diagnostic::malformed("block smaller than its header").at(cur.since(start)));
            }
            cur.seek(start.saturating_add(size));
            cx.push(Node::new(id).span(file.sub(start, size)).summary(format!("{size} bytes"))).await;
        }
    } else {
        // A table of section references: id, padding, offset, size.
        cur.seek(20);
        for _ in 0..sections {
            let start = cur.pos();
            let id = cur.u16().await?;
            cur.skip(2);
            let offset = u64::from(cur.u32().await?);
            let size = u64::from(cur.u32().await?);
            let name = match id {
                0x2000 => "SAR STRG".to_owned(),
                0x2001 => "SAR INFO".to_owned(),
                0x2002 => "SAR FILE".to_owned(),
                0x4000 => "INFO".to_owned(),
                0x4001 => "SEEK".to_owned(),
                0x4002 => "DATA".to_owned(),
                0x4003 => "REGN".to_owned(),
                0x4004 => "PDAT".to_owned(),
                0x7000 => "INFO".to_owned(),
                0x7001 => "DATA".to_owned(),
                _ => format!("Section {id:#06x}"),
            };
            cx.push(Node::new(name).span(file.sub(offset, size)).target(cur.since(start)).summary(format!("{size} bytes"))).await;
        }
    }
    cx.annotate(format!("Nintendo {magic} v{}.{}.{}, {sections} sections", version >> 24, (version >> 16) & 0xff, (version >> 8) & 0xff));
    Ok(())
}

fn nw4r_probe(h: &Head<'_>) -> bool {
    const MAGICS: &[&[u8; 4]] = &[b"RSTM", b"RWAV", b"RSAR", b"RSEQ", b"RBNK", b"RWSD", b"RWAR"];
    MAGICS.iter().any(|m| h.starts_with(*m)) && h.at(4, b"\xfe\xff")
}

declare_format!(pub NW4R = "nw4r-binary", "Nintendo NW4R (Wii) sound resource", ["brstm", "brwav", "brsar", "brseq", "brbnk", "brwsd", "brwar"], "application/x-nintendo-nw4r",
    Probe::Custom(nw4r_probe), nw4r);

async fn nw4r(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 16)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    let magic = f.ascii("Signature", 4).emit()?;
    f.u16("Byte-order mark").hex().emit()?;
    let version = f.u16("Version").hex().emit()?;
    f.u32("File size").emit()?;
    let header_len = f.u16("Header size").emit()?;
    let blocks = f.u16("Blocks").emit()?;
    // Block references (offset, size) follow, then the blocks: magic, size.
    let refs = cx.read_avail(file.sub(16, u64::from(blocks).saturating_mul(8))).await?;
    for i in 0..usize::from(blocks) {
        let offset = u64::from(u32_be(&refs, i.saturating_mul(8)).unwrap_or(0));
        let size = u64::from(u32_be(&refs, i.saturating_mul(8).saturating_add(4)).unwrap_or(0));
        let id = String::from_utf8_lossy(&cx.read_avail(file.sub(offset, 4)).await?).into_owned();
        cx.push(
            Node::new(if id.is_empty() { format!("Block {i}") } else { id })
                .span(file.sub(offset, size))
                .target(file.sub(16u64.saturating_add(to_u64(i).saturating_mul(8)), 8))
                .summary(format!("{size} bytes")),
        )
        .await;
    }
    let _ = header_len;
    cx.annotate(format!("Nintendo {magic} v{}.{}, {blocks} blocks", version >> 8, version & 0xff));
    Ok(())
}

// ---------------------------------------------------------------------------
// Minecraft NBT (uncompressed; gzipped NBT reaches here through gzip)

fn nbt_probe(h: &Head<'_>) -> bool {
    let Some(len) = u16_be(h.data, 1) else { return false };
    let len = usize::from(len);
    h.data.first() == Some(&10)
        && len <= 64
        && h.data.get(3..3usize.saturating_add(len)).is_some_and(|n| n.iter().all(|b| b.is_ascii_graphic() || *b == b' '))
        && h.data.get(3usize.saturating_add(len)).is_some_and(|&t| (1..=12).contains(&t))
}

declare_format!(pub NBT = "nbt", "Minecraft NBT", ["nbt", "dat", "schematic", "schem", "litematic"], "application/x-minecraft-nbt",
    Probe::Custom(nbt_probe), nbt);

const NBT_TYPES: &[&str] = &["End", "Byte", "Short", "Int", "Long", "Float", "Double", "Byte array", "String", "List", "Compound", "Int array", "Long array"];

fn nbt_type(t: u8) -> &'static str {
    NBT_TYPES.get(usize::from(t)).copied().unwrap_or("?")
}

async fn read_exact(cx: &Cx, region: Span, at: u64, n: u64) -> Result<Vec<u8>> {
    cx.read(region.sub_exact(at, n)?).await
}

async fn be_int(cx: &Cx, region: Span, at: u64, n: u64) -> Result<u64> {
    let b = read_exact(cx, region, at, n).await?;
    Ok(b.iter().fold(0u64, |acc, &x| acc.wrapping_shl(8) | u64::from(x)))
}

/// Length of a payload of type `t` at `pos` (iterative, so hostile nesting
/// cannot overflow the stack).
async fn nbt_skip(cx: &Cx, region: Span, start: u64, t: u8) -> Result<u64> {
    enum Frame {
        Compound,
        List(u8, u64),
    }
    let mut pos = start;
    let mut stack: Vec<Frame> = Vec::new();
    let mut pending = Some(t);
    loop {
        if let Some(t) = pending.take() {
            let fixed = |t: u8| match t {
                1 => Some(1u64),
                2 => Some(2),
                3 | 5 => Some(4),
                4 | 6 => Some(8),
                _ => None,
            };
            if let Some(n) = fixed(t) {
                pos = pos.saturating_add(n);
            } else {
                match t {
                    7 | 11 | 12 => {
                        let n = be_int(cx, region, pos, 4).await? & 0x7fff_ffff;
                        let unit = match t { 7 => 1, 11 => 4, _ => 8 };
                        pos = pos.saturating_add(4).saturating_add(n.saturating_mul(unit));
                    }
                    8 => {
                        let n = be_int(cx, region, pos, 2).await?;
                        pos = pos.saturating_add(2).saturating_add(n);
                    }
                    9 => {
                        let et = u8::try_from(be_int(cx, region, pos, 1).await?).unwrap_or(0);
                        let n = be_int(cx, region, pos.saturating_add(1), 4).await? & 0x7fff_ffff;
                        pos = pos.saturating_add(5);
                        if let Some(size) = fixed(et) {
                            pos = pos.saturating_add(n.saturating_mul(size));
                        } else if n > 0 {
                            stack.push(Frame::List(et, n));
                        }
                    }
                    10 => stack.push(Frame::Compound),
                    _ => return Err(Diagnostic::malformed(format!("unknown tag type {t}")).at(region.sub(pos, 1))),
                }
            }
            if pos > region.len {
                return Err(Diagnostic::malformed("tag runs past the end of the data").at(region.sub(start, 1)));
            }
        }
        if stack.len() > 512 {
            return Err(Diagnostic::limit("NBT nested deeper than 512").at(region.sub(start, 1)));
        }
        match stack.last_mut() {
            None => return Ok(pos.saturating_sub(start)),
            Some(Frame::List(et, n)) => {
                if *n == 0 {
                    stack.pop();
                } else {
                    *n = n.saturating_sub(1);
                    pending = Some(*et);
                }
            }
            Some(Frame::Compound) => {
                let t = u8::try_from(be_int(cx, region, pos, 1).await?).unwrap_or(0);
                pos = pos.saturating_add(1);
                if t == 0 {
                    stack.pop();
                } else {
                    let n = be_int(cx, region, pos, 2).await?;
                    pos = pos.saturating_add(2).saturating_add(n);
                    pending = Some(t);
                }
            }
        }
    }
}

/// A node for a payload of type `t` occupying `span` (within `region`).
async fn nbt_value(cx: &Cx, region: Span, name: String, header: u64, at: u64, t: u8) -> Result<Node> {
    let len = nbt_skip(cx, region, at, t).await?;
    let span = region.sub(at.saturating_sub(header), len.saturating_add(header));
    let payload = region.sub(at, len);
    let node = Node::new(name).span(span);
    let b = cx.read(payload.sub(0, 8)).await?;
    let int = |n: usize| -> i64 {
        let v = b.get(..n).unwrap_or_default().iter().fold(0u64, |acc, &x| acc.wrapping_shl(8) | u64::from(x));
        let shift = 64u32.saturating_sub(u32::try_from(n).unwrap_or(0).saturating_mul(8));
        i64::from_ne_bytes(v.wrapping_shl(shift).to_ne_bytes()).wrapping_shr(shift)
    };
    Ok(match t {
        1 => node.value(Value::Int { value: int(1), bits: 8 }),
        2 => node.value(Value::Int { value: int(2), bits: 16 }),
        3 => node.value(Value::Int { value: int(4), bits: 32 }),
        4 => node.value(Value::Int { value: int(8), bits: 64 }),
        5 => node.value(Value::Float(f32::from_bits(u32_be(&b, 0).unwrap_or(0)).into())),
        6 => node.value(Value::Float(f64::from_bits(u64::from_be_bytes(b.get(..8).and_then(|s| s.try_into().ok()).unwrap_or([0; 8]))))),
        8 => {
            let s = cx.read(payload.tail(2).sub(0, 256)).await?;
            node.value(text(String::from_utf8_lossy(&s).into_owned()))
        }
        7 | 11 | 12 => node.summary(format!("{} × {}", nbt_type(t), int(4))),
        9 => node
            .summary(format!("List of {} {}", u32_be(&b, 1).unwrap_or(0) & 0x7fff_ffff, nbt_type(b.first().copied().unwrap_or(0))))
            .lazy(crate::expander!(nbt_list: (Span, u8)), (payload, b.first().copied().unwrap_or(0))),
        10 => node.lazy(crate::expander!(nbt_compound: Span), payload),
        _ => node,
    })
}

async fn nbt_compound(cx: Cx, region: Span) -> Result<()> {
    let mut pos = 0u64;
    loop {
        let t = u8::try_from(be_int(&cx, region, pos, 1).await?).unwrap_or(0);
        if t == 0 {
            break;
        }
        let n = be_int(&cx, region, pos.saturating_add(1), 2).await?;
        let name = String::from_utf8_lossy(&read_exact(&cx, region, pos.saturating_add(3), n).await?).into_owned();
        let at = pos.saturating_add(3).saturating_add(n);
        let node = nbt_value(&cx, region, name, at.saturating_sub(pos), at, t).await?;
        let end = node.span.map_or(at, |s| s.end().saturating_sub(region.offset));
        cx.push(node).await;
        pos = end.max(at);
    }
    Ok(())
}

async fn nbt_list(cx: Cx, (region, et): (Span, u8)) -> Result<()> {
    let n = be_int(&cx, region, 1, 4).await? & 0x7fff_ffff;
    let mut pos = 5u64;
    for i in 0..n {
        let node = nbt_value(&cx, region, format!("[{i}]"), 0, pos, et).await?;
        let end = node.span.map_or(pos, |s| s.end().saturating_sub(region.offset));
        cx.push(node).await;
        if end <= pos {
            break;
        }
        pos = end;
    }
    Ok(())
}

async fn nbt(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let n = be_int(&cx, file, 1, 2).await?;
    let name = String::from_utf8_lossy(&read_exact(&cx, file, 3, n).await?).into_owned();
    let at = 3u64.saturating_add(n);
    let len = nbt_skip(&cx, file, at, 10).await?;
    let payload = file.sub(at, len);
    cx.annotate(format!("NBT compound {name:?}, {len} bytes"));
    nbt_compound(cx, payload).await
}

// ---------------------------------------------------------------------------
// Music: Doom MUS, HMI, AHX, MO3, DigiBooster, Farandole

declare_format!(pub MUS = "doom-mus", "DMX music (Doom MUS)", ["mus"], "audio/x-doom-mus",
    Probe::Magic(&[(0, b"MUS\x1a")]), mus);

record! {
    pub struct MusHeader {
        magic: ascii[4] "Signature",
        score_len: u16 "Score length",
        score_start: u16 "Score offset" .hex(),
        channels: u16 "Primary channels",
        secondary: u16 "Secondary channels",
        instruments: u16 "Instruments",
        reserved: u16 "Reserved",
    }
}

async fn mus(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: MusHeader = emit_record(&cx, file.sub(0, MusHeader::SIZE), LE).await?;
    cx.emit(Node::new("Instrument list").span(file.sub(16, u64::from(h.instruments).saturating_mul(2))));
    cx.emit(Node::new("Score").span(file.sub(h.score_start.into(), h.score_len.into())));
    cx.annotate(format!("Doom MUS, {} channels, {} instruments", h.channels, h.instruments));
    Ok(())
}

declare_format!(pub HMI = "hmi-midi", "HMI MIDI song", ["hmp", "hmi"], "audio/x-hmi",
    Probe::Magic(&[(0, b"HMIMIDIP"), (0, b"HMI-MIDISONG")]), hmi);

async fn hmi(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 0x40)).await?;
    let hmp = head.starts_with(b"HMIMIDIP");
    cx.emit(Node::new("Signature").span(file.sub(0, if hmp { 8 } else { 12 })).value(text(zstr(head.get(..18).unwrap_or_default()))));
    let tracks = if hmp { u32_le(&head, 0x30) } else { u16_le(&head, 0xe4).map(u32::from) }.unwrap_or(0);
    if hmp {
        cx.emit(Node::new("Tracks").span(file.sub(0x30, 4)).value(uint(tracks.into(), 32)));
    }
    cx.emit(Node::new("Body").span(file.tail(0x40)));
    cx.annotate(format!("HMI {} song{}", if hmp { "HMP" } else { "HMI" }, if hmp { format!(", {tracks} tracks") } else { String::new() }));
    Ok(())
}

declare_format!(pub AHX = "ahx", "AHX/THX chiptune module", ["ahx", "thx"], "audio/x-ahx",
    Probe::Magic(&[(0, b"THX\0"), (0, b"THX\x01")]), ahx);

async fn ahx(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 14)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Signature", 3).emit()?;
    let rev = f.u8("Revision").emit()?;
    let names = f.u16("Name table offset").hex().emit()?;
    let len = f.u16("Positions and flags").hex().emit()?;
    f.u16("Restart position").emit()?;
    f.u8("Track length").emit()?;
    let tracks = f.u8("Tracks").emit()?;
    let samples = f.u8("Instruments").emit()?;
    f.u8("Subsongs").emit()?;
    let (title, span) = cx.cstr(file.sub(names.into(), 256)).await?;
    cx.emit(Node::new("Title").span(span).value(text(title.clone())));
    cx.annotate(format!("AHX v{rev} {title:?}, {} positions, {tracks} tracks, {samples} instruments", len & 0xfff));
    Ok(())
}

declare_format!(pub MO3 = "mo3", "MO3 compressed module", ["mo3"], "audio/x-mo3",
    Probe::Magic(&[(0, b"MO3")]), mo3);

async fn mo3(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 8)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 3).emit()?;
    let version = f.u8("Version").emit()?;
    let size = f.u32("Decompressed header size").emit()?;
    cx.emit(Node::new("Compressed music data").span(file.tail(8)).diag(Diagnostic::unsupported("MO3 delta/LZ compression")));
    cx.annotate(format!("MO3 v{version} module, {size}-byte header"));
    Ok(())
}

declare_format!(pub DBM = "digibooster", "DigiBooster Pro module", ["dbm"], "audio/x-dbm",
    Probe::Magic(&[(0, b"DBM0")]), dbm);

async fn dbm(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 8)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Signature", 4).emit()?;
    let version = f.u16("Version").hex().emit()?;
    f.u16("Reserved").emit()?;
    let mut cur = Cursor::new(&cx, file, BE);
    cur.seek(8);
    let mut title = String::new();
    while cur.remaining() >= 8 {
        let start = cur.pos();
        let id = String::from_utf8_lossy(&cur.bytes(4).await?).into_owned();
        let size = u64::from(cur.u32().await?);
        let body = file.sub(cur.pos(), size);
        let mut node = Node::new(id.clone()).span(file.sub(start, size.saturating_add(8))).summary(format!("{size} bytes"));
        if id == "NAME" {
            title = zstr(&cx.read_avail(body.sub(0, 64)).await?);
            node = node.value(text(title.clone()));
        }
        cx.push(node).await;
        cur.skip(size);
    }
    cx.annotate(format!("DigiBooster Pro {}.{:02x} module {title:?}", version >> 8, version & 0xff));
    Ok(())
}

declare_format!(pub FAR = "farandole", "Farandole Composer module", ["far"], "audio/x-far",
    Probe::Magic(&[(0, b"FAR\xfe")]), far);

async fn far(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 0x32)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.bytes("Signature", 4).emit()?;
    let title = f.ascii("Title", 40).emit()?;
    f.bytes("EOF marker", 3).emit()?;
    let header = f.u16("Header length").emit()?;
    let version = f.u8("Version").hex().emit()?;
    cx.emit(Node::new("Patterns and samples").span(file.tail(header.into())));
    cx.annotate(format!("Farandole {}.{} module {:?}", version >> 4, version & 0xf, title.trim()));
    Ok(())
}

// ---------------------------------------------------------------------------
// Fonts: PSF console fonts, BMFont binary, FIGlet, TeX PK and GF

fn psf_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"\x72\xb5\x4a\x86") || h.starts_with(b"\x36\x04") && h.data.get(2).is_some_and(|&m| m < 8)
}

const PSF1_MODE: FlagTable = &[flag(1, "512 glyphs"), flag(2, "Unicode table"), flag(4, "Unicode sequences")];
const PSF2_FLAGS: FlagTable = &[flag(1, "Unicode table")];

declare_format!(pub PSF_FONT = "psf-font", "PC Screen Font (console font)", ["psf", "psfu"], "application/x-font-psf",
    Probe::Custom(psf_probe), psf_font);

async fn psf_font(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    if cx.read(file.sub(0, 2)).await? == b"\x36\x04" {
        let head = cx.block(file.sub(0, 4)).await?;
        let mut f = Fields::emitting(&cx, &head, LE);
        f.u16("Magic").hex().emit()?;
        let mode = f.u8("Mode").flags(PSF1_MODE).emit()?;
        let height = f.u8("Glyph height").emit()?;
        let glyphs: u64 = if mode & 1 != 0 { 512 } else { 256 };
        let bitmaps = file.sub(4, glyphs.saturating_mul(height.into()));
        cx.emit(Node::new("Glyphs").span(bitmaps).summary(format!("{glyphs} × 8×{height}")));
        if mode & 2 != 0 {
            cx.emit(Node::new("Unicode table").span(file.tail(bitmaps.end().saturating_sub(file.offset))));
        }
        cx.annotate(format!("PSF1 font, {glyphs} glyphs, 8×{height}"));
    } else {
        let head = cx.block(file.sub(0, 32)).await?;
        let mut f = Fields::emitting(&cx, &head, LE);
        f.u32("Magic").hex().emit()?;
        f.u32("Version").emit()?;
        let header = f.u32("Header size").emit()?;
        let flags = f.u32("Flags").flags(PSF2_FLAGS).emit()?;
        let glyphs = f.u32("Glyphs").emit()?;
        let size = f.u32("Bytes per glyph").emit()?;
        let height = f.u32("Height").emit()?;
        let width = f.u32("Width").emit()?;
        let bitmaps = file.sub(header.into(), u64::from(glyphs).saturating_mul(size.into()));
        cx.emit(Node::new("Glyphs").span(bitmaps).summary(format!("{glyphs} × {width}×{height}")));
        if flags & 1 != 0 {
            cx.emit(Node::new("Unicode table").span(file.tail(bitmaps.end().saturating_sub(file.offset))));
        }
        cx.annotate(format!("PSF2 font, {glyphs} glyphs, {width}×{height}"));
    }
    Ok(())
}

declare_format!(pub BMFONT = "bmfont", "AngelCode bitmap font (binary)", ["fnt"], "application/x-bmfont",
    Probe::Magic(&[(0, b"BMF\x03")]), bmfont);

async fn bmfont(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("Signature").span(file.sub(0, 4)));
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(4);
    let mut name = String::new();
    let mut chars = 0u64;
    while cur.remaining() >= 5 {
        let start = cur.pos();
        let kind = cur.u8().await?;
        let size = u64::from(cur.u32().await?);
        let body = file.sub(cur.pos(), size);
        let (label, summary) = match kind {
            1 => {
                let b = cx.read_avail(body.sub(0, 256)).await?;
                name = zstr(b.get(14..).unwrap_or_default());
                ("Info", format!("{name:?}, {} px", i16::from_le_bytes([b.first().copied().unwrap_or(0), b.get(1).copied().unwrap_or(0)])))
            }
            2 => {
                let b = cx.read_avail(body.sub(0, 15)).await?;
                ("Common", format!("line height {}, {} page(s)", u16_le(&b, 0).unwrap_or(0), u16_le(&b, 8).unwrap_or(0)))
            }
            3 => ("Pages", String::from_utf8_lossy(&cx.read_avail(body.sub(0, 256)).await?).replace('\0', ", ").trim_end_matches(", ").to_owned()),
            4 => {
                chars = size / 20;
                ("Characters", format!("{chars} × 20 bytes"))
            }
            5 => ("Kerning pairs", format!("{} × 10 bytes", size / 10)),
            _ => ("Unknown block", format!("type {kind}")),
        };
        cx.push(Node::new(label).span(file.sub(start, size.saturating_add(5))).summary(summary)).await;
        cur.skip(size);
    }
    cx.annotate(format!("BMFont {name:?}, {chars} characters"));
    Ok(())
}

declare_format!(pub FIGLET = "figlet", "FIGlet font", ["flf"], "application/x-figlet",
    Probe::Magic(&[(0, b"flf2a")]), figlet);

async fn figlet(cx: Cx, input: Input) -> Result<()> {
    let all = header_lines(&cx, input.span, 1 << 16).await?;
    let Some((first, span)) = all.first() else { return Ok(()) };
    let params: Vec<&str> = first.get(6..).unwrap_or_default().split_whitespace().collect();
    let names = ["Height", "Baseline", "Maximum length", "Old layout", "Comment lines", "Print direction", "Full layout", "Code-tagged characters"];
    cx.emit(Node::new("Signature").span(span.sub(0, 5)));
    cx.emit(Node::new("Hard blank").span(span.sub(5, 1)).value(text(first.get(5..6).unwrap_or_default())));
    for (label, value) in names.iter().zip(&params) {
        cx.emit(Node::new(*label).span(*span).value(text(*value)));
    }
    let comments: usize = params.get(4).and_then(|c| c.parse().ok()).unwrap_or(0);
    if let (Some((_, a)), Some((_, b))) = (all.get(1), all.get(comments.min(all.len().saturating_sub(1))))
        && comments > 0
    {
        cx.emit(Node::new("Comments").span(Span::new(a.source, a.offset, b.end().saturating_sub(a.offset))));
    }
    cx.annotate(format!("FIGlet font, height {}", params.first().unwrap_or(&"?")));
    Ok(())
}

declare_format!(pub TEX_PK = "tex-pk", "TeX packed font (PK)", ["pk"], "application/x-tex-pk",
    Probe::Magic(&[(0, b"\xf7\x59")]), tex_pk);

declare_format!(pub TEX_GF = "tex-gf", "TeX generic font (GF)", ["gf"], "application/x-tex-gf",
    Probe::Magic(&[(0, b"\xf7\x83")]), tex_gf);

async fn tex_pk(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let k = u64::from(cx.read(file.sub(2, 1)).await?.first().copied().unwrap_or(0));
    let comment = String::from_utf8_lossy(&cx.read(file.sub(3, k)).await?).into_owned();
    cx.emit(Node::new("Preamble").span(file.sub(0, k.saturating_add(19))));
    cx.emit(Node::new("Comment").span(file.sub(3, k)).value(text(comment.clone())));
    let rest = cx.read(file.sub(3u64.saturating_add(k), 16)).await?;
    let design = u32_be(&rest, 0).unwrap_or(0);
    cx.emit(Node::new("Design size").span(file.sub(3u64.saturating_add(k), 4)).value(Value::Float(f64::from(design) / 1_048_576.0)).summary("pt"));
    cx.emit(Node::new("Checksum").span(file.sub(7u64.saturating_add(k), 4)).value(Value::UInt { value: u32_be(&rest, 4).unwrap_or(0).into(), bits: 32, radix: Radix::Hex }));
    cx.emit(Node::new("Character packets").span(file.tail(k.saturating_add(19))));
    cx.annotate(format!("PK font {:?}, design size {:.1} pt", comment.trim(), f64::from(design) / 1_048_576.0));
    Ok(())
}

async fn tex_gf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let k = u64::from(cx.read(file.sub(2, 1)).await?.first().copied().unwrap_or(0));
    let comment = String::from_utf8_lossy(&cx.read(file.sub(3, k)).await?).into_owned();
    cx.emit(Node::new("Comment").span(file.sub(3, k)).value(text(comment.clone())));
    cx.emit(Node::new("Characters").span(file.tail(k.saturating_add(3))));
    cx.annotate(format!("GF font {:?}", comment.trim()));
    Ok(())
}

// ---------------------------------------------------------------------------
// Keys: Java keystores, PuTTY private keys

fn jks_probe(h: &Head<'_>) -> bool {
    (h.starts_with(b"\xfe\xed\xfe\xed") || h.starts_with(b"\xce\xce\xce\xce")) && u32_be(h.data, 4).is_some_and(|v| v == 1 || v == 2)
}

declare_format!(pub JKS = "java-keystore", "Java keystore (JKS/JCEKS)", ["jks", "keystore", "jceks", "ks"], "application/x-java-keystore",
    Probe::Custom(jks_probe), jks);

async fn jks(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 12)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    let magic = f.u32("Magic").hex().emit()?;
    let version = f.u32("Version").emit()?;
    let count = f.u32("Entries").emit()?;
    let mut cur = Cursor::new(&cx, file, BE);
    cur.seek(12);
    for i in 0..count {
        let start = cur.pos();
        let tag = cur.u32().await?;
        let alias_len = u64::from(cur.u16().await?);
        let alias = String::from_utf8_lossy(&cur.bytes(alias_len).await?).into_owned();
        cur.skip(8);
        let kind = match tag {
            1 => {
                let key_len = u64::from(cur.u32().await?);
                cur.skip(key_len);
                let chain = cur.u32().await?;
                for _ in 0..chain {
                    jks_skip_cert(&mut cur).await?;
                }
                "private key"
            }
            2 => {
                jks_skip_cert(&mut cur).await?;
                "trusted certificate"
            }
            3 => {
                // A Java-serialized SealedObject: its length is not recorded.
                cx.push(
                    Node::new(alias)
                        .span(file.tail(start))
                        .summary("secret key")
                        .diag(Diagnostic::unsupported("Java-serialized SealedObject; later entries are not listed")),
                )
                .await;
                cx.annotate(format!("JCEKS keystore v{version}, {count} entries"));
                return Ok(());
            }
            _ => return Err(Diagnostic::malformed(format!("unknown entry tag {tag}")).at(cur.since(start))),
        };
        let span = cur.since(start);
        cx.push(
            Node::new(alias)
                .span(span)
                .summary(format!("entry {i}: {kind}"))
                .lazy(jks_entry, (input, span)),
        )
        .await;
    }
    if cur.remaining() >= 20 {
        cx.emit(Node::new("Integrity digest (SHA-1)").span(file.sub(cur.pos(), 20)));
    }
    cx.annotate(format!("{} v{version}, {count} entries", if magic == 0xfeed_feed { "JKS keystore" } else { "JCEKS keystore" }));
    Ok(())
}

async fn jks_skip_cert(cur: &mut Cursor<'_>) -> Result<()> {
    let type_len = u64::from(cur.u16().await?);
    cur.skip(type_len);
    let len = u64::from(cur.u32().await?);
    if len > cur.remaining() {
        return Err(Diagnostic::malformed("certificate runs past the end of the file").at(cur.span(0)));
    }
    cur.skip(len);
    Ok(())
}

async fn jks_entry(cx: Cx, (input, entry): (Input, Span)) -> Result<()> {
    let mut cur = Cursor::new(&cx, entry, BE);
    let tag = cur.u32().await?;
    cx.emit(Node::new("Tag").span(cur.since(0)).value(Value::Enum { raw: tag.into(), bits: 32, name: match tag { 1 => Some("private key"), 2 => Some("trusted certificate"), 3 => Some("secret key"), _ => None } }));
    let alias_len = u64::from(cur.u16().await?);
    let alias_span = cur.span(alias_len);
    let alias = String::from_utf8_lossy(&cur.bytes(alias_len).await?).into_owned();
    cx.emit(Node::new("Alias").span(alias_span).value(text(alias)));
    let at = cur.pos();
    let millis = cur.u64().await?;
    cx.emit(Node::new("Created").span(cur.since(at)).value(Value::Timestamp { unix_seconds: i64::try_from(millis / 1000).unwrap_or(0) }));
    let mut certs = 1u32;
    if tag == 1 {
        let key_len = u64::from(cur.u32().await?);
        cx.emit(Node::new("Protected private key").span(cur.span(key_len)).summary(format!("{key_len} bytes")));
        cur.skip(key_len);
        certs = cur.u32().await?;
    }
    for c in 0..certs {
        let start = cur.pos();
        let type_len = u64::from(cur.u16().await?);
        let kind = String::from_utf8_lossy(&cur.bytes(type_len).await?).into_owned();
        let len = u64::from(cur.u32().await?);
        let data = cur.span(len);
        cur.skip(len);
        let name = if tag == 1 { format!("Certificate {c}") } else { "Certificate".to_owned() };
        let node = if kind == "X.509" {
            embedded_as(name, input.nested(data), &crate::formats::asn1::X509)
        } else {
            embedded(name, input.nested(data))
        };
        cx.push(node.summary(kind).target(cur.since(start))).await;
    }
    Ok(())
}

declare_format!(pub PPK = "putty-key", "PuTTY private key (PPK)", ["ppk"], "application/x-putty-private-key",
    Probe::Magic(&[(0, b"PuTTY-User-Key-File-")]), ppk);

async fn ppk(cx: Cx, input: Input) -> Result<()> {
    let all = header_lines(&cx, input.span, 1 << 16).await?;
    let mut version = String::new();
    let mut algorithm = String::new();
    let mut encryption = String::new();
    let mut comment = String::new();
    let mut i = 0usize;
    while let Some((line, span)) = all.get(i) {
        i = i.saturating_add(1);
        let Some((key, value)) = line.split_once(": ") else { continue };
        if let Some(n) = key.strip_suffix("-Lines").map(str::to_owned) {
            let count: usize = value.trim().parse().unwrap_or(0);
            let (Some((_, first)), Some((_, last))) = (all.get(i), all.get(i.saturating_add(count).saturating_sub(1).min(all.len().saturating_sub(1)))) else {
                continue;
            };
            let body = Span::new(first.source, first.offset, last.end().saturating_sub(first.offset));
            i = i.saturating_add(count);
            if n == "Public" {
                cx.emit(decoded_node("Public key", input, body, Transform::Base64));
            } else {
                cx.emit(Node::new(format!("{n} key")).span(body).summary(if encryption == "none" { "base64" } else { "encrypted, base64" }));
            }
            continue;
        }
        if let Some(v) = key.strip_prefix("PuTTY-User-Key-File-") {
            version = v.to_owned();
            algorithm = value.to_owned();
        }
        match key {
            "Encryption" => encryption = value.to_owned(),
            "Comment" => comment = value.to_owned(),
            _ => {}
        }
        cx.emit(Node::new(key.to_owned()).span(*span).value(text(value)));
    }
    cx.annotate(format!("PuTTY v{version} {algorithm} key {comment:?}, encryption {encryption}"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Audio: NIST SPHERE, Audio Visual Research, Portable Voice Format

declare_format!(pub SPHERE = "nist-sphere", "NIST SPHERE audio", ["sph", "nist", "wv1", "wv2"], "audio/x-nist-sphere",
    Probe::Magic(&[(0, b"NIST_1A\n")]), sphere);

async fn sphere(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let size: u64 = String::from_utf8_lossy(&cx.read(file.sub(8, 8)).await?).trim().parse().unwrap_or(1024);
    let header = file.sub(0, size);
    let all = header_lines(&cx, header, size).await?;
    let mut fields = Vec::new();
    for (line, span) in all.iter().skip(2) {
        if line.trim() == "end_head" {
            break;
        }
        let mut parts = line.splitn(3, ' ');
        if let (Some(k), Some(_), Some(v)) = (parts.next(), parts.next(), parts.next()) {
            fields.push((k.to_owned(), v.to_owned()));
            cx.emit(Node::new(k.to_owned()).span(*span).value(text(v)));
        }
    }
    cx.emit(Node::new("Samples").span(file.tail(size)));
    let get = |k: &str| fields.iter().find(|(a, _)| a == k).map_or("?", |(_, v)| v.as_str());
    cx.annotate(format!("NIST SPHERE, {} Hz, {} channel(s), {}", get("sample_rate"), get("channel_count"), get("sample_coding")));
    Ok(())
}

declare_format!(pub AVR = "avr", "Audio Visual Research sample", ["avr"], "audio/x-avr",
    Probe::Magic(&[(0, b"2BIT")]), avr);

record! {
    pub struct AvrHeader {
        magic: ascii[4] "Signature",
        name: ascii[8] "Name",
        mono: u16 "Channels (0 mono, 0xffff stereo)" .hex(),
        resolution: u16 "Bits per sample",
        signed: u16 "Signed (0xffff)" .hex(),
        looped: u16 "Looping (0xffff)" .hex(),
        midi: u16 "MIDI note" .hex(),
        rate: u32 "Sample rate (low 24 bits)" .hex(),
        length: u32 "Length (samples)",
        loop_begin: u32 "Loop begin",
        loop_end: u32 "Loop end",
    }
}

async fn avr(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: AvrHeader = emit_record(&cx, file.sub(0, AvrHeader::SIZE), BE).await?;
    cx.emit(Node::new("Samples").span(file.tail(128)));
    cx.annotate(format!("AVR {:?}, {} Hz, {}-bit {}", h.name.trim(), h.rate & 0xff_ffff, h.resolution, if h.mono == 0 { "mono" } else { "stereo" }));
    Ok(())
}

declare_format!(pub PVF = "pvf", "Portable Voice Format", ["pvf"], "audio/x-pvf",
    Probe::Magic(&[(0, b"PVF1\n"), (0, b"PVF2\n")]), pvf);

async fn pvf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let all = header_lines(&cx, file, 64).await?;
    let (Some((magic, m)), Some((params, p))) = (all.first(), all.get(1)) else { return Ok(()) };
    cx.emit(Node::new("Signature").span(*m).value(text(magic.clone())));
    let v: Vec<&str> = params.split_whitespace().collect();
    for (label, value) in ["Channels", "Sample rate", "Bits per sample"].iter().zip(&v) {
        cx.emit(Node::new(*label).span(*p).value(text(*value)));
    }
    cx.emit(Node::new("Samples").span(file.tail(p.end().saturating_sub(file.offset).saturating_add(1))));
    cx.annotate(format!("{magic} voice, {} channel(s), {} Hz, {}-bit", v.first().unwrap_or(&"?"), v.get(1).unwrap_or(&"?"), v.get(2).unwrap_or(&"?")));
    Ok(())
}

// ---------------------------------------------------------------------------
// Imagery: VICAR, PDS, ERDAS Imagine, ImageMagick MIFF, Utah RLE,
// Paint Shop Pro

/// `KEY=VALUE` pairs separated by whitespace (quoted values may contain
/// spaces), with spans relative to `base`.
fn label_pairs(data: &[u8], base: Span) -> Vec<(String, String, Span)> {
    let mut out = Vec::new();
    let mut i = 0usize;
    let n = data.len();
    while i < n {
        while i < n && data.get(i).is_some_and(|b| b.is_ascii_whitespace()) {
            i = i.saturating_add(1);
        }
        let start = i;
        while i < n && data.get(i).is_some_and(|&b| b != b'=' && !b.is_ascii_whitespace()) {
            i = i.saturating_add(1);
        }
        if data.get(i) != Some(&b'=') {
            break;
        }
        let key = String::from_utf8_lossy(data.get(start..i).unwrap_or_default()).into_owned();
        i = i.saturating_add(1);
        let vstart = i;
        if data.get(i) == Some(&b'\'') {
            i = i.saturating_add(1);
            while i < n && data.get(i) != Some(&b'\'') {
                i = i.saturating_add(1);
            }
            i = i.saturating_add(1).min(n);
        } else {
            while i < n && data.get(i).is_some_and(|b| !b.is_ascii_whitespace()) {
                i = i.saturating_add(1);
            }
        }
        let value = String::from_utf8_lossy(data.get(vstart..i).unwrap_or_default()).trim_matches('\'').to_owned();
        out.push((key, value, base.sub(to_u64(start), to_u64(i.saturating_sub(start)))));
    }
    out
}

declare_format!(pub VICAR = "vicar", "VICAR image", ["vic", "img", "vicar"], "image/x-vicar",
    Probe::Magic(&[(0, b"LBLSIZE=")]), vicar);

async fn vicar(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 32)).await?;
    let lblsize: u64 = String::from_utf8_lossy(head.get(8..).unwrap_or_default())
        .split_whitespace()
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let label = file.sub(0, lblsize.min(1 << 16));
    let data = cx.read(label).await?;
    let data = data.split(|&b| b == 0).next().unwrap_or_default();
    let pairs = label_pairs(data, label);
    for (k, v, span) in pairs.iter().take(256) {
        cx.emit(Node::new(k.clone()).span(*span).value(text(v.clone())));
    }
    cx.emit(Node::new("Image data").span(file.tail(lblsize)));
    let get = |k: &str| pairs.iter().find(|(a, _, _)| a == k).map_or("?", |(_, v, _)| v.as_str());
    cx.annotate(format!("VICAR {} image, {}×{}×{}", get("FORMAT"), get("NS"), get("NL"), get("NB")));
    Ok(())
}

declare_format!(pub PDS = "pds", "Planetary Data System label", ["lbl", "img", "pds"], "application/x-pds",
    Probe::Magic(&[(0, b"PDS_VERSION_ID"), (0, b"PDS3"), (0, b"ODL_VERSION_ID")]), pds);

async fn pds(cx: Cx, input: Input) -> Result<()> {
    let all = header_lines(&cx, input.span, 1 << 16).await?;
    let mut objects = Vec::new();
    let mut depth = 0usize;
    let mut label_end = 0u64;
    let mut record_bytes = 0u64;
    let mut image_rec = 0u64;
    for (line, span) in &all {
        let t = line.trim();
        if t == "END" {
            label_end = span.end().saturating_sub(input.span.offset);
            break;
        }
        let Some((k, v)) = t.split_once('=') else { continue };
        let (k, v) = (k.trim(), v.trim());
        match k {
            "OBJECT" => {
                depth = depth.saturating_add(1);
                objects.push(v.to_owned());
            }
            "END_OBJECT" => depth = depth.saturating_sub(1),
            "RECORD_BYTES" => record_bytes = v.parse().unwrap_or(0),
            "^IMAGE" => image_rec = v.split_whitespace().next().and_then(|s| s.parse().ok()).unwrap_or(0),
            _ => {}
        }
        if depth <= 1 {
            cx.emit(Node::new(format!("{}{k}", "  ".repeat(depth))).span(*span).value(text(v)));
        }
    }
    if image_rec > 0 && record_bytes > 0 {
        let at = image_rec.saturating_sub(1).saturating_mul(record_bytes);
        cx.emit(Node::new("Image").span(input.span.tail(at)));
    } else if label_end > 0 {
        cx.emit(Node::new("Data").span(input.span.tail(label_end)));
    }
    cx.annotate(format!("PDS label, objects: {}", objects.join(", ")));
    Ok(())
}

declare_format!(pub ERDAS = "erdas-img", "ERDAS IMAGINE image (HFA)", ["img"], "image/x-erdas-hfa",
    Probe::Magic(&[(0, b"EHFA_HEADER_TAG")]), erdas);

async fn erdas(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 20)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 16).emit()?;
    let ptr = f.u32("Header pointer").hex().emit()?;
    let h = cx.block(file.sub(ptr.into(), 18)).await?;
    let mut g = Fields::emitting(&cx, &h, LE);
    let version = g.u32("Version").emit()?;
    g.u32("Free list").hex().emit()?;
    let root = g.u32("Root entry").hex().emit()?;
    g.u16("Entry header length").emit()?;
    let dict = g.u32("Dictionary pointer").hex().emit()?;
    let (dictionary, span) = cx.cstr(file.sub(dict.into(), 1 << 16)).await?;
    cx.emit(Node::new("Data dictionary").span(span).summary(format!("{} type definitions", dictionary.matches('{').count())));
    // The root entry: next, prev, parent, child, data, data size, name[64], type[32], modtime.
    let e = cx.read_avail(file.sub(root.into(), 128)).await?;
    let name = zstr(e.get(24..88).unwrap_or_default());
    let kind = zstr(e.get(88..120).unwrap_or_default());
    cx.emit(Node::new("Root entry").span(file.sub(root.into(), 124)).summary(format!("{name:?} ({kind})")));
    cx.annotate(format!("ERDAS IMAGINE (HFA) v{version}"));
    Ok(())
}

declare_format!(pub MIFF = "miff", "ImageMagick image (MIFF)", ["miff", "mif"], "image/x-miff",
    Probe::Magic(&[(0, b"id=ImageMagick")]), miff);

async fn miff(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 1 << 16)).await?;
    let end = head.windows(2).position(|w| w == b":\x1a").unwrap_or(head.len());
    let header = head.get(..end).unwrap_or_default();
    // Strip {comments}.
    let pairs = label_pairs(header, file);
    for (k, v, span) in pairs.iter().take(256) {
        cx.emit(Node::new(k.clone()).span(*span).value(text(v.clone())));
    }
    cx.emit(Node::new("Pixels").span(file.tail(to_u64(end).saturating_add(2))));
    let get = |k: &str| pairs.iter().find(|(a, _, _)| a == k).map_or("?", |(_, v, _)| v.as_str());
    cx.annotate(format!("MIFF {} image, {}, {}", get("class"), get("columns").to_owned() + "×" + get("rows"), get("colorspace")));
    Ok(())
}

const RLE_FLAGS: FlagTable = &[flag(1, "clear first"), flag(2, "no background"), flag(4, "alpha"), flag(8, "comments")];

declare_format!(pub UTAH_RLE = "utah-rle", "Utah Raster Toolkit RLE", ["rle"], "image/x-utah-rle",
    Probe::Magic(&[(0, b"\x52\xcc")]), utah_rle);

async fn utah_rle(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 15)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.u16("Magic").hex().emit()?;
    f.u16("X position").emit()?;
    f.u16("Y position").emit()?;
    let w = f.u16("Width").emit()?;
    let h = f.u16("Height").emit()?;
    f.u8("Flags").flags(RLE_FLAGS).emit()?;
    let channels = f.u8("Colour channels").emit()?;
    let bits = f.u8("Bits per pixel").emit()?;
    f.u8("Colour map channels").emit()?;
    f.u8("Colour map length (log2)").emit()?;
    cx.emit(Node::new("Scanline data").span(file.tail(15)));
    cx.annotate(format!("Utah RLE, {w}×{h}, {channels} channel(s) × {bits} bits"));
    Ok(())
}

declare_format!(pub PSP = "psp-image", "Paint Shop Pro image", ["pspimage", "psp", "tub", "pspframe"], "image/x-psp",
    Probe::Magic(&[(0, b"Paint Shop Pro Image File\n\x1a")]), psp);

const PSP_BLOCKS: &[(u64, &str)] = &[
    (0, "Image attributes"),
    (1, "Creator"),
    (2, "Colour palette"),
    (3, "Layer bank"),
    (4, "Channel"),
    (5, "Selection"),
    (6, "Alpha bank"),
    (7, "Alpha channel"),
    (8, "Composite image"),
    (9, "Extended data"),
    (10, "Picture tube"),
    (11, "Adjustment layer"),
    (12, "Vector layer"),
    (13, "Shape"),
    (14, "Paint style"),
    (15, "Composite image bank"),
    (16, "Composite attributes"),
    (17, "JPEG"),
    (18, "Line style"),
    (19, "Table bank"),
    (20, "Table"),
    (21, "Paper"),
    (22, "Pattern"),
    (23, "Gradient"),
    (26, "Group extension"),
    (27, "Mask extension"),
    (28, "Brush"),
    (29, "Art media"),
];

async fn psp(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 36)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.bytes("Signature", 32).emit()?;
    let major = f.u16("Major version").emit()?;
    let minor = f.u16("Minor version").emit()?;
    // Blocks: "~BK\0", id, (initial length before v4), total length.
    let block_head: u64 = if major < 4 { 14 } else { 10 };
    let mut pos = 36u64;
    let mut n = 0u32;
    while pos.saturating_add(block_head) <= file.len {
        let h = cx.read(file.sub(pos, block_head)).await?;
        if h.get(..4) != Some(b"~BK\0") {
            return Err(Diagnostic::malformed("missing ~BK block marker").at(file.sub(pos, 4)));
        }
        let id = u64::from(u16_le(&h, 4).unwrap_or(0));
        let len = u64::from(u32_le(&h, if major < 4 { 10 } else { 6 }).unwrap_or(0));
        let name = PSP_BLOCKS.iter().find(|(k, _)| *k == id).map_or("Unknown block", |(_, v)| v);
        let mut node = Node::new(name).span(file.sub(pos, len.saturating_add(block_head))).summary(format!("{len} bytes"));
        if id == 0 {
            let a = cx.read_avail(file.sub(pos.saturating_add(block_head), 16)).await?;
            let (w, hgt) = if major < 4 { (u32_le(&a, 0), u32_le(&a, 4)) } else { (u32_le(&a, 4), u32_le(&a, 8)) };
            node = node.summary(format!("{}×{}", w.unwrap_or(0), hgt.unwrap_or(0)));
        }
        cx.push(node).await;
        n = n.saturating_add(1);
        pos = pos.saturating_add(block_head).saturating_add(len);
    }
    cx.annotate(format!("Paint Shop Pro image v{major}.{minor}, {n} blocks"));
    Ok(())
}
