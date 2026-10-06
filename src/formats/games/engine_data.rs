//! Game-engine data files: Havok packfiles and Bethesda materials, World of
//! Warcraft chunked files and client databases (and Warcraft III MDX),
//! Unreal Engine IoStore tables of contents, KiriKiri XP3 archives, Allegro
//! datafiles and compiled Ren'Py scripts.

use crate::bytes::{to_u64, u16_le, u32_be, u32_le, u64_le};
use crate::codec::inflate_span;
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{ChunkLayout, Cursor};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::{Codec, Head, Input, Probe, content, embedded};
use crate::node::Node;
use crate::value::{Radix, Value};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

fn text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

fn uint(value: u64, bits: u8) -> Value {
    Value::UInt {
        value,
        bits,
        radix: Radix::Dec,
    }
}

fn zstr(b: &[u8]) -> String {
    crate::text::until_nul(b)
}

// ---------------------------------------------------------------------------
// Havok packfiles, Bethesda materials

declare_format!(pub HKX = "havok-packfile", "Havok packfile (HKX)", ["hkx"], "application/x-havok",
    Probe::Magic(&[(0, b"\x57\xe0\xe0\x57\x10\xc0\xc0\x10")]), hkx);

async fn hkx(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 64)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.u32("Magic 0").hex().emit()?;
    f.u32("Magic 1").hex().emit()?;
    f.u32("User tag").hex().emit()?;
    let version = f.u32("File version").emit()?;
    let rules = f
        .bytes(
            "Layout rules (pointer size, little-endian, reuse padding, empty base)",
            4,
        )
        .emit()?;
    let sections = f.u32("Sections").emit()?;
    f.u32("Contents section").emit()?;
    f.u32("Contents offset").hex().emit()?;
    f.u32("Class name section").emit()?;
    f.u32("Class name offset").hex().emit()?;
    let sdk = f.ascii("Contents version", 16).emit()?;
    f.u32("Flags").hex().emit()?;
    f.u32("Padding").emit()?;
    let mut pos = 64u64;
    if version >= 11 {
        let pad = cx.read(file.sub(64, 4)).await?;
        let extra = u64::from(u16_le(&pad, 2).unwrap_or(0));
        cx.emit(Node::new("Predicate padding").span(file.sub(64, extra.saturating_add(4))));
        pos = pos.saturating_add(4).saturating_add(extra);
    }
    let section_len: u64 = if version >= 11 { 64 } else { 48 };
    for _ in 0..sections.min(16) {
        let s = cx.read(file.sub_exact(pos, section_len)?).await?;
        let name = zstr(s.get(..20).unwrap_or_default());
        let start = u64::from(u32_le(&s, 20).unwrap_or(0));
        let end = u64::from(u32_le(&s, 44).unwrap_or(0));
        cx.push(
            Node::new(format!("Section {name}"))
                .span(file.sub(pos, section_len))
                .summary(format!("data at {start:#x}, {end} bytes"))
                .target(file.sub(start, end)),
        )
        .await;
        pos = pos.saturating_add(section_len);
    }
    let pointer = rules.first().copied().unwrap_or(0);
    cx.annotate(format!(
        "Havok packfile v{version} ({}), {pointer}-byte pointers, {sections} sections",
        sdk.trim()
    ));
    Ok(())
}

declare_format!(pub BGSM = "bethesda-material", "Bethesda material (BGSM/BGEM)", ["bgsm", "bgem"], "application/x-bethesda-material",
    Probe::Magic(&[(0, b"BGSM"), (0, b"BGEM")]), bgsm);

async fn bgsm(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 8)).await?;
    let effect = head.starts_with(b"BGEM");
    let version = u32_le(&head, 4).unwrap_or(0);
    cx.emit(Node::new("Signature").span(file.sub(0, 4)));
    cx.emit(
        Node::new("Version")
            .span(file.sub(4, 4))
            .value(uint(version.into(), 32)),
    );
    // Texture paths: length-prefixed strings ending in ".dds".
    let body = cx.read_avail(file.sub(0, 1 << 14)).await?;
    let mut textures = 0u32;
    let mut i = 8usize;
    while i.saturating_add(4) < body.len() {
        let len = usize::try_from(u32_le(&body, i).unwrap_or(0)).unwrap_or(0);
        let s = body.get(i.saturating_add(4)..i.saturating_add(4).saturating_add(len));
        if let Some(s) = s.filter(|s| len > 4 && s.last() == Some(&0)) {
            let t = zstr(s);
            let lower = t.to_ascii_lowercase();
            if t.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
                && (lower.ends_with(".dds") || lower.ends_with(".bgsm"))
            {
                textures = textures.saturating_add(1);
                cx.push(
                    Node::new("Texture")
                        .span(file.sub(to_u64(i), to_u64(len).saturating_add(4)))
                        .value(text(t)),
                )
                .await;
                i = i.saturating_add(4).saturating_add(len);
                continue;
            }
        }
        i = i.saturating_add(1);
    }
    cx.annotate(format!(
        "Bethesda {} material v{version}, {textures} textures",
        if effect { "effect" } else { "shader" }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// World of Warcraft: chunked files (reversed IDs), client databases

fn wow_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"REVM\x04\0\0\0")
}

declare_format!(pub WOW_CHUNKED = "wow-chunked", "World of Warcraft chunked file (WMO/ADT/WDT/WDL)", ["wmo", "adt", "wdt", "wdl"], "application/x-wow-chunked",
    Probe::Custom(wow_probe), wow_chunked);

async fn wow_chunked(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, LE);
    let mut kinds = Vec::new();
    let mut n = 0u32;
    while let Some(chunk) = cur.chunk(ChunkLayout::new(4, 4, LE)).await? {
        let id: String = chunk.id.iter().rev().map(|&b| char::from(b)).collect();
        if n == 1 {
            kinds.push(match id.as_str() {
                "MOHD" => "WMO root",
                "MOGP" => "WMO group",
                "MHDR" => "ADT terrain tile",
                "MPHD" => "WDT world table",
                "MAOF" => "WDL low-resolution world",
                _ => "chunked file",
            });
        }
        cx.push(
            Node::new(id)
                .span(chunk.span)
                .summary(format!("{} bytes", chunk.body.len)),
        )
        .await;
        n = n.saturating_add(1);
    }
    cx.annotate(format!(
        "World of Warcraft {}, {n} chunks",
        kinds.first().copied().unwrap_or("chunked file")
    ));
    Ok(())
}

declare_format!(pub WOW_DB = "wow-db", "World of Warcraft client database (DBC/DB2)", ["dbc", "db2"], "application/x-wow-db",
    Probe::Magic(&[(0, b"WDBC"), (0, b"WDB2"), (0, b"WDB3"), (0, b"WDB4"), (0, b"WDB5"), (0, b"WDB6"), (0, b"WDC1"), (0, b"WDC2"), (0, b"WDC3"), (0, b"WDC4"), (0, b"WDC5")]), wow_db);

async fn wow_db(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 20)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    let magic = f.ascii("Signature", 4).emit()?;
    let records = f.u32("Records").emit()?;
    let fields = f.u32("Fields").emit()?;
    let size = f.u32("Record size").emit()?;
    let strings = f.u32("String block size").emit()?;
    if magic == "WDBC" {
        let data = u64::from(records).saturating_mul(size.into());
        cx.emit(
            Node::new("Records")
                .span(file.sub(20, data))
                .summary(format!("{records} × {size} bytes")),
        );
        let block = file.sub(20u64.saturating_add(data), strings.into());
        let sample = cx.read_avail(block.sub(0, 256)).await?;
        let first: Vec<String> = sample
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .take(6)
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect();
        cx.emit(
            Node::new("String block")
                .span(block)
                .summary(first.join(", ")),
        );
    } else {
        let more = cx.read_avail(file.sub(20, 8)).await?;
        cx.emit(
            Node::new("Table hash")
                .span(file.sub(20, 4))
                .value(Value::UInt {
                    value: u32_le(&more, 0).unwrap_or(0).into(),
                    bits: 32,
                    radix: Radix::Hex,
                }),
        );
        cx.emit(Node::new("Remaining header and sections").span(file.tail(24)));
    }
    cx.annotate(format!(
        "WoW {magic} database: {records} records × {fields} fields"
    ));
    Ok(())
}

declare_format!(pub WC3_MDX = "wc3-mdx", "Warcraft III model (MDX)", ["mdx"], "model/x-wc3-mdx",
    Probe::Magic(&[(0, b"MDLX")]), wc3_mdx);

async fn wc3_mdx(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("Signature").span(file.sub(0, 4)));
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(4);
    let mut name = String::new();
    let mut version = 0u32;
    while let Some(chunk) = cur.chunk(ChunkLayout::new(4, 4, LE)).await? {
        let mut node = chunk.node();
        match chunk.id.as_slice() {
            b"VERS" => {
                version = u32_le(&cx.read(chunk.body.sub(0, 4)).await?, 0).unwrap_or(0);
                node = node.value(uint(version.into(), 32));
            }
            b"MODL" => {
                name = zstr(&cx.read(chunk.body.sub(0, 80)).await?);
                node = node.value(text(name.clone()));
            }
            _ => {}
        }
        cx.push(node).await;
    }
    cx.annotate(format!("Warcraft III model {name:?}, version {version}"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Unreal Engine IoStore table of contents

declare_format!(pub UTOC = "unreal-utoc", "Unreal Engine IoStore TOC (utoc)", ["utoc"], "application/x-unreal-utoc",
    Probe::Magic(&[(0, b"-==--==--==--==-")]), utoc);

async fn utoc(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 64)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 16).emit()?;
    let version = f.u8("Version").emit()?;
    f.bytes("Reserved", 3).emit()?;
    f.u32("Header size").emit()?;
    let entries = f.u32("Entries").emit()?;
    let blocks = f.u32("Compressed blocks").emit()?;
    f.u32("Compressed block entry size").emit()?;
    let methods = f.u32("Compression methods").emit()?;
    f.u32("Compression method name length").emit()?;
    let block = f.u32("Compression block size").emit()?;
    f.u32("Directory index size").emit()?;
    f.u32("Partitions").emit()?;
    f.u64("Container ID").hex().emit()?;
    cx.emit(Node::new("Tables").span(file.tail(64)));
    cx.annotate(format!("Unreal IoStore TOC v{version}: {entries} chunks, {blocks} compressed blocks of {block} bytes, {methods} methods"));
    Ok(())
}

// ---------------------------------------------------------------------------
// KiriKiri XP3

declare_format!(pub XP3 = "kirikiri-xp3", "KiriKiri archive (XP3)", ["xp3"], "application/x-xp3",
    Probe::Magic(&[(0, b"XP3\r\n \n\x1a\x8b\x67\x01")]), xp3);

async fn xp3(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("Signature").span(file.sub(0, 11)));
    let mut index_at = u64_le(&cx.read(file.sub(11, 8)).await?, 0).unwrap_or(0);
    if index_at == 0x17 {
        // Version 2: a header block pointing to the real index.
        cx.emit(Node::new("Version 2 header").span(file.sub(0x17, 21)));
        index_at = u64_le(&cx.read(file.sub(0x17 + 13, 8)).await?, 0).unwrap_or(0);
    }
    let h = cx.read(file.sub_exact(index_at, 9)?).await?;
    let compressed = h.first().copied().unwrap_or(0) & 7 == 1;
    let (index, error) = if compressed {
        let packed = u64_le(&h, 1).unwrap_or(0);
        let original = u64_le(
            &cx.read(file.sub_exact(index_at.saturating_add(9), 8)?)
                .await?,
            0,
        )
        .unwrap_or(0);
        let d = inflate_span(
            &cx,
            file.sub(index_at.saturating_add(17), packed),
            true,
            Some(original),
        )
        .await?;
        cx.emit(
            Node::new("Index (zlib)")
                .span(file.sub(index_at, packed.saturating_add(17)))
                .summary(format!("{packed} → {original} bytes")),
        );
        (d.span, d.error)
    } else {
        let size = u64_le(&h, 1).unwrap_or(0);
        cx.emit(Node::new("Index").span(file.sub(index_at, size.saturating_add(9))));
        (file.sub(index_at.saturating_add(9), size), None)
    };
    if let Some(e) = error {
        cx.diag(e);
    }
    // "File" chunks with "info", "segm" and "adlr" sub-chunks.
    let mut cur = Cursor::new(&cx, index, LE);
    let mut n = 0u32;
    while let Some(entry) = cur.chunk(ChunkLayout::new(4, 8, LE)).await? {
        if entry.id != b"File" {
            continue;
        }
        let mut sub = Cursor::new(&cx, entry.body, LE);
        let mut name = String::new();
        let mut segments = Vec::new();
        while let Some(c) = sub.chunk(ChunkLayout::new(4, 8, LE)).await? {
            match c.id.as_slice() {
                b"info" => {
                    let b = cx.read(c.body.sub(0, 22)).await?;
                    let len = u64::from(u16_le(&b, 20).unwrap_or(0));
                    let raw = cx.read(c.body.sub(22, len.saturating_mul(2))).await?;
                    name = crate::text::utf16(&raw, LE);
                }
                b"segm" => {
                    let b = cx.read(c.body.sub(0, c.body.len.min(28 * 64))).await?;
                    for s in b.as_chunks::<28>().0 {
                        let flags = u32_le(s, 0).unwrap_or(0);
                        let offset = u64_le(s, 4).unwrap_or(0);
                        let original = u64_le(s, 12).unwrap_or(0);
                        let packed = u64_le(s, 20).unwrap_or(0);
                        segments.push((flags, offset, original, packed));
                    }
                }
                _ => {}
            }
        }
        let node = match segments.as_slice() {
            [(flags, offset, original, packed)] => {
                let data = file.sub(*offset, *packed);
                if flags & 7 == 1 {
                    content(name.clone(), input, data, Codec::Zlib, Some(*original))
                } else {
                    embedded(name.clone(), input.nested(data))
                }
            }
            _ => Node::new(name.clone()).summary(format!("{} segments", segments.len())),
        };
        cx.push(node).await;
        n = n.saturating_add(1);
    }
    cx.annotate(format!("KiriKiri XP3 archive, {n} files"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Allegro datafiles, Ren'Py compiled scripts

declare_format!(pub ALLEGRO = "allegro-dat", "Allegro datafile", ["dat"], "application/x-allegro-dat",
    Probe::Magic(&[(0, b"ALL."), (0, b"slh!")]), allegro);

async fn allegro(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    if cx.read(file.sub(0, 4)).await? == b"slh!" {
        cx.emit(Node::new("Signature").span(file.sub(0, 4)));
        cx.emit(
            Node::new("Packed data")
                .span(file.tail(4))
                .diag(Diagnostic::unsupported("Allegro LZSS packing")),
        );
        cx.annotate("Allegro packed datafile");
        return Ok(());
    }
    let count = u32_be(&cx.read(file.sub(4, 4)).await?, 0).unwrap_or(0);
    cx.emit(Node::new("Signature").span(file.sub(0, 4)));
    cx.emit(
        Node::new("Objects")
            .span(file.sub(4, 4))
            .value(uint(count.into(), 32)),
    );
    let mut cur = Cursor::new(&cx, file, BE);
    cur.seek(8);
    for _ in 0..count {
        let start = cur.pos();
        let mut name = String::new();
        let mut kind;
        loop {
            kind = cur.bytes(4).await?;
            if kind != b"prop" {
                break;
            }
            let ptype = cur.bytes(4).await?;
            let size = u64::from(cur.u32().await?);
            let value = cur.bytes(size.min(256)).await?;
            cur.skip(size.saturating_sub(256.min(size)));
            if ptype == b"NAME" {
                name = String::from_utf8_lossy(&value).into_owned();
            }
        }
        let packed = u64::from(cur.u32().await?);
        let _unpacked = cur.u32().await?;
        let data = cur.span(packed);
        cur.skip(packed);
        let kind = String::from_utf8_lossy(&kind).trim().to_owned();
        cx.push(
            Node::new(if name.is_empty() { kind.clone() } else { name })
                .span(cur.since(start))
                .summary(format!("{kind}, {packed} bytes"))
                .target(data),
        )
        .await;
    }
    cx.annotate(format!("Allegro datafile, {count} objects"));
    Ok(())
}

declare_format!(pub RPYC = "renpy-rpyc", "Ren'Py compiled script", ["rpyc", "rpymc"], "application/x-renpy-rpyc",
    Probe::Magic(&[(0, b"RENPY RPC2")]), rpyc);

async fn rpyc(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("Signature").span(file.sub(0, 10)));
    let mut pos = 10u64;
    let mut slots = 0u32;
    loop {
        let e = cx.read(file.sub_exact(pos, 12)?).await?;
        let slot = u32_le(&e, 0).unwrap_or(0);
        if slot == 0 {
            cx.emit(Node::new("End of slot table").span(file.sub(pos, 12)));
            break;
        }
        let start = u64::from(u32_le(&e, 4).unwrap_or(0));
        let len = u64::from(u32_le(&e, 8).unwrap_or(0));
        // Each slot is a zlib-compressed pickle.
        cx.push(
            content(
                format!("Slot {slot}"),
                input,
                file.sub(start, len),
                Codec::Zlib,
                None,
            )
            .target(file.sub(pos, 12)),
        )
        .await;
        slots = slots.saturating_add(1);
        pos = pos.saturating_add(12);
    }
    cx.annotate(format!("Ren'Py compiled script, {slots} slots"));
    Ok(())
}
