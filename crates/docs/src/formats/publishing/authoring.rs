//! Multimedia authoring: Macromedia/Adobe Director and Shockwave movies
//! and casts (RIFX with a memory map, or Afterburner-compressed), HyperCard
//! stacks, After Effects projects and Corel CMX (RIFF forms), Figma
//! documents, Rive animations and Live2D Cubism models.

use crate::bytes::{to_u64, u16_be, u32_be, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{ChunkLayout, Cursor};
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::fmt::fourcc;
use crate::formats::util::val::{hex, int, text, uint};
use crate::formats::{Codec, Head, Input, Probe, content, embedded};
use crate::node::Node;
use crate::span::Span;
use crate::value::Value;

// ---------------------------------------------------------------------------
// Director / Shockwave

const DIRECTOR_CODECS: &[&[u8; 4]] = &[b"MV93", b"MC95", b"FGDM", b"FGDC"];

fn director_probe(h: &Head<'_>) -> bool {
    let codec = |rev: bool| {
        h.data.get(8..12).is_some_and(|c| {
            let mut c: [u8; 4] = c.try_into().unwrap_or_default();
            if rev {
                c.reverse();
            }
            DIRECTOR_CODECS.contains(&&c)
        })
    };
    (h.starts_with(b"RIFX") && codec(false)) || (h.starts_with(b"XFIR") && codec(true))
}

declare_format!(pub DIRECTOR = "director", "Macromedia Director / Shockwave movie", ["dir", "dxr", "cst", "cxt", "dcr", "cct"], "application/x-director",
    Probe::Custom(director_probe), director);

/// A four-character code read in the file's byte order (XFIR files store
/// them reversed), as text.
fn tag(b: &[u8], endian: Endian) -> String {
    let mut t: [u8; 4] = b
        .get(..4)
        .and_then(|s| s.try_into().ok())
        .unwrap_or_default();
    if endian == Endian::Little {
        t.reverse();
    }
    fourcc(&t)
}

const DIRECTOR_CHUNKS: &[(&str, &str)] = &[
    ("imap", "Initial map"),
    ("mmap", "Memory map"),
    ("KEY*", "Key table"),
    ("CAS*", "Cast member table"),
    ("CASt", "Cast member"),
    ("VWCF", "Movie configuration"),
    ("DRCF", "Movie configuration"),
    ("VWSC", "Score"),
    ("VWLB", "Score labels"),
    ("VWFI", "File info"),
    ("Lctx", "Script context"),
    ("LctX", "Script context"),
    ("Lnam", "Script names"),
    ("Lscr", "Script bytecode"),
    ("STXT", "Styled text"),
    ("BITD", "Bitmap"),
    ("CLUT", "Palette"),
    ("snd ", "Sound"),
    ("sndH", "Sound header"),
    ("sndS", "Sound samples"),
    ("ediM", "Media"),
    ("XMED", "Extended media"),
    ("Sord", "Score order"),
    ("MCsL", "Cast list"),
    ("Cinf", "Cast info"),
    ("SCRF", "Score references"),
    ("Fmap", "Font map"),
    ("THUM", "Thumbnail"),
    ("free", "Free"),
    ("junk", "Junk"),
    ("Fver", "File version"),
    ("Fcdr", "Compression descriptions"),
    ("ABMP", "Afterburner map"),
    ("FGEI", "Initial load segment"),
];

fn chunk_name(t: &str) -> Option<&'static str> {
    DIRECTOR_CHUNKS
        .iter()
        .find(|(k, _)| *k == t)
        .map(|(_, v)| *v)
}

async fn director(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h = cx.read(file.sub_exact(0, 12)?).await?;
    let endian = if h.starts_with(b"XFIR") {
        Endian::Little
    } else {
        Endian::Big
    };
    let codec = tag(h.get(8..).unwrap_or_default(), endian);
    let size = match endian {
        Endian::Little => u32_le(&h, 4),
        Endian::Big => u32_be(&h, 4),
    }
    .unwrap_or(0);
    cx.emit(
        Node::new("Header")
            .span(file.sub(0, 12))
            .value(text(codec.clone()))
            .summary(format!(
                "{}, {size} bytes",
                if endian == Endian::Big {
                    "RIFX (big-endian)"
                } else {
                    "XFIR (little-endian)"
                }
            )),
    );
    let kind = match codec.as_str() {
        "MV93" => "Director movie",
        "MC95" => "Director cast",
        "FGDM" => "Shockwave movie",
        _ => "Shockwave cast",
    };
    if codec.starts_with("FGD") {
        let n = afterburner(&cx, input, endian).await?;
        cx.annotate(format!("{kind} (Afterburner), {n} sections"));
        return Ok(());
    }
    // imap: map count, memory map offset, map version.
    let mut cur = Cursor::new(&cx, file, endian);
    cur.seek(12);
    let imap = cur
        .chunk(ChunkLayout::new(4, 4, endian))
        .await?
        .ok_or_else(|| Diagnostic::truncated(file.tail(12), file.len.saturating_sub(12)))?;
    if tag(&imap.id, endian) != "imap" {
        cx.emit(
            imap.node()
                .diag(Diagnostic::malformed("expected the imap chunk")),
        );
        return Ok(());
    }
    let d = cx.read(imap.body.sub(0, 12)).await?;
    let word = |i: usize| {
        match endian {
            Endian::Little => u32_le(&d, i),
            Endian::Big => u32_be(&d, i),
        }
        .unwrap_or(0)
    };
    let mmap_at = u64::from(word(4));
    cx.emit(
        Node::new("imap")
            .span(imap.span)
            .summary(format!("memory map at {mmap_at:#x}")),
    );
    let mut mc = Cursor::new(&cx, file, endian);
    mc.seek(mmap_at);
    let mmap = mc
        .chunk(ChunkLayout::new(4, 4, endian))
        .await?
        .ok_or_else(|| Diagnostic::truncated(file.sub(mmap_at, 8), 0))?;
    let mut m = Cursor::new(&cx, mmap.body, endian);
    let header_len = u64::from(m.u16().await?);
    let entry_len = u64::from(m.u16().await?);
    let _max = m.u32().await?;
    let used = m.u32().await?;
    cx.emit(
        Node::new("mmap")
            .span(mmap.span)
            .summary(format!("{used} entries of {entry_len} bytes")),
    );
    if entry_len < 12 {
        return Err(
            Diagnostic::malformed(format!("memory map entry size {entry_len}")).at(mmap.span),
        );
    }
    let entries = mmap
        .body
        .sub_exact(header_len, u64::from(used).saturating_mul(entry_len))?;
    let mut shown = 0u32;
    for i in 0..u64::from(used) {
        let e = cx
            .read(entries.sub(i.saturating_mul(entry_len), 12))
            .await?;
        let t = tag(&e, endian);
        let (len, off) = match endian {
            Endian::Little => (u32_le(&e, 4), u32_le(&e, 8)),
            Endian::Big => (u32_be(&e, 4), u32_be(&e, 8)),
        };
        let (len, off) = (u64::from(len.unwrap_or(0)), u64::from(off.unwrap_or(0)));
        if matches!(
            t.as_str(),
            "free" | "junk" | "imap" | "mmap" | "RIFX" | "XFIR"
        ) {
            continue;
        }
        shown = shown.saturating_add(1);
        let whole = file.sub(off, len.saturating_add(8));
        let body = file.sub(off.saturating_add(8), len);
        let node = Node::new(format!("[{i}] {t}")).span(whole).summary(format!(
            "{}{len} bytes",
            chunk_name(&t).map(|n| format!("{n}, ")).unwrap_or_default()
        ));
        let node = match t.as_str() {
            "ediM" => node.lazy(media, (input, body)),
            "STXT" => node.lazy(stxt, (body, endian)),
            "KEY*" => node.lazy(key_table, (body, endian)),
            _ => node,
        };
        cx.push(node).await;
    }
    cx.annotate(format!(
        "{kind} ({}), {shown} chunks",
        if endian == Endian::Big {
            "Mac"
        } else {
            "Windows"
        }
    ));
    Ok(())
}

async fn media(cx: Cx, (input, body): (Input, Span)) -> Result<()> {
    cx.emit(embedded("Media data", input.nested(body)));
    Ok(())
}

/// Styled text: header length, text length, style data length; then text.
async fn stxt(cx: Cx, (body, _): (Span, Endian)) -> Result<()> {
    // STXT is big-endian even in XFIR files.
    let h = cx.read(body.sub_exact(0, 12)?).await?;
    let hl = u64::from(u32_be(&h, 0).unwrap_or(12));
    let tl = u64::from(u32_be(&h, 4).unwrap_or(0));
    cx.emit(
        Node::new("Header")
            .span(body.sub(0, 12))
            .summary(format!("text {tl} bytes")),
    );
    let t = body.sub(hl, tl);
    let s = cx.read(t.sub(0, 4096)).await?;
    cx.emit(
        Node::new("Text")
            .span(t)
            .value(text(String::from_utf8_lossy(&s).replace('\r', "\n"))),
    );
    cx.emit(Node::new("Formatting").span(body.tail(hl.saturating_add(tl))));
    Ok(())
}

/// Key table: which chunk belongs to which cast member.
async fn key_table(cx: Cx, (body, endian): (Span, Endian)) -> Result<()> {
    let h = cx.read(body.sub_exact(0, 12)?).await?;
    let half = |i: usize| {
        match endian {
            Endian::Little => h.get(i..i.saturating_add(2)).map(|b| {
                u16::from_le_bytes([
                    b.first().copied().unwrap_or(0),
                    b.get(1).copied().unwrap_or(0),
                ])
            }),
            Endian::Big => u16_be(&h, i),
        }
        .unwrap_or(0)
    };
    let word = |i: usize| {
        match endian {
            Endian::Little => u32_le(&h, i),
            Endian::Big => u32_be(&h, i),
        }
        .unwrap_or(0)
    };
    let entry = u64::from(half(0)).max(12);
    let used = word(8);
    let table = body.sub_exact(12, u64::from(used).saturating_mul(12))?;
    let data = cx.read(table).await?;
    for (i, e) in data.as_chunks::<12>().0.iter().enumerate() {
        let w = |o: usize| {
            match endian {
                Endian::Little => u32_le(e, o),
                Endian::Big => u32_be(e, o),
            }
            .unwrap_or(0)
        };
        let t = tag(e.get(8..).unwrap_or_default(), endian);
        cx.push(
            Node::new(format!("{t} → section {}", w(0)))
                .span(table.sub(to_u64(i).saturating_mul(entry.min(12)), 12))
                .value(uint(w(4), 32))
                .summary("owner (cast member or library)"),
        )
        .await;
    }
    Ok(())
}

/// A Shockwave variable-length integer: 7 bits per byte, big-endian, high
/// bit set on all but the last.
async fn varint(cur: &mut Cursor<'_>) -> Result<u64> {
    let mut v = 0u64;
    for _ in 0..10 {
        let b = cur.u8().await?;
        v = v.wrapping_shl(7) | u64::from(b & 0x7f);
        if b & 0x80 == 0 {
            return Ok(v);
        }
    }
    Err(Diagnostic::malformed("variable-length integer too long").at(cur.span(1)))
}

/// Afterburner sections: tag and length, up to the initial load segment.
async fn afterburner(cx: &Cx, input: Input, endian: Endian) -> Result<u32> {
    let file = input.span;
    let mut cur = Cursor::new(cx, file, endian);
    cur.seek(12);
    let mut n = 0u32;
    while cur.remaining() >= 5 {
        let start = cur.pos();
        let t = tag(&cur.bytes(4).await?, endian);
        if t == "FGEI" {
            let rest = file.tail(start);
            cx.push(
                Node::new("FGEI")
                    .span(rest)
                    .summary("initial load segment (compressed chunks)"),
            )
            .await;
            n = n.saturating_add(1);
            break;
        }
        let len = varint(&mut cur).await?;
        let body = cur.span(len);
        if body.len < len {
            return Err(Diagnostic::truncated(
                Span::new(body.source, body.offset, len),
                body.len,
            ));
        }
        cur.skip(len);
        let node = Node::new(t.clone()).span(cur.since(start)).summary(format!(
            "{}{len} bytes",
            chunk_name(&t).map(|s| format!("{s}, ")).unwrap_or_default()
        ));
        let node = if t == "Fcdr" || t == "ABMP" {
            node.lazy(afterburner_zlib, (input, body, t == "ABMP"))
        } else {
            node
        };
        cx.push(node).await;
        n = n.saturating_add(1);
    }
    Ok(n)
}

/// Fcdr is zlib data; ABMP has two varints before its zlib stream.
async fn afterburner_zlib(cx: Cx, (input, body, abmp): (Input, Span, bool)) -> Result<()> {
    let mut cur = Cursor::new(&cx, body, Endian::Big);
    if abmp {
        let at = cur.pos();
        let a = varint(&mut cur).await?;
        let b = varint(&mut cur).await?;
        cx.emit(
            Node::new("Header")
                .span(cur.since(at))
                .value(text(format!("{a}, uncompressed {b} bytes"))),
        );
    }
    cx.emit(content(
        "Compressed data",
        input,
        body.tail(cur.pos()),
        Codec::Zlib,
        None,
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// HyperCard

fn hypercard_probe(h: &Head<'_>) -> bool {
    h.at(4, b"STAK")
        && h.at(8, b"\xff\xff\xff\xff")
        && u32_be(h.data, 0).is_some_and(|s| s >= 0x180 && u64::from(s) <= h.len)
}

declare_format!(pub HYPERCARD = "hypercard", "HyperCard stack", ["stak", "stack"], "application/x-hypercard",
    Probe::Custom(hypercard_probe), hypercard);

const HC_BLOCKS: &[(&str, &str)] = &[
    ("STAK", "Stack"),
    ("MAST", "Master index"),
    ("LIST", "Card list"),
    ("PAGE", "Card list page"),
    ("BKGD", "Background"),
    ("CARD", "Card"),
    ("BMAP", "Bitmap"),
    ("FREE", "Free block"),
    ("STBL", "Style table"),
    ("FTBL", "Font table"),
    ("PRNT", "Print settings"),
    ("PRST", "Page setup"),
    ("PRFT", "Report template"),
    ("TAIL", "End of stack"),
];

async fn hypercard(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, Endian::Big);
    let (mut cards, mut stack) = (0u32, None);
    while let Some(chunk) = cur
        .chunk(ChunkLayout::new(4, 4, Endian::Big).size_first().inclusive())
        .await?
    {
        let t = fourcc(&chunk.id);
        let id = i32::from_ne_bytes(
            u32_be(&cx.read(chunk.body.sub(0, 4)).await?, 0)
                .unwrap_or(0)
                .to_ne_bytes(),
        );
        let name = HC_BLOCKS.iter().find(|(k, _)| *k == t).map(|(_, v)| *v);
        let node = Node::new(format!("{t} {id}"))
            .span(chunk.span)
            .summary(format!(
                "{}{} bytes",
                name.map(|n| format!("{n}, ")).unwrap_or_default(),
                chunk.span.len
            ));
        let node = if t == "STAK" {
            node.lazy(stak, chunk.span)
        } else {
            node
        };
        if t == "CARD" {
            cards = cards.saturating_add(1);
        }
        if t == "STAK" {
            let d = cx.read(chunk.span.sub(0x10, 0x24)).await?;
            stack = Some((u32_be(&d, 0).unwrap_or(0), u32_be(&d, 0x1c).unwrap_or(0)));
        }
        cx.push(node).await;
        if t == "TAIL" {
            break;
        }
    }
    let (format, ncards) = stack.unwrap_or_default();
    cx.annotate(format!(
        "HyperCard stack, format {format} ({}), {} cards",
        if format >= 10 { "2.x" } else { "1.x" },
        if ncards > 0 { ncards } else { cards }
    ));
    Ok(())
}

async fn stak(cx: Cx, span: Span) -> Result<()> {
    let d = cx.read(span.sub(0, 0x50)).await?;
    let w = |o: usize| u32_be(&d, o).unwrap_or(0);
    let field =
        |name: &'static str, o: u64, v: Value| Node::new(name).span(span.sub(o, 4)).value(v);
    cx.emit(field("Block size", 0, uint(w(0), 32)));
    cx.emit(Node::new("Type").span(span.sub(4, 4)).value(text("STAK")));
    cx.emit(field(
        "ID",
        8,
        int(i32::from_ne_bytes(w(8).to_ne_bytes()), 32),
    ));
    cx.emit(field("Format", 0x10, uint(w(0x10), 32)).desc("1-9: HyperCard 1.x; 10: HyperCard 2.x"));
    cx.emit(field("Total size", 0x14, uint(w(0x14), 32)));
    cx.emit(field("Stack size", 0x18, uint(w(0x18), 32)));
    cx.emit(field("Backgrounds", 0x24, uint(w(0x24), 32)));
    cx.emit(field("First background ID", 0x28, hex(w(0x28), 32)));
    cx.emit(field("Cards", 0x2c, uint(w(0x2c), 32)));
    cx.emit(field("First card ID", 0x30, hex(w(0x30), 32)));
    cx.emit(field("List block ID", 0x34, hex(w(0x34), 32)));
    cx.emit(field("Free blocks", 0x38, uint(w(0x38), 32)));
    cx.emit(field("Free size", 0x3c, uint(w(0x3c), 32)));
    cx.emit(field("Print block ID", 0x40, hex(w(0x40), 32)));
    Ok(())
}

// ---------------------------------------------------------------------------
// RIFF forms: After Effects projects and Corel CMX (the generic walker)

declare_format!(pub AEP = "after-effects", "Adobe After Effects project", ["aep", "aet"], "application/x-aftereffects",
    Probe::Custom(|h| h.starts_with(b"RIFX") && h.at(8, b"Egg!")), riff_form);
declare_format!(pub CMX = "corel-cmx", "Corel Presentation Exchange", ["cmx"], "application/x-cmx",
    Probe::Custom(|h| (h.starts_with(b"RIFF") || h.starts_with(b"RIFX")) && h.at(8, b"CMX1")), riff_form);

async fn riff_form(cx: Cx, input: Input) -> Result<()> {
    let h = cx.read(input.span.sub(0, 12)).await?;
    crate::formats::iff::dissect(cx.clone(), input).await?;
    cx.annotate(match h.get(8..12) {
        Some(b"Egg!") => "Adobe After Effects project (RIFX)",
        _ => "Corel Presentation Exchange (CMX)",
    });
    Ok(())
}

// ---------------------------------------------------------------------------
// Figma

declare_format!(pub FIGMA = "figma", "Figma document", ["fig", "jam"], "application/x-figma",
    Probe::Magic(&[(0, b"fig-kiwi"), (0, b"fig-jam.")]), figma);

async fn figma(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h = cx.read(file.sub_exact(0, 12)?).await?;
    let version = u32_le(&h, 8).unwrap_or(0);
    let kind = if h.starts_with(b"fig-jam.") {
        "FigJam board"
    } else {
        "Figma design"
    };
    cx.emit(
        Node::new("Signature")
            .span(file.sub(0, 8))
            .value(text(String::from_utf8_lossy(
                h.get(..8).unwrap_or_default(),
            ))),
    );
    cx.emit(
        Node::new("Version")
            .span(file.sub(8, 4))
            .value(uint(version, 32)),
    );
    let mut cur = Cursor::new(&cx, file, Endian::Little);
    cur.seek(12);
    let mut n = 0u32;
    while let Some(chunk) = cur.chunk(ChunkLayout::new(0, 4, Endian::Little)).await? {
        let name = match n {
            0 => "Schema",
            1 => "Message",
            _ => "Chunk",
        };
        let magic = cx.read_avail(chunk.body.sub(0, 4)).await?;
        let node = if magic.as_slice() == b"\x28\xb5\x2f\xfd" {
            content(name, input, chunk.body, Codec::Zstd, None)
                .summary(format!("{} bytes, Zstandard (kiwi binary)", chunk.body.len))
        } else if magic.starts_with(b"\x89PNG") {
            embedded(name, input.nested(chunk.body)).summary("PNG image")
        } else {
            content(name, input, chunk.body, Codec::Deflate, None)
                .summary(format!("{} bytes, deflate (kiwi binary)", chunk.body.len))
        };
        cx.push(node).await;
        n = n.saturating_add(1);
    }
    cx.annotate(format!("{kind}, format version {version}, {n} chunks"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Rive

declare_format!(pub RIVE = "rive", "Rive animation", ["riv"], "application/x-rive",
    Probe::Custom(|h| h.starts_with(b"RIVE") && h.data.get(4).is_some_and(|&v| (1..=20).contains(&v))), rive);

async fn leb_field(cx: &Cx, cur: &mut Cursor<'_>, name: &'static str) -> Result<u64> {
    let at = cur.pos();
    let v = cur.uleb128().await?;
    cx.emit(Node::new(name).span(cur.since(at)).value(uint(v, 64)));
    Ok(v)
}

async fn rive(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("Signature").span(file.sub(0, 4)));
    let mut cur = Cursor::new(&cx, file, Endian::Little);
    cur.seek(4);
    let major = leb_field(&cx, &mut cur, "Major version").await?;
    let minor = leb_field(&cx, &mut cur, "Minor version").await?;
    let id = leb_field(&cx, &mut cur, "File ID").await?;
    // Table of contents: property keys (ending with 0), then two bits per
    // key giving its field type, packed into 32-bit words.
    let at = cur.pos();
    let mut keys = Vec::new();
    loop {
        let k = cur.uleb128().await?;
        if k == 0 {
            break;
        }
        if keys.len() < 4096 {
            keys.push(k);
        } else {
            return Err(Diagnostic::limit("more than 4096 property keys").at(cur.since(at)));
        }
    }
    let types = to_u64(keys.len()).div_ceil(16).saturating_mul(4);
    cur.skip(types);
    let shown: Vec<String> = keys.iter().take(32).map(u64::to_string).collect();
    cx.emit(
        Node::new("Table of contents")
            .span(cur.since(at))
            .value(text(shown.join(", ")))
            .summary(format!("{} property keys", keys.len())),
    );
    cx.emit(
        Node::new("Objects")
            .span(file.tail(cur.pos()))
            .diag(Diagnostic::unsupported("Rive object records")),
    );
    cx.annotate(format!("Rive runtime file v{major}.{minor}, file ID {id}"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Live2D Cubism model (moc3)

declare_format!(pub MOC3 = "moc3", "Live2D Cubism model", ["moc3"], "application/x-moc3",
    Probe::Custom(|h| h.starts_with(b"MOC3") && h.data.get(4).is_some_and(|&v| (1..=6).contains(&v)) && h.data.get(5).is_some_and(|&e| e <= 1)), moc3);

const MOC3_VERSIONS: &[(u8, &str)] = &[
    (1, "3.0"),
    (2, "3.3"),
    (3, "4.0"),
    (4, "4.2"),
    (5, "5.0"),
    (6, "5.3"),
];

async fn moc3(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h = cx.read(file.sub_exact(0, 64)?).await?;
    let version = h.get(4).copied().unwrap_or(0);
    let big = h.get(5) == Some(&1);
    let name = MOC3_VERSIONS
        .iter()
        .find(|(k, _)| *k == version)
        .map(|(_, v)| *v);
    cx.emit(Node::new("Signature").span(file.sub(0, 4)));
    cx.emit(
        Node::new("Version")
            .span(file.sub(4, 1))
            .value(Value::Enum {
                raw: version.into(),
                bits: 8,
                name,
            }),
    );
    cx.emit(
        Node::new("Big-endian")
            .span(file.sub(5, 1))
            .value(Value::Bool(big)),
    );
    cx.emit(Node::new("Padding").span(file.sub(6, 58)));
    let endian = if big { Endian::Big } else { Endian::Little };
    let mut cur = Cursor::new(&cx, file, endian);
    cur.seek(64);
    let at = cur.pos();
    let count_info = cur.u32().await?;
    cx.emit(
        Node::new("Section offsets")
            .span(file.sub(at, 640))
            .summary(format!("count info at {count_info:#x}"))
            .diag(Diagnostic::unsupported("moc3 section table")),
    );
    cx.annotate(format!(
        "Live2D Cubism model, moc3 {}",
        name.unwrap_or("(unknown version)")
    ));
    Ok(())
}
