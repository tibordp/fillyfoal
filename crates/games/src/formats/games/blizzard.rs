//! Blizzard game assets: BLP textures, M2 models and Warcraft III maps.

use crate::bytes::u32_le;
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Cursor;
use crate::error::Result;
use crate::fields::{Endian, Fields};
use crate::formats::util::val::{text, uint};
use crate::formats::{Input, Probe, embedded};
use crate::node::Node;
use crate::text::until_nul;
use crate::value::{Radix, Value};

const LE: Endian = Endian::Little;

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
        let encoding = f
            .u8("Encoding")
            .enumeration(&[(1, "palettized"), (2, "DXT"), (3, "uncompressed BGRA")])
            .emit()?;
        f.u8("Alpha depth").emit()?;
        f.u8("Alpha encoding")
            .enumeration(&[(0, "DXT1"), (1, "DXT3"), (7, "DXT5")])
            .emit()?;
        f.u8("Has mipmaps").emit()?;
        let w = f.u32("Width").emit()?;
        let h = f.u32("Height").emit()?;
        (
            w,
            h,
            match encoding {
                1 => "palettized",
                2 => "DXT",
                3 => "BGRA",
                _ => "unknown",
            },
        )
    } else {
        let compression = f
            .u32("Compression")
            .enumeration(&[(0, "JPEG"), (1, "palettized")])
            .emit()?;
        f.u32("Alpha bits").emit()?;
        let w = f.u32("Width").emit()?;
        let h = f.u32("Height").emit()?;
        f.u32("Extra").emit()?;
        f.u32("Has mipmaps").emit()?;
        (
            w,
            h,
            if compression == 0 {
                "JPEG"
            } else {
                "palettized"
            },
        )
    };
    let table = cx.read(file.sub(head_len, 128)).await?;
    for level in 0..16usize {
        let offset = u64::from(u32_le(&table, level.saturating_mul(4)).unwrap_or(0));
        let size =
            u64::from(u32_le(&table, level.saturating_mul(4).saturating_add(64)).unwrap_or(0));
        if offset == 0 || size == 0 {
            break;
        }
        cx.push(
            Node::new(format!("Mipmap {level}"))
                .span(file.sub(offset, size))
                .summary(format!(
                    "{}×{}",
                    (width >> level).max(1),
                    (height >> level).max(1)
                )),
        )
        .await;
    }
    cx.annotate(format!(
        "BLP{} {kind} texture, {width}×{height}",
        if v2 { 2 } else { 1 }
    ));
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
    let name = until_nul(
        &cx.read_avail(body.sub(name_at.into(), u64::from(name_len).min(256)))
            .await?,
    );
    cx.emit(
        Node::new("Name")
            .span(body.sub(name_at.into(), name_len.into()))
            .value(text(name.clone())),
    );
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
    cx.emit(
        Node::new("Map name")
            .span(name_span)
            .value(text(name.clone())),
    );
    cx.emit(
        Node::new("Flags")
            .span(cur.since(cur.pos().saturating_sub(8)).sub(0, 4))
            .value(Value::UInt {
                value: flags.into(),
                bits: 32,
                radix: Radix::Hex,
            }),
    );
    cx.emit(
        Node::new("Maximum players")
            .span(cur.since(cur.pos().saturating_sub(4)))
            .value(uint(players, 32)),
    );
    let archive = file.tail(512);
    cx.emit(embedded("MPQ archive", input.nested(archive)));
    cx.annotate(format!("Warcraft III map {name:?}, {players} players"));
    Ok(())
}
