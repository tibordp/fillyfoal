//! Game-engine packages: Godot PCK, Unity asset bundles (UnityFS),
//! GameMaker data files and Ren'Py archives (RPA).

use crate::bytes::{u32_le, u64_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::{Input, Probe, embedded};
use crate::node::{Count, Node};
use crate::value::{EnumTable, Value, lookup};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// Godot PCK

declare_format!(pub GODOT_PCK = "godot-pck", "Godot resource pack", ["pck"], "application/x-godot-pck",
    Probe::Magic(&[(0, b"GDPC")]), godot_pck);

async fn godot_pck(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 20)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Magic", 4).emit()?;
    let format = f.u32("Pack format version").emit()?;
    let major = f.u32("Godot major").emit()?;
    let minor = f.u32("Godot minor").emit()?;
    f.u32("Godot patch").emit()?;
    let mut at = 20u64;
    let mut base = 0u64;
    if format >= 2 {
        // Pack flags, then the offset files are relative to.
        let v2 = cx.read(file.sub(20, 12)).await?;
        base = u64_le(&v2, 4).unwrap_or(0);
        at = 32;
    }
    at = at.saturating_add(64); // reserved
    let count = u32_le(&cx.read(file.sub(at, 4)).await?, 0).unwrap_or(0);
    at = at.saturating_add(4);
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(at);
    cx.set_count(Count::AtLeast(count.into()));
    for _ in 0..count.min(1_000_000) {
        let start = cur.pos();
        let len = cur.u32().await?;
        let path = crate::text::until_nul(&cur.bytes(len.into()).await?);
        let offset = cur.u64().await?;
        let size = cur.u64().await?;
        cur.skip(16); // MD5
        if format >= 2 {
            cur.skip(4); // flags
        }
        let data = file.sub(base.saturating_add(offset), size);
        cx.push(
            embedded(path, input.nested(data))
                .summary(format!("{size} bytes"))
                .target(cur.since(start)),
        )
        .await;
    }
    cx.annotate(format!("Godot {major}.{minor} pack, {count} files"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Unity asset bundles (UnityFS)

declare_format!(pub UNITYFS = "unityfs", "Unity asset bundle", ["unity3d", "bundle", "assetbundle"], "application/x-unityfs",
    Probe::Magic(&[(0, b"UnityFS\0"), (0, b"UnityWeb\0"), (0, b"UnityRaw\0")]), unityfs);

const UNITY_COMPRESSION: EnumTable = &[
    (0, "none"),
    (1, "LZMA"),
    (2, "LZ4"),
    (3, "LZ4HC"),
    (4, "LZHAM"),
];

async fn unityfs(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, BE);
    let (signature, s1) = cur.cstr(16).await?;
    let version = cur.u32().await?;
    let (player, s2) = cur.cstr(64).await?;
    let (engine, s3) = cur.cstr(64).await?;
    cx.emit(
        Node::new("Signature")
            .span(s1)
            .value(Value::Text(signature.clone())),
    );
    cx.emit(
        Node::new("Format version")
            .span(file.sub(s1.len, 4))
            .value(Value::UInt {
                value: version.into(),
                bits: 32,
                radix: crate::value::Radix::Dec,
            }),
    );
    cx.emit(
        Node::new("Player version")
            .span(s2)
            .value(Value::Text(player)),
    );
    cx.emit(
        Node::new("Engine version")
            .span(s3)
            .value(Value::Text(engine.clone())),
    );
    if signature == "UnityFS" {
        let start = cur.pos();
        let size = cur.u64().await?;
        let compressed = cur.u32().await?;
        let uncompressed = cur.u32().await?;
        let flags = cur.u32().await?;
        let scheme = flags & 0x3f;
        cx.emit(
            Node::new("Bundle header")
                .span(cur.since(start))
                .summary(format!(
                    "{size} bytes; blocks info {compressed} → {uncompressed} bytes, {}",
                    lookup(UNITY_COMPRESSION, scheme.into()).unwrap_or("unknown compression")
                )),
        );
        let rest = file.tail(cur.pos());
        let mut node = Node::new("Blocks and directory").span(rest);
        if scheme != 0 {
            node = node.diag(Diagnostic::unsupported(format!(
                "{} compression",
                lookup(UNITY_COMPRESSION, scheme.into()).unwrap_or("unknown")
            )));
        }
        cx.emit(node);
    }
    cx.annotate(format!("{signature} v{version}, Unity {engine}"));
    Ok(())
}

// ---------------------------------------------------------------------------
// GameMaker data (IFF-like, little-endian lengths)

fn gamemaker_probe(h: &crate::formats::Head<'_>) -> bool {
    h.starts_with(b"FORM") && h.at(8, b"GEN8")
}

declare_format!(pub GAMEMAKER = "gamemaker", "GameMaker data file", ["win", "unx", "ios", "droid"], "application/x-gamemaker",
    Probe::Custom(gamemaker_probe), gamemaker);

async fn gamemaker(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, LE);
    cur.skip(8);
    let mut chunks = 0u32;
    while cur.remaining() >= 8 {
        let start = cur.pos();
        let id = String::from_utf8_lossy(&cur.bytes(4).await?).into_owned();
        let len = cur.u32().await?;
        cur.skip(len.into());
        chunks = chunks.saturating_add(1);
        cx.push(
            Node::new(id)
                .span(cur.since(start))
                .summary(format!("{len} bytes")),
        )
        .await;
    }
    let gen8 = cx.read_avail(file.sub(16, 0x40)).await?;
    let name_offset = u32_le(&gen8, 0x28).unwrap_or(0);
    let name = if name_offset > 0 {
        cx.cstr(file.sub(name_offset.into(), 128))
            .await
            .map(|(n, _)| n)
            .unwrap_or_default()
    } else {
        String::new()
    };
    cx.annotate(format!("GameMaker data {name:?}, {chunks} chunks"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Ren'Py archives (RPA)

declare_format!(pub RPA = "rpa", "Ren'Py archive", ["rpa", "rpi"], "application/x-renpy-archive",
    Probe::Magic(&[(0, b"RPA-3.0 "), (0, b"RPA-3.2 "), (0, b"RPA-2.0 ")]), rpa);

async fn rpa(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let line = cx.read_avail(file.sub(0, 128)).await?;
    let end = line.iter().position(|&b| b == b'\n').unwrap_or(line.len());
    let text = String::from_utf8_lossy(line.get(..end).unwrap_or_default()).into_owned();
    let mut parts = text.split_whitespace();
    let version = parts.next().unwrap_or_default().to_owned();
    let offset = u64::from_str_radix(parts.next().unwrap_or("0"), 16).unwrap_or(0);
    let key = parts.next().map(str::to_owned);
    cx.emit(
        Node::new("Header")
            .span(file.sub(0, crate::bytes::to_u64(end).saturating_add(1)))
            .value(Value::Text(text.clone())),
    );
    // The index is a zlib-compressed Python pickle.
    let index = file.tail(offset);
    cx.emit(crate::formats::content(
        "Index (pickle)",
        input,
        index,
        crate::formats::Codec::Zlib,
        None,
    ));
    cx.annotate(format!(
        "{version}{}",
        key.map_or(String::new(), |k| format!(", key {k}"))
    ));
    Ok(())
}
