//! Digital content creation scenes: Maya binary, Cinema 4D, Houdini bgeo
//! and Alembic.

use crate::bytes::{u16_be, u32_be, u64_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{ChunkLayout, Cursor, Path};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::val::{text, uint};
use crate::formats::{Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{Radix, Value};

const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// Maya binary (IFF-85 with 4-byte alignment)

fn maya_probe(h: &Head<'_>) -> bool {
    (h.starts_with(b"FOR4") && h.at(8, b"Maya")) || (h.starts_with(b"FOR8") && h.at(16, b"Maya"))
}

declare_format!(pub MAYA = "maya-binary", "Maya binary scene", ["mb"], "application/x-maya",
    Probe::Custom(maya_probe), maya);

const MAYA_GROUPS: &[&[u8]] = &[b"FOR4", b"LIS4", b"CAT4", b"PROP"];

async fn maya(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    if cx.read(file.sub(0, 4)).await? == b"FOR8" {
        cx.emit(Node::new("Header").span(file.sub(0, 20)));
        cx.emit(
            Node::new("Chunks")
                .span(file.tail(20))
                .diag(Diagnostic::unsupported("64-bit (FOR8) layout")),
        );
        cx.annotate("Maya binary scene (64-bit)");
        return Ok(());
    }
    let size = u64::from(u32_be(&cx.read(file.sub(4, 4)).await?, 0).unwrap_or(0));
    cx.emit(
        Node::new("FOR4 Maya")
            .span(file.sub(0, 12))
            .summary(format!("{size} bytes")),
    );
    let body = file.sub(12, size.saturating_sub(4));
    maya_group(cx.clone(), (body, Path::new())).await?;
    cx.annotate("Maya binary scene");
    Ok(())
}

async fn maya_group(cx: Cx, (region, path): (Span, Path)) -> Result<()> {
    let mut cur = Cursor::new(&cx, region, BE);
    while let Some(chunk) = cur.chunk(ChunkLayout::new(4, 4, BE).align(4)).await? {
        if MAYA_GROUPS.contains(&chunk.id.as_slice()) && chunk.body.len >= 4 {
            let kind = String::from_utf8_lossy(&cx.read(chunk.body.sub(0, 4)).await?).into_owned();
            let node = Node::new(format!("{} {kind}", chunk.name()))
                .span(chunk.span)
                .summary(format!("{} bytes", chunk.body.len));
            match path.enter(chunk.span.offset, 32) {
                Ok(child) => {
                    cx.push(node.lazy(
                        crate::expander!(self::maya_group: (Span, Path)),
                        (chunk.body.tail(4), child),
                    ))
                    .await
                }
                Err(d) => cx.push(node.diag(d)).await,
            }
        } else {
            let mut node = chunk.node();
            if matches!(
                chunk.id.as_slice(),
                b"VERS"
                    | b"PLAT"
                    | b"FINF"
                    | b"AUNI"
                    | b"LUNI"
                    | b"TUNI"
                    | b"MADE"
                    | b"CHNG"
                    | b"OBJN"
                    | b"INCL"
                    | b"STR "
            ) {
                let t = cx.read_avail(chunk.body.sub(0, 256)).await?;
                node = node.value(text(
                    String::from_utf8_lossy(&t)
                        .replace('\0', " ")
                        .trim()
                        .to_owned(),
                ));
            }
            cx.push(node).await;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Cinema 4D, Houdini, Alembic

declare_format!(pub C4D = "cinema4d", "Cinema 4D scene", ["c4d"], "application/x-c4d",
    Probe::Magic(&[(0, b"XC4DC4D6")]), c4d);

async fn c4d(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("Signature").span(file.sub(0, 8)));
    cx.emit(Node::new("Hyperfile").span(file.tail(8)));
    cx.annotate("Cinema 4D scene (C4D6 hyperfile)");
    Ok(())
}

declare_format!(pub BGEO = "houdini-bgeo", "Houdini binary geometry", ["bgeo", "bhclassic"], "model/x-houdini-bgeo",
    Probe::Magic(&[(0, b"BgeoV"), (0, b"NSJb")]), bgeo);

async fn bgeo(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    if cx.read(file.sub(0, 4)).await? == b"NSJb" {
        cx.emit(Node::new("Signature").span(file.sub(0, 4)));
        cx.emit(Node::new("Binary JSON").span(file.tail(4)));
        cx.annotate("Houdini geometry (binary JSON)");
        return Ok(());
    }
    let head = cx.block(file.sub(0, 41)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Signature", 5).emit()?;
    let version = f.u32("Version").emit()?;
    let points = f.u32("Points").emit()?;
    let prims = f.u32("Primitives").emit()?;
    f.u32("Point groups").emit()?;
    f.u32("Primitive groups").emit()?;
    f.u32("Point attributes").emit()?;
    f.u32("Vertex attributes").emit()?;
    f.u32("Primitive attributes").emit()?;
    f.u32("Detail attributes").emit()?;
    cx.emit(Node::new("Geometry").span(file.tail(41)));
    cx.annotate(format!(
        "Houdini classic geometry v{version}: {points} points, {prims} primitives"
    ));
    Ok(())
}

declare_format!(pub ALEMBIC = "alembic", "Alembic archive (Ogawa)", ["abc"], "application/x-alembic",
    Probe::Magic(&[(0, b"Ogawa")]), alembic);

async fn alembic(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 16)).await?;
    cx.emit(Node::new("Signature").span(file.sub(0, 5)));
    cx.emit(
        Node::new("Frozen")
            .span(file.sub(5, 1))
            .value(Value::Bool(head.get(5) == Some(&0xff))),
    );
    cx.emit(
        Node::new("Version")
            .span(file.sub(6, 2))
            .value(uint(u16_be(&head, 6).unwrap_or(0), 16)),
    );
    let root = u64_le(&head, 8).unwrap_or(0);
    cx.emit(
        Node::new("Root group offset")
            .span(file.sub(8, 8))
            .value(Value::UInt {
                value: root,
                bits: 64,
                radix: Radix::Hex,
            }),
    );
    // A group: a child count, then child offsets (high bit: data, else group).
    let count = u64_le(&cx.read(file.sub_exact(root, 8)?).await?, 0).unwrap_or(0);
    let shown = count.min(256);
    let children = cx
        .read(file.sub_exact(root.saturating_add(8), shown.saturating_mul(8))?)
        .await?;
    let mut groups = 0u32;
    let mut data = 0u32;
    for c in children.chunks(8) {
        let v = u64_le(c, 0).unwrap_or(0);
        if v >> 63 == 1 {
            data = data.saturating_add(1);
        } else {
            groups = groups.saturating_add(1);
        }
    }
    cx.emit(
        Node::new("Root group")
            .span(file.sub(root, count.saturating_add(1).saturating_mul(8)))
            .summary(format!("{count} children: {groups} groups, {data} data")),
    );
    cx.annotate(format!(
        "Alembic (Ogawa) archive, root with {count} children"
    ));
    Ok(())
}
