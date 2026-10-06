//! Game and real-time 3D models: DirectX `.x`, MilkShape 3D, Cal3D, Ogre
//! meshes, Gamebryo NIF, id Tech sprites and models, and Source engine VVD
//! and DMX.

use crate::bytes::{to_u64, u16_le, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{ChunkLayout, Cursor, Record, emit_record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::text::scan::head_lines;
use crate::formats::{Head, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{Radix, Value};

const LE: Endian = Endian::Little;

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

/// The text up to the first newline in `span` (or all of it), and its span.
async fn line_at(cx: &Cx, span: Span) -> Result<(String, Span)> {
    let b = cx.read_avail(span).await?;
    let end = b.iter().position(|&c| c == b'\n').unwrap_or(b.len());
    let line = String::from_utf8_lossy(b.get(..end).unwrap_or_default()).into_owned();
    Ok((line, span.sub(0, to_u64(end))))
}

// ---------------------------------------------------------------------------
// DirectX .x

declare_format!(pub DIRECTX_X = "directx-x", "DirectX model (.x)", ["x"], "model/x-directx",
    Probe::Magic(&[(0, b"xof 03")]), directx_x);

async fn directx_x(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 16)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 4).emit()?;
    let version = f.ascii("Version", 4).emit()?;
    let format = f.ascii("Format", 4).emit()?;
    let float = f.ascii("Float size", 4).emit()?;
    let mut templates = Vec::new();
    if format.trim() == "txt" {
        let body = cx.read_avail(file.sub(16, 1 << 16)).await?;
        // Top-level objects: an identifier at brace depth 0 followed by `{`.
        let mut depth = 0i32;
        let mut word = String::new();
        for &b in &body {
            match b {
                b'{' => {
                    if depth == 0 && !word.is_empty() && templates.len() < 64 {
                        templates.push(
                            word.split_whitespace()
                                .next()
                                .unwrap_or_default()
                                .to_owned(),
                        );
                    }
                    depth = depth.saturating_add(1);
                    word.clear();
                }
                b'}' => {
                    depth = depth.saturating_sub(1);
                    word.clear();
                }
                b';' | b'\n' if depth == 0 => word.clear(),
                _ if depth == 0 && (b.is_ascii_alphanumeric() || b == b'_' || b == b' ') => {
                    word.push(char::from(b))
                }
                _ => {}
            }
        }
        cx.emit(
            Node::new("Objects")
                .span(file.tail(16))
                .summary(templates.join(", ")),
        );
    } else {
        cx.emit(
            Node::new("Data")
                .span(file.tail(16))
                .summary(format.trim().to_owned()),
        );
    }
    cx.annotate(format!(
        "DirectX model {}.{} ({}, {}-bit floats){}",
        version.get(..2).unwrap_or("?"),
        version.get(2..).unwrap_or("?"),
        format.trim(),
        float,
        if templates.is_empty() {
            String::new()
        } else {
            format!(": {}", templates.join(", "))
        }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// MilkShape 3D

declare_format!(pub MS3D = "milkshape", "MilkShape 3D model", ["ms3d"], "model/x-ms3d",
    Probe::Magic(&[(0, b"MS3D000000")]), milkshape);

async fn milkshape(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, LE);
    cur.skip(10);
    let version = cur.u32().await?;
    cx.emit(Node::new("Signature").span(file.sub(0, 10)));
    cx.emit(
        Node::new("Version")
            .span(file.sub(10, 4))
            .value(uint(version.into(), 32)),
    );
    let at = cur.pos();
    let vertices = u64::from(cur.u16().await?);
    cur.skip(vertices.saturating_mul(15));
    cx.emit(
        Node::new("Vertices")
            .span(cur.since(at))
            .summary(format!("{vertices} × 15 bytes")),
    );
    let at = cur.pos();
    let triangles = u64::from(cur.u16().await?);
    cur.skip(triangles.saturating_mul(70));
    cx.emit(
        Node::new("Triangles")
            .span(cur.since(at))
            .summary(format!("{triangles} × 70 bytes")),
    );
    let at = cur.pos();
    let groups = cur.u16().await?;
    let mut names = Vec::new();
    for _ in 0..groups {
        let g = cur.pos();
        cur.skip(1);
        let name = zstr(&cur.bytes(32).await?);
        let n = u64::from(cur.u16().await?);
        cur.skip(n.saturating_mul(2).saturating_add(1));
        names.push(name.clone());
        let _ = g;
    }
    cx.emit(
        Node::new("Groups")
            .span(cur.since(at))
            .summary(names.join(", ")),
    );
    let at = cur.pos();
    let materials = u64::from(cur.u16().await?);
    cur.skip(materials.saturating_mul(361));
    cx.emit(
        Node::new("Materials")
            .span(cur.since(at))
            .summary(format!("{materials} × 361 bytes")),
    );
    if cur.remaining() >= 14 {
        let at = cur.pos();
        cur.skip(12);
        let joints = cur.u16().await?;
        cx.emit(
            Node::new("Animation and joints")
                .span(file.tail(at))
                .summary(format!("{joints} joints")),
        );
    }
    cx.annotate(format!("MilkShape 3D v{version}: {vertices} vertices, {triangles} triangles, {groups} groups, {materials} materials"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Cal3D

declare_format!(pub CAL3D = "cal3d", "Cal3D binary file", ["cmf", "csf", "caf", "crf"], "model/x-cal3d",
    Probe::Magic(&[(0, b"CMF\0"), (0, b"CSF\0"), (0, b"CAF\0"), (0, b"CRF\0")]), cal3d);

async fn cal3d(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 16)).await?;
    let kind = head.get(1).copied().unwrap_or(0);
    let version = u32_le(&head, 4).unwrap_or(0);
    cx.emit(Node::new("Signature").span(file.sub(0, 4)));
    cx.emit(
        Node::new("Version")
            .span(file.sub(4, 4))
            .value(uint(version.into(), 32)),
    );
    let (what, detail) = match kind {
        b'M' => (
            "mesh",
            format!("{} submeshes", u32_le(&head, 8).unwrap_or(0)),
        ),
        b'S' => (
            "skeleton",
            format!("{} bones", u32_le(&head, 8).unwrap_or(0)),
        ),
        b'A' => (
            "animation",
            format!(
                "{:.2} s, {} tracks",
                f32::from_bits(u32_le(&head, 8).unwrap_or(0)),
                u32_le(&head, 12).unwrap_or(0)
            ),
        ),
        _ => ("material", "colours, shininess and maps".to_owned()),
    };
    cx.emit(Node::new("Body").span(file.tail(8)).summary(detail.clone()));
    cx.annotate(format!("Cal3D {what} v{version}, {detail}"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Ogre

fn ogre_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"\x00\x10[MeshSerializer_") || h.starts_with(b"\x00\x10[Serializer_v")
}

declare_format!(pub OGRE = "ogre-mesh", "OGRE binary mesh or skeleton", ["mesh", "skeleton"], "model/x-ogre",
    Probe::Custom(ogre_probe), ogre);

fn ogre_chunk(id: u16) -> &'static str {
    match id {
        0x3000 => "Mesh",
        0x4000 => "Submesh",
        0x5000 => "Geometry",
        0x6000 => "Skeleton link",
        0x7000 => "Bone assignment",
        0x8000 => "LOD",
        0x9000 => "Bounds",
        0xa000 => "Submesh name table",
        0xb000 => "Edge lists",
        0xc000 => "Poses",
        0xd000 => "Animations",
        0xe000 => "Table extremes",
        0x1000 => "Header",
        0x2000 => "Bone",
        0x3001 => "Bone parent",
        0x4001 => "Skeleton animation",
        _ => "Chunk",
    }
}

async fn ogre(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let (version, span) = line_at(&cx, file.sub(2, 64)).await?;
    cx.emit(
        Node::new("Header")
            .span(file.sub(0, span.len.saturating_add(3)))
            .value(text(version.clone())),
    );
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(span.len.saturating_add(3));
    let mut n = 0u32;
    while let Some(chunk) = cur.chunk(ChunkLayout::new(2, 4, LE).inclusive()).await? {
        let id = u16_le(&chunk.id, 0).unwrap_or(0);
        cx.push(
            Node::new(ogre_chunk(id))
                .span(chunk.span)
                .summary(format!("id {id:#06x}, {} bytes", chunk.body.len)),
        )
        .await;
        n = n.saturating_add(1);
    }
    cx.annotate(format!("OGRE {version}, {n} top-level chunks"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Gamebryo / NetImmerse NIF

fn nif_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"Gamebryo File Format, Version ")
        || h.starts_with(b"NetImmerse File Format, Version")
}

declare_format!(pub NIF = "nif", "Gamebryo/NetImmerse model (NIF)", ["nif", "kf", "kfm", "nifcache"], "model/x-nif",
    Probe::Custom(nif_probe), nif);

async fn short_string(cur: &mut Cursor<'_>) -> Result<(String, Span)> {
    let len = u64::from(cur.u8().await?);
    let span = cur.span(len);
    Ok((zstr(&cur.bytes(len).await?), span))
}

async fn nif(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let (header, span) = line_at(&cx, file.sub(0, 128)).await?;
    cx.emit(
        Node::new("Header string")
            .span(span)
            .value(text(header.clone())),
    );
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(span.len.saturating_add(1));
    let at = cur.pos();
    let version = cur.u32().await?;
    let dotted = format!(
        "{}.{}.{}.{}",
        version >> 24,
        (version >> 16) & 0xff,
        (version >> 8) & 0xff,
        version & 0xff
    );
    cx.emit(
        Node::new("Version")
            .span(cur.since(at))
            .value(text(dotted.clone())),
    );
    if version < 0x1402_0005 {
        cx.emit(
            Node::new("Header and blocks")
                .span(file.tail(cur.pos()))
                .diag(Diagnostic::unsupported(
                    "block sizes are recorded only from version 20.2.0.5",
                )),
        );
        cx.annotate(format!("NIF {dotted}"));
        return Ok(());
    }
    let at = cur.pos();
    let endian = cur.u8().await?;
    cx.emit(
        Node::new("Endianness")
            .span(cur.since(at))
            .value(text(if endian == 0 { "big" } else { "little" })),
    );
    let at = cur.pos();
    let user = cur.u32().await?;
    cx.emit(
        Node::new("User version")
            .span(cur.since(at))
            .value(uint(user.into(), 32)),
    );
    let at = cur.pos();
    let blocks = cur.u32().await?;
    cx.emit(
        Node::new("Blocks")
            .span(cur.since(at))
            .value(uint(blocks.into(), 32)),
    );
    let mut game = String::new();
    if user >= 3 {
        // Bethesda stream header.
        let at = cur.pos();
        let bs = cur.u32().await?;
        let (author, _) = short_string(&mut cur).await?;
        if bs > 130 {
            cur.skip(4);
        }
        if bs < 131 {
            short_string(&mut cur).await?;
        }
        short_string(&mut cur).await?;
        if bs >= 103 {
            short_string(&mut cur).await?;
        }
        game = match bs {
            34 => "Oblivion",
            83 => "Skyrim",
            100 => "Skyrim SE",
            130 => "Fallout 4",
            155 => "Fallout 76",
            172 => "Starfield",
            _ => "Bethesda",
        }
        .to_owned();
        cx.emit(
            Node::new("Bethesda header")
                .span(cur.since(at))
                .summary(format!("BS version {bs} ({game}), author {author:?}")),
        );
    }
    let at = cur.pos();
    let ntypes = cur.u16().await?;
    let mut types = Vec::new();
    for _ in 0..ntypes {
        let l = u64::from(cur.u32().await?);
        types.push(String::from_utf8_lossy(&cur.bytes(l.min(1 << 10)).await?).into_owned());
    }
    cx.emit(Node::new("Block types").span(cur.since(at)).summary(
        format!("{ntypes}: {}", types.iter().take(12).cloned().collect::<Vec<_>>().join(", ")),
    ));
    let n = u64::from(blocks);
    let index = cur.bytes(n.saturating_mul(2)).await?;
    let sizes = cur.bytes(n.saturating_mul(4)).await?;
    let at = cur.pos();
    let strings = cur.u32().await?;
    cur.skip(4);
    for _ in 0..strings {
        let l = u64::from(cur.u32().await?);
        cur.skip(l);
    }
    let groups = cur.u32().await?;
    cur.skip(u64::from(groups).saturating_mul(4));
    cx.emit(
        Node::new("String table and groups")
            .span(cur.since(at))
            .summary(format!("{strings} strings")),
    );
    let mut pos = cur.pos();
    for i in 0..usize::try_from(blocks).unwrap_or(0) {
        let t = u16_le(&index, i.saturating_mul(2)).unwrap_or(0) & 0x7fff;
        let size = u64::from(u32_le(&sizes, i.saturating_mul(4)).unwrap_or(0));
        let kind = types
            .get(usize::from(t))
            .cloned()
            .unwrap_or_else(|| format!("type {t}"));
        cx.push(
            Node::new(format!("{i}: {kind}"))
                .span(file.sub(pos, size))
                .summary(format!("{size} bytes")),
        )
        .await;
        pos = pos.saturating_add(size);
    }
    cx.annotate(format!(
        "NIF {dotted}{}, {blocks} blocks",
        if game.is_empty() {
            String::new()
        } else {
            format!(" ({game})")
        }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// id Tech: sprites (SPR/SP2) and RtCW/Quake 3 derived models, Hexen II

declare_format!(pub QUAKE_SPR = "quake-spr", "Quake / Half-Life sprite (SPR)", ["spr"], "image/x-quake-spr",
    Probe::Magic(&[(0, b"IDSP\x01\0\0\0"), (0, b"IDSP\x02\0\0\0")]), quake_spr);

async fn quake_spr(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let hl = cx.read(file.sub(4, 1)).await?.first() == Some(&2);
    let len = if hl { 40 } else { 36 };
    let head = cx.block(file.sub(0, len)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 4).emit()?;
    f.u32("Version").emit()?;
    let kind = f
        .u32("Orientation")
        .enumeration(&[
            (0, "parallel upright"),
            (1, "facing upright"),
            (2, "parallel"),
            (3, "oriented"),
            (4, "parallel oriented"),
        ])
        .emit()?;
    if hl {
        f.u32("Texture format")
            .enumeration(&[
                (0, "normal"),
                (1, "additive"),
                (2, "index alpha"),
                (3, "alpha test"),
            ])
            .emit()?;
    }
    f.f32("Bounding radius").emit()?;
    let w = f.u32("Maximum width").emit()?;
    let h = f.u32("Maximum height").emit()?;
    let frames = f.u32("Frames").emit()?;
    f.f32("Beam length").emit()?;
    f.u32("Sync type").emit()?;
    let _ = kind;
    cx.emit(Node::new(if hl { "Palette and frames" } else { "Frames" }).span(file.tail(len)));
    cx.annotate(format!(
        "{} sprite, {frames} frames, up to {w}×{h}",
        if hl { "Half-Life" } else { "Quake" }
    ));
    Ok(())
}

declare_format!(pub QUAKE2_SP2 = "quake2-sp2", "Quake II sprite (SP2)", ["sp2"], "image/x-quake2-sp2",
    Probe::Magic(&[(0, b"IDS2")]), sp2);

async fn sp2(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 12)).await?;
    let frames = u32_le(&head, 8).unwrap_or(0);
    cx.emit(Node::new("Signature").span(file.sub(0, 4)));
    cx.emit(
        Node::new("Version")
            .span(file.sub(4, 4))
            .value(uint(u32_le(&head, 4).unwrap_or(0).into(), 32)),
    );
    cx.emit(
        Node::new("Frames")
            .span(file.sub(8, 4))
            .value(uint(frames.into(), 32)),
    );
    for i in 0..u64::from(frames.min(1024)) {
        let at = 12u64.saturating_add(i.saturating_mul(80));
        let fr = cx.read(file.sub_exact(at, 80)?).await?;
        let name = zstr(fr.get(16..80).unwrap_or_default());
        cx.push(Node::new(name).span(file.sub(at, 80)).summary(format!(
            "{}×{}",
            u32_le(&fr, 0).unwrap_or(0),
            u32_le(&fr, 4).unwrap_or(0)
        )))
        .await;
    }
    cx.annotate(format!("Quake II sprite, {frames} frames"));
    Ok(())
}

record! {
    pub struct MdcHeader {
        ident: ascii[4] "Signature",
        version: u32 "Version",
        name: ascii[64] "Name",
        flags: u32 "Flags" .hex(),
        frames: u32 "Frames",
        tags: u32 "Tags",
        surfaces: u32 "Surfaces",
        skins: u32 "Skins",
        ofs_frames: u32 "Frames offset" .hex(),
        ofs_tag_names: u32 "Tag names offset" .hex(),
        ofs_tags: u32 "Tags offset" .hex(),
        ofs_surfaces: u32 "Surfaces offset" .hex(),
        ofs_end: u32 "End offset" .hex(),
    }
}

record! {
    pub struct MdsHeader {
        ident: ascii[4] "Signature",
        version: u32 "Version",
        name: ascii[64] "Name",
        lod_scale: f32 "LOD scale",
        lod_bias: f32 "LOD bias",
        frames: u32 "Frames",
        bones: u32 "Bones",
        ofs_frames: u32 "Frames offset" .hex(),
        ofs_bones: u32 "Bones offset" .hex(),
        torso_parent: u32 "Torso parent",
        surfaces: u32 "Surfaces",
        ofs_surfaces: u32 "Surfaces offset" .hex(),
        tags: u32 "Tags",
        ofs_tags: u32 "Tags offset" .hex(),
        ofs_end: u32 "End offset" .hex(),
    }
}

record! {
    pub struct MdxHeader {
        ident: ascii[4] "Signature",
        version: u32 "Version",
        name: ascii[64] "Name",
        frames: u32 "Frames",
        bones: u32 "Bones",
        ofs_frames: u32 "Frames offset" .hex(),
        ofs_bones: u32 "Bones offset" .hex(),
        torso_parent: u32 "Torso parent",
        ofs_end: u32 "End offset" .hex(),
    }
}

record! {
    pub struct MdmHeader {
        ident: ascii[4] "Signature",
        version: u32 "Version",
        name: ascii[64] "Name",
        lod_scale: f32 "LOD scale",
        lod_bias: f32 "LOD bias",
        surfaces: u32 "Surfaces",
        ofs_surfaces: u32 "Surfaces offset" .hex(),
        tags: u32 "Tags",
        ofs_tags: u32 "Tags offset" .hex(),
        ofs_end: u32 "End offset" .hex(),
    }
}

declare_format!(pub RTCW_MODEL = "rtcw-model", "Return to Castle Wolfenstein / Enemy Territory model", ["mdc", "mds", "mdx", "mdm"], "model/x-rtcw",
    Probe::Magic(&[(0, b"IDPC"), (0, b"MDSW"), (0, b"MDXW"), (0, b"MDMW")]), rtcw_model);

async fn rtcw_model(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let magic = cx.read(file.sub(0, 4)).await?;
    let summary = match magic.as_slice() {
        b"IDPC" => {
            let h: MdcHeader = emit_record(&cx, file.sub(0, MdcHeader::SIZE), LE).await?;
            format!(
                "MDC compressed model {:?}: {} frames, {} surfaces, {} tags",
                h.name, h.frames, h.surfaces, h.tags
            )
        }
        b"MDSW" => {
            let h: MdsHeader = emit_record(&cx, file.sub(0, MdsHeader::SIZE), LE).await?;
            format!(
                "MDS skeletal model {:?}: {} frames, {} bones, {} surfaces",
                h.name, h.frames, h.bones, h.surfaces
            )
        }
        b"MDXW" => {
            let h: MdxHeader = emit_record(&cx, file.sub(0, MdxHeader::SIZE), LE).await?;
            format!(
                "MDX skeletal animation {:?}: {} frames, {} bones",
                h.name, h.frames, h.bones
            )
        }
        _ => {
            let h: MdmHeader = emit_record(&cx, file.sub(0, MdmHeader::SIZE), LE).await?;
            format!(
                "MDM skeletal mesh {:?}: {} surfaces, {} tags",
                h.name, h.surfaces, h.tags
            )
        }
    };
    cx.annotate(summary);
    Ok(())
}

record! {
    pub struct Hexen2Header {
        ident: ascii[4] "Signature",
        version: u32 "Version",
        scale: bytes[12] "Scale",
        translate: bytes[12] "Origin",
        radius: f32 "Bounding radius",
        eye: bytes[12] "Eye position",
        skins: u32 "Skins",
        skin_width: u32 "Skin width",
        skin_height: u32 "Skin height",
        vertices: u32 "Vertices",
        triangles: u32 "Triangles",
        frames: u32 "Frames",
        sync: u32 "Sync type",
        flags: u32 "Flags" .hex(),
        size: f32 "Average size",
    }
}

declare_format!(pub HEXEN2_MDL = "hexen2-mdl", "Hexen II model", ["mdl"], "model/x-hexen2-mdl",
    Probe::Magic(&[(0, b"RAPO")]), hexen2_mdl);

async fn hexen2_mdl(cx: Cx, input: Input) -> Result<()> {
    let h: Hexen2Header = emit_record(&cx, input.span.sub(0, Hexen2Header::SIZE), LE).await?;
    cx.emit(
        Node::new("Skins, vertices, triangles and frames")
            .span(input.span.tail(Hexen2Header::SIZE)),
    );
    cx.annotate(format!(
        "Hexen II model: {} vertices, {} triangles, {} frames, {} skins",
        h.vertices, h.triangles, h.frames, h.skins
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Source engine: VVD vertex data, DMX

declare_format!(pub VVD = "source-vvd", "Source engine vertex data (VVD)", ["vvd"], "model/x-source-vvd",
    Probe::Magic(&[(0, b"IDSV")]), vvd);

async fn vvd(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 64)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 4).emit()?;
    let version = f.u32("Version").emit()?;
    f.u32("Checksum").hex().emit()?;
    let lods = f.u32("LODs").emit()?;
    let mut counts = Vec::new();
    for _ in 0..8 {
        counts.push(f.u32("Vertices in LOD").emit()?);
    }
    let fixups = f.u32("Fixups").emit()?;
    f.u32("Fixup table offset").hex().emit()?;
    let vertex = f.u32("Vertex data offset").hex().emit()?;
    let tangent = f.u32("Tangent data offset").hex().emit()?;
    let n = u64::from(counts.first().copied().unwrap_or(0));
    cx.emit(
        Node::new("Vertices")
            .span(file.sub(vertex.into(), n.saturating_mul(48)))
            .summary(format!("{n} × 48 bytes")),
    );
    cx.emit(Node::new("Tangents").span(file.sub(tangent.into(), n.saturating_mul(16))));
    cx.annotate(format!(
        "Source VVD v{version}: {lods} LODs, {n} vertices, {fixups} fixups"
    ));
    Ok(())
}

declare_format!(pub DMX = "source-dmx", "Valve Data Model Exchange (DMX)", ["dmx", "pcf"], "application/x-dmx",
    Probe::Magic(&[(0, b"<!-- dmx encoding ")]), dmx);

async fn dmx(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let lines = head_lines(&cx, file, 256).await?;
    let (header, span) = lines
        .first()
        .cloned()
        .unwrap_or((String::new(), file.sub(0, 0)));
    let words: Vec<&str> = header.split_whitespace().collect();
    let encoding = words.get(3).copied().unwrap_or("?");
    let enc_version = words.get(4).copied().unwrap_or("?");
    let format = words.get(6).copied().unwrap_or("?");
    let fmt_version = words.get(7).copied().unwrap_or("?");
    cx.emit(Node::new("Header").span(span).value(text(header.clone())));
    cx.emit(
        Node::new("Body")
            .span(file.tail(span.len.saturating_add(1)))
            .summary(format!("{encoding} encoding")),
    );
    cx.annotate(format!(
        "DMX {format} v{fmt_version} ({encoding} encoding v{enc_version})"
    ));
    Ok(())
}
