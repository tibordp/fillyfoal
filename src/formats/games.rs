//! Game data: lump archives, maps and models from id Software, Valve and Epic
//! engines.

use crate::bytes::{to_u64, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::{Head, Input, Probe, embedded};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::Value;

const LE: Endian = Endian::Little;

// ---------------------------------------------------------------------------
// Doom WAD (IWAD/PWAD)

declare_format!(pub WAD = "wad", "Doom WAD", ["wad"], "application/x-doom",
    Probe::Magic(&[(0, b"IWAD"), (0, b"PWAD")]), wad);

record! {
    pub struct WadHeader {
        magic: ascii[4] "Identification" .desc("IWAD (game data) or PWAD (patch)"),
        lumps: u32 "Number of lumps",
        directory: u32 "Directory offset" .hex(),
    }
}

record! {
    pub struct WadEntry {
        offset: u32 "Lump offset" .hex(),
        size: u32 "Lump size",
        name: ascii[8] "Name",
    }
}

async fn wad(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: WadHeader = read_record(&cx, file.sub(0, WadHeader::SIZE), LE).await?;
    cx.emit(WadHeader::node("Header", file.sub(0, WadHeader::SIZE), LE));
    let dir = file.sub_exact(
        h.directory.into(),
        u64::from(h.lumps).saturating_mul(WadEntry::SIZE),
    )?;
    cx.emit(
        Node::new("Directory")
            .span(dir)
            .summary(format!("{} lumps", h.lumps))
            .lazy(wad_directory, (input, dir)),
    );
    cx.annotate(format!("{}, {} lumps", h.magic, h.lumps));
    Ok(())
}

async fn wad_directory(cx: Cx, (input, dir): (Input, Span)) -> Result<()> {
    let count = dir.len / WadEntry::SIZE;
    cx.set_count(Count::Exact(count));
    let mut cur = Cursor::new(&cx, dir, LE);
    for _ in 0..count {
        let (e, span) = cur.record::<WadEntry>().await?;
        let data = input.span.sub(e.offset.into(), e.size.into());
        let node = if e.size == 0 {
            Node::new(e.name.clone()).summary("marker")
        } else {
            embedded(e.name.clone(), input.nested(data)).summary(format!("{} bytes", e.size))
        };
        cx.push(node.span(span).target(data)).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Quake PAK

declare_format!(pub PAK = "quake-pak", "Quake PAK archive", ["pak"], "application/x-quake-pak",
    Probe::Magic(&[(0, b"PACK")]), pak);

record! {
    pub struct PakHeader {
        magic: ascii[4] "Magic",
        offset: u32 "Directory offset" .hex(),
        size: u32 "Directory size",
    }
}

record! {
    pub struct PakEntry {
        name: ascii[56] "Name",
        offset: u32 "Offset" .hex(),
        size: u32 "Size",
    }
}

async fn pak(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: PakHeader = read_record(&cx, file.sub(0, PakHeader::SIZE), LE).await?;
    cx.emit(PakHeader::node("Header", file.sub(0, PakHeader::SIZE), LE));
    let dir = file.sub_exact(h.offset.into(), h.size.into())?;
    let count = dir.len / PakEntry::SIZE;
    cx.set_count(Count::Exact(count.saturating_add(1)));
    let mut cur = Cursor::new(&cx, dir, LE);
    for _ in 0..count {
        let (e, span) = cur.record::<PakEntry>().await?;
        let data = file.sub(e.offset.into(), e.size.into());
        cx.push(
            embedded(e.name.clone(), input.nested(data))
                .summary(format!("{} bytes", e.size))
                .target(span),
        )
        .await;
    }
    cx.annotate(format!("{count} files"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Quake / Half-Life texture WADs (WAD2, WAD3)

declare_format!(pub WAD2 = "wad2", "Quake / Half-Life texture WAD", ["wad"], "application/x-wad",
    Probe::Magic(&[(0, b"WAD2"), (0, b"WAD3")]), wad2);

record! {
    pub struct Wad2Entry {
        offset: u32 "Offset" .hex(),
        disk_size: u32 "Size on disk",
        size: u32 "Uncompressed size",
        kind: u8 "Type" .enumeration(&[(0x40, "palette"), (0x42, "qpic"), (0x43, "miptex (WAD3)"), (0x44, "miptex"), (0x45, "font")]),
        compression: u8 "Compression",
        _padding: u16 "Padding",
        name: ascii[16] "Name",
    }
}

async fn wad2(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: WadHeader = read_record(&cx, file.sub(0, WadHeader::SIZE), LE).await?;
    cx.emit(WadHeader::node("Header", file.sub(0, WadHeader::SIZE), LE));
    let dir = file.sub_exact(
        h.directory.into(),
        u64::from(h.lumps).saturating_mul(Wad2Entry::SIZE),
    )?;
    cx.set_count(Count::Exact(u64::from(h.lumps).saturating_add(1)));
    let mut cur = Cursor::new(&cx, dir, LE);
    for _ in 0..h.lumps {
        let (e, span) = cur.record::<Wad2Entry>().await?;
        let data = file.sub(e.offset.into(), e.disk_size.into());
        cx.push(
            Wad2Entry::node(e.name.clone(), span, LE)
                .summary(format!("{} bytes", e.size))
                .target(data),
        )
        .await;
    }
    cx.annotate(format!("{}, {} entries", h.magic, h.lumps));
    Ok(())
}

// ---------------------------------------------------------------------------
// Valve VPK

declare_format!(pub VPK = "vpk", "Valve pak (VPK)", ["vpk"], "application/x-vpk",
    Probe::Magic(&[(0, b"\x34\x12\xaa\x55")]), vpk);

record! {
    pub struct VpkHeader {
        signature: u32 "Signature" .hex(),
        version: u32 "Version",
        tree_size: u32 "Directory tree size",
    }
}

async fn vpk(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: VpkHeader = read_record(&cx, file.sub(0, VpkHeader::SIZE), LE).await?;
    let header_len = if h.version == 2 { 28 } else { 12 };
    cx.emit(VpkHeader::node("Header", file.sub(0, header_len), LE));
    let tree = file.sub(header_len, h.tree_size.into());
    cx.emit(
        Node::new("Directory tree")
            .span(tree)
            .lazy(vpk_tree, (input, tree)),
    );
    cx.annotate(format!("VPK v{}", h.version));
    Ok(())
}

/// The tree is: extension, path, file name (each NUL-terminated, each level
/// ending with an empty string), then a 18-byte entry per file.
async fn vpk_tree(cx: Cx, (input, tree): (Input, Span)) -> Result<()> {
    let mut cur = Cursor::new(&cx, tree, LE);
    loop {
        let (ext, _) = cur.cstr(256).await?;
        if ext.is_empty() {
            break;
        }
        loop {
            let (path, _) = cur.cstr(1024).await?;
            if path.is_empty() {
                break;
            }
            loop {
                let start = cur.pos();
                let (name, _) = cur.cstr(256).await?;
                if name.is_empty() {
                    break;
                }
                let _crc = cur.u32().await?;
                let preload = cur.u16().await?;
                let archive = cur.u16().await?;
                let offset = cur.u32().await?;
                let length = cur.u32().await?;
                let _terminator = cur.u16().await?;
                let preload_span = cur.span(preload.into());
                cur.skip(preload.into());
                let full = if path == " " {
                    format!("{name}.{ext}")
                } else {
                    format!("{path}/{name}.{ext}")
                };
                let node = if archive == 0x7fff {
                    // Stored in this file, after the tree.
                    let data = input.span.sub(
                        tree.offset
                            .saturating_sub(input.span.offset)
                            .saturating_add(tree.len)
                            .saturating_add(offset.into()),
                        length.into(),
                    );
                    embedded(full, input.nested(data)).summary(format!("{length} bytes"))
                } else if preload > 0 {
                    embedded(full, input.nested(preload_span))
                        .summary(format!("{preload} preloaded bytes"))
                } else {
                    Node::new(full).summary(format!("{length} bytes in archive {archive:03}"))
                };
                cx.push(node.target(cur.since(start))).await;
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// BSP maps

fn quake1_bsp(h: &Head<'_>) -> bool {
    // Version 29, then 15 lump entries whose offsets lie within the file.
    h.at(0, b"\x1d\x00\x00\x00")
        && (0..15usize).all(|i| {
            let at = 4usize.saturating_add(i.saturating_mul(8));
            let offset = u32_le(h.data, at).unwrap_or(u32::MAX);
            let size = u32_le(h.data, at.saturating_add(4)).unwrap_or(u32::MAX);
            u64::from(offset).saturating_add(size.into()) <= h.len
        })
}

declare_format!(pub BSP = "bsp", "Quake / Quake II / Quake III / Source map", ["bsp"], "application/x-bsp",
    Probe::Custom(|h| h.starts_with(b"IBSP") || h.starts_with(b"VBSP") || h.starts_with(b"RBSP") || quake1_bsp(h)), bsp);

const Q1_LUMPS: [&str; 15] = [
    "entities",
    "planes",
    "textures",
    "vertexes",
    "visibility",
    "nodes",
    "texinfo",
    "faces",
    "lighting",
    "clipnodes",
    "leafs",
    "marksurfaces",
    "edges",
    "surfedges",
    "models",
];
const Q2_LUMPS: [&str; 19] = [
    "entities",
    "planes",
    "vertices",
    "visibility",
    "nodes",
    "texinfo",
    "faces",
    "lighting",
    "leafs",
    "leaf faces",
    "leaf brushes",
    "edges",
    "surface edges",
    "models",
    "brushes",
    "brush sides",
    "pop",
    "areas",
    "area portals",
];
const Q3_LUMPS: [&str; 17] = [
    "entities",
    "shaders",
    "planes",
    "nodes",
    "leafs",
    "leaf surfaces",
    "leaf brushes",
    "models",
    "brushes",
    "brush sides",
    "draw vertices",
    "draw indices",
    "fogs",
    "surfaces",
    "lightmaps",
    "light grid",
    "visibility",
];

async fn bsp(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 8)).await?;
    let magic = head.get(..4).unwrap_or_default();
    let version = u32_le(&head, 4).unwrap_or(0);
    let (kind, names, table, source): (&str, &[&str], u64, bool) = match magic {
        b"IBSP" if version == 38 => ("Quake II", &Q2_LUMPS, 8, false),
        b"IBSP" | b"RBSP" => ("Quake III", &Q3_LUMPS, 8, false),
        b"VBSP" => ("Source", &[], 8, true),
        _ => ("Quake", &Q1_LUMPS, 4, false),
    };
    cx.emit(
        Node::new("Header")
            .span(file.sub(0, table))
            .summary(format!(
                "{kind} BSP version {}",
                if table == 4 {
                    u32_le(&head, 0).unwrap_or(0)
                } else {
                    version
                }
            )),
    );
    let count = if source { 64u64 } else { to_u64(names.len()) };
    let entry = if source { 16u64 } else { 8 };
    let lumps = cx
        .read(file.sub(table, count.saturating_mul(entry)))
        .await?;
    let mut entities = None;
    for i in 0..count {
        let at = crate::bytes::to_usize(i.saturating_mul(entry));
        let offset = u32_le(&lumps, at).unwrap_or(0);
        let size = u32_le(&lumps, at.saturating_add(4)).unwrap_or(0);
        if source && size == 0 {
            continue;
        }
        let name = names
            .get(crate::bytes::to_usize(i))
            .map_or_else(|| format!("lump {i}"), |n| (*n).to_owned());
        let data = file.sub(offset.into(), size.into());
        if i == 0 {
            entities = Some(data);
        }
        cx.emit(Node::new(name).span(data).summary(format!("{size} bytes")));
    }
    if let Some(span) = entities {
        let text = cx.read_avail(span.sub(0, 1 << 16)).await?;
        let count = text.iter().filter(|&&b| b == b'{').count();
        cx.annotate(format!("{kind} map, {count} entities"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Quake models

declare_format!(pub MDL = "quake-mdl", "Quake model", ["mdl"], "model/x-quake-mdl",
    Probe::Magic(&[(0, b"IDPO")]), mdl);
declare_format!(pub MD2 = "md2", "Quake II model", ["md2"], "model/x-md2",
    Probe::Magic(&[(0, b"IDP2")]), md2);
declare_format!(pub MD3 = "md3", "Quake III model", ["md3"], "model/x-md3",
    Probe::Magic(&[(0, b"IDP3")]), md3);

record! {
    pub struct MdlHeader {
        magic: ascii[4] "Magic",
        version: u32 "Version",
        scale: bytes[12] "Scale (3 × f32)",
        translate: bytes[12] "Translation (3 × f32)",
        radius: f32 "Bounding radius",
        eye: bytes[12] "Eye position (3 × f32)",
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

async fn mdl(cx: Cx, input: Input) -> Result<()> {
    let h: MdlHeader = read_record(&cx, input.span.sub(0, MdlHeader::SIZE), LE).await?;
    cx.emit(MdlHeader::node(
        "Header",
        input.span.sub(0, MdlHeader::SIZE),
        LE,
    ));
    cx.annotate(format!(
        "{} vertices, {} triangles, {} frames",
        h.vertices, h.triangles, h.frames
    ));
    Ok(())
}

record! {
    pub struct Md2Header {
        magic: ascii[4] "Magic",
        version: u32 "Version",
        skin_width: u32 "Skin width",
        skin_height: u32 "Skin height",
        frame_size: u32 "Frame size",
        skins: u32 "Skins",
        vertices: u32 "Vertices",
        st: u32 "Texture coordinates",
        triangles: u32 "Triangles",
        gl_commands: u32 "GL commands",
        frames: u32 "Frames",
        skins_offset: u32 "Skins offset" .hex(),
        st_offset: u32 "Texture coordinates offset" .hex(),
        triangles_offset: u32 "Triangles offset" .hex(),
        frames_offset: u32 "Frames offset" .hex(),
        gl_offset: u32 "GL commands offset" .hex(),
        end: u32 "End offset" .hex(),
    }
}

async fn md2(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: Md2Header = read_record(&cx, file.sub(0, Md2Header::SIZE), LE).await?;
    cx.emit(Md2Header::node("Header", file.sub(0, Md2Header::SIZE), LE));
    let skins = file.sub(h.skins_offset.into(), u64::from(h.skins).saturating_mul(64));
    cx.emit(Node::new("Skins").span(skins).lazy(md2_skins, skins));
    cx.emit(Node::new("Frames").span(file.sub(
        h.frames_offset.into(),
        u64::from(h.frames).saturating_mul(h.frame_size.into()),
    )));
    cx.annotate(format!(
        "{} vertices, {} triangles, {} frames",
        h.vertices, h.triangles, h.frames
    ));
    Ok(())
}

async fn md2_skins(cx: Cx, span: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, LE);
    while cur.remaining() >= 64 {
        let at = cur.span(64);
        let name = crate::text::until_nul(&cur.bytes(64).await?);
        cx.push(Node::new(name).span(at)).await;
    }
    Ok(())
}

record! {
    pub struct Md3Header {
        magic: ascii[4] "Magic",
        version: u32 "Version",
        name: ascii[64] "Name",
        flags: u32 "Flags" .hex(),
        frames: u32 "Frames",
        tags: u32 "Tags",
        surfaces: u32 "Surfaces",
        skins: u32 "Skins",
        frames_offset: u32 "Frames offset" .hex(),
        tags_offset: u32 "Tags offset" .hex(),
        surfaces_offset: u32 "Surfaces offset" .hex(),
        end: u32 "End offset" .hex(),
    }
}

async fn md3(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: Md3Header = read_record(&cx, file.sub(0, Md3Header::SIZE), LE).await?;
    cx.emit(Md3Header::node("Header", file.sub(0, Md3Header::SIZE), LE));
    // Surfaces form a chain: each records its own end offset.
    let mut at = u64::from(h.surfaces_offset);
    for _ in 0..h.surfaces.min(4096) {
        let header = cx.read(file.sub(at, 108)).await?;
        if !header.starts_with(b"IDP3") {
            cx.diag(Diagnostic::malformed("expected a surface").at(file.sub(at, 4)));
            break;
        }
        let name = crate::text::until_nul(header.get(4..68).unwrap_or_default());
        let end = u64::from(u32_le(&header, 104).unwrap_or(0));
        let verts = u32_le(&header, 88).unwrap_or(0);
        let tris = u32_le(&header, 92).unwrap_or(0);
        cx.push(
            Node::new(name)
                .span(file.sub(at, end))
                .summary(format!("{verts} vertices, {tris} triangles")),
        )
        .await;
        if end == 0 {
            break;
        }
        at = at.saturating_add(end);
    }
    cx.annotate(format!(
        "{:?}, {} surfaces, {} frames",
        h.name.trim_end(),
        h.surfaces,
        h.frames
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Unreal packages

declare_format!(pub UNREAL = "unreal-package", "Unreal Engine package", ["u", "upk", "uasset", "umap", "utx", "uax", "unr"],
    "application/x-unreal-package", Probe::Magic(&[(0, b"\xc1\x83\x2a\x9e")]), unreal);

async fn unreal(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 8)).await?;
    let version = u32_le(&head, 4).unwrap_or(0);
    let legacy = version & 0xffff;
    let licensee = version >> 16;
    // Since UE4 the second field is a negative "legacy file version".
    if (version as i32) < 0 {
        cx.emit(Node::new("Tag").span(file.sub(0, 4)));
        cx.emit(
            Node::new("Legacy file version")
                .span(file.sub(4, 4))
                .value(Value::Int {
                    value: (version as i32).into(),
                    bits: 32,
                }),
        );
        cx.annotate(format!(
            "Unreal Engine 4/5 package (legacy version {})",
            version as i32
        ));
        return Ok(());
    }
    let table = cx.read(file.sub(8, 28)).await?;
    cx.emit(Node::new("Tag").span(file.sub(0, 4)));
    cx.emit(
        Node::new("File version")
            .span(file.sub(4, 2))
            .value(Value::UInt {
                value: legacy.into(),
                bits: 16,
                radix: crate::value::Radix::Dec,
            }),
    );
    cx.emit(
        Node::new("Licensee version")
            .span(file.sub(6, 2))
            .value(Value::UInt {
                value: licensee.into(),
                bits: 16,
                radix: crate::value::Radix::Dec,
            }),
    );
    let field = |at: usize| u32_le(&table, at).unwrap_or(0);
    let offset = if legacy >= 249 { 4usize } else { 0 };
    let names = (
        field(offset.saturating_add(4)),
        field(offset.saturating_add(8)),
    );
    let exports = (
        field(offset.saturating_add(12)),
        field(offset.saturating_add(16)),
    );
    let imports = (
        field(offset.saturating_add(20)),
        field(offset.saturating_add(24)),
    );
    cx.emit(
        Node::new("Name table")
            .summary(format!("{} names at {:#x}", names.0, names.1))
            .span(file.tail(names.1.into()).sub(0, 0)),
    );
    cx.emit(
        Node::new("Export table").summary(format!("{} exports at {:#x}", exports.0, exports.1)),
    );
    cx.emit(
        Node::new("Import table").summary(format!("{} imports at {:#x}", imports.0, imports.1)),
    );
    cx.annotate(format!(
        "Unreal package v{legacy}, {} names, {} exports",
        names.0, exports.0
    ));
    Ok(())
}
