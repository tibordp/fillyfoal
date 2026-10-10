//! Console game assets: Nintendo (BFRES, BNTX, BYML, MSBT, CGFX, J3D,
//! RARC, BRRES; TPL is in retro::extras), Sony (GIM, GXT, RCO, NPD/EDAT), Xbox (XDBF, XPR,
//! XACT sound and global settings) and Sega (PVR/GVR textures, Ninja
//! chunks).

use crate::bytes::{u16_be, u16_le, u32_be, u32_le, u64_be};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{ChunkLayout, Cursor};
use crate::error::Result;
use crate::fields::{Endian, Fields};
use crate::formats::util::binutil::get;
use crate::formats::util::val::{text, uint};
use crate::formats::{Head, Input, Probe, embedded};
use crate::node::Node;
use crate::text::until_nul;
use crate::value::EnumTable;

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

fn bom(b: &[u8]) -> Endian {
    if b == b"\xfe\xff" { BE } else { LE }
}

// ---------------------------------------------------------------------------
// BFRES (Wii U and Switch)

declare_format!(pub BFRES = "bfres", "Nintendo binary resource (BFRES)", ["bfres"], "application/x-bfres",
    Probe::Magic(&[(0, b"FRES")]), bfres);

const FRES_GROUPS: [&str; 12] = [
    "Models (FMDL)",
    "Textures (FTEX)",
    "Skeletal animations (FSKA)",
    "Shader parameter animations",
    "Colour animations",
    "Texture SRT animations",
    "Texture pattern animations (FTXP)",
    "Bone visibility animations (FVIS)",
    "Material visibility animations",
    "Shape animations (FSHA)",
    "Scene animations (FSCN)",
    "Embedded files",
];

async fn bfres(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 0x68)).await?;
    if head.get(4..8) == Some(b"    ") {
        // Switch: "FRES    ", version, BOM, alignment, address size,
        // file name offset, flags, block offset, relocation table, size.
        let e = bom(head.get(12..14).unwrap_or_default());
        let version = get::<u32>(&head, 8, e).unwrap_or(0);
        cx.emit(Node::new("Signature").span(file.sub(0, 8)));
        cx.emit(
            Node::new("Version")
                .span(file.sub(8, 4))
                .value(text(format!(
                    "{}.{}.{}",
                    version >> 16,
                    (version >> 8) & 0xff,
                    version & 0xff
                ))),
        );
        cx.emit(
            Node::new("Byte order")
                .span(file.sub(12, 2))
                .value(text(if e == BE {
                    "big-endian"
                } else {
                    "little-endian"
                })),
        );
        cx.emit(Node::new("Body").span(file.tail(0x20)));
        cx.annotate(format!(
            "BFRES (Switch) v{}.{}",
            version >> 16,
            (version >> 8) & 0xff
        ));
        return Ok(());
    }
    let e = bom(head.get(8..10).unwrap_or_default());
    let block = cx.block(file.sub(0, 0x68)).await?;
    let mut f = Fields::emitting(&cx, &block, e);
    f.ascii("Signature", 4).emit()?;
    let version = f.u32("Version").hex().emit()?;
    f.u16("Byte-order mark").hex().emit()?;
    f.u16("Header size").emit()?;
    f.u32("File size").emit()?;
    f.u32("Alignment").emit()?;
    let name_rel = f.u32("File name offset (relative)").hex().emit()?;
    f.u32("String table size").emit()?;
    f.u32("String table offset (relative)").hex().emit()?;
    for _ in 0..12 {
        f.u32("Index group offset (relative)").hex().emit()?;
    }
    let mut parts = Vec::new();
    for g in FRES_GROUPS {
        let n = f.u16(g).emit()?;
        if n > 0 {
            parts.push(format!(
                "{n} {}",
                g.split(" (").next().unwrap_or(g).to_lowercase()
            ));
        }
    }
    let name_at = 0x14u64.saturating_add(name_rel.into());
    let (name, _) = cx.cstr(file.sub(name_at, 128)).await?;
    cx.annotate(format!(
        "BFRES (Wii U) {name:?} v{version:#x}: {}",
        parts.join(", ")
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// BNTX (Switch textures)

declare_format!(pub BNTX = "bntx", "Nintendo Switch texture container (BNTX)", ["bntx"], "image/x-bntx",
    Probe::Magic(&[(0, b"BNTX\0\0\0\0")]), bntx);

async fn bntx(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 0x30)).await?;
    let e = bom(head.get(12..14).unwrap_or_default());
    let block = cx.block(file.sub(0, 0x24)).await?;
    let mut f = Fields::emitting(&cx, &block, e);
    f.ascii("Signature", 8).emit()?;
    let version = f.u32("Version").hex().emit()?;
    f.u16("Byte-order mark").hex().emit()?;
    f.u8("Alignment (log2)").emit()?;
    f.u8("Target address size").emit()?;
    f.u32("File name offset").hex().emit()?;
    f.u16("Flags").hex().emit()?;
    f.u16("First block offset").hex().emit()?;
    f.u32("Relocation table offset").hex().emit()?;
    f.u32("File size").emit()?;
    f.ascii("Target", 4).emit()?;
    let textures = get::<u32>(&head, 0x24, e).unwrap_or(0);
    cx.emit(
        Node::new("Textures")
            .span(file.sub(0x24, 4))
            .value(uint(textures, 32)),
    );
    cx.emit(Node::new("Texture info and data").span(file.tail(0x28)));
    cx.annotate(format!(
        "BNTX v{}.{}, {textures} textures",
        version >> 16,
        (version >> 8) & 0xff
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// BYML

fn byml_probe(h: &Head<'_>) -> bool {
    let e = if h.starts_with(b"BY") {
        BE
    } else if h.starts_with(b"YB") {
        LE
    } else {
        return false;
    };
    let version = get::<u16>(h.data, 2, e).unwrap_or(0);
    let keys = get::<u32>(h.data, 4, e).unwrap_or(0);
    (1..=10).contains(&version) && (keys == 0 || (keys >= 16 && u64::from(keys) < h.len))
}

declare_format!(pub BYML = "byml", "Nintendo binary YAML (BYML)", ["byml", "bgyml", "byaml"], "application/x-byml",
    Probe::Custom(byml_probe), byml);

fn byml_type(t: u8) -> &'static str {
    match t {
        0xa0 => "string",
        0xa1 => "binary",
        0xc0 => "array",
        0xc1 => "dictionary",
        0xc2 => "string table",
        0xd0 => "bool",
        0xd1 => "int",
        0xd2 => "float",
        0xd3 => "uint",
        0xd4 => "int64",
        0xd5 => "uint64",
        0xd6 => "double",
        0xff => "null",
        _ => "unknown",
    }
}

async fn byml(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let e = if cx.read(file.sub(0, 2)).await? == b"BY" {
        BE
    } else {
        LE
    };
    let block = cx.block(file.sub(0, 16)).await?;
    let mut f = Fields::emitting(&cx, &block, e);
    f.ascii("Signature", 2).emit()?;
    let version = f.u16("Version").emit()?;
    let keys = f.u32("Key table offset").hex().emit()?;
    let strings = f.u32("String table offset").hex().emit()?;
    let root = f.u32("Root node offset").hex().emit()?;
    let mut key_count = 0u32;
    for (name, at) in [("Key table", keys), ("String table", strings)] {
        if at == 0 {
            continue;
        }
        let h = cx.read(file.sub_exact(at.into(), 4)?).await?;
        let n = get::<u32>(&h, 0, e).unwrap_or(0) & 0xff_ffff;
        if name == "Key table" {
            key_count = n;
        }
        cx.emit(
            Node::new(name)
                .span(file.sub(at.into(), 4))
                .summary(format!(
                    "{} with {n} entries",
                    byml_type(h.first().copied().unwrap_or(0))
                )),
        );
    }
    let mut root_kind = "empty";
    if root != 0 {
        let h = cx.read(file.sub_exact(root.into(), 4)?).await?;
        root_kind = byml_type(h.first().copied().unwrap_or(0));
        let n = get::<u32>(&h, 0, e).unwrap_or(0) & 0xff_ffff;
        cx.emit(
            Node::new("Root node")
                .span(file.sub(root.into(), 4))
                .summary(format!("{root_kind} with {n} entries")),
        );
    }
    cx.annotate(format!(
        "BYML v{version} ({}), root {root_kind}, {key_count} keys",
        if e == BE {
            "big-endian"
        } else {
            "little-endian"
        }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// LibMessageStudio (MSBT/MSBP/MSBF)

declare_format!(pub MSBT = "msbt", "LibMessageStudio file (MSBT/MSBP/MSBF)", ["msbt", "msbp", "msbf"], "application/x-msbt",
    Probe::Magic(&[(0, b"MsgStdBn"), (0, b"MsgPrjBn"), (0, b"MsgFlwBn")]), msbt);

async fn msbt(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 32)).await?;
    let e = bom(head.get(8..10).unwrap_or_default());
    let block = cx.block(file.sub(0, 32)).await?;
    let mut f = Fields::emitting(&cx, &block, e);
    let magic = f.ascii("Signature", 8).emit()?;
    f.u16("Byte-order mark").hex().emit()?;
    f.u16("Reserved").emit()?;
    let encoding = f
        .u8("Encoding")
        .enumeration(&[(0, "UTF-8"), (1, "UTF-16"), (2, "UTF-32")])
        .emit()?;
    let version = f.u8("Version").emit()?;
    let sections = f.u16("Sections").emit()?;
    f.u16("Reserved").emit()?;
    f.u32("File size").emit()?;
    // Sections: id, size, 8 bytes padding, data padded to 16.
    let mut pos = 32u64;
    let mut messages = 0u32;
    for _ in 0..sections {
        let h = cx.read(file.sub_exact(pos, 16)?).await?;
        let id = String::from_utf8_lossy(h.get(..4).unwrap_or_default()).into_owned();
        let size = u64::from(get::<u32>(&h, 4, e).unwrap_or(0));
        let mut node = Node::new(id.clone())
            .span(file.sub(pos, size.saturating_add(16)))
            .summary(format!("{size} bytes"));
        if matches!(id.as_str(), "TXT2" | "LBL1" | "ATR1" | "NLI1" | "TXTW") {
            let c = cx.read(file.sub_exact(pos.saturating_add(16), 4)?).await?;
            let n = get::<u32>(&c, 0, e).unwrap_or(0);
            if id == "TXT2" || id == "TXTW" {
                messages = n;
            }
            node = node.summary(format!("{n} entries, {size} bytes"));
        }
        cx.push(node).await;
        pos = pos
            .saturating_add(16)
            .saturating_add(size)
            .checked_next_multiple_of(16)
            .unwrap_or(u64::MAX);
    }
    let _ = encoding;
    cx.annotate(format!(
        "{magic} v{version}, {sections} sections, {messages} messages"
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// CGFX (3DS)

declare_format!(pub CGFX = "cgfx", "Nintendo 3DS graphics (CGFX/BCRES)", ["bcres", "bcmdl", "bctex", "cgfx"], "model/x-cgfx",
    Probe::Magic(&[(0, b"CGFX\xff\xfe"), (0, b"CGFX\xfe\xff")]), cgfx);

const CGFX_DICTS: [&str; 15] = [
    "Models",
    "Textures",
    "Lookup tables",
    "Materials",
    "Shaders",
    "Cameras",
    "Lights",
    "Fogs",
    "Environments",
    "Skeletal animations",
    "Texture animations",
    "Visibility animations",
    "Camera animations",
    "Light animations",
    "Emitters",
];

async fn cgfx(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 0x14)).await?;
    let e = bom(head.get(4..6).unwrap_or_default());
    let block = cx.block(file.sub(0, 0x14)).await?;
    let mut f = Fields::emitting(&cx, &block, e);
    f.ascii("Signature", 4).emit()?;
    f.u16("Byte-order mark").hex().emit()?;
    let header = f.u16("Header size").emit()?;
    let revision = f.u32("Revision").hex().emit()?;
    f.u32("File size").emit()?;
    f.u32("Blocks").emit()?;
    let data_at = u64::from(header);
    let d = cx
        .read(file.sub_exact(data_at, 8u64.saturating_add(15 * 8))?)
        .await?;
    let mut parts = Vec::new();
    for (i, name) in CGFX_DICTS.iter().enumerate() {
        let n = get::<u32>(&d, 8usize.saturating_add(i.saturating_mul(8)), e).unwrap_or(0);
        if n > 0 {
            parts.push(format!("{n} {}", name.to_lowercase()));
        }
    }
    cx.emit(
        Node::new("DATA")
            .span(file.sub(data_at, u64::from(get::<u32>(&d, 4, e).unwrap_or(0))))
            .summary(parts.join(", ")),
    );
    cx.emit(
        Node::new("Other blocks")
            .span(file.tail(data_at.saturating_add(u64::from(get::<u32>(&d, 4, e).unwrap_or(0))))),
    );
    cx.annotate(format!("CGFX r{revision:#x}: {}", parts.join(", ")));
    Ok(())
}

// ---------------------------------------------------------------------------
// J3D (GameCube/Wii models and animations), RARC, BRRES (TPL lives in
// retro::extras)

fn j3d_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"J3D1") || h.starts_with(b"J3D2")
}

declare_format!(pub J3D = "j3d", "Nintendo J3D model or animation (BMD/BDL/BCK/BTK...)", ["bmd", "bdl", "bck", "btk", "brk", "btp", "bva", "bpk", "bca", "bla", "blk"], "model/x-j3d",
    Probe::Custom(j3d_probe), j3d);

async fn j3d(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 0x20)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    let magic = f.ascii("Signature", 8).emit()?;
    f.u32("File size").emit()?;
    let sections = f.u32("Sections").emit()?;
    f.ascii("Subversion", 4).emit()?;
    let mut cur = Cursor::new(&cx, file, BE);
    cur.seek(0x20);
    let mut names = Vec::new();
    while let Some(chunk) = cur.chunk(ChunkLayout::new(4, 4, BE).inclusive()).await? {
        names.push(chunk.name());
        cx.push(chunk.node()).await;
    }
    let kind = match magic.get(4..7).unwrap_or("") {
        "bmd" => "model",
        "bdl" => "display-list model",
        "bck" => "skeletal animation",
        "btk" => "texture SRT animation",
        "brk" => "colour animation",
        "btp" => "texture pattern animation",
        "bva" => "visibility animation",
        "bpk" => "colour key animation",
        "bca" | "bla" | "blk" => "animation",
        _ => "file",
    };
    cx.annotate(format!(
        "J3D {kind} ({magic}), {sections} sections: {}",
        names.join(", ")
    ));
    Ok(())
}

declare_format!(pub RARC = "rarc", "Nintendo RARC archive", ["arc", "rarc", "szs"], "application/x-rarc",
    Probe::Magic(&[(0, b"RARC")]), rarc);

async fn rarc(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 0x40)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Signature", 4).emit()?;
    f.u32("File size").emit()?;
    let header = f.u32("Header size").emit()?;
    let data_rel = f.u32("File data offset (from header end)").hex().emit()?;
    f.u32("File data length").emit()?;
    f.u32("MRAM preload size").emit()?;
    f.u32("ARAM preload size").emit()?;
    f.u32("Reserved").emit()?;
    let nodes = f.u32("Directory nodes").emit()?;
    let nodes_rel = f.u32("Node table offset").hex().emit()?;
    let entries = f.u32("Entries").emit()?;
    let entries_rel = f.u32("Entry table offset").hex().emit()?;
    let strings_len = f.u32("String table size").emit()?;
    let strings_rel = f.u32("String table offset").hex().emit()?;
    f.u16("Next free file ID").emit()?;
    f.u8("IDs synchronised").emit()?;
    let base = u64::from(header);
    let data = base.saturating_add(data_rel.into());
    let strings = cx
        .read(file.sub_exact(base.saturating_add(strings_rel.into()), strings_len.into())?)
        .await?;
    let name_at = |off: u16| until_nul(strings.get(usize::from(off)..).unwrap_or_default());
    let table = file.sub(
        base.saturating_add(entries_rel.into()),
        u64::from(entries).saturating_mul(20),
    );
    let mut files = 0u32;
    for i in 0..u64::from(entries.min(65536)) {
        let e = cx.read(table.sub_exact(i.saturating_mul(20), 20)?).await?;
        let kind = e.get(4).copied().unwrap_or(0);
        let name = name_at(u16_be(&e, 6).unwrap_or(0));
        if kind & 0x02 != 0 {
            continue; // directories (including "." and "..")
        }
        let offset = u64::from(u32_be(&e, 8).unwrap_or(0));
        let size = u64::from(u32_be(&e, 12).unwrap_or(0));
        cx.push(
            embedded(
                name,
                input.nested(file.sub(data.saturating_add(offset), size)),
            )
            .target(table.sub(i.saturating_mul(20), 20)),
        )
        .await;
        files = files.saturating_add(1);
    }
    let _ = nodes_rel;
    cx.annotate(format!("RARC archive, {nodes} directories, {files} files"));
    Ok(())
}

declare_format!(pub BRRES = "brres", "Wii binary resource (BRRES)", ["brres"], "application/x-brres",
    Probe::Magic(&[(0, b"bres\xfe\xff")]), brres);

async fn brres(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 16)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Signature", 4).emit()?;
    f.u16("Byte-order mark").hex().emit()?;
    f.u16("Padding").emit()?;
    f.u32("File size").emit()?;
    let root = f.u16("Root offset").hex().emit()?;
    let sections = f.u16("Sections").emit()?;
    let mut cur = Cursor::new(&cx, file, BE);
    cur.seek(root.into());
    let mut kinds = Vec::new();
    while let Some(chunk) = cur
        .chunk(ChunkLayout::new(4, 4, BE).inclusive().align(4))
        .await?
    {
        let name = chunk.name();
        if name != "root" {
            kinds.push(name);
        }
        cx.push(chunk.node()).await;
    }
    cx.annotate(format!("BRRES, {sections} sections: {}", kinds.join(", ")));
    Ok(())
}

// ---------------------------------------------------------------------------
// Sony: GIM, GXT, RCO, NPD (EDAT/SDAT)

declare_format!(pub GIM = "gim", "Sony GIM image", ["gim"], "image/x-gim",
    Probe::Magic(&[(0, b"MIG.00.1PSP\0"), (0, b".GIM1.00\0PSP")]), gim);

fn gim_block(kind: u16) -> &'static str {
    match kind {
        0x02 => "Root",
        0x03 => "Picture",
        0x04 => "Image",
        0x05 => "Palette",
        0xff => "File info",
        _ => "Block",
    }
}

async fn gim(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let big = cx.read(file.sub(0, 1)).await? == b".";
    let e = if big { BE } else { LE };
    cx.emit(Node::new("Signature").span(file.sub(0, 16)));
    // Blocks: type, unknown, block size, next offset, data offset. Root and
    // picture blocks contain their children; walk them depth-first.
    let mut pos = 16u64;
    let mut images = Vec::new();
    while pos.saturating_add(16) <= file.len {
        let h = cx.read(file.sub(pos, 16)).await?;
        let kind = get::<u16>(&h, 0, e).unwrap_or(0);
        let size = u64::from(get::<u32>(&h, 4, e).unwrap_or(0));
        let next = u64::from(get::<u32>(&h, 8, e).unwrap_or(0));
        let data = u64::from(get::<u32>(&h, 12, e).unwrap_or(0));
        let mut node = Node::new(gim_block(kind))
            .span(file.sub(pos, size))
            .summary(format!("{size} bytes"));
        if kind == 0x04 || kind == 0x05 {
            let d = cx
                .read_avail(file.sub(pos.saturating_add(data), 16))
                .await?;
            let format = get::<u16>(&d, 4, e).unwrap_or(0);
            let w = get::<u16>(&d, 8, e).unwrap_or(0);
            let hgt = get::<u16>(&d, 10, e).unwrap_or(0);
            let fmt = [
                "RGBA5650", "RGBA5551", "RGBA4444", "RGBA8888", "index4", "index8", "index16",
                "index32", "DXT1", "DXT3", "DXT5",
            ]
            .get(usize::from(format))
            .copied()
            .unwrap_or("unknown");
            node = node.summary(format!("{w}×{hgt} {fmt}"));
            if kind == 0x04 {
                images.push(format!("{w}×{hgt} {fmt}"));
            }
        }
        cx.push(node).await;
        let step = if matches!(kind, 0x02 | 0x03) {
            data
        } else {
            next.max(size)
        };
        if step == 0 {
            break;
        }
        pos = pos.saturating_add(step);
    }
    cx.annotate(format!(
        "GIM image ({}): {}",
        if big { "PS3" } else { "PSP" },
        images.join(", ")
    ));
    Ok(())
}

declare_format!(pub GXT = "gxt", "PlayStation Vita texture (GXT)", ["gxt"], "image/x-gxt",
    Probe::Magic(&[(0, b"GXT\0")]), gxt);

async fn gxt(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 32)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 4).emit()?;
    let version = f.u32("Version").hex().emit()?;
    let count = f.u32("Textures").emit()?;
    f.u32("Data offset").hex().emit()?;
    f.u32("Data size").emit()?;
    f.u32("P4 palettes").emit()?;
    f.u32("P8 palettes").emit()?;
    f.u32("Padding").emit()?;
    for i in 0..u64::from(count.min(1024)) {
        let at = 32u64.saturating_add(i.saturating_mul(32));
        let t = cx.read(file.sub_exact(at, 32)?).await?;
        let offset = u64::from(u32_le(&t, 0).unwrap_or(0));
        let size = u64::from(u32_le(&t, 4).unwrap_or(0));
        let kind = u32_le(&t, 16).unwrap_or(0);
        let w = u16_le(&t, 24).unwrap_or(0);
        let h = u16_le(&t, 26).unwrap_or(0);
        let layout = match kind {
            0 => "swizzled",
            0x4000_0000 => "cube",
            0x6000_0000 => "linear",
            0x8000_0000 => "tiled",
            _ => "other",
        };
        cx.push(
            Node::new(format!("Texture {i}"))
                .span(file.sub(at, 32))
                .summary(format!(
                    "{w}×{h}, {layout}, format {:#010x}",
                    u32_le(&t, 20).unwrap_or(0)
                ))
                .target(file.sub(offset, size)),
        )
        .await;
    }
    cx.annotate(format!("GXT v{version:#x}, {count} textures"));
    Ok(())
}

declare_format!(pub RCO = "rco", "Sony resource container (RCO)", ["rco"], "application/x-rco",
    Probe::Magic(&[(0, b"\x00PRF")]), rco);

async fn rco(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 0x48)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.bytes("Signature", 4).emit()?;
    let version = f.u32("Version").hex().emit()?;
    f.u32("Reserved").emit()?;
    let compression = f.u32("Compression").emit()?;
    for name in [
        "Main table",
        "VSMX table",
        "Text table",
        "Sound table",
        "Model table",
        "Image table",
        "Unknown table",
        "Font table",
        "Object table",
        "Anim table",
    ] {
        f.u32(name).hex().emit()?;
    }
    f.u32("Text index offset").hex().emit()?;
    f.u32("Text label offset").hex().emit()?;
    f.u32("Event offset").hex().emit()?;
    cx.emit(Node::new("Tables and data").span(file.tail(0x48)));
    let method = match compression >> 4 {
        0 => "uncompressed",
        1 => "zlib",
        2 => "RLZ",
        _ => "unknown compression",
    };
    cx.annotate(format!("Sony RCO v{version:#x}, {method}"));
    Ok(())
}

declare_format!(pub NPD = "ps3-npd", "PS3 NPDRM data (EDAT/SDAT)", ["edat", "sdat"], "application/x-ps3-npd",
    Probe::Magic(&[(0, b"NPD\0")]), npd);

async fn npd(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 0x90)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Signature", 4).emit()?;
    let version = f.u32("Version").emit()?;
    let license = f
        .u32("License")
        .enumeration(&[(1, "network"), (2, "local"), (3, "free")])
        .emit()?;
    let kind = f.u32("Type").hex().emit()?;
    let id = f.ascii("Content ID", 48).emit()?;
    f.bytes("Digest", 16).emit()?;
    f.bytes("Title hash", 16).emit()?;
    f.bytes("Developer hash", 16).emit()?;
    f.u64("Unknown").hex().emit()?;
    f.u64("Unknown").hex().emit()?;
    let flags = f.u32("Flags").hex().emit()?;
    let block = f.u32("Block size").emit()?;
    let size = f.u64("Data size").emit()?;
    cx.emit(Node::new("Metadata and encrypted blocks").span(file.tail(0x90)));
    let _ = (license, kind);
    cx.annotate(format!(
        "PS3 {} v{version} {:?}, {size} bytes in {block}-byte blocks{}",
        if flags & 1 != 0 { "SDAT" } else { "EDAT" },
        id.trim(),
        if flags & 1 != 0 { "" } else { ", licensed" }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Xbox: XDBF (GPD/SPA), XPR textures, XACT XSB/XGS

declare_format!(pub XDBF = "xdbf", "Xbox data file (XDBF: GPD/SPA)", ["gpd", "spa", "xdbf"], "application/x-xdbf",
    Probe::Magic(&[(0, b"XDBF")]), xdbf);

const XDBF_NAMESPACES: EnumTable = &[
    (1, "metadata"),
    (2, "image"),
    (3, "setting"),
    (4, "title"),
    (5, "string"),
    (6, "avatar award"),
];

async fn xdbf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 24)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Signature", 4).emit()?;
    let version = f.u32("Version").hex().emit()?;
    let table_len = f.u32("Entry table length").emit()?;
    let count = f.u32("Entries").emit()?;
    let free_len = f.u32("Free table length").emit()?;
    f.u32("Free entries").emit()?;
    let data = 24u64
        .saturating_add(u64::from(table_len).saturating_mul(18))
        .saturating_add(u64::from(free_len).saturating_mul(8));
    for i in 0..u64::from(count.min(table_len).min(4096)) {
        let at = 24u64.saturating_add(i.saturating_mul(18));
        let e = cx.read(file.sub_exact(at, 18)?).await?;
        let ns = u16_be(&e, 0).unwrap_or(0);
        let id = u64_be(&e, 2).unwrap_or(0);
        let offset = u64::from(u32_be(&e, 10).unwrap_or(0));
        let len = u64::from(u32_be(&e, 14).unwrap_or(0));
        let ns_name = XDBF_NAMESPACES
            .iter()
            .find(|(k, _)| *k == u64::from(ns))
            .map_or("unknown", |(_, v)| v);
        let span = file.sub(data.saturating_add(offset), len);
        let name = format!("{ns_name} {id:#x}");
        let node = if ns == 2 {
            embedded(name, input.nested(span))
        } else {
            Node::new(name).span(span).summary(format!("{len} bytes"))
        };
        cx.push(node.target(file.sub(at, 18))).await;
    }
    cx.annotate(format!("XDBF v{version:#x}, {count} entries"));
    Ok(())
}

declare_format!(pub XPR = "xpr", "Xbox packed resource (XPR)", ["xpr"], "application/x-xpr",
    Probe::Magic(&[(0, b"XPR0"), (0, b"XPR1"), (0, b"XPR2")]), xpr);

async fn xpr(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let magic = cx.read(file.sub(0, 4)).await?;
    let e = if magic == b"XPR2" { BE } else { LE };
    let head = cx.block(file.sub(0, 16)).await?;
    let mut f = Fields::emitting(&cx, &head, e);
    f.ascii("Signature", 4).emit()?;
    if e == BE {
        let header = f.u32("Header size").emit()?;
        let data = f.u32("Data size").emit()?;
        let resources = f.u32("Resources").emit()?;
        cx.emit(
            Node::new("Resource directory")
                .span(file.sub(16, u64::from(resources).saturating_mul(16))),
        );
        cx.emit(
            Node::new("Resource data")
                .span(file.sub(u64::from(header).saturating_add(12), data.into())),
        );
        cx.annotate(format!(
            "Xbox 360 packed resource (XPR2), {resources} resources"
        ));
    } else {
        let total = f.u32("Total size").emit()?;
        let header = f.u32("Header size").emit()?;
        cx.emit(
            Node::new("Resource headers").span(file.sub(12, u64::from(header).saturating_sub(12))),
        );
        cx.emit(Node::new("Resource data").span(file.sub(
            header.into(),
            u64::from(total).saturating_sub(header.into()),
        )));
        cx.annotate(format!(
            "Xbox packed resource ({})",
            String::from_utf8_lossy(&magic)
        ));
    }
    Ok(())
}

declare_format!(pub XACT = "xact-project", "XACT sound bank or global settings (XSB/XGS)", ["xsb", "xgs"], "audio/x-xact",
    Probe::Magic(&[(0, b"SDBK"), (0, b"KBDS"), (0, b"XGSF"), (0, b"FSGX")]), xact);

async fn xact(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let magic = cx.read(file.sub(0, 4)).await?;
    let e = if magic == b"SDBK" || magic == b"XGSF" {
        LE
    } else {
        BE
    };
    let head = cx.read(file.sub(0, 0x70)).await?;
    let content = get::<u16>(&head, 4, e).unwrap_or(0);
    let tool = get::<u16>(&head, 6, e).unwrap_or(0);
    cx.emit(Node::new("Signature").span(file.sub(0, 4)));
    cx.emit(
        Node::new("Content version")
            .span(file.sub(4, 2))
            .value(uint(content, 16)),
    );
    cx.emit(
        Node::new("Tool version")
            .span(file.sub(6, 2))
            .value(uint(tool, 16)),
    );
    let (kind, summary) = if magic == b"SDBK" || magic == b"KBDS" {
        // The sound bank's name is 64 bytes at 0x4a (content version 46).
        let name = until_nul(
            head.get(0x4a..0x8a)
                .unwrap_or(head.get(0x4a..).unwrap_or_default()),
        );
        let cues = get::<u16>(&head, 0x13, e).unwrap_or(0);
        ("sound bank", format!("{name:?}, {cues} simple cues"))
    } else {
        let categories = get::<u16>(&head, 0x12, e).unwrap_or(0);
        let variables = get::<u16>(&head, 0x14, e).unwrap_or(0);
        (
            "global settings",
            format!("{categories} categories, {variables} variables"),
        )
    };
    cx.emit(
        Node::new("Body")
            .span(file.tail(8))
            .summary(summary.clone()),
    );
    cx.annotate(format!("XACT {kind} v{content}, {summary}"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Sega: PVR/GVR textures, Ninja chunk files

fn sega_tex_probe(h: &Head<'_>) -> bool {
    let start = if h.starts_with(b"GBIX") || h.starts_with(b"GCIX") {
        u32_le(h.data, 4)
            .and_then(|n| usize::try_from(n).ok())
            .map_or(0, |n| n.saturating_add(8))
    } else {
        0
    };
    h.at(start, b"PVRT") || h.at(start, b"GVRT")
}

declare_format!(pub SEGA_TEXTURE = "sega-texture", "Sega PVR (Dreamcast) / GVR (GameCube) texture", ["pvr", "gvr"], "image/x-sega-pvr",
    Probe::Custom(sega_tex_probe), sega_texture);

async fn sega_texture(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut pos = 0u64;
    let first = cx.read(file.sub(0, 8)).await?;
    if first.starts_with(b"GBIX") || first.starts_with(b"GCIX") {
        let len = u64::from(u32_le(&first, 4).unwrap_or(0));
        let index = cx.read(file.sub(8, 4)).await?;
        cx.emit(
            Node::new("Global index")
                .span(file.sub(0, len.saturating_add(8)))
                .value(uint(u32_be(&index, 0).unwrap_or(0), 32)),
        );
        pos = len.saturating_add(8);
    }
    let h = cx.read(file.sub_exact(pos, 16)?).await?;
    let gvr = h.starts_with(b"GVRT");
    let size = u64::from(u32_le(&h, 4).unwrap_or(0));
    let (pixel, data, w, hgt) = if gvr {
        (
            h.get(10).copied().unwrap_or(0) >> 4,
            h.get(11).copied().unwrap_or(0),
            u16_be(&h, 12).unwrap_or(0),
            u16_be(&h, 14).unwrap_or(0),
        )
    } else {
        (
            h.get(8).copied().unwrap_or(0),
            h.get(9).copied().unwrap_or(0),
            u16_le(&h, 12).unwrap_or(0),
            u16_le(&h, 14).unwrap_or(0),
        )
    };
    cx.emit(
        Node::new(if gvr { "GVRT" } else { "PVRT" })
            .span(file.sub(pos, size.saturating_add(8)))
            .summary(format!(
                "{w}×{hgt}, pixel format {pixel}, data format {data:#04x}"
            )),
    );
    cx.annotate(format!(
        "Sega {} texture, {w}×{hgt}",
        if gvr {
            "GVR (GameCube)"
        } else {
            "PVR (Dreamcast)"
        }
    ));
    Ok(())
}

declare_format!(pub NINJA = "sega-ninja", "Sega Ninja chunk file (NJ/NJM)", ["nj", "njm", "njtl", "njcm"], "model/x-sega-ninja",
    Probe::Magic(&[(0, b"NJTL"), (0, b"NJCM"), (0, b"NJBM"), (0, b"NMDM"), (0, b"GJTL"), (0, b"GJCM")]), ninja);

async fn ninja(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, LE);
    let mut names = Vec::new();
    while let Some(chunk) = cur.chunk(ChunkLayout::new(4, 4, LE)).await? {
        names.push(chunk.name());
        cx.push(chunk.node()).await;
    }
    let kinds: Vec<&str> = names
        .iter()
        .map(|n| match n.as_str() {
            "NJTL" | "GJTL" => "texture list",
            "NJCM" | "GJCM" => "chunk model",
            "NJBM" => "basic model",
            "NMDM" => "motion",
            "POF0" | "POF1" => "pointer fixups",
            _ => "chunk",
        })
        .collect();
    cx.annotate(format!("Sega Ninja file: {}", kinds.join(", ")));
    Ok(())
}
