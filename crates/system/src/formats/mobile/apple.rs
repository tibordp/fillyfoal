//! Apple platform binaries: compiled NIB archives (`NIBArchive`), Metal
//! libraries (`MTLB`), compiled asset catalogs (`Assets.car`, a BOMStore
//! with a `CARHEADER`), standalone code signatures, Apple Encrypted
//! Archives (`AEA1`), trust caches and Swift module files.

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u16_le, u32_be, u32_le, u64_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::system::bom::{Bom, BomHeader, TreeWalk, read_bom};
use crate::formats::util::datakit::{hex_string, size};
use crate::formats::util::val::{text, uint};
use crate::formats::{Head, Input, Probe, embedded};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Value, lookup};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// NIBArchive (compiled .nib)

declare_format!(pub NIB = "nib-archive", "Compiled Interface Builder archive (NIBArchive)", ["nib"], "application/x-nib",
    Probe::Magic(&[(0, b"NIBArchive")]), nib);

record! {
    pub struct NibHeader {
        magic: ascii[10] "Magic",
        unknown: u32 "Unknown (1)",
        version: u32 "Format version",
        objects: u32 "Object count",
        objects_at: u32 "Objects offset" .hex(),
        keys: u32 "Key count",
        keys_at: u32 "Keys offset" .hex(),
        values: u32 "Value count",
        values_at: u32 "Values offset" .hex(),
        classes: u32 "Class name count",
        classes_at: u32 "Class names offset" .hex(),
    }
}

/// NIBArchive's variable-length integer: 7 bits per byte, least
/// significant first; the last byte has its high bit set.
async fn nib_varint(cur: &mut Cursor<'_>) -> Result<u64> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let b = cur.u8().await?;
        value |= u64::from(b & 0x7f).checked_shl(shift).unwrap_or(0);
        if b & 0x80 != 0 {
            return Ok(value);
        }
    }
    Err(Diagnostic::malformed("varint too long").at(cur.span(1)))
}

/// The parsed tables of a NIB archive.
struct Nib {
    file: Span,
    classes: Vec<String>,
    keys: Vec<String>,
    /// Start of each value, relative to the file.
    values: Vec<u64>,
    objects: Span,
    count: u32,
}

const NIB_TYPES: EnumTable = &[
    (0, "int8"),
    (1, "int16"),
    (2, "int32"),
    (3, "int64"),
    (4, "true"),
    (5, "false"),
    (6, "float"),
    (7, "double"),
    (8, "data"),
    (9, "nil"),
    (10, "object"),
];

async fn nib(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let (h, span) = Cursor::new(&cx, file, LE).record::<NibHeader>().await?;
    cx.emit(NibHeader::node("Header", span, LE));
    let table = |at: u32| file.tail(at.into());
    // Class names.
    let mut cur = Cursor::new(&cx, table(h.classes_at), LE);
    let mut classes = Vec::new();
    for _ in 0..h.classes {
        let len = nib_varint(&mut cur).await?;
        let extras = nib_varint(&mut cur).await?;
        cur.skip(extras.saturating_mul(4));
        let name = cur.bytes(len).await?;
        classes.push(crate::text::until_nul(&name));
    }
    let classes_span = cur.since(0);
    // Keys.
    let mut cur = Cursor::new(&cx, table(h.keys_at), LE);
    let mut keys = Vec::new();
    for _ in 0..h.keys {
        let len = nib_varint(&mut cur).await?;
        keys.push(String::from_utf8_lossy(&cur.bytes(len).await?).into_owned());
    }
    let keys_span = cur.since(0);
    // Value positions.
    let mut cur = Cursor::new(&cx, table(h.values_at), LE);
    let mut values = Vec::new();
    for _ in 0..h.values {
        values.push(u64::from(h.values_at).saturating_add(cur.pos()));
        nib_varint(&mut cur).await?;
        let kind = cur.u8().await?;
        let len = match kind {
            0 | 4 | 5 | 9 => u64::from(kind == 0),
            1 => 2,
            2 | 6 | 10 => 4,
            3 | 7 => 8,
            8 => nib_varint(&mut cur).await?,
            _ => return Err(Diagnostic::malformed(format!("value type {kind}")).at(cur.span(1))),
        };
        cur.skip(len);
        cx.checkpoint().await;
    }
    let values_span = cur.since(0);
    let objects = table(h.objects_at).sub(
        0,
        u64::from(h.values_at).saturating_sub(h.objects_at.into()),
    );
    let nib = Arc::new(Nib {
        file,
        classes,
        keys,
        values,
        objects,
        count: h.objects,
    });
    cx.emit(
        Node::new("Objects")
            .span(objects)
            .summary(format!("{} objects", h.objects))
            .lazy(nib_objects, nib.clone()),
    );
    cx.emit(
        Node::new("Keys")
            .span(keys_span)
            .summary(format!("{} keys", h.keys))
            .lazy(nib_strings, (nib.clone(), true)),
    );
    cx.emit(
        Node::new("Values")
            .span(values_span)
            .summary(format!("{} values", h.values)),
    );
    cx.emit(
        Node::new("Class names")
            .span(classes_span)
            .summary(nib.classes.join(", "))
            .lazy(nib_strings, (nib.clone(), false)),
    );
    let root = nib.classes.first().cloned().unwrap_or_default();
    cx.annotate(format!(
        "NIB archive v{}, {} objects, {} classes (first: {root})",
        h.version, h.objects, h.classes
    ));
    Ok(())
}

async fn nib_strings(cx: Cx, (nib, keys): (Arc<Nib>, bool)) -> Result<()> {
    let list = if keys { &nib.keys } else { &nib.classes };
    for (i, s) in list.iter().enumerate() {
        cx.push(Node::new(format!("[{i}]")).value(text(s.clone())))
            .await;
    }
    Ok(())
}

async fn nib_objects(cx: Cx, nib: Arc<Nib>) -> Result<()> {
    let mut cur = Cursor::new(&cx, nib.objects, LE);
    cx.set_count(Count::Exact(nib.count.into()));
    for i in 0..nib.count {
        let start = cur.pos();
        let class = nib_varint(&mut cur).await?;
        let first = nib_varint(&mut cur).await?;
        let count = nib_varint(&mut cur).await?;
        let name = usize::try_from(class)
            .ok()
            .and_then(|c| nib.classes.get(c))
            .cloned()
            .unwrap_or_else(|| format!("class {class}"));
        cx.push(
            Node::new(format!("Object {i}"))
                .span(cur.since(start))
                .value(text(name))
                .summary(format!("{count} values"))
                .lazy(nib_object, (nib.clone(), first, count)),
        )
        .await;
    }
    Ok(())
}

async fn nib_object(cx: Cx, (nib, first, count): (Arc<Nib>, u64, u64)) -> Result<()> {
    let end = first.saturating_add(count);
    for index in first..end {
        let Some(&at) = usize::try_from(index).ok().and_then(|i| nib.values.get(i)) else {
            return Err(Diagnostic::malformed(format!(
                "value index {index} out of range"
            )));
        };
        let mut cur = Cursor::new(&cx, nib.file.tail(at), LE);
        let key = nib_varint(&mut cur).await?;
        let kind = cur.u8().await?;
        let value = match kind {
            0 => Value::Int {
                value: i8::from_ne_bytes([cur.u8().await?]).into(),
                bits: 8,
            },
            1 => Value::Int {
                value: i16::from_ne_bytes(cur.u16().await?.to_ne_bytes()).into(),
                bits: 16,
            },
            2 => Value::Int {
                value: i32::from_ne_bytes(cur.u32().await?.to_ne_bytes()).into(),
                bits: 32,
            },
            3 => Value::Int {
                value: i64::from_ne_bytes(cur.u64().await?.to_ne_bytes()),
                bits: 64,
            },
            4 => Value::Bool(true),
            5 => Value::Bool(false),
            6 => Value::Float(f64::from(f32::from_bits(cur.u32().await?))),
            7 => Value::Float(f64::from_bits(cur.u64().await?)),
            8 => {
                let len = nib_varint(&mut cur).await?;
                let data = cur.bytes(len.min(256)).await?;
                cur.skip(len.saturating_sub(256));
                if std::str::from_utf8(&data).is_ok_and(|s| !s.is_empty() && !s.contains('\0')) {
                    text(String::from_utf8_lossy(&data).into_owned())
                } else {
                    Value::Bytes(data)
                }
            }
            9 => text("nil"),
            10 => {
                let target = cur.u32().await?;
                text(format!("→ object {target}"))
            }
            _ => Value::Enum {
                raw: kind.into(),
                bits: 8,
                name: lookup(NIB_TYPES, kind.into()),
            },
        };
        let name = usize::try_from(key)
            .ok()
            .and_then(|k| nib.keys.get(k))
            .cloned()
            .unwrap_or_else(|| format!("key {key}"));
        cx.push(Node::new(name).span(cur.since(0)).value(value))
            .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Metal library (.metallib)

fn metallib_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"MTLB") && u64_le(h.data, 16) == Some(h.len)
}

declare_format!(pub METALLIB = "metallib", "Metal library", ["metallib"], "application/x-metallib",
    Probe::Custom(metallib_probe), metallib);

const METAL_PLATFORM: EnumTable = &[(0x8001, "macOS"), (0x0001, "iOS")];
const METAL_LIB_TYPE: EnumTable = &[
    (0, "executable"),
    (1, "core image"),
    (2, "dynamic"),
    (3, "symbol companion"),
];
const METAL_FN_TYPE: EnumTable = &[
    (0, "vertex"),
    (1, "fragment"),
    (2, "kernel"),
    (3, "unqualified"),
    (4, "visible"),
    (5, "extern"),
    (6, "intersection"),
];

struct MetalHeader {
    functions: (u64, u64),
    bitcode: (u64, u64),
}

fn metal_header(f: &mut Fields<'_>, _: &()) -> Result<MetalHeader> {
    f.ascii("Magic", 4).emit()?;
    f.u16("Target platform")
        .enumeration(METAL_PLATFORM)
        .hex()
        .emit()?;
    f.u16("Version major").emit()?;
    f.u16("Version minor").emit()?;
    f.u8("Library type").enumeration(METAL_LIB_TYPE).emit()?;
    f.u8("Target OS").emit()?;
    f.u16("OS version major").emit()?;
    f.u16("OS version minor").emit()?;
    f.u64("File size").emit()?;
    let functions = (
        f.u64("Function list offset").hex().emit()?,
        f.u64("Function list size").emit()?,
    );
    f.u64("Public metadata offset").hex().emit()?;
    f.u64("Public metadata size").emit()?;
    f.u64("Private metadata offset").hex().emit()?;
    f.u64("Private metadata size").emit()?;
    let bitcode = (
        f.u64("Bitcode offset").hex().emit()?,
        f.u64("Bitcode size").emit()?,
    );
    Ok(MetalHeader { functions, bitcode })
}

async fn metallib(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = file.sub(0, 88);
    let h = crate::fields::parse(&cx, head, LE, &(), metal_header).await?;
    cx.emit(struct_node("Header", head, LE, (), metal_header));
    let list = file.sub(h.functions.0, h.functions.1);
    let bitcode = file.sub(h.bitcode.0, h.bitcode.1);
    let mut cur = Cursor::new(&cx, list, LE);
    let count = cur.u32().await?;
    let mut names = Vec::new();
    let mut entries = Vec::new();
    for _ in 0..count {
        let start = cur.pos();
        let len = u64::from(cur.u32().await?);
        if len < 4 {
            return Err(
                Diagnostic::malformed(format!("function entry of {len} bytes"))
                    .at(cur.since(start)),
            );
        }
        let entry = list.sub(start, len);
        cur.seek(start.saturating_add(len));
        let tags = metal_tags(&cx, entry.tail(4)).await?;
        let name = tags
            .iter()
            .find(|t| &t.0 == b"NAME")
            .map(|t| t.2.clone())
            .unwrap_or_default();
        names.push(name.clone());
        entries.push((entry, name, tags));
        cx.checkpoint().await;
    }
    let fl = Node::new("Functions")
        .span(list)
        .summary(format!("{count} functions"));
    cx.emit(fl.lazy(metal_functions, (input, bitcode, Arc::new(entries))));
    cx.emit(
        Node::new("Bitcode")
            .span(bitcode)
            .summary(size(bitcode.len)),
    );
    cx.annotate(format!(
        "Metal library, {count} functions: {}",
        names.join(", ")
    ));
    Ok(())
}

/// The tags of a function entry: `(tag, span, display)`, up to `ENDT`.
async fn metal_tags(cx: &Cx, span: Span) -> Result<Vec<([u8; 4], Span, String, Vec<u8>)>> {
    let mut cur = Cursor::new(cx, span, LE);
    let mut out = Vec::new();
    while !cur.at_end() {
        let start = cur.pos();
        let tag: [u8; 4] = cur.bytes(4).await?.try_into().unwrap_or_default();
        if &tag == b"ENDT" {
            out.push((tag, cur.since(start), String::new(), Vec::new()));
            break;
        }
        let len = cur.u16().await?;
        let data = cur.bytes(len.into()).await?;
        let shown = match &tag {
            b"NAME" => crate::text::until_nul(&data),
            b"TYPE" => data.first().map_or_else(String::new, |&t| {
                lookup(METAL_FN_TYPE, t.into()).unwrap_or("?").to_owned()
            }),
            b"HASH" => hex_string(&data),
            b"MDSZ" => {
                u64_le(&data, 0).map_or_else(String::new, |v| format!("{v} bytes of bitcode"))
            }
            b"OFFT" => format!(
                "public {:#x}, private {:#x}, bitcode {:#x}",
                u64_le(&data, 0).unwrap_or(0),
                u64_le(&data, 8).unwrap_or(0),
                u64_le(&data, 16).unwrap_or(0)
            ),
            b"VERS" => {
                let v: Vec<String> = [0usize, 2, 4, 6]
                    .iter()
                    .filter_map(|&i| u16_le(&data, i))
                    .map(|x| x.to_string())
                    .collect();
                v.join(".")
            }
            _ => format!("{len} bytes"),
        };
        out.push((tag, cur.since(start), shown, data));
    }
    Ok(out)
}

type MetalEntries = Arc<Vec<(Span, String, Vec<([u8; 4], Span, String, Vec<u8>)>)>>;

async fn metal_functions(
    cx: Cx,
    (input, bitcode, entries): (Input, Span, MetalEntries),
) -> Result<()> {
    for (span, name, tags) in entries.iter() {
        let kind = tags
            .iter()
            .find(|t| &t.0 == b"TYPE")
            .map(|t| t.2.clone())
            .unwrap_or_default();
        cx.push(
            Node::new(name.clone())
                .span(*span)
                .summary(kind)
                .lazy(metal_function, (input, bitcode, *span, entries.clone())),
        )
        .await;
    }
    Ok(())
}

async fn metal_function(
    cx: Cx,
    (input, bitcode, span, entries): (Input, Span, Span, MetalEntries),
) -> Result<()> {
    let Some((_, _, tags)) = entries.iter().find(|e| e.0 == span) else {
        return Ok(());
    };
    cx.emit(
        Node::new("Entry size")
            .span(span.sub(0, 4))
            .value(uint(span.len, 64)),
    );
    let mut size = None;
    let mut offset = None;
    for (tag, tspan, shown, data) in tags {
        let label = String::from_utf8_lossy(tag).into_owned();
        cx.emit(Node::new(label).span(*tspan).value(text(shown.clone())));
        match tag {
            b"MDSZ" => size = u64_le(data, 0),
            b"OFFT" => offset = u64_le(data, 16),
            _ => {}
        }
    }
    if let (Some(size), Some(offset)) = (size, offset) {
        cx.emit(
            embedded("Bitcode", input.nested(bitcode.sub(offset, size)))
                .summary(format!("{size} bytes")),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Compiled asset catalog (Assets.car)

fn car_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"BOMStore")
        && (crate::formats::text::probe::contains(h.data, b"CARHEADER")
            || crate::formats::text::probe::contains(h.tail, b"CARHEADER"))
}

declare_format!(pub CAR = "asset-catalog", "Compiled asset catalog (Assets.car)", ["car"], "application/x-apple-car",
    Probe::Custom(car_probe), car);

/// Rendition key attributes (`KEYFORMAT` tokens).
const CAR_ATTRIBUTES: EnumTable = &[
    (0, "ThemeLook"),
    (1, "Element"),
    (2, "Part"),
    (3, "Size"),
    (4, "Direction"),
    (5, "Placeholder"),
    (6, "Value"),
    (7, "ThemeAppearance"),
    (8, "Dimension1"),
    (9, "Dimension2"),
    (10, "State"),
    (11, "Layer"),
    (12, "Scale"),
    (13, "Localization"),
    (14, "PresentationState"),
    (15, "Idiom"),
    (16, "Subtype"),
    (17, "Identifier"),
    (18, "PreviousValue"),
    (19, "PreviousState"),
    (20, "HorizontalSizeClass"),
    (21, "VerticalSizeClass"),
    (22, "MemoryLevelClass"),
    (23, "GraphicsFeatureSetClass"),
    (24, "DisplayGamut"),
    (25, "DeploymentTarget"),
];

fn car_header(f: &mut Fields<'_>, _: &()) -> Result<u32> {
    f.ascii("Tag", 4)
        .desc("'CTAR', stored little-endian")
        .emit()?;
    f.u32("CoreUI version").emit()?;
    f.u32("Storage version").emit()?;
    f.u32("Storage timestamp").timestamp().emit()?;
    let count = f.u32("Rendition count").emit()?;
    f.ascii("Main version", 128).emit()?;
    f.ascii("Version", 256).emit()?;
    f.bytes("UUID", 16).emit()?;
    f.u32("Associated checksum").hex().emit()?;
    f.u32("Schema version").emit()?;
    f.u32("Color space ID").emit()?;
    f.u32("Key semantics").emit()?;
    Ok(count)
}

fn car_metadata(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.ascii("Tag", 4)
        .desc("'META', stored little-endian")
        .emit()?;
    f.ascii("Thinning arguments", 256).emit()?;
    f.ascii("Deployment platform version", 256).emit()?;
    f.ascii("Deployment platform", 256).emit()?;
    f.ascii("Authoring tool", 256).emit()?;
    Ok(())
}

fn csi_header(f: &mut Fields<'_>, _: &()) -> Result<(String, u32, u32, u32, String, u32)> {
    f.ascii("Tag", 4)
        .desc("'CTSI', stored little-endian")
        .emit()?;
    f.u32("Version").emit()?;
    f.u32("Rendition flags").hex().emit()?;
    let width = f.u32("Width").emit()?;
    let height = f.u32("Height").emit()?;
    let scale = f.u32("Scale factor").desc("Hundredths").emit()?;
    let format = f.bytes("Pixel format", 4).emit()?;
    f.u32("Color space").hex().emit()?;
    f.u32("Modification time").timestamp().emit()?;
    f.u16("Layout").emit()?;
    f.u16("Zero").emit()?;
    let name = f.ascii("Name", 128).emit()?;
    let tlv = f.u32("TLV length").emit()?;
    f.u32("Unknown").emit()?;
    f.u32("Zero").emit()?;
    f.u32("Rendition length").emit()?;
    let format: String = format.iter().rev().map(|&b| char::from(b)).collect();
    Ok((name, width, height, scale, format.trim().to_owned(), tlv))
}

async fn car(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let header: BomHeader = crate::dsl::read_record(&cx, file.sub(0, BomHeader::SIZE), BE).await?;
    cx.emit(BomHeader::node(
        "BOM header",
        file.sub(0, BomHeader::SIZE),
        BE,
    ));
    let bom = Arc::new(read_bom(&cx, input).await?);
    let mut renditions = 0u32;
    let mut tokens = Vec::new();
    if let Some(kf) = bom.var("KEYFORMAT") {
        let data = cx.read(kf.sub(0, 4096)).await?;
        let n = u32_le(&data, 8).unwrap_or(0).min(64);
        tokens = (0..n)
            .filter_map(|i| {
                u32_le(
                    &data,
                    to_usize(u64::from(i).saturating_mul(4)).saturating_add(12),
                )
            })
            .collect();
    }
    let tokens = Arc::new(tokens);
    // Every byte that belongs to something: the header, the blocks, the
    // index and the variables; the rest is unused (zeros between blocks).
    let mut used: Vec<(u64, u64)> = vec![(0, BomHeader::SIZE)];
    for (name, block, var) in &bom.vars {
        let span = bom.block(*block).unwrap_or(file.sub(0, 0));
        let node = match name.as_str() {
            "CARHEADER" => {
                renditions = crate::fields::parse(&cx, span, LE, &(), car_header)
                    .await
                    .unwrap_or(0);
                struct_node(name.clone(), span, LE, (), car_header)
            }
            "EXTENDED_METADATA" => struct_node(name.clone(), span, LE, (), car_metadata),
            "KEYFORMAT" => Node::new(name.clone())
                .span(span)
                .summary(format!("{} attributes", tokens.len()))
                .lazy(key_format, (span, tokens.clone())),
            "RENDITIONS" => Node::new(name.clone())
                .span(span)
                .summary("B+ tree of rendition keys")
                .lazy(renditions_tree, (bom.clone(), *block, tokens.clone())),
            "FACETKEYS" | "APPEARANCEKEYS" | "BITMAPKEYS" | "LOCALIZATIONKEYS" => {
                let kind = match name.as_str() {
                    "FACETKEYS" => TreeKind::Facets,
                    "APPEARANCEKEYS" | "LOCALIZATIONKEYS" => TreeKind::Names,
                    _ => TreeKind::Bitmaps,
                };
                Node::new(name.clone())
                    .span(span)
                    .summary("B+ tree")
                    .lazy(car_tree, (bom.clone(), *block, kind))
            }
            _ => Node::new(name.clone())
                .span(span)
                .summary(format!("block {block}, {} bytes", span.len)),
        };
        cx.push(node.target(*var)).await;
    }
    let index = file.sub(header.index_offset.into(), header.index_length.into());
    let vars = file.sub(header.vars_offset.into(), header.vars_length.into());
    cx.push(
        Node::new("Block index")
            .span(index)
            .summary(format!("{} slots", bom.block_count()))
            .lazy(block_index, (bom.clone(), index)),
    )
    .await;
    cx.push(
        Node::new("Variables")
            .span(vars)
            .summary(format!("{} variables", bom.vars.len()))
            .lazy(variables, (bom.clone(), vars)),
    )
    .await;
    used.push((index.offset.saturating_sub(file.offset), index.len));
    used.push((vars.offset.saturating_sub(file.offset), vars.len));
    for id in 0..bom.block_count().min(1 << 20) {
        if id.is_multiple_of(1024) {
            cx.checkpoint().await;
        }
        if let Some(s) = bom.block(id)
            && s.len > 0
        {
            used.push((s.offset.saturating_sub(file.offset), s.len));
        }
    }
    used.sort_unstable();
    let mut pos = 0u64;
    for (at, len) in used {
        if at > pos {
            let s = file.sub(pos, at.saturating_sub(pos));
            cx.push(Node::new("Unused").span(s).summary(size(s.len)))
                .await;
        }
        pos = pos.max(at.saturating_add(len));
    }
    if pos < file.len {
        let s = file.tail(pos);
        cx.push(Node::new("Unused").span(s).summary(size(s.len)))
            .await;
    }
    let names: Vec<&str> = bom.vars.iter().map(|v| v.0.as_str()).collect();
    cx.annotate(format!(
        "Asset catalog, {renditions} renditions ({})",
        names.join(", ")
    ));
    Ok(())
}

/// The block index: a slot count, (offset, length) per slot (null blocks
/// are zero), then the free list.
async fn block_index(cx: Cx, (bom, span): (Arc<Bom>, Span)) -> Result<()> {
    let block = cx.block(span.sub(0, 4)).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    let count = f.u32("Slot count").emit()?;
    let mut used = 0u32;
    for id in 0..count.min(1 << 20) {
        let at = 4u64.saturating_add(u64::from(id).saturating_mul(8));
        let Some(s) = bom.block(id) else { break };
        let entry = span.sub(at, 8);
        if s.len == 0 && s.offset == bom.file.offset {
            continue;
        }
        used = used.saturating_add(1);
        cx.push(
            Node::new(format!("Block {id}"))
                .span(entry)
                .summary(format!(
                    "{} at {:#x}",
                    size(s.len),
                    s.offset.saturating_sub(bom.file.offset)
                ))
                .target(s),
        )
        .await;
    }
    let after = 4u64.saturating_add(u64::from(count).saturating_mul(8));
    if after < span.len {
        let rest = span.tail(after);
        cx.push(
            Node::new("Null slots and free list")
                .span(rest)
                .summary(size(rest.len)),
        )
        .await;
    }
    let _ = used;
    Ok(())
}

/// Named variables: block number, name length, name.
async fn variables(cx: Cx, (bom, span): (Arc<Bom>, Span)) -> Result<()> {
    let block = cx.block(span.sub(0, 4)).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    f.u32("Count").emit()?;
    for (name, block, var) in &bom.vars {
        cx.push(
            struct_node(name.clone(), *var, BE, (), |f, _| {
                f.u32("Block").emit()?;
                let len = f.u8("Name length").emit()?;
                f.ascii("Name", len.into()).emit()?;
                Ok(())
            })
            .summary(format!("block {block}")),
        )
        .await;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TreeKind {
    /// Facet name → hot spot and rendition attributes.
    Facets,
    /// Name (appearance, localization) → identifier.
    Names,
    /// Inline name identifier → bitmap key words.
    Bitmaps,
}

fn tree_header(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.ascii("Tag", 4).emit()?;
    f.u32("Version").emit()?;
    f.u32("Root page").emit()?;
    f.u32("Page size").emit()?;
    f.u32("Path count").emit()?;
    f.u8("Inline keys")
        .desc("1 when leaf keys are values rather than block numbers")
        .emit()?;
    let rest = f.remaining();
    if rest > 0 {
        f.bytes("Unknown", rest).emit()?;
    }
    Ok(())
}

/// The pages of a BOM tree, root first then breadth first (bounded).
async fn tree_pages(cx: &Cx, bom: &Bom, root: u32) -> Vec<(u32, Span, bool, Vec<(u32, u32)>)> {
    let mut out = Vec::new();
    let mut queue = std::collections::VecDeque::from([root]);
    let mut seen = std::collections::BTreeSet::new();
    while let Some(page) = queue.pop_front() {
        if !seen.insert(page) || out.len() >= 4096 {
            continue;
        }
        let Some(span) = bom.block(page) else {
            continue;
        };
        let Ok(h) = cx.read(span.sub(0, 12)).await else {
            continue;
        };
        let leaf = crate::bytes::u16_be(&h, 0).unwrap_or(0) != 0;
        let count = crate::bytes::u16_be(&h, 2).unwrap_or(0);
        let Ok(raw) = cx
            .read(span.sub(12, u64::from(count).saturating_mul(8)))
            .await
        else {
            continue;
        };
        let entries: Vec<(u32, u32)> = raw
            .chunks(8)
            .map(|e| (u32_be(e, 0).unwrap_or(0), u32_be(e, 4).unwrap_or(0)))
            .collect();
        if !leaf {
            queue.extend(entries.iter().map(|e| e.0));
        }
        out.push((page, span, leaf, entries));
    }
    out
}

fn page_fields(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u16("Is leaf").emit()?;
    let count = f.u16("Count").emit()?;
    f.u32("Forward").emit()?;
    f.u32("Backward").emit()?;
    for _ in 0..count {
        f.u32("Value").emit()?;
        f.u32("Key").emit()?;
    }
    let rest = f.remaining();
    if rest > 0 {
        f.bytes("Unused", rest).emit()?;
    }
    Ok(())
}

async fn pages(cx: Cx, (bom, root): (Arc<Bom>, u32)) -> Result<()> {
    for (page, span, leaf, entries) in tree_pages(&cx, &bom, root).await {
        cx.push(
            struct_node(format!("Page {page}"), span, BE, (), page_fields).summary(format!(
                "{}, {}",
                if leaf { "leaf" } else { "index" },
                crate::formats::util::fmt::count(to_u64(entries.len()), "entry", "entries")
            )),
        )
        .await;
    }
    Ok(())
}

async fn car_tree(cx: Cx, (bom, block, kind): (Arc<Bom>, u32, TreeKind)) -> Result<()> {
    let span = bom
        .block(block)
        .ok_or_else(|| Diagnostic::malformed("missing tree block"))?;
    cx.emit(struct_node("Tree header", span, BE, (), tree_header));
    let head = cx.read(span.sub(0, 21)).await?;
    let root = u32_be(&head, 8).unwrap_or(0);
    let inline = head.get(20) == Some(&1) || kind == TreeKind::Bitmaps;
    let all = tree_pages(&cx, &bom, root).await;
    cx.emit(
        Node::new("Pages")
            .summary(crate::formats::util::fmt::plural(to_u64(all.len()), "page"))
            .lazy(pages, (bom.clone(), root)),
    );
    for (_, _, leaf, entries) in all {
        if !leaf {
            continue;
        }
        for (value, key) in entries {
            let Some(v) = bom.block(value) else { continue };
            let name = if inline {
                format!("Identifier {key}")
            } else {
                match bom.block(key) {
                    Some(k) => crate::text::until_nul(&cx.read(k.sub(0, 256)).await?),
                    None => format!("key {key}"),
                }
            };
            let key_span = if inline { None } else { bom.block(key) };
            let data = cx.read(v.sub(0, 4096)).await?;
            let node = match kind {
                TreeKind::Facets => {
                    let n = u16_le(&data, 4).unwrap_or(0);
                    let attrs: Vec<String> = (0..usize::from(n).min(32))
                        .filter_map(|i| {
                            let at = 6usize.saturating_add(i.saturating_mul(4));
                            let a = u16_le(&data, at)?;
                            let val = u16_le(&data, at.saturating_add(2))?;
                            Some(format!(
                                "{}={val}",
                                lookup(CAR_ATTRIBUTES, a.into()).unwrap_or("?")
                            ))
                        })
                        .collect();
                    Node::new(name).span(v).summary(attrs.join(", "))
                }
                TreeKind::Names => Node::new(name)
                    .span(v)
                    .value(uint(u16_le(&data, 0).unwrap_or(0), 16)),
                TreeKind::Bitmaps => {
                    Node::new(name)
                        .span(v)
                        .summary(crate::formats::util::fmt::plural(
                            to_u64(data.len() / 4),
                            "word",
                        ))
                }
            };
            cx.push(node.lazy(car_entry, (key_span, v, kind))).await;
        }
    }
    Ok(())
}

async fn car_entry(cx: Cx, (key, value, kind): (Option<Span>, Span, TreeKind)) -> Result<()> {
    if let Some(k) = key {
        let text = crate::text::until_nul(&cx.read(k.sub(0, 256)).await?);
        cx.emit(Node::new("Key").span(k).value(text_value(text)));
    }
    let block = cx.block(value).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    match kind {
        TreeKind::Facets => {
            f.u16("Hot spot x").emit()?;
            f.u16("Hot spot y").emit()?;
            let n = f.u16("Attribute count").emit()?;
            for _ in 0..n.min(256) {
                let a = f.u16("Attribute").enumeration(CAR_ATTRIBUTES).emit()?;
                let _ = a;
                f.u16("Value").emit()?;
            }
        }
        TreeKind::Names => {
            f.u16("Identifier").emit()?;
        }
        TreeKind::Bitmaps => {
            while f.remaining() >= 4 {
                f.u32("Word").hex().emit()?;
            }
        }
    }
    let rest = f.remaining();
    if rest > 0 {
        f.bytes("Rest", rest).emit()?;
    }
    Ok(())
}

fn text_value(s: String) -> Value {
    text(s)
}

async fn key_format(cx: Cx, (span, tokens): (Span, Arc<Vec<u32>>)) -> Result<()> {
    let block = cx.block(span.sub(0, 12)).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.ascii("Tag", 4).emit()?;
    f.u32("Version").emit()?;
    f.u32("Token count").emit()?;
    for (i, t) in tokens.iter().enumerate() {
        let at = 12u64.saturating_add(to_u64(i).saturating_mul(4));
        cx.emit(
            Node::new(format!("[{i}]"))
                .span(span.sub(at, 4))
                .value(Value::Enum {
                    raw: (*t).into(),
                    bits: 32,
                    name: lookup(CAR_ATTRIBUTES, (*t).into()),
                }),
        );
    }
    Ok(())
}

async fn renditions_tree(
    cx: Cx,
    (bom, block, tokens): (Arc<Bom>, u32, Arc<Vec<u32>>),
) -> Result<()> {
    let mut walk = TreeWalk::new(&cx, &bom, block).await?;
    cx.emit(
        struct_node("Tree header", walk.span, BE, (), tree_header)
            .summary(format!("root page {}, {} paths", walk.root, walk.paths)),
    );
    cx.emit(
        Node::new("Pages")
            .summary("index and leaf pages")
            .lazy(pages, (bom.clone(), walk.root)),
    );
    while let Some((value, key)) = walk.next(&cx, &bom).await? {
        cx.push(rendition_node(&cx, &bom, key, value, &tokens).await?)
            .await;
    }
    Ok(())
}

async fn rendition_node(cx: &Cx, bom: &Bom, key: u32, value: u32, tokens: &[u32]) -> Result<Node> {
    let key_span = bom.block(key).unwrap_or(bom.file.sub(0, 0));
    let value_span = bom.block(value).unwrap_or(bom.file.sub(0, 0));
    let k = cx.read(key_span.sub(0, 256)).await?;
    let attrs: Vec<String> = tokens
        .iter()
        .enumerate()
        .filter_map(|(i, t)| {
            let v = u16_le(&k, i.saturating_mul(2))?;
            (v != 0).then(|| format!("{}={v}", lookup(CAR_ATTRIBUTES, (*t).into()).unwrap_or("?")))
        })
        .collect();
    let (name, w, h, scale, format, _) =
        crate::fields::parse(cx, value_span.sub(0, 184), LE, &(), csi_header)
            .await
            .unwrap_or_default();
    let what = if w > 0 {
        format!("{w}×{h} @{}x {format}", scale / 100)
    } else {
        format.clone()
    };
    Ok(Node::new(if name.is_empty() {
        format!("block {value}")
    } else {
        name
    })
    .span(value_span)
    .summary(format!("{what}; {}", attrs.join(", ")))
    .lazy(
        rendition,
        (bom.input, key_span, value_span, Arc::new(tokens.to_vec())),
    ))
}

/// CSI TLV tags (`kCSIElement…` as seen in CoreUI output).
const CSI_TLV: EnumTable = &[
    (1001, "Slices"),
    (1003, "Metrics"),
    (1004, "Blend mode and opacity"),
    (1005, "UTI"),
    (1006, "EXIF orientation"),
    (1007, "Bytes per row"),
];

/// Compression of a `MLEC` pixel rendition.
const CSI_COMPRESSION: EnumTable = &[
    (0, "uncompressed"),
    (1, "RLE"),
    (2, "zip"),
    (3, "LZVN"),
    (4, "LZFSE"),
    (5, "JPEG + LZFSE"),
    (6, "blurred"),
    (7, "ASTC"),
    (8, "palette image"),
    (9, "HEVC"),
    (10, "deepmap LZFSE"),
    (11, "deepmap2"),
];

async fn rendition(
    cx: Cx,
    (input, key, value, tokens): (Input, Span, Span, Arc<Vec<u32>>),
) -> Result<()> {
    cx.emit(
        Node::new("Key")
            .span(key)
            .summary(format!("{} attributes", key.len / 2))
            .lazy(rendition_key, (key, tokens)),
    );
    let head = value.sub(0, 184);
    let (_, _, _, _, _, tlv) = crate::fields::parse(&cx, head, LE, &(), csi_header).await?;
    cx.emit(struct_node("CSI header", head, LE, (), csi_header));
    let tlv_span = value.sub(184, tlv.into());
    cx.emit(
        Node::new("TLV")
            .span(tlv_span)
            .summary(size(tlv_span.len))
            .lazy(csi_tlv, tlv_span),
    );
    let data = value.tail(184u64.saturating_add(tlv.into()));
    let magic = cx.read_avail(data.sub(0, 4)).await?;
    if magic.len() == 4 && magic.iter().all(u8::is_ascii_alphanumeric) {
        // A CoreUI-encoded rendition; the tag is stored little-endian.
        let tag: String = magic.iter().rev().map(|&b| char::from(b)).collect();
        cx.emit(
            Node::new("Rendition data")
                .span(data)
                .summary(format!("'{tag}', {} bytes", data.len))
                .lazy(rendition_data, (input, data, tag)),
        );
    } else {
        cx.emit(
            embedded("Rendition data", input.nested(data)).summary(format!("{} bytes", data.len)),
        );
    }
    Ok(())
}

async fn rendition_key(cx: Cx, (key, tokens): (Span, Arc<Vec<u32>>)) -> Result<()> {
    let data = cx.read(key).await?;
    for (i, w) in data.chunks(2).enumerate() {
        let name = tokens
            .get(i)
            .and_then(|&t| lookup(CAR_ATTRIBUTES, t.into()))
            .unwrap_or("attribute");
        cx.push(
            Node::new(name)
                .span(key.sub(to_u64(i).saturating_mul(2), 2))
                .value(uint(u16_le(w, 0).unwrap_or(0), 16)),
        )
        .await;
    }
    Ok(())
}

/// Tag, length and value records after the CSI header.
async fn csi_tlv(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read(span).await?;
    let mut at = 0usize;
    while at.saturating_add(8) <= data.len() {
        let tag = u32_le(&data, at).unwrap_or(0);
        let len = u32_le(&data, at.saturating_add(4)).unwrap_or(0);
        let whole = span.sub(to_u64(at), u64::from(len).saturating_add(8));
        cx.push(
            Node::new(crate::formats::util::val::name_or(
                CSI_TLV,
                tag.into(),
                "Tag",
            ))
            .span(whole)
            .lazy(tlv_entry, (whole, tag)),
        )
        .await;
        at = at.saturating_add(8).saturating_add(to_usize(len.into()));
    }
    if at < data.len() {
        let rest = span.tail(to_u64(at));
        cx.push(Node::new("Trailing bytes").span(rest)).await;
    }
    Ok(())
}

async fn tlv_entry(cx: Cx, (span, tag): (Span, u32)) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u32("Tag").enumeration(CSI_TLV).emit()?;
    f.u32("Length").emit()?;
    match tag {
        1001 => {
            let n = f.u32("Slice count").emit()?;
            for _ in 0..n.min(1024) {
                f.u32("x").emit()?;
                f.u32("y").emit()?;
                f.u32("Width").emit()?;
                f.u32("Height").emit()?;
            }
        }
        1003 => {
            let n = f.u32("Metric count").emit()?;
            for _ in 0..n.min(1024) {
                f.u32("Top-left inset width").emit()?;
                f.u32("Top-left inset height").emit()?;
                f.u32("Bottom-right inset width").emit()?;
                f.u32("Bottom-right inset height").emit()?;
                f.u32("Image width").emit()?;
                f.u32("Image height").emit()?;
            }
        }
        1004 => {
            f.u32("Blend mode").emit()?;
            f.f32("Opacity").emit()?;
        }
        1005 => {
            let len = f.u32("UTI length").emit()?;
            f.u32("Reserved").emit()?;
            f.ascii("UTI", len.into()).emit()?;
        }
        1006 => {
            f.u32("Orientation").emit()?;
        }
        1007 => {
            f.u32("Bytes per row").emit()?;
        }
        _ => {}
    }
    let rest = f.remaining();
    if rest > 0 {
        f.bytes("Value", rest).emit()?;
    }
    Ok(())
}

async fn rendition_data(cx: Cx, (input, data, tag): (Input, Span, String)) -> Result<()> {
    let block = cx.block(data.sub(0, 16)).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.ascii("Tag", 4).desc("Stored little-endian").emit()?;
    match tag.as_str() {
        "CELM" => {
            f.u32("Version").emit()?;
            f.u32("Compression").enumeration(CSI_COMPRESSION).emit()?;
            let len = f.u32("Length").emit()?;
            let pixels = data.sub(16, len.into());
            cx.emit(
                Node::new("Compressed pixels")
                    .span(pixels)
                    .summary(size(pixels.len))
                    .desc("CoreUI pixel data in the compression named above"),
            );
        }
        "COLR" => {
            f.u32("Version").emit()?;
            f.u32("Flags").hex().emit()?;
            let n = f.u32("Component count").emit()?;
            let comps = cx
                .block(data.sub(16, u64::from(n).saturating_mul(8)))
                .await?;
            let mut g = Fields::emitting(&cx, &comps, LE);
            for _ in 0..n.min(16) {
                g.f64("Component").emit()?;
            }
        }
        "RAWD" => {
            f.u32("Version").emit()?;
            let len = f.u32("Length").emit()?;
            cx.emit(
                embedded("Data", input.nested(data.sub(12, len.into()))).summary(size(len.into())),
            );
        }
        _ => {
            let rest = data.tail(4);
            cx.emit(Node::new("Payload").span(rest).summary(size(rest.len)));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Standalone code signature

fn csig_probe(h: &Head<'_>) -> bool {
    matches!(u32_be(h.data, 0), Some(0xfade_0cc0 | 0xfade_0cc1))
        && u32_be(h.data, 4).is_some_and(|l| l >= 12 && u64::from(l) <= h.len)
        && u32_be(h.data, 8).is_some_and(|n| (1..=64).contains(&n))
}

declare_format!(pub CODE_SIGNATURE = "apple-code-signature", "Apple code signature (SuperBlob)", ["csig", "sig"], "application/x-apple-code-signature",
    Probe::Custom(csig_probe), code_signature);

async fn code_signature(cx: Cx, input: Input) -> Result<()> {
    let span = input.span;
    let summary = crate::formats::executable::macho::codesign::summary(&cx, span)
        .await
        .unwrap_or_else(|_| "detached".to_owned());
    crate::formats::executable::macho::codesign::superblob(cx.clone(), span).await?;
    cx.annotate(format!("Apple code signature, {summary}"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Apple Encrypted Archive (.aea)

const AEA_PROFILES: EnumTable = &[
    (0, "signed, not encrypted"),
    (1, "symmetric key encryption"),
    (2, "symmetric key encryption, signed"),
    (3, "ECDHE encryption"),
    (4, "ECDHE encryption, signed"),
    (5, "scrypt password encryption"),
];

fn aea_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"AEA1") && crate::bytes::u24_le(h.data, 4).is_some_and(|p| p <= 5)
}

declare_format!(pub AEA = "aea", "Apple Encrypted Archive", ["aea"], "application/x-apple-encrypted-archive",
    Probe::Custom(aea_probe), aea);

async fn aea(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 12)).await?;
    let profile = crate::bytes::u24_le(&head, 4).unwrap_or(0);
    let auth_len = u32_le(&head, 8).unwrap_or(0);
    cx.emit(struct_node("Header", file.sub(0, 12), LE, (), |f, _| {
        f.ascii("Magic", 4).emit()?;
        f.bytes("Profile", 3)
            .with(|b, n| {
                let p = u64::from(crate::bytes::u24_le(b, 0).unwrap_or(0));
                n.summary(lookup(AEA_PROFILES, p).unwrap_or("unknown"))
            })
            .emit()?;
        f.u8("Scrypt strength").emit()?;
        f.u32("Auth data size").emit()?;
        Ok(())
    }));
    let auth = file.sub(12, auth_len.into());
    cx.emit(
        Node::new("Auth data")
            .span(auth)
            .summary(format!("{auth_len} bytes"))
            .lazy(aea_auth, auth),
    );
    cx.emit(
        Node::new("Signature, keys and encrypted segments")
            .span(file.tail(12u64.saturating_add(auth_len.into()))),
    );
    cx.annotate(format!(
        "Apple Encrypted Archive, {}",
        lookup(AEA_PROFILES, profile.into()).unwrap_or("unknown profile")
    ));
    Ok(())
}

/// Auth data: entries of a 32-bit size (including itself) and `key\0value`.
async fn aea_auth(cx: Cx, auth: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, auth, LE);
    while cur.remaining() >= 4 {
        let start = cur.pos();
        let len = u64::from(cur.u32().await?);
        if len < 4 {
            return Err(
                Diagnostic::malformed(format!("auth entry of {len} bytes")).at(cur.since(start))
            );
        }
        let body = cur.bytes(len.saturating_sub(4)).await?;
        let (key, value) = match body.iter().position(|&b| b == 0) {
            Some(i) => (
                body.get(..i).unwrap_or_default(),
                body.get(i.saturating_add(1)..).unwrap_or_default(),
            ),
            None => (&[][..], body.as_slice()),
        };
        let value = if std::str::from_utf8(value).is_ok() {
            text(String::from_utf8_lossy(value).into_owned())
        } else {
            Value::Bytes(value.to_vec())
        };
        cx.push(
            Node::new(String::from_utf8_lossy(key).into_owned())
                .span(cur.since(start))
                .value(value),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Trust cache

fn trustcache_entry(version: u32) -> Option<u64> {
    match version {
        0 => Some(20),
        1 => Some(22),
        2 => Some(24),
        _ => None,
    }
}

fn trustcache_probe(h: &Head<'_>) -> bool {
    let (Some(version), Some(count)) = (u32_le(h.data, 0), u32_le(h.data, 20)) else {
        return false;
    };
    trustcache_entry(version)
        .is_some_and(|e| count > 0 && e.saturating_mul(count.into()).saturating_add(24) == h.len)
}

declare_format!(pub TRUSTCACHE = "apple-trustcache", "Apple trust cache", ["trustcache", "img4"], "application/x-apple-trustcache",
    Probe::Custom(trustcache_probe), trustcache);

async fn trustcache(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 24)).await?;
    let version = u32_le(&head, 0).unwrap_or(0);
    let count = u32_le(&head, 20).unwrap_or(0);
    let entry = trustcache_entry(version).unwrap_or(24);
    cx.emit(struct_node("Header", file.sub(0, 24), LE, (), |f, _| {
        f.u32("Version").emit()?;
        f.bytes("UUID", 16).emit()?;
        f.u32("Entry count").emit()?;
        Ok(())
    }));
    let mut cur = Cursor::new(&cx, file.tail(24), LE);
    cx.set_count(Count::Exact(u64::from(count).saturating_add(1)));
    for _ in 0..count {
        let start = cur.pos();
        let data = cur.bytes(entry).await?;
        let hash = hex_string(data.get(..20).unwrap_or_default());
        let mut summary = String::new();
        if entry > 20 {
            let kind = data.get(20).copied().unwrap_or(0);
            let flags = data.get(21).copied().unwrap_or(0);
            summary = format!("hash type {kind}, flags {flags:#x}");
            if entry > 22 {
                summary.push_str(&format!(
                    ", constraint category {}",
                    data.get(22).copied().unwrap_or(0)
                ));
            }
        }
        cx.push(
            Node::new("CDHash")
                .span(cur.since(start))
                .value(text(hash))
                .summary(summary),
        )
        .await;
    }
    cx.annotate(format!("Apple trust cache v{version}, {count} CDHashes"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Swift module (.swiftmodule)

declare_format!(pub SWIFTMODULE = "swiftmodule", "Swift module (serialized AST)", ["swiftmodule"], "application/x-swiftmodule",
    Probe::Magic(&[(0, b"\xe2\x9c\xa8\x0e")]), swiftmodule);

const SWIFT_BLOCKS: EnumTable = &[
    (0, "BLOCKINFO"),
    (8, "MODULE_BLOCK"),
    (9, "CONTROL_BLOCK"),
    (10, "INPUT_BLOCK"),
    (11, "DECLS_AND_TYPES_BLOCK"),
    (12, "IDENTIFIER_DATA_BLOCK"),
    (13, "INDEX_BLOCK"),
    (14, "SIL_BLOCK"),
    (15, "SIL_INDEX_BLOCK"),
    (16, "OPTIONS_BLOCK"),
];

async fn swiftmodule(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(
        Node::new("Magic")
            .span(file.sub(0, 4))
            .value(Value::Bytes(b"\xe2\x9c\xa8\x0e".to_vec()))
            .desc("✨ followed by 0x0E"),
    );
    let mut at = 4u64;
    let mut blocks = Vec::new();
    while at < file.len {
        let window = cx.read_avail(file.sub(at, 16)).await?;
        let mut bits = crate::formats::bytecode::bitcode::Bits::new(&window);
        let abbrev = bits.read(2);
        if abbrev != Some(1) {
            // Top level holds only blocks (ENTER_SUBBLOCK).
            cx.emit(
                Node::new("Unparsed")
                    .span(file.tail(at))
                    .summary(format!("abbreviation {abbrev:?} at top level")),
            );
            break;
        }
        let (Some(id), Some(_width)) = (bits.vbr(8), bits.vbr(4)) else {
            return Err(Diagnostic::truncated(
                file.sub(at, 16),
                to_u64(window.len()),
            ));
        };
        let words_at = bits.pos.div_ceil(32).saturating_mul(4);
        let words = u64::from(
            u32_le(&window, to_usize(words_at))
                .ok_or_else(|| Diagnostic::truncated(file.sub(at, 16), to_u64(window.len())))?,
        );
        let len = words_at
            .saturating_add(4)
            .saturating_add(words.saturating_mul(4));
        let span = file.sub(at, len);
        let name = lookup(SWIFT_BLOCKS, id).map_or_else(|| format!("block {id}"), str::to_owned);
        blocks.push(name.clone());
        cx.push(
            Node::new(name)
                .span(span)
                .summary(format!("{} bytes", words.saturating_mul(4))),
        )
        .await;
        at = at.saturating_add(len);
    }
    cx.annotate(format!("Swift module, blocks: {}", blocks.join(", ")));
    Ok(())
}
