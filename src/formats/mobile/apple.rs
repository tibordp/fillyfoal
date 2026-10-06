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
use crate::formats::datakit::{hex_string, size};
use crate::formats::{Head, Input, Probe, embedded};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value, lookup};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

fn text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

fn uint(value: u64) -> Value {
    Value::UInt {
        value,
        bits: 64,
        radix: Radix::Dec,
    }
}

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
            .value(uint(span.len)),
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

/// The BOMStore's named blocks (variables) and its block index.
struct Bom {
    input: Input,
    file: Span,
    index: Vec<u8>,
    vars: Vec<(String, u32, Span)>,
}

impl Bom {
    fn block(&self, id: u32) -> Option<Span> {
        let at = to_usize(u64::from(id).saturating_mul(8)).saturating_add(4);
        let offset = u32_be(&self.index, at)?;
        let len = u32_be(&self.index, at.saturating_add(4))?;
        Some(self.file.sub(offset.into(), len.into()))
    }

    fn var(&self, name: &str) -> Option<Span> {
        self.vars
            .iter()
            .find(|v| v.0 == name)
            .and_then(|v| self.block(v.1))
    }
}

async fn read_bom(cx: &Cx, input: Input) -> Result<Bom> {
    let file = input.span;
    let head = cx.read(file.sub(0, 32)).await?;
    let index_at = u32_be(&head, 16).unwrap_or(0);
    let index_len = u32_be(&head, 20).unwrap_or(0);
    let vars_at = u32_be(&head, 24).unwrap_or(0);
    let vars_len = u32_be(&head, 28).unwrap_or(0);
    let index = cx
        .read(file.sub_exact(index_at.into(), index_len.into())?)
        .await?;
    let mut cur = Cursor::new(cx, file.sub(vars_at.into(), vars_len.into()), BE);
    let count = cur.u32().await?;
    let mut vars = Vec::new();
    for _ in 0..count.min(1024) {
        let start = cur.pos();
        let block = cur.u32().await?;
        let len = cur.u8().await?;
        let name = String::from_utf8_lossy(&cur.bytes(len.into()).await?).into_owned();
        vars.push((name, block, cur.since(start)));
    }
    Ok(Bom {
        input,
        file,
        index,
        vars,
    })
}

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
    cx.emit(
        Node::new("BOM header")
            .span(file.sub(0, 32))
            .lazy(bom_header, file),
    );
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
            _ => Node::new(name.clone())
                .span(span)
                .summary(format!("block {block}, {} bytes", span.len)),
        };
        cx.push(node.target(*var)).await;
    }
    let names: Vec<&str> = bom.vars.iter().map(|v| v.0.as_str()).collect();
    cx.annotate(format!(
        "Asset catalog, {renditions} renditions ({})",
        names.join(", ")
    ));
    Ok(())
}

async fn bom_header(cx: Cx, file: Span) -> Result<()> {
    let block = cx.block(file.sub(0, 32)).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    f.ascii("Magic", 8).emit()?;
    f.u32("Version").emit()?;
    f.u32("Non-null blocks").emit()?;
    f.u32("Block index offset").hex().emit()?;
    f.u32("Block index length").emit()?;
    f.u32("Variables offset").hex().emit()?;
    f.u32("Variables length").emit()?;
    Ok(())
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

/// Most tree pages followed.
const MAX_PAGES: usize = 100_000;

async fn renditions_tree(
    cx: Cx,
    (bom, block, tokens): (Arc<Bom>, u32, Arc<Vec<u32>>),
) -> Result<()> {
    let tree = bom
        .block(block)
        .ok_or_else(|| Diagnostic::malformed("missing tree block"))?;
    let head = cx.read(tree.sub(0, 21)).await?;
    if head.get(..4) != Some(b"tree") {
        return Err(Diagnostic::malformed("not a BOM tree").at(tree.sub(0, 4)));
    }
    let mut page = u32_be(&head, 8).unwrap_or(0);
    let paths = u32_be(&head, 16).unwrap_or(0);
    cx.emit(
        Node::new("Tree header")
            .span(tree)
            .summary(format!("root page {page}, {paths} paths")),
    );
    // Descend to the leftmost leaf, then follow the leaves' forward links.
    let mut visited = std::collections::BTreeSet::new();
    loop {
        if !visited.insert(page) || visited.len() > MAX_PAGES {
            return Err(Diagnostic::malformed(format!("tree page {page} revisited")));
        }
        let span = bom
            .block(page)
            .ok_or_else(|| Diagnostic::malformed(format!("missing page {page}")))?;
        let h = cx.read(span.sub(0, 12)).await?;
        let leaf = u16::from_be_bytes([
            h.first().copied().unwrap_or(0),
            h.get(1).copied().unwrap_or(0),
        ]) != 0;
        let count = crate::bytes::u16_be(&h, 2).unwrap_or(0);
        let forward = u32_be(&h, 4).unwrap_or(0);
        let entries = cx
            .read(span.sub_exact(12, u64::from(count).saturating_mul(8))?)
            .await?;
        if !leaf {
            page = u32_be(&entries, 0)
                .ok_or_else(|| Diagnostic::malformed("empty index page").at(span))?;
            continue;
        }
        for i in 0..usize::from(count) {
            let value = u32_be(&entries, i.saturating_mul(8)).unwrap_or(0);
            let key = u32_be(&entries, i.saturating_mul(8).saturating_add(4)).unwrap_or(0);
            cx.push(rendition_node(&cx, &bom, key, value, &tokens).await?)
                .await;
        }
        if forward == 0 {
            break;
        }
        page = forward;
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
    Ok(Node::new(if name.is_empty() {
        format!("block {value}")
    } else {
        name
    })
    .span(value_span)
    .summary(format!(
        "{w}×{h} @{}x {format}; {}",
        scale / 100,
        attrs.join(", ")
    ))
    .lazy(rendition, (bom.input, key_span, value_span)))
}

async fn rendition(cx: Cx, (input, key, value): (Input, Span, Span)) -> Result<()> {
    cx.emit(
        Node::new("Key")
            .span(key)
            .summary(format!("{} attributes", key.len / 2)),
    );
    let head = value.sub(0, 184);
    let (_, _, _, _, _, tlv) = crate::fields::parse(&cx, head, LE, &(), csi_header).await?;
    cx.emit(struct_node("CSI header", head, LE, (), csi_header));
    cx.emit(Node::new("TLV").span(value.sub(184, tlv.into())));
    let data = value.tail(184u64.saturating_add(tlv.into()));
    let magic = cx.read_avail(data.sub(0, 4)).await?;
    if magic.len() == 4 && magic.iter().all(u8::is_ascii_alphanumeric) {
        // A CoreUI-encoded rendition (e.g. "MLEC" compressed pixels).
        let tag: String = magic.iter().rev().map(|&b| char::from(b)).collect();
        cx.emit(
            Node::new("Rendition data")
                .span(data)
                .summary(format!("'{tag}', {} bytes", data.len)),
        );
    } else {
        cx.emit(
            embedded("Rendition data", input.nested(data)).summary(format!("{} bytes", data.len)),
        );
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
    let summary = crate::formats::macho::codesign::summary(&cx, span)
        .await
        .unwrap_or_else(|_| "detached".to_owned());
    crate::formats::macho::codesign::superblob(cx.clone(), span).await?;
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

/// Little-endian bit reader over a small buffer.
struct Bits<'a> {
    data: &'a [u8],
    pos: u64,
}

impl Bits<'_> {
    fn read(&mut self, n: u32) -> Option<u64> {
        let mut v = 0u64;
        for i in 0..n {
            let byte = self.data.get(to_usize(self.pos / 8))?;
            let bit = byte
                .checked_shr(u32::try_from(self.pos % 8).unwrap_or(0))
                .unwrap_or(0)
                & 1;
            v |= u64::from(bit).checked_shl(i)?;
            self.pos = self.pos.saturating_add(1);
        }
        Some(v)
    }

    fn vbr(&mut self, n: u32) -> Option<u64> {
        let hi = 1u64.checked_shl(n.saturating_sub(1))?;
        let mut v = 0u64;
        let mut shift = 0u32;
        loop {
            let chunk = self.read(n)?;
            v |= (chunk & hi.saturating_sub(1)).checked_shl(shift)?;
            if chunk & hi == 0 {
                return Some(v);
            }
            shift = shift.saturating_add(n.saturating_sub(1));
            if shift >= 64 {
                return None;
            }
        }
    }
}

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
        let mut bits = Bits {
            data: &window,
            pos: 0,
        };
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
