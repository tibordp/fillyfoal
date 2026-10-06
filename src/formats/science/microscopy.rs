//! Microscopy and electron-microscopy images: MRC/CCP4 maps, Zeiss CZI,
//! Nikon ND2, Leica LIF, FEI/TIA SER, and Gatan Digital Micrograph
//! (DM3/DM4).

use crate::bytes::{to_u64, to_usize, u16_le, u32_be, u32_le, u64_be};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::lines::{float, int, preview, summarize, text, uint};
use crate::formats::{Head, Input, Probe, embedded};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Value, lookup};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// MRC / CCP4 density maps and image stacks

fn mrc_probe(h: &Head<'_>) -> bool {
    let mode = u32_le(h.data, 12).unwrap_or(u32::MAX);
    h.at(208, b"MAP ")
        && (mode <= 6 || mode == 12 || mode == 101 || u32_be(h.data, 12).is_some_and(|m| m <= 6))
}

declare_format!(pub MRC = "mrc", "MRC/CCP4 density map or image stack", ["mrc", "mrcs", "map", "ccp4", "rec", "st", "ali"], "application/x-mrc",
    Probe::Custom(mrc_probe), mrc);

const MRC_MODES: EnumTable = &[
    (0, "int8"),
    (1, "int16"),
    (2, "float32"),
    (3, "complex int16"),
    (4, "complex float32"),
    (6, "uint16"),
    (12, "float16"),
    (101, "4-bit packed"),
];

fn mrc_voxel_bits(mode: u32) -> u64 {
    match mode {
        0 => 8,
        1 | 6 | 12 => 16,
        2 | 3 => 32,
        4 => 64,
        101 => 4,
        _ => 0,
    }
}

record! {
    pub struct MrcHeader {
        nx: u32 "NX (columns)",
        ny: u32 "NY (rows)",
        nz: u32 "NZ (sections)",
        mode: u32 "MODE" .enumeration(MRC_MODES),
        nxstart: i32 "NXSTART",
        nystart: i32 "NYSTART",
        nzstart: i32 "NZSTART",
        mx: u32 "MX",
        my: u32 "MY",
        mz: u32 "MZ",
        cell_a: f32 "Cell a (Å)",
        cell_b: f32 "Cell b (Å)",
        cell_c: f32 "Cell c (Å)",
        alpha: f32 "Cell α",
        beta: f32 "Cell β",
        gamma: f32 "Cell γ",
        mapc: u32 "MAPC (axis for columns)",
        mapr: u32 "MAPR (axis for rows)",
        maps: u32 "MAPS (axis for sections)",
        dmin: f32 "DMIN",
        dmax: f32 "DMAX",
        dmean: f32 "DMEAN",
        ispg: u32 "ISPG (space group)",
        nsymbt: u32 "NSYMBT (extended header bytes)",
        extra1: bytes[8] "EXTRA",
        exttyp: ascii[4] "EXTTYP",
        nversion: u32 "NVERSION",
        extra2: bytes[84] "EXTRA",
        origin_x: f32 "Origin X",
        origin_y: f32 "Origin Y",
        origin_z: f32 "Origin Z",
        map: ascii[4] "MAP",
        machst: bytes[4] "MACHST (machine stamp)",
        rms: f32 "RMS",
        nlabl: u32 "NLABL",
    }
}

async fn mrc(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let stamp = cx.read(file.sub(212, 1)).await?;
    let endian = if stamp.first() == Some(&0x11) { BE } else { LE };
    let hs = file.sub(0, MrcHeader::SIZE);
    let h: MrcHeader = read_record(&cx, hs, endian).await?;
    cx.emit(MrcHeader::node("Header", hs, endian));
    let labels = cx.read_avail(file.sub(224, 800)).await?;
    let list: Vec<String> = labels
        .chunks(80)
        .take(to_usize(h.nlabl.min(10).into()))
        .map(|l| {
            String::from_utf8_lossy(l)
                .trim_end_matches(['\0', ' '])
                .to_owned()
        })
        .collect();
    cx.emit(
        Node::new("Labels")
            .span(file.sub(224, 800))
            .value(uint(h.nlabl.into()))
            .lazy(mrc_labels, (file.sub(224, 800), list.clone())),
    );
    if h.nsymbt > 0 {
        cx.emit(
            Node::new("Extended header")
                .span(file.sub(1024, h.nsymbt.into()))
                .value(text(h.exttyp.trim_end_matches('\0'))),
        );
    }
    let data_at = 1024u64.saturating_add(h.nsymbt.into());
    let section = u64::from(h.nx)
        .saturating_mul(h.ny.into())
        .saturating_mul(mrc_voxel_bits(h.mode))
        .div_ceil(8);
    let data = file.tail(data_at);
    cx.emit(
        Node::new("Sections")
            .span(data)
            .value(uint(h.nz.into()))
            .summary(format!(
                "{}×{} {}",
                h.nx,
                h.ny,
                lookup(MRC_MODES, h.mode.into()).unwrap_or("?")
            ))
            .lazy(mrc_sections, (data, section, h.nz)),
    );
    let apix = if h.mx > 0 {
        h.cell_a / h.mx as f32
    } else {
        0.0
    };
    cx.annotate(format!(
        "MRC{}, {}×{}×{} {}, {apix:.3} Å/pixel, density {}…{} (mean {}){}",
        if h.nversion > 0 {
            format!(" {}", h.nversion)
        } else {
            String::new()
        },
        h.nx,
        h.ny,
        h.nz,
        lookup(MRC_MODES, h.mode.into()).unwrap_or("?"),
        h.dmin,
        h.dmax,
        h.dmean,
        list.first()
            .map(|l| format!("; {}", preview(l, 60)))
            .unwrap_or_default()
    ));
    Ok(())
}

async fn mrc_labels(cx: Cx, (span, list): (Span, Vec<String>)) -> Result<()> {
    for (i, l) in list.into_iter().enumerate() {
        cx.emit(
            Node::new(format!("Label {i}"))
                .span(span.sub(to_u64(i).saturating_mul(80), 80))
                .value(text(l)),
        );
    }
    Ok(())
}

async fn mrc_sections(cx: Cx, (data, size, nz): (Span, u64, u32)) -> Result<()> {
    if size == 0 {
        return Ok(());
    }
    cx.set_count(Count::Exact(nz.into()));
    for z in 0..u64::from(nz) {
        let s = data.sub(z.saturating_mul(size), size);
        if s.len == 0 {
            break;
        }
        cx.push(Node::new(format!("Section {z}")).span(s)).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Zeiss CZI

declare_format!(pub CZI = "czi", "Carl Zeiss Image (CZI)", ["czi"], "image/x-czi",
    Probe::Magic(&[(0, b"ZISRAWFILE\0\0\0\0\0\0")]), czi);

const CZI_PIXELS: EnumTable = &[
    (0, "Gray8"),
    (1, "Gray16"),
    (2, "Gray32Float"),
    (3, "Bgr24"),
    (4, "Bgr48"),
    (8, "Bgr96Float"),
    (9, "Bgra32"),
    (10, "Gray64ComplexFloat"),
    (11, "Bgr192ComplexFloat"),
    (12, "Gray32"),
    (13, "Gray64"),
];
const CZI_COMPRESSION: EnumTable = &[
    (0, "uncompressed"),
    (1, "JPEG"),
    (2, "LZW"),
    (4, "JPEG XR"),
    (5, "zstd"),
    (6, "zstd (with header)"),
];

record! {
    pub struct CziSegment {
        id: ascii[16] "Segment ID",
        allocated: u64 "Allocated size",
        used: u64 "Used size",
    }
}

record! {
    pub struct CziFileHeader {
        major: u32 "Major version",
        minor: u32 "Minor version",
        reserved1: u32 "Reserved",
        reserved2: u32 "Reserved",
        primary: guid "Primary file GUID",
        file_guid: guid "File GUID",
        part: u32 "File part",
        directory: u64 "Directory position" .hex(),
        metadata: u64 "Metadata position" .hex(),
        update: u32 "Update pending",
        attachments: u64 "Attachment directory position" .hex(),
    }
}

/// A DV directory entry: (pixel type, file position, compression, dimensions, size).
async fn czi_entry(cx: &Cx, span: Span) -> Result<(u32, u64, u32, String, u64)> {
    let b = cx.block(span.sub(0, 32)).await?;
    let mut f = Fields::new(&b, LE);
    f.ascii("Schema", 2).get()?;
    let pixel = f.u32("Pixel type").get()?;
    let pos = f.u64("File position").get()?;
    f.u32("File part").get()?;
    let compression = f.u32("Compression").get()?;
    f.u8("Pyramid type").get()?;
    f.bytes("Reserved", 5).get()?;
    let n = f.u32("Dimension count").get()?;
    let dims = cx
        .read_avail(span.sub(32, u64::from(n.min(64)).saturating_mul(20)))
        .await?;
    let list: Vec<String> = dims
        .chunks(20)
        .filter(|c| c.len() == 20)
        .map(|c| {
            format!(
                "{}={}+{}",
                String::from_utf8_lossy(c.get(..4).unwrap_or_default()).trim_end_matches('\0'),
                crate::bytes::i32_le(c, 4).unwrap_or(0),
                u32_le(c, 8).unwrap_or(0)
            )
        })
        .collect();
    Ok((
        pixel,
        pos,
        compression,
        list.join(" "),
        32u64.saturating_add(u64::from(n).saturating_mul(20)),
    ))
}

async fn czi(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let fh_span = file.sub(32, CziFileHeader::SIZE);
    let h: CziFileHeader = read_record(&cx, fh_span, LE).await?;
    let mut pos = 0u64;
    let mut counts: Vec<(String, u64)> = Vec::new();
    let mut i = 0u64;
    while pos.saturating_add(CziSegment::SIZE) <= file.len {
        let seg: CziSegment = read_record(&cx, file.sub(pos, CziSegment::SIZE), LE).await?;
        let id = seg.id.trim_end_matches('\0').to_owned();
        if id.is_empty() {
            break;
        }
        let span = file.sub(pos, CziSegment::SIZE.saturating_add(seg.allocated));
        let data = file.sub(pos.saturating_add(CziSegment::SIZE), seg.used);
        crate::formats::util::lines::tally(&mut counts, &id, 32);
        let summary = match id.as_str() {
            "ZISRAWSUBBLOCK" => {
                let (pixel, _, compression, dims, _) = czi_entry(&cx, data.sub(16, 0x1000))
                    .await
                    .unwrap_or_default();
                format!(
                    "{} {}, {dims}",
                    lookup(CZI_PIXELS, pixel.into()).unwrap_or("?"),
                    lookup(CZI_COMPRESSION, compression.into()).unwrap_or("?")
                )
            }
            "ZISRAWATTACH" => {
                let b = cx.read_avail(data.sub(16, 128)).await?;
                format!(
                    "{} ({})",
                    crate::text::until_nul(b.get(48..128).unwrap_or_default()),
                    crate::text::until_nul(b.get(40..48).unwrap_or_default())
                )
            }
            _ => format!("{} bytes", seg.used),
        };
        cx.push(
            Node::new(format!("{id} @{pos:#x}"))
                .span(span)
                .summary(summary)
                .lazy(czi_segment, (input, pos, id.clone(), seg.used)),
        )
        .await;
        i = i.saturating_add(1);
        pos = pos
            .saturating_add(CziSegment::SIZE)
            .saturating_add(seg.allocated.max(1));
    }
    let subblocks = counts
        .iter()
        .find(|(k, _)| k == "ZISRAWSUBBLOCK")
        .map_or(0, |(_, n)| *n);
    cx.annotate(format!(
        "CZI {}.{}, {i} segment(s), {subblocks} subblock(s), file {}",
        h.major, h.minor, h.file_guid
    ));
    Ok(())
}

async fn czi_segment(cx: Cx, (input, pos, id, used): (Input, u64, String, u64)) -> Result<()> {
    let file = input.span;
    cx.emit(CziSegment::node(
        "Segment header",
        file.sub(pos, CziSegment::SIZE),
        LE,
    ));
    let data = file.sub(pos.saturating_add(CziSegment::SIZE), used);
    match id.as_str() {
        "ZISRAWFILE" => cx.emit(CziFileHeader::node(
            "File header",
            data.sub(0, CziFileHeader::SIZE),
            LE,
        )),
        "ZISRAWMETADATA" => {
            let b = cx.read_avail(data.sub(0, 8)).await?;
            let xml = u64::from(u32_le(&b, 0).unwrap_or(0));
            let att = u64::from(u32_le(&b, 4).unwrap_or(0));
            cx.emit(Node::new("XML size").span(data.sub(0, 4)).value(uint(xml)));
            cx.emit(
                Node::new("Attachment size")
                    .span(data.sub(4, 4))
                    .value(uint(att)),
            );
            let x = cx.read_avail(data.sub(256, xml.min(512))).await?;
            cx.emit(
                Node::new("XML")
                    .span(data.sub(256, xml))
                    .value(text(preview(&String::from_utf8_lossy(&x), 200))),
            );
        }
        "ZISRAWDIRECTORY" => {
            let b = cx.read_avail(data.sub(0, 4)).await?;
            let n = u32_le(&b, 0).unwrap_or(0);
            cx.emit(
                Node::new("Entry count")
                    .span(data.sub(0, 4))
                    .value(uint(n.into())),
            );
            let mut at = 128u64;
            for k in 0..n.min(1_000_000) {
                let (pixel, fpos, compression, dims, len) =
                    czi_entry(&cx, data.sub(at, 0x1000)).await?;
                cx.push(
                    Node::new(format!("Entry {k}"))
                        .span(data.sub(at, len))
                        .value(text(dims))
                        .summary(format!(
                            "{} {}",
                            lookup(CZI_PIXELS, pixel.into()).unwrap_or("?"),
                            lookup(CZI_COMPRESSION, compression.into()).unwrap_or("?")
                        ))
                        .target(file.sub(fpos, CziSegment::SIZE)),
                )
                .await;
                at = at.saturating_add(len.max(1));
            }
        }
        "ZISRAWSUBBLOCK" => {
            let b = cx.block(data.sub(0, 16)).await?;
            let mut f = Fields::emitting(&cx, &b, LE);
            let meta = f.u32("Metadata size").emit()?;
            let att = f.u32("Attachment size").emit()?;
            let size = f.u64("Data size").emit()?;
            let (pixel, _, compression, dims, len) = czi_entry(&cx, data.sub(16, 0x1000)).await?;
            cx.emit(
                Node::new("Directory entry")
                    .span(data.sub(16, len))
                    .value(text(dims))
                    .summary(format!(
                        "{} {}",
                        lookup(CZI_PIXELS, pixel.into()).unwrap_or("?"),
                        lookup(CZI_COMPRESSION, compression.into()).unwrap_or("?")
                    )),
            );
            let header = 16u64.saturating_add(len).max(256);
            let m = data.sub(header, meta.into());
            let x = cx.read_avail(m.sub(0, 512)).await?;
            cx.emit(
                Node::new("Metadata")
                    .span(m)
                    .value(text(preview(&String::from_utf8_lossy(&x), 200))),
            );
            let d = data.sub(header.saturating_add(meta.into()), size);
            cx.emit(if compression == 1 {
                embedded("Data (JPEG)", input.nested(d))
            } else {
                Node::new("Data").span(d)
            });
            if att > 0 {
                cx.emit(Node::new("Attachments").span(data.sub(
                    header.saturating_add(meta.into()).saturating_add(size),
                    att.into(),
                )));
            }
        }
        "ZISRAWATTACH" => {
            let b = cx.read_avail(data.sub(0, 256)).await?;
            let size = u64::from(u32_le(&b, 0).unwrap_or(0));
            cx.emit(
                Node::new("Data size")
                    .span(data.sub(0, 4))
                    .value(uint(size)),
            );
            let name = crate::text::until_nul(b.get(64..144).unwrap_or_default());
            let kind = crate::text::until_nul(b.get(56..64).unwrap_or_default());
            cx.emit(Node::new("Name").span(data.sub(64, 80)).value(text(name)));
            cx.emit(
                Node::new("Content type")
                    .span(data.sub(56, 8))
                    .value(text(kind.clone())),
            );
            // Embedded images and CZI files are dissected; other attachments are Zeiss-specific tables.
            let body = data.sub(256, size);
            cx.emit(if matches!(kind.as_str(), "JPG" | "CZI" | "PNG" | "BMP") {
                embedded("Data", input.nested(body))
            } else {
                Node::new("Data").span(body)
            });
        }
        _ => cx.emit(Node::new("Data").span(data)),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Nikon ND2

declare_format!(pub ND2 = "nd2", "Nikon NIS-Elements image (ND2)", ["nd2"], "image/x-nd2",
    Probe::Custom(|h| h.at(0, b"\xda\xce\xbe\x0a") && u32_le(h.data, 4).is_some_and(|n| (1..=1024).contains(&n))), nd2);

async fn nd2(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, LE);
    let mut count = 0u64;
    let mut images = 0u64;
    let mut version = String::new();
    while cur.remaining() >= 16 {
        let start = cur.pos();
        let magic = cur.u32().await?;
        if magic != 0x0abe_ceda {
            // Files end with the chunk map signature and the map's position.
            let tail = cx.read_avail(file.sub(start, 40)).await?;
            if tail.starts_with(b"ND2 CHUNK MAP SIGNATURE") {
                let at = crate::bytes::u64_le(&tail, 32).unwrap_or(0);
                cx.push(
                    Node::new("Chunk map pointer")
                        .span(file.sub(start, 40))
                        .value(crate::formats::util::lines::hex(at, 64)),
                )
                .await;
            } else {
                cx.diag(
                    Diagnostic::malformed(format!("chunk magic {magic:#010x}"))
                        .at(file.sub(start, 4)),
                );
            }
            break;
        }
        let name_len = cur.u32().await?;
        let data_len = cur.u64().await?;
        let name = cur
            .cstr(name_len.into())
            .await
            .map(|(s, _)| s)
            .unwrap_or_default();
        cur.seek(start.saturating_add(16).saturating_add(name_len.into()));
        let data = cur.span(data_len);
        cur.skip(data_len);
        if name.starts_with("ND2 FILE SIGNATURE") {
            version = String::from_utf8_lossy(&cx.read_avail(data.sub(0, 16)).await?)
                .trim_end_matches('\0')
                .to_owned();
        }
        if name.starts_with("ImageDataSeq") {
            images = images.saturating_add(1);
        }
        let mut node = Node::new(name.clone())
            .span(cur.since(start))
            .summary(format!("{data_len} bytes"));
        if name.starts_with("ND2 CHUNK MAP") {
            node = node.lazy(nd2_map, data);
        } else if name.contains("TextInfo")
            || name.ends_with("LV!")
            || name.contains("Metadata")
            || name.contains("Attributes")
        {
            node = node.lazy(nd2_lv, (data, 0u32));
        }
        cx.push(node).await;
        count = count.saturating_add(1);
    }
    cx.annotate(format!(
        "Nikon ND2 {version}, {count} chunk(s), {images} image frame(s)"
    ));
    Ok(())
}

/// The chunk map: names terminated by '!' followed by position and size.
async fn nd2_map(cx: Cx, data: Span) -> Result<()> {
    let b = cx.read_avail(data.sub(0, cx.limits().max_read)).await?;
    let mut at = 0usize;
    while at < b.len() {
        let Some(bang) = b.get(at..).and_then(|r| r.iter().position(|&c| c == b'!')) else {
            break;
        };
        let end = at.saturating_add(bang).saturating_add(1);
        let name = String::from_utf8_lossy(b.get(at..end).unwrap_or_default()).into_owned();
        if name.starts_with("ND2 CHUNK MAP") {
            break;
        }
        let pos = crate::bytes::u64_le(&b, end).unwrap_or(0);
        let size = crate::bytes::u64_le(&b, end.saturating_add(8)).unwrap_or(0);
        cx.push(
            Node::new(name)
                .span(data.sub(
                    to_u64(at),
                    to_u64(end.saturating_add(16).saturating_sub(at)),
                ))
                .value(crate::formats::util::lines::hex(pos, 64))
                .summary(format!("{size} bytes")),
        )
        .await;
        at = end.saturating_add(16);
    }
    Ok(())
}

/// Nikon "LV" key/value variant structures.
async fn nd2_lv(cx: Cx, (data, depth): (Span, u32)) -> Result<()> {
    if depth > 16 {
        return Err(Diagnostic::limit("variants nested too deeply"));
    }
    let mut cur = Cursor::new(&cx, data, LE);
    let mut items = 0u32;
    while cur.remaining() >= 2 && items < 10_000 {
        let start = cur.pos();
        let kind = cur.u8().await?;
        let name_len = cur.u8().await?;
        let name = crate::text::utf16(&cur.bytes(u64::from(name_len).saturating_mul(2)).await?, LE)
            .trim_end_matches('\0')
            .to_owned();
        let value = match kind {
            1 => uint(cur.u8().await?.into()),
            2 => int(i64::from(cur.u32().await?.cast_signed())),
            3 => uint(cur.u32().await?.into()),
            4 => int(cur.u64().await?.cast_signed()),
            5 => uint(cur.u64().await?),
            6 => float(cur.int::<f64>().await?),
            8 => {
                let mut units = Vec::new();
                loop {
                    let u = cur.u16().await?;
                    if u == 0 || units.len() > 0x10000 {
                        break;
                    }
                    units.push(u);
                }
                text(String::from_utf16_lossy(&units))
            }
            9 => {
                let n = cur.u64().await?;
                cur.skip(n);
                text(format!("{n} bytes"))
            }
            11 => {
                let count = cur.u32().await?;
                let len = cur.u64().await?;
                let body = cur.span(len);
                cur.skip(len);
                // A table of `count` item offsets follows the nested items.
                cur.skip(u64::from(count).saturating_mul(8));
                cx.push(
                    Node::new(name)
                        .span(cur.since(start))
                        .summary(format!("{count} item(s)"))
                        .lazy(
                            crate::expander!(self::nd2_lv: (Span, u32)),
                            (body, depth.saturating_add(1)),
                        ),
                )
                .await;
                items = items.saturating_add(1);
                continue;
            }
            _ => {
                cx.diag(
                    Diagnostic::unsupported(format!("variant type {kind}")).at(cur.since(start)),
                );
                break;
            }
        };
        cx.push(Node::new(name).span(cur.since(start)).value(value))
            .await;
        items = items.saturating_add(1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Leica LIF

declare_format!(pub LIF = "lif", "Leica Image File (LIF)", ["lif", "lof", "xlif"], "image/x-lif",
    Probe::Custom(|h| h.at(0, b"\x70\x00\x00\x00") && h.data.get(8) == Some(&0x2a) && h.at(13, b"<\0")), lif);

async fn lif(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, LE);
    let start = cur.pos();
    cur.skip(9);
    let chars = cur.u32().await?;
    let xml_span = cur.span(u64::from(chars).saturating_mul(2));
    let head = cx.read_avail(xml_span.sub(0, 0x10000)).await?;
    let xml = crate::text::utf16(&head, LE);
    cur.skip(xml_span.len);
    cx.emit(
        Node::new("XML header")
            .span(cur.since(start))
            .value(text(preview(&xml, 200)))
            .summary(format!("{chars} characters")),
    );
    let version: u32 = xml
        .split_once("Version=\"")
        .and_then(|(_, r)| r.split('"').next())
        .and_then(|v| v.parse().ok())
        .unwrap_or(2);
    let images = xml
        .matches("<Image>")
        .count()
        .saturating_add(xml.matches("<Image ").count());
    let names: Vec<String> = xml
        .split("<Element Name=\"")
        .skip(1)
        .filter_map(|s| s.split('"').next().map(str::to_owned))
        .take(8)
        .collect();
    let mut blocks = 0u64;
    while cur.remaining() >= 9 {
        let bstart = cur.pos();
        let magic = cur.u32().await?;
        if magic != 0x70 {
            cx.diag(
                Diagnostic::malformed(format!("memory block test value {magic:#x}"))
                    .at(cur.since(bstart)),
            );
            break;
        }
        cur.skip(5);
        let size = if version >= 2 {
            cur.u64().await?
        } else {
            u64::from(cur.u32().await?)
        };
        cur.skip(1);
        let dchars = cur.u32().await?;
        let desc = crate::text::utf16(
            &cur.bytes(u64::from(dchars.min(0x1000)).saturating_mul(2))
                .await?,
            LE,
        );
        let data = cur.span(size);
        cur.skip(size);
        cx.push(
            Node::new(desc)
                .span(cur.since(bstart))
                .summary(format!("{size} bytes"))
                .target(data),
        )
        .await;
        blocks = blocks.saturating_add(1);
    }
    cx.annotate(format!(
        "Leica LIF v{version}, {images} image(s), {blocks} memory block(s){}",
        if names.is_empty() {
            String::new()
        } else {
            format!(": {}", preview(&names.join(", "), 80))
        }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// FEI/TIA series (SER)

declare_format!(pub SER = "tia-ser", "FEI TIA series (SER)", ["ser"], "application/x-tia-ser",
    Probe::Custom(|h| h.at(0, b"\x49\x49\x97\x01") && u16_le(h.data, 4).is_some_and(|v| v == 0x210 || v == 0x220)), ser);

const SER_DATA: EnumTable = &[(0x4120, "1D spectra"), (0x4122, "2D images")];
const SER_TAGS: EnumTable = &[(0x4152, "time"), (0x4142, "time and position")];
const SER_TYPES: EnumTable = &[
    (1, "uint8"),
    (2, "uint16"),
    (3, "uint32"),
    (4, "int8"),
    (5, "int16"),
    (6, "int32"),
    (7, "float32"),
    (8, "float64"),
    (9, "complex64"),
    (10, "complex128"),
];

fn ser_size(t: u16) -> u64 {
    match t {
        1 | 4 => 1,
        2 | 5 => 2,
        3 | 6 | 7 => 4,
        8 | 9 => 8,
        10 => 16,
        _ => 0,
    }
}

async fn ser(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 34)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.u16("Byte order").hex().emit()?;
    f.u16("Series ID").hex().emit()?;
    let version = f.u16("Series version").hex().emit()?;
    let kind = f.u32("Data type").enumeration(SER_DATA).emit()?;
    f.u32("Tag type").enumeration(SER_TAGS).emit()?;
    let total = f.u32("Total elements").emit()?;
    let valid = f.u32("Valid elements").emit()?;
    let wide = version >= 0x220;
    let offsets = if wide {
        f.u64("Offset array offset").hex().emit()?
    } else {
        u64::from(f.u32("Offset array offset").hex().emit()?)
    };
    let ndims = f.u32("Number of dimensions").emit()?;
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(f.pos());
    let mut dims = Vec::new();
    for _ in 0..ndims.min(16) {
        let start = cur.pos();
        let size = cur.u32().await?;
        let offset = cur.int::<f64>().await?;
        let delta = cur.int::<f64>().await?;
        cur.skip(4);
        let dlen = cur.u32().await?;
        let desc = String::from_utf8_lossy(&cur.bytes(dlen.min(0x1000).into()).await?).into_owned();
        let ulen = cur.u32().await?;
        let units =
            String::from_utf8_lossy(&cur.bytes(ulen.min(0x1000).into()).await?).into_owned();
        cx.emit(
            Node::new(format!("Dimension {desc}"))
                .span(cur.since(start))
                .value(uint(size.into()))
                .summary(format!("offset {offset}, step {delta} {units}")),
        );
        dims.push(size);
    }
    let entry = if wide { 8u64 } else { 4 };
    let table = file.sub(offsets, u64::from(total).saturating_mul(entry));
    cx.emit(
        Node::new("Elements")
            .span(table)
            .value(uint(valid.into()))
            .lazy(ser_elements, (input, table, valid, wide, kind)),
    );
    cx.emit(Node::new("Tag offsets").span(file.sub(
        table.end().saturating_sub(file.offset),
        u64::from(total).saturating_mul(entry),
    )));
    cx.annotate(format!(
        "FEI TIA series v{version:#x}, {valid} {} of {total}",
        lookup(SER_DATA, kind.into()).unwrap_or("elements")
    ));
    Ok(())
}

async fn ser_elements(
    cx: Cx,
    (input, table, valid, wide, kind): (Input, Span, u32, bool, u32),
) -> Result<()> {
    let file = input.span;
    let entry = if wide { 8u64 } else { 4 };
    let raw = cx
        .read_avail(table.sub(0, u64::from(valid).saturating_mul(entry)))
        .await?;
    for (i, c) in raw.chunks(to_usize(entry)).enumerate() {
        let at = if wide {
            crate::bytes::u64_le(c, 0).unwrap_or(0)
        } else {
            u64::from(u32_le(c, 0).unwrap_or(0))
        };
        let (header, node) = if kind == 0x4122 {
            let b = cx.block(file.sub(at, 50)).await?;
            let mut f = Fields::new(&b, LE);
            f.skip(40);
            let t = f.u16("Data type").get()?;
            let x = f.u32("Array size X").get()?;
            let y = f.u32("Array size Y").get()?;
            let len = u64::from(x)
                .saturating_mul(y.into())
                .saturating_mul(ser_size(t));
            (
                50u64,
                Node::new(format!("Image {i}"))
                    .summary(format!(
                        "{x}×{y} {}",
                        lookup(SER_TYPES, t.into()).unwrap_or("?")
                    ))
                    .span(file.sub(at, 50u64.saturating_add(len))),
            )
        } else {
            let b = cx.block(file.sub(at, 26)).await?;
            let mut f = Fields::new(&b, LE);
            f.skip(20);
            let t = f.u16("Data type").get()?;
            let n = f.u32("Array length").get()?;
            let len = u64::from(n).saturating_mul(ser_size(t));
            (
                26u64,
                Node::new(format!("Spectrum {i}"))
                    .summary(format!(
                        "{n} {}",
                        lookup(SER_TYPES, t.into()).unwrap_or("?")
                    ))
                    .span(file.sub(at, 26u64.saturating_add(len))),
            )
        };
        cx.push(node.lazy(ser_element, (file.sub(at, header), kind)))
            .await;
    }
    Ok(())
}

async fn ser_element(cx: Cx, (span, kind): (Span, u32)) -> Result<()> {
    let b = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &b, LE);
    let axes: &[&str] = if kind == 0x4122 { &["X", "Y"] } else { &[""] };
    for axis in axes {
        let _ = axis;
        f.f64("Calibration offset").emit()?;
        f.f64("Calibration delta").emit()?;
        f.u32("Calibration element").emit()?;
    }
    f.u16("Data type").enumeration(SER_TYPES).emit()?;
    if kind == 0x4122 {
        f.u32("Array size X").emit()?;
        f.u32("Array size Y").emit()?;
    } else {
        f.u32("Array length").emit()?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Gatan Digital Micrograph (DM3/DM4)

fn dm_probe(h: &Head<'_>) -> bool {
    match u32_be(h.data, 0) {
        Some(3) => {
            u32_be(h.data, 8).is_some_and(|o| o <= 1)
                && h.data.get(12).is_some_and(|&b| b <= 1)
                && h.data.get(13).is_some_and(|&b| b <= 1)
        }
        Some(4) => {
            u32_be(h.data, 12).is_some_and(|o| o <= 1)
                && h.data.get(16).is_some_and(|&b| b <= 1)
                && h.data.get(17).is_some_and(|&b| b <= 1)
        }
        _ => false,
    }
}

declare_format!(pub GATAN_DM = "gatan-dm", "Gatan Digital Micrograph image (DM3/DM4)", ["dm3", "dm4"], "image/x-gatan-dm",
    Probe::Custom(dm_probe), gatan_dm);

/// Sizes of DM simple types.
fn dm_size(t: u64) -> u64 {
    match t {
        2 | 4 => 2,
        3 | 5 | 6 => 4,
        7 | 11 | 12 => 8,
        8..=10 => 1,
        _ => 0,
    }
}

const DM_TYPES: EnumTable = &[
    (2, "int16"),
    (3, "int32"),
    (4, "uint16"),
    (5, "uint32"),
    (6, "float32"),
    (7, "float64"),
    (8, "bool"),
    (9, "char"),
    (10, "int8"),
    (11, "int64"),
    (12, "uint64"),
    (15, "struct"),
    (18, "string"),
    (20, "array"),
];

#[derive(Clone, Copy, Debug)]
struct DmCtx {
    file: Span,
    v4: bool,
    little: bool,
}

async fn gatan_dm(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let version = u32_be(&cx.read(file.sub(0, 4)).await?, 0).unwrap_or(3);
    let v4 = version == 4;
    let head = cx.block(file.sub(0, if v4 { 16 } else { 12 })).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.u32("Version").emit()?;
    if v4 {
        f.u64("Root length").emit()?;
    } else {
        f.u32("Root length").emit()?;
    }
    let order = f.u32("Byte order").desc("1 = little-endian data").emit()?;
    let ctx = DmCtx {
        file,
        v4,
        little: order == 1,
    };
    let root_at = if v4 { 16u64 } else { 12 };
    let (n, _) = dm_group_header(&cx, ctx, root_at).await?;
    cx.emit(
        Node::new("Root tag group")
            .span(file.tail(root_at))
            .value(uint(n))
            .lazy(dm_group, (ctx, root_at, 0u32)),
    );
    // Image dimensions are in ImageList, the last image usually being the main one.
    cx.annotate(format!(
        "Gatan DM{version} ({} data), {n} root tag(s)",
        if ctx.little {
            "little-endian"
        } else {
            "big-endian"
        }
    ));
    Ok(())
}

/// Reads a group header: (tag count, header length).
async fn dm_group_header(cx: &Cx, ctx: DmCtx, at: u64) -> Result<(u64, u64)> {
    let b = cx
        .read(ctx.file.sub_exact(at, if ctx.v4 { 10 } else { 6 })?)
        .await?;
    let n = if ctx.v4 {
        u64_be(&b, 2).unwrap_or(0)
    } else {
        u64::from(u32_be(&b, 2).unwrap_or(0))
    };
    Ok((n, if ctx.v4 { 10 } else { 6 }))
}

async fn dm_word(cur: &mut Cursor<'_>, v4: bool) -> Result<u64> {
    if v4 {
        cur.u64().await
    } else {
        Ok(u64::from(cur.u32().await?))
    }
}

/// Walks a group's tags; returns the position after the group.
async fn dm_group(cx: Cx, (ctx, at, depth): (DmCtx, u64, u32)) -> Result<()> {
    if depth > 32 {
        return Err(Diagnostic::limit("tag groups nested too deeply"));
    }
    let (count, header) = dm_group_header(&cx, ctx, at).await?;
    let mut pos = at.saturating_add(header);
    let mut unnamed = 0u64;
    for _ in 0..count.min(1_000_000) {
        let (node, next) = dm_tag(&cx, ctx, pos, depth, &mut unnamed).await?;
        cx.push(node).await;
        if next <= pos {
            break;
        }
        pos = next;
    }
    Ok(())
}

/// Reads one tag at `pos`: a node and the position after it.
async fn dm_tag(
    cx: &Cx,
    ctx: DmCtx,
    pos: u64,
    depth: u32,
    unnamed: &mut u64,
) -> Result<(Node, u64)> {
    let mut cur = Cursor::new(cx, ctx.file, BE);
    cur.seek(pos);
    let kind = cur.u8().await?;
    let len = cur.u16().await?;
    let label = String::from_utf8_lossy(&cur.bytes(len.into()).await?).into_owned();
    let label = if label.is_empty() {
        let l = format!("[{unnamed}]");
        *unnamed = unnamed.saturating_add(1);
        l
    } else {
        label
    };
    // DM4 records the size of the rest of the tag.
    let total = if ctx.v4 { Some(cur.u64().await?) } else { None };
    let after = cur.pos();
    if kind == 20 {
        let at = cur.pos();
        let end = match total {
            Some(t) => at.saturating_add(t),
            None => dm_skip_group(cx, ctx, at, depth.saturating_add(1)).await?,
        };
        let (n, _) = dm_group_header(cx, ctx, at).await?;
        let node = Node::new(label)
            .span(ctx.file.sub(pos, end.saturating_sub(pos)))
            .summary(format!("{n} tag(s)"))
            .lazy(
                crate::expander!(self::dm_group: (DmCtx, u64, u32)),
                (ctx, at, depth.saturating_add(1)),
            );
        return Ok((node, end));
    }
    if kind != 21 {
        return Err(Diagnostic::malformed(format!("tag type {kind}")).at(ctx.file.sub(pos, 1)));
    }
    let delim = cur.bytes(4).await?;
    if delim != b"%%%%" {
        return Err(Diagnostic::malformed("missing %%%% delimiter")
            .at(ctx.file.sub(cur.pos().saturating_sub(4), 4)));
    }
    let ninfo = dm_word(&mut cur, ctx.v4).await?;
    let mut info = Vec::new();
    for _ in 0..ninfo.min(1024) {
        info.push(dm_word(&mut cur, ctx.v4).await?);
    }
    let data_at = cur.pos();
    let endian = if ctx.little { LE } else { BE };
    let mut dcur = Cursor::new(cx, ctx.file, endian);
    dcur.seek(data_at);
    let t = info.first().copied().unwrap_or(0);
    let (value, summary, len): (Option<Value>, String, u64) = match t {
        2..=12 => {
            let v = dm_simple(&mut dcur, t).await?;
            (Some(v), String::new(), dm_size(t))
        }
        18 => {
            let n = info.get(1).copied().unwrap_or(0);
            let b = dcur.bytes(n.saturating_mul(2).min(0x10000)).await?;
            (
                Some(text(crate::text::utf16(&b, endian))),
                String::new(),
                n.saturating_mul(2),
            )
        }
        15 => {
            let fields = info.get(2).copied().unwrap_or(0);
            let types: Vec<u64> = (0..fields.min(64))
                .filter_map(|i| info.get(to_usize(i.saturating_mul(2).saturating_add(4))))
                .copied()
                .collect();
            let mut vals = Vec::new();
            for &ft in &types {
                vals.push(match dm_simple(&mut dcur, ft).await? {
                    Value::Float(f) => f.to_string(),
                    Value::Int { value, .. } => value.to_string(),
                    Value::UInt { value, .. } => value.to_string(),
                    Value::Bool(b) => b.to_string(),
                    v => format!("{v:?}"),
                });
            }
            let size: u64 = types.iter().map(|&ft| dm_size(ft)).sum();
            (
                Some(text(format!("({})", vals.join(", ")))),
                "struct".to_owned(),
                size,
            )
        }
        20 => {
            let elem = info.get(1).copied().unwrap_or(0);
            let count = info.last().copied().unwrap_or(0);
            let elem_size = if elem == 15 {
                let fields = info.get(3).copied().unwrap_or(0);
                (0..fields.min(64))
                    .filter_map(|i| info.get(to_usize(i.saturating_mul(2).saturating_add(5))))
                    .map(|&ft| dm_size(ft))
                    .sum()
            } else {
                dm_size(elem)
            };
            let len = count.saturating_mul(elem_size);
            // Short character arrays (uint16) are usually text.
            let value = if elem == 4 && count <= 256 {
                let b = dcur.bytes(len).await?;
                Some(text(crate::text::utf16(&b, endian)))
            } else {
                None
            };
            (
                value,
                format!("array of {count} {}", lookup(DM_TYPES, elem).unwrap_or("?")),
                len,
            )
        }
        _ => (None, format!("type {t}"), 0),
    };
    let end = total.map_or(data_at.saturating_add(len), |t| after.saturating_add(t));
    let mut node = Node::new(label).span(
        ctx.file
            .sub(pos, data_at.saturating_add(len).saturating_sub(pos)),
    );
    if let Some(v) = value {
        node = node.value(v);
    }
    node = summarize(node, summary);
    if t == 20 && len > 0 {
        node = node.target(ctx.file.sub(data_at, len));
    }
    Ok((node, end))
}

async fn dm_simple(cur: &mut Cursor<'_>, t: u64) -> Result<Value> {
    Ok(match t {
        2 => int(i64::from(cur.u16().await?.cast_signed())),
        3 => int(i64::from(cur.u32().await?.cast_signed())),
        4 => uint(cur.u16().await?.into()),
        5 => uint(cur.u32().await?.into()),
        6 => crate::formats::util::lines::float32(cur.int::<f32>().await?),
        7 => float(cur.int::<f64>().await?),
        8 => Value::Bool(cur.u8().await? != 0),
        9 => text(char::from(cur.u8().await?).to_string()),
        10 => int(i64::from(cur.u8().await?.cast_signed())),
        11 => int(cur.u64().await?.cast_signed()),
        12 => uint(cur.u64().await?),
        _ => return Err(Diagnostic::unsupported(format!("DM type {t}"))),
    })
}

/// Skips a DM3 group (sizes are implicit), returning the position after it.
async fn dm_skip_group(cx: &Cx, ctx: DmCtx, at: u64, depth: u32) -> Result<u64> {
    if depth > 32 {
        return Err(Diagnostic::limit("tag groups nested too deeply"));
    }
    let (count, header) = dm_group_header(cx, ctx, at).await?;
    let mut pos = at.saturating_add(header);
    let mut unnamed = 0u64;
    for _ in 0..count.min(1_000_000) {
        let (_, next) = Box::pin(dm_tag(cx, ctx, pos, depth, &mut unnamed)).await?;
        if next <= pos {
            break;
        }
        pos = next;
        cx.checkpoint().await;
    }
    Ok(pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(mrc_voxel_bits(2), 32);
        assert_eq!(ser_size(7), 4);
        assert_eq!(dm_size(7), 8);
    }
}
