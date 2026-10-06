//! Geospatial, legacy archive/installer, camera, subtitle, 3D and font
//! formats.

use crate::bytes::{to_u64, u16_le, u32_be, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, emit_record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::{Codec, Head, Input, Probe, content};
use crate::node::Node;
use crate::record;
use crate::value::Value;

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

fn text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

use crate::formats::text::scan::head_lines as lines;

// ---------------------------------------------------------------------------
// OpenStreetMap PBF

fn osm_probe(h: &Head<'_>) -> bool {
    h.at(4, b"\x0a\x09OSMHeader")
}

declare_format!(pub OSM_PBF = "osm-pbf", "OpenStreetMap PBF", ["pbf", "osm.pbf"], "application/x-osm-pbf",
    Probe::Custom(osm_probe), osm_pbf);

/// Decodes a protobuf varint at `at`.
fn varint(data: &[u8], at: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    for i in 0..10u32 {
        let b = *data.get(*at)?;
        *at = at.saturating_add(1);
        value |= u64::from(b & 0x7f).checked_shl(i.saturating_mul(7))?;
        if b & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

async fn osm_pbf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut pos = 0u64;
    let mut blocks = 0u32;
    while pos.saturating_add(4) <= file.len {
        let len = u64::from(u32_be(&cx.read(file.sub(pos, 4)).await?, 0).unwrap_or(0));
        if len == 0 || len > 64 * 1024 {
            return Err(Diagnostic::malformed("implausible BlobHeader length").at(file.sub(pos, 4)));
        }
        let header = cx.read(file.sub(pos.saturating_add(4), len)).await?;
        // BlobHeader: 1 = type (string), 3 = datasize (varint).
        let mut at = 0usize;
        let mut kind = String::new();
        let mut size = 0u64;
        while at < header.len() {
            let Some(key) = varint(&header, &mut at) else {
                break;
            };
            match key {
                0x0a => {
                    let n = crate::bytes::to_usize(varint(&header, &mut at).unwrap_or(0));
                    kind = String::from_utf8_lossy(
                        header.get(at..at.saturating_add(n)).unwrap_or_default(),
                    )
                    .into_owned();
                    at = at.saturating_add(n);
                }
                0x18 => size = varint(&header, &mut at).unwrap_or(0),
                _ => {
                    let n = crate::bytes::to_usize(varint(&header, &mut at).unwrap_or(0));
                    at = at.saturating_add(n);
                }
            }
        }
        let blob = file.sub(pos.saturating_add(4).saturating_add(len), size);
        // Blob: 1 = raw, 2 = raw_size, 3 = zlib_data.
        let b = cx.read_avail(blob.sub(0, 16)).await?;
        let mut bat = 0usize;
        let mut node = crate::node::Node::new(kind.clone())
            .span(file.sub(pos, 4u64.saturating_add(len).saturating_add(size)));
        let mut raw_size = None;
        while bat < b.len() {
            let Some(key) = varint(&b, &mut bat) else {
                break;
            };
            match key {
                0x10 => raw_size = varint(&b, &mut bat),
                0x1a => {
                    let n = varint(&b, &mut bat).unwrap_or(0);
                    let data = blob.sub(to_u64(bat), n);
                    node = content(kind.clone(), input, data, Codec::Zlib, raw_size)
                        .span(file.sub(pos, 4u64.saturating_add(len).saturating_add(size)));
                    break;
                }
                _ => break,
            }
        }
        blocks = blocks.saturating_add(1);
        cx.push(node.summary(format!("{size} bytes"))).await;
        pos = pos
            .saturating_add(4)
            .saturating_add(len)
            .saturating_add(size);
    }
    cx.annotate(format!("OSM PBF, {blocks} blocks"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Elevation and imagery: SRTM HGT, DTED, NITF

fn hgt_probe(h: &Head<'_>) -> bool {
    matches!(h.len, 2_884_802 | 25_934_402)
}

declare_format!(pub HGT = "srtm-hgt", "SRTM elevation tile (HGT)", ["hgt"], "application/x-srtm-hgt",
    Probe::Custom(hgt_probe), hgt);

async fn hgt(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let side = if file.len == 2_884_802 { 1201u64 } else { 3601 };
    let row = side.saturating_mul(2);
    // Sample the centre post.
    let centre = (side / 2)
        .saturating_mul(row)
        .saturating_add((side / 2).saturating_mul(2));
    let sample = cx.read(file.sub(centre, 2)).await?;
    let height = i16::from_be_bytes([
        sample.first().copied().unwrap_or(0),
        sample.get(1).copied().unwrap_or(0),
    ]);
    cx.emit(
        Node::new("Grid")
            .span(file)
            .summary(format!("{side}×{side} big-endian 16-bit posts")),
    );
    cx.emit(
        Node::new("Centre elevation")
            .span(file.sub(centre, 2))
            .value(Value::Int {
                value: height.into(),
                bits: 16,
            }),
    );
    cx.annotate(format!(
        "SRTM{} tile, {side}×{side} posts",
        if side == 1201 { 3 } else { 1 }
    ));
    Ok(())
}

declare_format!(pub DTED = "dted", "Digital Terrain Elevation Data", ["dt0", "dt1", "dt2"], "application/x-dted",
    Probe::Magic(&[(0, b"UHL1")]), dted);

record! {
    pub struct DtedUhl {
        sentinel: ascii[4] "Sentinel",
        longitude: ascii[8] "Origin longitude (DDDMMSSH)",
        latitude: ascii[8] "Origin latitude (DDDMMSSH)",
        lon_interval: ascii[4] "Longitude interval (0.1 s)",
        lat_interval: ascii[4] "Latitude interval (0.1 s)",
        accuracy: ascii[4] "Absolute vertical accuracy (m)",
        security: ascii[3] "Security code",
        reference: ascii[12] "Unique reference",
        lon_lines: ascii[4] "Longitude lines",
        lat_points: ascii[4] "Latitude points",
        multiple: ascii[1] "Multiple accuracy",
    }
}

async fn dted(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: DtedUhl = emit_record(&cx, file.sub(0, DtedUhl::SIZE), BE).await?;
    cx.emit(Node::new("Data set identification (DSI)").span(file.sub(80, 648)));
    cx.emit(Node::new("Accuracy (ACC)").span(file.sub(728, 2700)));
    cx.emit(Node::new("Elevation records").span(file.tail(3428)));
    cx.annotate(format!(
        "DTED tile at {} {}, {}×{} posts",
        h.latitude, h.longitude, h.lon_lines, h.lat_points
    ));
    Ok(())
}

declare_format!(pub NITF = "nitf", "National Imagery Transmission Format", ["ntf", "nitf", "nsf"], "image/x-nitf",
    Probe::Magic(&[(0, b"NITF02.10"), (0, b"NITF02.00"), (0, b"NSIF01.00")]), nitf);

record! {
    pub struct NitfHeader {
        profile: ascii[4] "File profile",
        version: ascii[5] "Version",
        complexity: ascii[2] "Complexity level",
        system: ascii[4] "Standard type",
        station: ascii[10] "Originating station",
        datetime: ascii[14] "File date and time",
        title: ascii[80] "File title",
        classification: ascii[1] "Security classification",
    }
}

async fn nitf(cx: Cx, input: Input) -> Result<()> {
    let h: NitfHeader = emit_record(&cx, input.span.sub(0, NitfHeader::SIZE), BE).await?;
    cx.emit(Node::new("Security and segments").span(input.span.tail(NitfHeader::SIZE)));
    cx.annotate(format!(
        "{}{} {:?} from {}",
        h.profile,
        h.version,
        h.title.trim(),
        h.station.trim()
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Archives and installers: ALZip, EGG, KGB, InstallShield

declare_format!(pub ALZ = "alz", "ALZip archive", ["alz"], "application/x-alz",
    Probe::Magic(&[(0, b"ALZ\x01")]), alz);

async fn alz(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("Header").span(file.sub(0, 8)));
    let head = cx.read_avail(file.sub(0, 1 << 16)).await?;
    let entries = head.windows(4).filter(|w| *w == b"BLZ\x01").count();
    cx.emit(Node::new("Local file records").span(file.tail(8)));
    cx.annotate(format!("ALZip archive, {entries}+ entries"));
    Ok(())
}

declare_format!(pub EGG = "egg", "EGG archive", ["egg"], "application/x-egg",
    Probe::Magic(&[(0, b"EGGA")]), egg);

async fn egg(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 14)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 4).emit()?;
    let version = f.u16("Version").hex().emit()?;
    f.u32("Header ID").hex().emit()?;
    f.u32("Reserved").emit()?;
    cx.emit(Node::new("Blocks").span(file.tail(14)));
    cx.annotate(format!("EGG archive v{}.{}", version >> 8, version & 0xff));
    Ok(())
}

declare_format!(pub KGB = "kgb", "KGB archive", ["kgb", "kge"], "application/x-kgb",
    Probe::Magic(&[(0, b"KGB_arch")]), kgb);

async fn kgb(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("Signature").span(file.sub(0, 8)));
    cx.emit(
        Node::new("Compressed data")
            .span(file.tail(8))
            .diag(Diagnostic::unsupported("PAQ6-based compression")),
    );
    cx.annotate("KGB archive");
    Ok(())
}

declare_format!(pub ISCAB = "installshield-cab", "InstallShield cabinet", ["cab", "hdr"], "application/x-installshield-cab",
    Probe::Magic(&[(0, b"ISc(")]), iscab);

async fn iscab(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 20)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 4).emit()?;
    let version = f.u32("Version").hex().emit()?;
    f.u32("Volume info").hex().emit()?;
    let descriptor = f.u32("Cabinet descriptor offset").hex().emit()?;
    f.u32("Cabinet descriptor size").emit()?;
    cx.emit(Node::new("Cabinet descriptor").span(file.tail(descriptor.into())));
    let major = match version >> 24 {
        1 => (version >> 12) & 0xf,
        2 | 4 => version & 0xffff,
        _ => 0,
    };
    cx.annotate(format!("InstallShield cabinet, version {major}"));
    Ok(())
}

declare_format!(pub ISZ = "installshield-z", "InstallShield 3 archive (.Z)", ["z"], "application/x-installshield-z",
    Probe::Magic(&[(0, b"\x13\x5d\x65\x8c")]), isz);

async fn isz(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 0x29)).await?;
    let files = u16_le(&head, 0x0c).unwrap_or(0);
    let total = u32_le(&head, 0x12).unwrap_or(0);
    let dirs = u16_le(&head, 0x31).unwrap_or(0);
    cx.emit(Node::new("Header").span(file.sub(0, 0xff)));
    cx.emit(
        Node::new("Compressed data")
            .span(file.tail(0xff))
            .diag(Diagnostic::unsupported("PKWARE DCL implode")),
    );
    cx.annotate(format!(
        "InstallShield 3 archive, {files} files, {total} bytes, {dirs} directories"
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Cameras: Kodak Photo CD, Sigma X3F

fn photocd_probe(h: &Head<'_>) -> bool {
    h.at(0x800, b"PCD_IPI")
}

declare_format!(pub PHOTO_CD = "photo-cd", "Kodak Photo CD image pack", ["pcd"], "image/x-photo-cd",
    Probe::Custom(photocd_probe), photo_cd);

async fn photo_cd(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("Image pack information").span(file.sub(0x800, 0x800)));
    cx.emit(Node::new("Base/16 image").span(file.sub(0x2000, 0x2400)));
    cx.emit(Node::new("Base/4 image").span(file.sub(0xb800, 0x9000)));
    cx.emit(Node::new("Base image").span(file.sub(0x30000, 0x24000)));
    cx.annotate("Kodak Photo CD image (Base/16 to Base resolutions)");
    Ok(())
}

declare_format!(pub X3F = "x3f", "Sigma/Foveon raw image", ["x3f"], "image/x-sigma-x3f",
    Probe::Magic(&[(0, b"FOVb")]), x3f);

async fn x3f(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 40)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 4).emit()?;
    let version = f.u32("Version").hex().emit()?;
    f.bytes("Unique identifier", 16).emit()?;
    f.u32("Mark bits").hex().emit()?;
    let width = f.u32("Width").emit()?;
    let height = f.u32("Height").emit()?;
    let rotation = f.u32("Rotation").emit()?;
    let dir_at =
        u64::from(u32_le(&cx.read(file.sub(file.len.saturating_sub(4), 4)).await?, 0).unwrap_or(0));
    let dir = cx.read_avail(file.sub(dir_at, 12)).await?;
    if dir.starts_with(b"SECd") {
        let count = u32_le(&dir, 8).unwrap_or(0);
        for i in 0..count.min(256) {
            let at = dir_at
                .saturating_add(12)
                .saturating_add(u64::from(i).saturating_mul(12));
            let e = cx.read(file.sub(at, 12)).await?;
            let offset = u64::from(u32_le(&e, 0).unwrap_or(0));
            let len = u64::from(u32_le(&e, 4).unwrap_or(0));
            let kind = String::from_utf8_lossy(e.get(8..12).unwrap_or_default()).into_owned();
            cx.push(
                Node::new(kind)
                    .span(file.sub(offset, len))
                    .summary(format!("{len} bytes"))
                    .target(file.sub(at, 12)),
            )
            .await;
        }
    }
    cx.annotate(format!(
        "Sigma X3F v{}.{}, {width}×{height}, rotation {rotation}",
        version >> 16,
        version & 0xffff
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Subtitles: EBU STL, Scenarist SCC, VobSub index

fn ebu_probe(h: &Head<'_>) -> bool {
    h.at(3, b"STL25.01") || h.at(3, b"STL30.01") || h.at(3, b"STL24.01") || h.at(3, b"STL50.01")
}

declare_format!(pub EBU_STL = "ebu-stl", "EBU STL subtitles", ["stl"], "application/x-ebu-stl",
    Probe::Custom(ebu_probe), ebu_stl);

record! {
    pub struct EbuGsi {
        code_page: ascii[3] "Code page",
        disk_format: ascii[8] "Disk format code",
        display_standard: ascii[1] "Display standard",
        character_table: ascii[2] "Character code table",
        language: ascii[2] "Language code",
        programme: ascii[32] "Original programme title",
        episode: ascii[32] "Original episode title",
        translated_programme: ascii[32] "Translated programme title",
        translated_episode: ascii[32] "Translated episode title",
        translator: ascii[32] "Translator's name",
        translator_contact: ascii[32] "Translator's contact details",
        reference: ascii[16] "Subtitle list reference",
        created: ascii[6] "Creation date",
        revised: ascii[6] "Revision date",
        revision: ascii[2] "Revision number",
        tti_blocks: ascii[5] "Total TTI blocks",
        subtitles: ascii[5] "Total subtitles",
        groups: ascii[3] "Subtitle groups",
    }
}

async fn ebu_stl(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let gsi: EbuGsi = emit_record(&cx, file.sub(0, EbuGsi::SIZE), LE).await?;
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(1024);
    let mut n = 0u32;
    while cur.remaining() >= 128 {
        let start = cur.pos();
        let block = cur.bytes(128).await?;
        n = n.saturating_add(1);
        let number = u16_le(&block, 1).unwrap_or(0);
        let tc = |at: usize| {
            format!(
                "{:02}:{:02}:{:02}:{:02}",
                block.get(at).copied().unwrap_or(0),
                block.get(at.saturating_add(1)).copied().unwrap_or(0),
                block.get(at.saturating_add(2)).copied().unwrap_or(0),
                block.get(at.saturating_add(3)).copied().unwrap_or(0)
            )
        };
        let text_field: String = block
            .get(16..128)
            .unwrap_or_default()
            .iter()
            .filter(|&&b| (0x20..0x7f).contains(&b))
            .map(|&b| char::from(b))
            .collect();
        cx.push(
            Node::new(format!("Subtitle {number}"))
                .span(cur.since(start))
                .summary(format!("{} → {}: {}", tc(5), tc(9), text_field.trim())),
        )
        .await;
    }
    cx.annotate(format!(
        "EBU STL ({}), {:?}, {n} TTI blocks",
        gsi.disk_format,
        gsi.programme.trim()
    ));
    Ok(())
}

declare_format!(pub SCC = "scc", "Scenarist closed captions", ["scc"], "text/x-scc",
    Probe::Magic(&[(0, b"Scenarist_SCC V1.0")]), scc);

async fn scc(cx: Cx, input: Input) -> Result<()> {
    let all = lines(&cx, input.span, 1 << 20).await?;
    let mut captions = 0u32;
    for (line, span) in all {
        if let Some((tc, codes)) = line.split_once('\t') {
            captions = captions.saturating_add(1);
            cx.push(
                Node::new(tc.to_owned())
                    .span(span)
                    .summary(format!("{} code words", codes.split_whitespace().count())),
            )
            .await;
        } else if line.starts_with("Scenarist") {
            cx.emit(Node::new("Header").span(span).value(text(line)));
        }
    }
    cx.annotate(format!("SCC captions, {captions} lines"));
    Ok(())
}

declare_format!(pub VOBSUB = "vobsub-idx", "VobSub subtitle index", ["idx"], "text/x-vobsub",
    Probe::Magic(&[(0, b"# VobSub index file")]), vobsub);

async fn vobsub(cx: Cx, input: Input) -> Result<()> {
    let all = lines(&cx, input.span, 1 << 20).await?;
    let mut tracks = Vec::new();
    let mut stamps = 0u32;
    for (line, span) in all {
        if let Some(rest) = line.strip_prefix("id: ") {
            tracks.push(rest.split(',').next().unwrap_or_default().to_owned());
            cx.push(Node::new(format!("Track {rest}")).span(span)).await;
        } else if line.starts_with("timestamp:") {
            stamps = stamps.saturating_add(1);
        } else if let Some((k, v)) = line.split_once(": ").filter(|_| !line.starts_with('#')) {
            cx.push(Node::new(k.to_owned()).span(span).value(text(v)))
                .await;
        }
    }
    cx.annotate(format!(
        "VobSub index, tracks [{}], {stamps} subtitles",
        tracks.join(", ")
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// NUT container

declare_format!(pub NUT = "nut", "NUT multimedia container", ["nut"], "video/x-nut",
    Probe::Magic(&[(0, b"nut/multimedia container\0")]), nut);

async fn nut(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("File ID string").span(file.sub(0, 25)));
    let head = cx.read_avail(file.sub(0, 1 << 16)).await?;
    let count = |code: u64| head.windows(8).filter(|w| *w == code.to_be_bytes()).count();
    let main = count(0x4e4d_7a56_1f5f_04ad);
    let streams = count(0x4e53_1140_5bf2_f9db);
    cx.emit(Node::new("Packets").span(file.tail(25)));
    cx.annotate(format!(
        "NUT container, {main} main header(s), {streams} stream header(s) in the first 64 KiB"
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// 3D text formats: VRML, OFF, MD5 mesh; binary: Source MDL, Unreal PSK

declare_format!(pub VRML = "vrml", "VRML world", ["wrl", "vrml"], "model/vrml",
    Probe::Magic(&[(0, b"#VRML V2.0"), (0, b"#VRML V1.0"), (0, b"#VRML ")]), vrml);

async fn vrml(cx: Cx, input: Input) -> Result<()> {
    let all = lines(&cx, input.span, 1 << 20).await?;
    let header = all.first().map(|(l, _)| l.clone()).unwrap_or_default();
    if let Some((line, span)) = all.first() {
        cx.emit(Node::new("Header").span(*span).value(text(line.clone())));
    }
    let mut defs = 0u32;
    for (line, span) in all.iter().skip(1) {
        let t = line.trim_start();
        if let Some(rest) = t.strip_prefix("DEF ") {
            defs = defs.saturating_add(1);
            cx.push(
                Node::new(
                    rest.split_whitespace()
                        .next()
                        .unwrap_or_default()
                        .to_owned(),
                )
                .span(*span)
                .summary(
                    rest.split_whitespace()
                        .nth(1)
                        .unwrap_or_default()
                        .to_owned(),
                ),
            )
            .await;
        }
    }
    cx.annotate(format!(
        "{}, {defs} named nodes",
        header.trim_start_matches('#').trim()
    ));
    Ok(())
}

fn off_probe(h: &Head<'_>) -> bool {
    ["OFF\n", "OFF\r\n", "COFF\n", "NOFF\n", "OFF \n"]
        .iter()
        .any(|m| h.starts_with(m.as_bytes()))
        || (h.starts_with(b"OFF ") && h.data.get(4).is_some_and(u8::is_ascii_digit))
}

declare_format!(pub OFF = "off", "Object File Format mesh", ["off"], "model/x-off",
    Probe::Custom(off_probe), off);

async fn off(cx: Cx, input: Input) -> Result<()> {
    let all = lines(&cx, input.span, 4096).await?;
    let mut numbers = Vec::new();
    for (line, _) in &all {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let t = t
            .trim_start_matches(|c: char| c.is_ascii_alphabetic())
            .trim();
        numbers.extend(t.split_whitespace().filter_map(|w| w.parse::<u64>().ok()));
        if numbers.len() >= 2 {
            break;
        }
    }
    if let Some((line, span)) = all.first() {
        cx.emit(Node::new("Header").span(*span).value(text(line.clone())));
    }
    cx.emit(Node::new("Data").span(input.span));
    cx.annotate(format!(
        "OFF mesh, {} vertices, {} faces",
        numbers.first().copied().unwrap_or(0),
        numbers.get(1).copied().unwrap_or(0)
    ));
    Ok(())
}

declare_format!(pub MD5MESH = "md5mesh", "id Tech 4 MD5 model", ["md5mesh", "md5anim"], "model/x-md5",
    Probe::Magic(&[(0, b"MD5Version ")]), md5mesh);

async fn md5mesh(cx: Cx, input: Input) -> Result<()> {
    let all = lines(&cx, input.span, 1 << 20).await?;
    let mut kv = Vec::new();
    for (line, span) in &all {
        let mut it = line.split_whitespace();
        if let (Some(k), Some(v)) = (it.next(), it.next())
            && (k.starts_with("num") || k == "MD5Version" || k == "commandline" || k == "frameRate")
        {
            kv.push((k.to_owned(), v.to_owned()));
            cx.emit(
                Node::new(k.to_owned())
                    .span(*span)
                    .value(text(v.trim_matches('"'))),
            );
        }
    }
    let get = |k: &str| {
        kv.iter()
            .find(|(a, _)| a == k)
            .map_or(String::from("?"), |(_, v)| v.clone())
    };
    let anim = kv.iter().any(|(k, _)| k == "numFrames");
    cx.annotate(if anim {
        format!(
            "MD5 animation, {} frames at {} fps",
            get("numFrames"),
            get("frameRate")
        )
    } else {
        format!(
            "MD5 mesh, {} joints, {} meshes",
            get("numJoints"),
            get("numMeshes")
        )
    });
    Ok(())
}

declare_format!(pub SOURCE_MDL = "source-mdl", "Source engine model", ["mdl"], "model/x-source-mdl",
    Probe::Magic(&[(0, b"IDST")]), source_mdl);

record! {
    pub struct StudioHeader {
        id: ascii[4] "Identifier",
        version: i32 "Version",
        checksum: u32 "Checksum" .hex(),
        name: ascii[64] "Name",
        length: i32 "File length",
    }
}

async fn source_mdl(cx: Cx, input: Input) -> Result<()> {
    let h: StudioHeader = emit_record(&cx, input.span.sub(0, StudioHeader::SIZE), LE).await?;
    cx.emit(Node::new("Model data").span(input.span.tail(StudioHeader::SIZE)));
    cx.annotate(format!(
        "Source model {:?}, version {}",
        h.name.trim_end(),
        h.version
    ));
    Ok(())
}

declare_format!(pub PSK = "unreal-psk", "Unreal skeletal mesh (PSK/PSA)", ["psk", "psa", "pskx"], "model/x-unreal-psk",
    Probe::Magic(&[(0, b"ACTRHEAD"), (0, b"ANIMHEAD")]), psk);

async fn psk(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, LE);
    let mut chunks = Vec::new();
    while cur.remaining() >= 32 {
        let start = cur.pos();
        let id = crate::text::until_nul(&cur.bytes(20).await?);
        let _flags = cur.u32().await?;
        let size = cur.u32().await?;
        let count = cur.u32().await?;
        cur.skip(u64::from(size).saturating_mul(count.into()));
        chunks.push(id.clone());
        cx.push(
            Node::new(id)
                .span(cur.since(start))
                .summary(format!("{count} × {size} bytes")),
        )
        .await;
    }
    cx.annotate(format!(
        "Unreal {} ({} chunks)",
        if chunks.first().is_some_and(|c| c == "ANIMHEAD") {
            "animation"
        } else {
            "skeletal mesh"
        },
        chunks.len()
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Sony BBeB e-books, Adobe font metrics and PFA fonts

declare_format!(pub LRF = "lrf", "Sony BBeB e-book (LRF)", ["lrf", "lrx"], "application/x-sony-bbeb",
    Probe::Magic(&[(0, b"L\0R\0F\0\0\0")]), lrf);

async fn lrf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 0x58)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.bytes("Signature", 8).emit()?;
    let version = f.u16("Version").emit()?;
    f.u16("Pseudo-encryption key").hex().emit()?;
    f.u32("Root object ID").emit()?;
    let objects = f.u64("Number of objects").emit()?;
    f.u64("Object index offset").hex().emit()?;
    cx.emit(Node::new("Objects").span(file.tail(0x58)));
    cx.annotate(format!("Sony BBeB e-book v{version}, {objects} objects"));
    Ok(())
}

declare_format!(pub AFM = "afm", "Adobe font metrics", ["afm"], "application/x-font-afm",
    Probe::Magic(&[(0, b"StartFontMetrics")]), afm);

async fn afm(cx: Cx, input: Input) -> Result<()> {
    let all = lines(&cx, input.span, 1 << 20).await?;
    let mut name = String::new();
    let mut chars = 0u32;
    for (line, span) in &all {
        let (k, v) = line.split_once(' ').unwrap_or((line.as_str(), ""));
        match k {
            "FontName" | "FullName" | "FamilyName" | "Weight" | "Version" | "Notice"
            | "EncodingScheme" | "ItalicAngle" | "IsFixedPitch" | "FontBBox" | "CapHeight"
            | "XHeight" | "Ascender" | "Descender" | "StartFontMetrics" => {
                if k == "FontName" {
                    name = v.to_owned();
                }
                cx.emit(Node::new(k.to_owned()).span(*span).value(text(v)));
            }
            "StartCharMetrics" => chars = v.trim().parse().unwrap_or(0),
            _ => {}
        }
    }
    cx.annotate(format!("{name}, {chars} character metrics"));
    Ok(())
}

declare_format!(pub PFA = "pfa", "PostScript Type 1 font (ASCII)", ["pfa", "pfb.txt", "t1"], "application/x-font-type1",
    Probe::Magic(&[(0, b"%!PS-AdobeFont-"), (0, b"%!FontType1")]), pfa);

async fn pfa(cx: Cx, input: Input) -> Result<()> {
    let all = lines(&cx, input.span, 8192).await?;
    let first = all.first().map(|(l, _)| l.clone()).unwrap_or_default();
    if let Some((_, span)) = all.first() {
        cx.emit(Node::new("Header").span(*span).value(text(first.clone())));
    }
    let mut name = first
        .split(':')
        .nth(1)
        .unwrap_or_default()
        .trim()
        .to_owned();
    for (line, span) in &all {
        if let Some(rest) = line.trim().strip_prefix("/FontName") {
            name = rest
                .trim()
                .trim_start_matches('/')
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_owned();
            cx.emit(Node::new("FontName").span(*span).value(text(name.clone())));
        } else if line.contains("eexec") {
            cx.emit(
                Node::new("eexec-encrypted portion").span(
                    input
                        .span
                        .tail(span.end().saturating_sub(input.span.offset)),
                ),
            );
            break;
        }
    }
    cx.annotate(format!("Type 1 font {name}"));
    Ok(())
}
