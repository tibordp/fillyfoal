//! Font binaries and font sources not covered by the `font` module: bare
//! CFF/CFF2, Windows raster fonts (FNT) and printer font metrics (PFM), TeX
//! font metrics (TFM) and virtual fonts (VF), Amiga font contents, Bitstream
//! PFR, Borland BGI stroked fonts, FontLab VFB, FontForge SFD, Glyphs
//! (OpenStep property list), and UFO glyph and designspace XML.

use crate::bytes::{to_u64, u16_be, u16_le, u32_be, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record};
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::text::scan::Lines;
use crate::formats::text::{probe, xml};
use crate::formats::{Head, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Value};

use super::{Rd, hex, int, text, uint};

const BE: Endian = Endian::Big;
const LE: Endian = Endian::Little;

// ---------------------------------------------------------------------------
// CFF / CFF2

fn cff_probe(h: &Head<'_>) -> bool {
    let d = h.data;
    match d.get(..4) {
        // CFF 1: header size 4, offset size 1-4, then a Name INDEX with one
        // or a few fonts whose first offset is 1.
        Some([1, 0, 4, off]) if (1..=4).contains(off) => {
            u16_be(d, 4).is_some_and(|n| (1..=16).contains(&n))
                && d.get(6).is_some_and(|o| (1..=4).contains(o))
                && d.get(7..7usize.saturating_add(usize::from(d.get(6).copied().unwrap_or(1))))
                    .is_some_and(|o| o.iter().rev().skip(1).all(|&b| b == 0) && o.last() == Some(&1))
        }
        // CFF 2: header size 5, then the Top DICT length.
        Some([2, 0, 5, _]) => u16_be(d, 3).is_some_and(|l| l > 0 && u64::from(l).saturating_add(5) < h.len),
        _ => false,
    }
}

declare_format!(pub CFF = "cff", "Compact Font Format font", ["cff", "cff2"], "font/x-cff",
    Probe::Custom(cff_probe), cff);

/// An INDEX: a count, an offset size, `count + 1` offsets and the data.
#[derive(Clone, Copy, Debug)]
struct Index {
    span: Span,
    count: u32,
    off_size: u8,
    /// Region offset of the offset array.
    offsets: u64,
    /// Region offset of the byte before the data (offsets are 1-based).
    base: u64,
}

async fn read_index(cx: &Cx, region: Span, at: u64, cff2: bool) -> Result<Index> {
    let mut cur = Cursor::new(cx, region, BE);
    cur.seek(at);
    let count = if cff2 { cur.u32().await? } else { u32::from(cur.u16().await?) };
    if count == 0 {
        return Ok(Index { span: cur.since(at), count, off_size: 1, offsets: cur.pos(), base: cur.pos() });
    }
    let off_size = cur.u8().await?;
    if !(1..=4).contains(&off_size) {
        return Err(Diagnostic::malformed(format!("INDEX offset size {off_size}")).at(cur.since(at)));
    }
    let offsets = cur.pos();
    let table = u64::from(count).saturating_add(1).saturating_mul(off_size.into());
    region.sub_exact(offsets, table)?;
    let last = offset(cx, region, offsets, off_size, count).await?;
    let base = offsets.saturating_add(table).saturating_sub(1);
    let end = base.saturating_add(last);
    region.sub_exact(at, end.saturating_sub(at))?;
    Ok(Index { span: region.sub(at, end.saturating_sub(at)), count, off_size, offsets, base })
}

async fn offset(cx: &Cx, region: Span, offsets: u64, off_size: u8, i: u32) -> Result<u64> {
    let at = offsets.saturating_add(u64::from(i).saturating_mul(off_size.into()));
    let b = cx.read(region.sub_exact(at, off_size.into())?).await?;
    Ok(b.iter().fold(0u64, |a, &x| a.wrapping_shl(8) | u64::from(x)))
}

impl Index {
    async fn entry(&self, cx: &Cx, region: Span, i: u32) -> Result<Span> {
        let a = offset(cx, region, self.offsets, self.off_size, i).await?;
        let b = offset(cx, region, self.offsets, self.off_size, i.saturating_add(1)).await?;
        if a == 0 || b < a {
            return Err(Diagnostic::malformed(format!("INDEX entry {i} has offsets {a}..{b}")).at(self.span));
        }
        Ok(region.sub(self.base.saturating_add(a), b.saturating_sub(a)))
    }

    fn end(&self, region: Span) -> u64 {
        self.span.offset.saturating_add(self.span.len).saturating_sub(region.offset)
    }
}

/// Decoded DICT entries: operator, operands, byte range.
fn dict_entries(data: &[u8]) -> Vec<(u16, Vec<f64>, usize, usize)> {
    let mut out = Vec::new();
    let mut ops = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    while let Some(&b0) = data.get(i) {
        let b1 = data.get(i.saturating_add(1)).copied().unwrap_or(0);
        let (v, n): (Option<f64>, usize) = match b0 {
            32..=246 => (Some(f64::from(i16::from(b0).saturating_sub(139))), 1),
            247..=250 => (Some(f64::from(b0.saturating_sub(247)) * 256.0 + f64::from(b1) + 108.0), 2),
            251..=254 => (Some(-f64::from(b0.saturating_sub(251)) * 256.0 - f64::from(b1) - 108.0), 2),
            28 => (u16_be(data, i.saturating_add(1)).map(|v| f64::from(i16::from_ne_bytes(v.to_ne_bytes()))), 3),
            29 => (u32_be(data, i.saturating_add(1)).map(|v| f64::from(i32::from_ne_bytes(v.to_ne_bytes()))), 5),
            30 => {
                let (v, n) = real(data.get(i.saturating_add(1)..).unwrap_or_default());
                (Some(v), n.saturating_add(1))
            }
            12 => {
                let op = 1200u16.saturating_add(b1.into());
                out.push((op, std::mem::take(&mut ops), start, i.saturating_add(2)));
                i = i.saturating_add(2);
                start = i;
                continue;
            }
            0..=21 => {
                out.push((b0.into(), std::mem::take(&mut ops), start, i.saturating_add(1)));
                i = i.saturating_add(1);
                start = i;
                continue;
            }
            _ => (None, 1),
        };
        if let Some(v) = v
            && ops.len() < 64
        {
            ops.push(v);
        }
        i = i.saturating_add(n);
    }
    out
}

/// A real number: packed decimal nibbles ending in 0xf.
fn real(data: &[u8]) -> (f64, usize) {
    let mut s = String::new();
    for (i, &b) in data.iter().enumerate().take(32) {
        for nib in [b >> 4, b & 0xf] {
            match nib {
                0..=9 => s.push(char::from(b'0'.saturating_add(nib))),
                0xa => s.push('.'),
                0xb => s.push('E'),
                0xc => s.push_str("E-"),
                0xe => s.push('-'),
                0xf => return (s.parse().unwrap_or(0.0), i.saturating_add(1)),
                _ => {}
            }
        }
    }
    (s.parse().unwrap_or(0.0), data.len().min(32))
}

const TOP_DICT: &[(u16, &str)] = &[
    (0, "version"), (1, "Notice"), (2, "FullName"), (3, "FamilyName"), (4, "Weight"), (5, "FontBBox"),
    (13, "UniqueID"), (14, "XUID"), (15, "charset"), (16, "Encoding"), (17, "CharStrings"), (18, "Private"),
    (24, "vstore"), (25, "maxstack"),
    (1200, "Copyright"), (1201, "isFixedPitch"), (1202, "ItalicAngle"), (1203, "UnderlinePosition"),
    (1204, "UnderlineThickness"), (1205, "PaintType"), (1206, "CharstringType"), (1207, "FontMatrix"),
    (1208, "StrokeWidth"), (1220, "SyntheticBase"), (1221, "PostScript"), (1222, "BaseFontName"),
    (1223, "BaseFontBlend"), (1230, "ROS"), (1231, "CIDFontVersion"), (1232, "CIDFontRevision"),
    (1233, "CIDFontType"), (1234, "CIDCount"), (1235, "UIDBase"), (1236, "FDArray"), (1237, "FDSelect"),
    (1238, "FontName"),
    // Private DICT
    (6, "BlueValues"), (7, "OtherBlues"), (8, "FamilyBlues"), (9, "FamilyOtherBlues"), (10, "StdHW"),
    (11, "StdVW"), (19, "Subrs"), (20, "defaultWidthX"), (21, "nominalWidthX"), (22, "vsindex"), (23, "blend"),
    (1209, "BlueScale"), (1210, "BlueShift"), (1211, "BlueFuzz"), (1212, "StemSnapH"), (1213, "StemSnapV"),
    (1214, "ForceBold"), (1217, "LanguageGroup"), (1218, "ExpansionFactor"), (1219, "initialRandomSeed"),
];

/// Operators whose single operand is a string ID.
const SID_OPS: &[u16] = &[0, 1, 2, 3, 4, 1200, 1221, 1222, 1238];

fn op_name(op: u16) -> String {
    TOP_DICT.iter().find(|(k, _)| *k == op).map_or_else(
        || if op >= 1200 { format!("12 {}", op.saturating_sub(1200)) } else { format!("op {op}") },
        |(_, v)| (*v).to_owned(),
    )
}

fn num(v: f64) -> String {
    format!("{v}")
}

#[derive(Clone, Copy, Debug)]
struct Cff {
    region: Span,
    strings: Option<Index>,
}

async fn sid(cx: &Cx, cff: &Cff, sid: f64) -> Result<String> {
    let n = sid as u32;
    if n < 391 {
        // The tail of the standard strings: the usual weight names.
        const WEIGHTS: [&str; 8] = ["Black", "Bold", "Book", "Light", "Medium", "Regular", "Roman", "Semibold"];
        return Ok(n.checked_sub(383).and_then(|i| WEIGHTS.get(usize::try_from(i).ok()?)).map_or_else(|| format!("standard string {n}"), |s| (*s).to_owned()));
    }
    let Some(strings) = cff.strings else {
        return Ok(format!("SID {n}"));
    };
    if n.saturating_sub(391) >= strings.count {
        return Ok(format!("SID {n} (out of range)"));
    }
    let span = strings.entry(cx, cff.region, n.saturating_sub(391)).await?;
    Ok(String::from_utf8_lossy(&cx.read(span.sub(0, 256)).await?).into_owned())
}

async fn cff(cx: Cx, input: Input) -> Result<()> {
    let region = input.span;
    let h = cx.read(region.sub(0, 5)).await?;
    let major = h.first().copied().unwrap_or(0);
    let cff2 = major == 2;
    let hdr = u64::from(h.get(2).copied().unwrap_or(4));
    cx.emit(Node::new("Version").span(region.sub(0, 2)).value(text(format!("{major}.{}", h.get(1).copied().unwrap_or(0)))));
    cx.emit(Node::new("Header size").span(region.sub(2, 1)).value(uint(hdr, 8)));
    if cff2 {
        let len = u64::from(u16_be(&h, 3).unwrap_or(0));
        let top = region.sub_exact(hdr, len)?;
        let cff = Cff { region, strings: None };
        cx.emit(Node::new("Top DICT").span(top).lazy(dict, (cff, top)));
        let gsubrs = read_index(&cx, region, hdr.saturating_add(len), true).await?;
        cx.emit(index_node("Global Subrs INDEX", gsubrs));
        let entries = dict_entries(&cx.read(top).await?);
        let glyphs = charstrings(&cx, region, &entries, true).await?;
        cx.annotate(format!("CFF2 font, {glyphs} glyphs"));
        return Ok(());
    }
    cx.emit(Node::new("Offset size").span(region.sub(3, 1)).value(uint(h.get(3).copied().unwrap_or(0), 8)));
    let names = read_index(&cx, region, hdr, false).await?;
    let top = read_index(&cx, region, names.end(region), false).await?;
    let strings = read_index(&cx, region, top.end(region), false).await?;
    let gsubrs = read_index(&cx, region, strings.end(region), false).await?;
    let cff = Cff { region, strings: Some(strings) };
    let mut font_names = Vec::new();
    for i in 0..names.count.min(16) {
        let s = names.entry(&cx, region, i).await?;
        font_names.push(String::from_utf8_lossy(&cx.read(s.sub(0, 256)).await?).into_owned());
    }
    cx.emit(index_node("Name INDEX", names).value(text(font_names.join(", "))).lazy(index_strings, (region, names)));
    cx.emit(index_node("Top DICT INDEX", top).lazy(top_dicts, (cff, top)));
    cx.emit(index_node("String INDEX", strings).lazy(index_strings, (region, strings)));
    cx.emit(index_node("Global Subrs INDEX", gsubrs));
    let mut glyphs = 0;
    if top.count > 0 {
        let span = top.entry(&cx, region, 0).await?;
        let entries = dict_entries(&cx.read(span).await?);
        glyphs = charstrings(&cx, region, &entries, false).await?;
    }
    cx.annotate(format!("CFF font {}, {glyphs} glyphs", font_names.first().map_or("", String::as_str)));
    Ok(())
}

/// Emits the CharStrings INDEX and Private DICT a Top DICT points to;
/// returns the glyph count.
async fn charstrings(cx: &Cx, region: Span, entries: &[(u16, Vec<f64>, usize, usize)], cff2: bool) -> Result<u32> {
    let mut glyphs = 0;
    for (op, args, _, _) in entries {
        match (op, args.as_slice()) {
            (17, [at]) => {
                let idx = read_index(cx, region, *at as u64, cff2).await?;
                glyphs = idx.count;
                cx.emit(index_node("CharStrings INDEX", idx).summary(format!("{} glyphs", idx.count)));
            }
            (18, [size, at]) => {
                let span = region.sub_exact(*at as u64, *size as u64)?;
                let cff = Cff { region, strings: None };
                cx.emit(Node::new("Private DICT").span(span).summary(format!("{size} bytes")).lazy(dict, (cff, span)));
            }
            _ => {}
        }
    }
    Ok(glyphs)
}

fn index_node(name: &'static str, idx: Index) -> Node {
    Node::new(name).span(idx.span).summary(format!("{} entries", idx.count))
}

async fn index_strings(cx: Cx, (region, idx): (Span, Index)) -> Result<()> {
    for i in 0..idx.count {
        let s = idx.entry(&cx, region, i).await?;
        let t = String::from_utf8_lossy(&cx.read(s.sub(0, 1024)).await?).into_owned();
        cx.push(Node::new(format!("[{i}]")).span(s).value(text(t))).await;
    }
    Ok(())
}

async fn top_dicts(cx: Cx, (cff, idx): (Cff, Index)) -> Result<()> {
    for i in 0..idx.count {
        let s = idx.entry(&cx, cff.region, i).await?;
        cx.push(Node::new(format!("Top DICT {i}")).span(s).lazy(dict, (cff, s))).await;
    }
    Ok(())
}

async fn dict(cx: Cx, (cff, span): (Cff, Span)) -> Result<()> {
    let data = cx.read(span).await?;
    for (op, args, a, b) in dict_entries(&data) {
        let node = Node::new(op_name(op)).span(span.sub(to_u64(a), to_u64(b.saturating_sub(a))));
        let node = match args.as_slice() {
            [v] if SID_OPS.contains(&op) => node.value(text(sid(&cx, &cff, *v).await?)),
            [v] => node.value(Value::Float(*v)),
            _ => node.value(text(args.iter().map(|v| num(*v)).collect::<Vec<_>>().join(" "))),
        };
        cx.push(node).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Windows raster fonts (FNT) and printer font metrics (PFM)

record! {
    /// FONTINFO, up to dfBitsOffset (shared by FNT and PFM).
    pub struct FontInfo {
        version: u16 "dfVersion" .hex(),
        size: u32 "dfSize",
        copyright: ascii[60] "dfCopyright",
        kind: u16 "dfType" .hex() .desc("Bit 0: vector font; bit 7: realized by the device"),
        points: u16 "dfPoints",
        vert_res: u16 "dfVertRes",
        horiz_res: u16 "dfHorizRes",
        ascent: u16 "dfAscent",
        internal_leading: u16 "dfInternalLeading",
        external_leading: u16 "dfExternalLeading",
        italic: u8 "dfItalic",
        underline: u8 "dfUnderline",
        strike_out: u8 "dfStrikeOut",
        weight: u16 "dfWeight",
        charset: u8 "dfCharSet" .enumeration(CHARSETS),
        pix_width: u16 "dfPixWidth",
        pix_height: u16 "dfPixHeight",
        pitch_family: u8 "dfPitchAndFamily" .hex(),
        avg_width: u16 "dfAvgWidth",
        max_width: u16 "dfMaxWidth",
        first_char: u8 "dfFirstChar",
        last_char: u8 "dfLastChar",
        default_char: u8 "dfDefaultChar",
        break_char: u8 "dfBreakChar",
        width_bytes: u16 "dfWidthBytes",
        device: u32 "dfDevice" .hex(),
        face: u32 "dfFace" .hex(),
        bits_pointer: u32 "dfBitsPointer" .hex(),
        bits_offset: u32 "dfBitsOffset" .hex(),
    }
}

record! {
    pub struct FntV3 {
        reserved: u8 "dfReserved",
        flags: u32 "dfFlags" .hex(),
        a_space: u16 "dfAspace",
        b_space: u16 "dfBspace",
        c_space: u16 "dfCspace",
        color_pointer: u32 "dfColorPointer" .hex(),
        reserved1: bytes[16] "dfReserved1",
    }
}

record! {
    pub struct PfmExtension {
        size_fields: u16 "dfSizeFields",
        ext_metrics: u32 "dfExtMetricsOffset" .hex(),
        extent_table: u32 "dfExtentTable" .hex(),
        origin_table: u32 "dfOriginTable" .hex(),
        pair_kern_table: u32 "dfPairKernTable" .hex(),
        track_kern_table: u32 "dfTrackKernTable" .hex(),
        driver_info: u32 "dfDriverInfo" .hex(),
        reserved: u32 "dfReserved",
    }
}

const CHARSETS: EnumTable = &[
    (0, "ANSI"), (1, "DEFAULT"), (2, "SYMBOL"), (77, "MAC"), (128, "SHIFTJIS"), (129, "HANGUL"),
    (134, "GB2312"), (136, "CHINESEBIG5"), (161, "GREEK"), (162, "TURKISH"), (177, "HEBREW"),
    (178, "ARABIC"), (186, "BALTIC"), (204, "RUSSIAN"), (222, "THAI"), (238, "EASTEUROPE"), (255, "OEM"),
];

fn fontinfo_probe(h: &Head<'_>, versions: &[u16]) -> bool {
    u16_le(h.data, 0).is_some_and(|v| versions.contains(&v))
        && u32_le(h.data, 2).is_some_and(|s| u64::from(s) == h.len)
        && h.data.get(6..66).is_some_and(|c| c.iter().all(|&b| b == 0 || (0x20..0x7f).contains(&b) || b >= 0xa0))
        && h.data.get(95).zip(h.data.get(96)).is_some_and(|(f, l)| f <= l)
}

declare_format!(pub FNT = "windows-fnt", "Windows raster/vector font resource", ["fnt"], "application/x-font-fnt",
    Probe::Custom(|h| fontinfo_probe(h, &[0x200, 0x300])), fnt);

async fn face_name(cx: &Cx, file: Span, at: u32) -> Result<Option<(String, Span)>> {
    if at == 0 || u64::from(at) >= file.len {
        return Ok(None);
    }
    Ok(Some(cx.cstr(file.sub(at.into(), 256)).await?))
}

async fn fnt(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, LE);
    let (info, span) = cur.record::<FontInfo>().await?;
    cx.emit(FontInfo::node("Font info", span, LE));
    let v3 = info.version >= 0x300;
    if v3 {
        let (_, span) = cur.record::<FntV3>().await?;
        cx.emit(FntV3::node("Version 3 fields", span, LE));
    } else {
        cur.skip(1);
    }
    let count = u64::from(info.last_char.saturating_sub(info.first_char)).saturating_add(2);
    let entry: u64 = if v3 { 6 } else { 4 };
    let table = file.sub_exact(cur.pos(), count.saturating_mul(entry))?;
    let vector = info.kind & 1 != 0;
    cx.emit(Node::new("Character table").span(table).summary(format!("{count} entries")).lazy(fnt_chars, (file, table, info.first_char, v3, info.pix_height, vector)));
    let face = face_name(&cx, file, info.face).await?;
    if let Some((name, span)) = &face {
        cx.emit(Node::new("Face name").span(*span).value(text(name.clone())));
    }
    if let Some((name, span)) = face_name(&cx, file, info.device).await? {
        cx.emit(Node::new("Device name").span(span).value(text(name)));
    }
    cx.annotate(format!(
        "Windows {} font{}, {}pt, {}px high, chars {}-{}",
        if vector { "vector" } else { "raster" },
        face.map(|(n, _)| format!(" {n:?}")).unwrap_or_default(),
        info.points,
        info.pix_height,
        info.first_char,
        info.last_char
    ));
    Ok(())
}

async fn fnt_chars(cx: Cx, (file, table, first, v3, height, vector): (Span, Span, u8, bool, u16, bool)) -> Result<()> {
    let data = cx.read(table).await?;
    let entry = if v3 { 6usize } else { 4 };
    for (i, e) in data.chunks_exact(entry).enumerate() {
        let width = u16_le(e, 0).unwrap_or(0);
        let offset = if v3 { u32_le(e, 2).unwrap_or(0) } else { u16_le(e, 2).map_or(0, u32::from) };
        let code = u32::from(first).saturating_add(u32::try_from(i).unwrap_or(u32::MAX));
        let sentinel = i.saturating_add(1) == data.len().checked_div(entry).unwrap_or(0);
        let name = if sentinel || code > 255 {
            "Sentinel".to_owned()
        } else {
            let c = char::from(u8::try_from(code).unwrap_or(0));
            if c.is_ascii_graphic() { format!("0x{code:02x} '{c}'") } else { format!("0x{code:02x}") }
        };
        let mut node = Node::new(name).span(table.sub(to_u64(i).saturating_mul(to_u64(entry)), to_u64(entry))).value(uint(width, 16)).summary(format!("width {width}, offset {offset:#x}"));
        if !vector && !sentinel && code <= 255 {
            // Bitmaps are stored column by column, one byte per 8 pixels.
            let len = u64::from(width.div_ceil(8)).saturating_mul(height.into());
            node = node.target(file.sub(offset.into(), len));
        }
        cx.push(node).await;
    }
    Ok(())
}

declare_format!(pub PFM = "windows-pfm", "Windows printer font metrics", ["pfm"], "application/x-font-pfm",
    Probe::Custom(|h| fontinfo_probe(h, &[0x100])), pfm);

async fn pfm(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, LE);
    let (info, span) = cur.record::<FontInfo>().await?;
    cx.emit(FontInfo::node("Font info", span, LE));
    let (ext, span) = cur.record::<PfmExtension>().await?;
    cx.emit(PfmExtension::node("PFM extension", span, LE));
    if ext.ext_metrics != 0 {
        let at = u64::from(ext.ext_metrics);
        let size = u64::from(u16_le(&cx.read(file.sub_exact(at, 2)?).await?, 0).unwrap_or(0));
        cx.emit(Node::new("Extended text metrics").span(file.sub(at, size.max(2))).summary(format!("{size} bytes")));
    }
    let mut postscript = None;
    for (name, at) in [("Device name", info.device), ("Windows face name", info.face), ("PostScript font name", ext.driver_info)] {
        if let Some((s, span)) = face_name(&cx, file, at).await? {
            if name.starts_with("PostScript") {
                postscript = Some(s.clone());
            }
            cx.emit(Node::new(name).span(span).value(text(s)));
        }
    }
    if ext.extent_table != 0 {
        let count = u64::from(info.last_char.saturating_sub(info.first_char)).saturating_add(1);
        cx.emit(Node::new("Width table").span(file.sub(ext.extent_table.into(), count.saturating_mul(2))).summary(format!("{count} widths")));
    }
    if ext.pair_kern_table != 0 {
        let at = u64::from(ext.pair_kern_table);
        let n = u64::from(u16_le(&cx.read(file.sub_exact(at, 2)?).await?, 0).unwrap_or(0));
        let pairs = file.sub_exact(at.saturating_add(2), n.saturating_mul(4))?;
        cx.emit(Node::new("Kerning pairs").span(file.sub(at, n.saturating_mul(4).saturating_add(2))).summary(format!("{n} pairs")).lazy(kern_pairs, pairs));
    }
    cx.annotate(format!("Windows printer font metrics{}, {}pt", postscript.map(|p| format!(" for {p}")).unwrap_or_default(), info.points));
    Ok(())
}

async fn kern_pairs(cx: Cx, pairs: Span) -> Result<()> {
    let data = cx.read(pairs).await?;
    for (i, p) in data.as_chunks::<4>().0.iter().enumerate() {
        let [a, b, k0, k1] = *p;
        let kern = i16::from_le_bytes([k0, k1]);
        let ch = |c: u8| if c.is_ascii_graphic() { char::from(c).to_string() } else { format!("\\x{c:02x}") };
        cx.push(Node::new(format!("{}{}", ch(a), ch(b))).span(pairs.sub(to_u64(i).saturating_mul(4), 4)).value(int(kern, 16))).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// TeX font metrics (TFM)

/// The twelve table lengths of a TFM file.
fn tfm_lengths(d: &[u8]) -> Option<[u16; 12]> {
    let mut l = [0u16; 12];
    for (i, v) in l.iter_mut().enumerate() {
        *v = u16_be(d, i.checked_mul(2)?)?;
    }
    Some(l)
}

fn tfm_probe(h: &Head<'_>) -> bool {
    let Some([lf, lh, bc, ec, nw, nh, nd, ni, nl, nk, ne, np]) = tfm_lengths(h.data) else {
        return false;
    };
    let chars = if bc > ec { ec == bc.wrapping_sub(1) } else { ec <= 255 };
    let sum = [lh, nw, nh, nd, ni, nl, nk, ne, np].iter().map(|&v| u32::from(v)).sum::<u32>()
        .saturating_add(6)
        .saturating_add(u32::from(ec.saturating_add(1).saturating_sub(bc)));
    chars && lh >= 2 && nw >= 1 && nh >= 1 && nd >= 1 && ni >= 1 && ne <= 256
        && u32::from(lf) == sum && u64::from(lf).saturating_mul(4) == h.len
}

declare_format!(pub TFM = "tex-tfm", "TeX font metrics", ["tfm"], "application/x-tex-tfm",
    Probe::Custom(tfm_probe), tfm);

const TFM_TABLES: [&str; 12] = ["lf", "lh", "bc", "ec", "nw", "nh", "nd", "ni", "nl", "nk", "ne", "np"];
const TFM_PARAMS: &[&str] = &["slant", "space", "space_stretch", "space_shrink", "x_height", "quad", "extra_space"];

fn fix_word(v: u32) -> f64 {
    f64::from(i32::from_ne_bytes(v.to_ne_bytes())) / f64::from(1u32 << 20)
}

async fn tfm(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub_exact(0, 24)?).await?;
    let l = tfm_lengths(&head).ok_or_else(|| Diagnostic::truncated(file.sub(0, 24), file.len))?;
    let lengths = file.sub(0, 24);
    cx.emit(Node::new("Table lengths").span(lengths).value(text(TFM_TABLES.iter().zip(l).map(|(n, v)| format!("{n}={v}")).collect::<Vec<_>>().join(" "))));
    let [_, lh, bc, ec, nw, nh, nd, ni, nl, nk, ne, np] = l;
    let words = |n: u16| u64::from(n).saturating_mul(4);
    let header = file.sub(24, words(lh));
    let hd = cx.read(header).await?;
    let checksum = u32_be(&hd, 0).unwrap_or(0);
    let design = fix_word(u32_be(&hd, 4).unwrap_or(0));
    cx.emit(Node::new("Checksum").span(header.sub(0, 4)).value(hex(checksum, 32)));
    cx.emit(Node::new("Design size").span(header.sub(4, 4)).value(Value::Float(design)).summary("points"));
    let bcpl = |at: usize, max: usize| {
        let n = usize::from(hd.get(at).copied().unwrap_or(0)).min(max);
        String::from_utf8_lossy(hd.get(at.saturating_add(1)..at.saturating_add(1).saturating_add(n)).unwrap_or_default()).into_owned()
    };
    let scheme = if lh >= 12 { bcpl(8, 39) } else { String::new() };
    if lh >= 12 {
        cx.emit(Node::new("Coding scheme").span(header.sub(8, 40)).value(text(scheme.clone())));
    }
    if lh >= 17 {
        cx.emit(Node::new("Font family").span(header.sub(48, 20)).value(text(bcpl(48, 19))));
    }
    let mut at = 24u64.saturating_add(words(lh));
    let chars = u64::from(ec.saturating_add(1).saturating_sub(bc));
    let char_info = file.sub(at, chars.saturating_mul(4));
    at = at.saturating_add(char_info.len);
    let mut tables = Vec::new();
    for (name, n) in [("Widths", nw), ("Heights", nh), ("Depths", nd), ("Italic corrections", ni), ("Lig/kern program", nl), ("Kerns", nk), ("Extensible recipes", ne), ("Parameters", np)] {
        let span = file.sub(at, words(n));
        tables.push(span);
        at = at.saturating_add(words(n));
        let node = Node::new(name).span(span).summary(format!("{n} words"));
        cx.emit(if name == "Parameters" { node.lazy(tfm_params, (span, design)) } else { node });
    }
    let dims = (tables.first().copied().unwrap_or(char_info), tables.get(1).copied().unwrap_or(char_info), tables.get(2).copied().unwrap_or(char_info));
    cx.emit(Node::new("Characters").span(char_info).summary(format!("codes {bc}-{ec}")).lazy(tfm_chars, (char_info, bc, design, dims)));
    cx.annotate(format!("TeX font metrics, {design}pt{}", if scheme.is_empty() { String::new() } else { format!(", {scheme}") }));
    Ok(())
}

async fn tfm_params(cx: Cx, (span, design): (Span, f64)) -> Result<()> {
    let data = cx.read(span).await?;
    for (i, w) in data.as_chunks::<4>().0.iter().enumerate() {
        let v = fix_word(u32::from_be_bytes(*w));
        let name = TFM_PARAMS.get(i).map_or_else(|| format!("param {}", i.saturating_add(1)), |s| (*s).to_owned());
        // Slant is a pure number; the others scale with the design size.
        let v = if i == 0 { v } else { v * design };
        cx.push(Node::new(name).span(span.sub(to_u64(i).saturating_mul(4), 4)).value(Value::Float(v))).await;
    }
    Ok(())
}

async fn tfm_chars(cx: Cx, (span, bc, design, (w, h, d)): (Span, u16, f64, (Span, Span, Span))) -> Result<()> {
    let data = cx.read(span).await?;
    let (wd, ht, dp) = (cx.read(w).await?, cx.read(h).await?, cx.read(d).await?);
    let dim = |t: &[u8], i: u8| u32_be(t, usize::from(i).saturating_mul(4)).map_or(0.0, |v| fix_word(v) * design);
    for (i, ci) in data.as_chunks::<4>().0.iter().enumerate() {
        let [wi, hd, it, _] = *ci;
        if wi == 0 {
            continue;
        }
        let code = u32::from(bc).saturating_add(u32::try_from(i).unwrap_or(0));
        let c = char::from_u32(code).filter(|c| c.is_ascii_graphic());
        let name = c.map_or_else(|| format!("{code:#04x}"), |c| format!("{code:#04x} '{c}'"));
        let tag = match it & 3 {
            1 => ", lig/kern",
            2 => ", charlist",
            3 => ", extensible",
            _ => "",
        };
        cx.push(
            Node::new(name)
                .span(span.sub(to_u64(i).saturating_mul(4), 4))
                .value(Value::Float(dim(&wd, wi)))
                .summary(format!("height {:.3}, depth {:.3}{tag}", dim(&ht, hd >> 4), dim(&dp, hd & 0xf))),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// TeX virtual fonts (VF)

declare_format!(pub VF = "tex-vf", "TeX virtual font", ["vf"], "application/x-tex-vf",
    Probe::Custom(|h| h.starts_with(b"\xf7\xca") && h.data.get(2).is_some_and(|&k| u64::from(k).saturating_add(11) <= h.len)), vf);

async fn vf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, BE);
    cur.skip(2);
    let k = cur.u8().await?;
    let comment = cur.bytes(k.into()).await?;
    let cs = cur.u32().await?;
    let ds = cur.u32().await?;
    let comment = String::from_utf8_lossy(&comment).into_owned();
    cx.emit(Node::new("Preamble").span(cur.since(0)).value(text(comment.clone())).summary(format!("checksum {cs:#x}, design size {}pt", fix_word(ds))));
    let (mut fonts, mut chars) = (0u32, 0u32);
    while !cur.at_end() {
        let start = cur.pos();
        let op = cur.u8().await?;
        let node = match op {
            0..=241 => {
                let cc = cur.u8().await?;
                let wd = cur.bytes(3).await?;
                cur.skip(op.into());
                chars = chars.saturating_add(1);
                let w = u32::from_be_bytes([0, wd.first().copied().unwrap_or(0), wd.get(1).copied().unwrap_or(0), wd.get(2).copied().unwrap_or(0)]);
                char_packet(cc.into(), op.into(), w)
            }
            242 => {
                let pl = cur.u32().await?;
                let cc = cur.u32().await?;
                let w = cur.u32().await?;
                cur.skip(pl.into());
                chars = chars.saturating_add(1);
                char_packet(cc, pl, w)
            }
            243..=246 => {
                let n = u64::from(op.saturating_sub(242));
                let id = cur.bytes(n).await?.iter().fold(0u32, |a, &b| a.wrapping_shl(8) | u32::from(b));
                cur.skip(12);
                let a = cur.u8().await?;
                let l = cur.u8().await?;
                let name = cur.bytes(u64::from(a).saturating_add(l.into())).await?;
                fonts = fonts.saturating_add(1);
                Node::new(format!("Font {id}")).value(text(String::from_utf8_lossy(&name)))
            }
            248 => {
                cx.emit(Node::new("Postamble").span(file.tail(start)));
                break;
            }
            _ => {
                cx.emit(Node::new("Unknown command").span(file.sub(start, 1)).diag(Diagnostic::malformed(format!("VF command {op}"))));
                break;
            }
        };
        if cur.pos() > file.len {
            return Err(Diagnostic::truncated(file.tail(start), file.len.saturating_sub(start)));
        }
        cx.push(node.span(cur.since(start))).await;
    }
    cx.annotate(format!("TeX virtual font, {fonts} fonts, {chars} characters"));
    Ok(())
}

fn char_packet(code: u32, len: u32, width: u32) -> Node {
    let c = char::from_u32(code).filter(|c| c.is_ascii_graphic());
    Node::new(c.map_or_else(|| format!("Char {code:#04x}"), |c| format!("Char {code:#04x} '{c}'")))
        .summary(format!("{len} bytes of DVI, width {:.4}", fix_word(width)))
}

// ---------------------------------------------------------------------------
// Amiga font contents (.font)

fn amiga_font_probe(h: &Head<'_>) -> bool {
    matches!(u16_be(h.data, 0), Some(0x0f00 | 0x0f02))
        && u16_be(h.data, 2).is_some_and(|n| n >= 1 && u64::from(n).saturating_mul(260).saturating_add(4) == h.len)
        && h.data.get(4).is_some_and(|&b| b.is_ascii_graphic())
}

declare_format!(pub AMIGA_FONT = "amiga-font", "Amiga font contents", ["font"], "application/x-amiga-font",
    Probe::Custom(amiga_font_probe), amiga_font);

const AMIGA_STYLES: &[(u8, &str)] = &[(1, "underlined"), (2, "bold"), (4, "italic"), (8, "extended")];

async fn amiga_font(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 4)).await?;
    let id = u16_be(&head, 0).unwrap_or(0);
    let n = u16_be(&head, 2).unwrap_or(0);
    cx.emit(Node::new("File ID").span(file.sub(0, 2)).value(hex(id, 16)).summary(if id == 0x0f02 { "TFCH_ID (tagged)" } else { "FCH_ID" }));
    cx.emit(Node::new("Entries").span(file.sub(2, 2)).value(uint(n, 16)));
    let mut sizes = Vec::new();
    for i in 0..u64::from(n) {
        let at = 4u64.saturating_add(i.saturating_mul(260));
        let e = cx.read(file.sub_exact(at, 260)?).await?;
        let name_len = if id == 0x0f02 { 254 } else { 256 };
        let name = crate::text::until_nul(e.get(..name_len).unwrap_or_default());
        let ysize = u16_be(&e, 256).unwrap_or(0);
        let style = e.get(258).copied().unwrap_or(0);
        let styles: Vec<_> = AMIGA_STYLES.iter().filter(|(b, _)| style & b != 0).map(|(_, s)| *s).collect();
        sizes.push(ysize.to_string());
        cx.push(Node::new(name).span(file.sub(at, 260)).value(uint(ysize, 16)).summary(if styles.is_empty() { "plain".to_owned() } else { styles.join(", ") })).await;
    }
    cx.annotate(format!("Amiga font contents, sizes {}", sizes.join(", ")));
    Ok(())
}

// ---------------------------------------------------------------------------
// Bitstream Portable Font Resource (PFR)

declare_format!(pub PFR = "pfr", "Bitstream Portable Font Resource", ["pfr"], "application/font-tdpfr",
    Probe::Custom(|h| h.starts_with(b"PFR0") && h.at(6, b"\x0d\x0a") && u16_be(h.data, 8).is_some_and(|s| s >= 58)), pfr);

async fn pfr(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let d = cx.read(file.sub_exact(0, 58)?).await?;
    let mut r = Rd::at(&d, 4, BE);
    let mut field = |cx: &Cx, name: &'static str, width: usize| -> u32 {
        let at = r.pos;
        let v = r.take(width).unwrap_or_default().iter().fold(0u32, |a, &b| a.wrapping_shl(8) | u32::from(b));
        cx.emit(Node::new(name).span(file.sub(to_u64(at), to_u64(width))).value(uint(v, 32)));
        v
    };
    cx.emit(Node::new("Signature").span(file.sub(0, 4)));
    let _ = field(&cx, "Version", 2);
    let _ = field(&cx, "Signature 2", 2);
    let _ = field(&cx, "Header size", 2);
    let _ = field(&cx, "Logical font directory size", 2);
    let dir = field(&cx, "Logical font directory offset", 2);
    let _ = field(&cx, "Logical font max size", 2);
    let _ = field(&cx, "Logical font section size", 3);
    let _ = field(&cx, "Logical font section offset", 3);
    let _ = field(&cx, "Physical font max size", 2);
    let _ = field(&cx, "Physical font section size", 3);
    let _ = field(&cx, "Physical font section offset", 3);
    let _ = field(&cx, "Glyph program strings max size", 2);
    let _ = field(&cx, "Glyph program strings section size", 3);
    let _ = field(&cx, "Glyph program strings section offset", 3);
    let _ = field(&cx, "Max blue values", 1);
    let _ = field(&cx, "Max X orus", 1);
    let _ = field(&cx, "Max Y orus", 1);
    let _ = field(&cx, "Physical font max size (high)", 1);
    let _ = field(&cx, "Colour flags", 1);
    let _ = field(&cx, "Bitmap character table max size", 3);
    let _ = field(&cx, "Bitmap character table set max size", 3);
    let _ = field(&cx, "Physical bitmap character table set max size", 3);
    let phys = field(&cx, "Physical fonts", 2);
    let _ = field(&cx, "Max vertical stem snaps", 1);
    let _ = field(&cx, "Max horizontal stem snaps", 1);
    let max_chars = field(&cx, "Max characters", 2);
    // Logical font directory: count, then (size u24, offset u24) pairs.
    let at = u64::from(dir);
    let n = u64::from(u16_be(&cx.read(file.sub_exact(at, 2)?).await?, 0).unwrap_or(0));
    let entries = file.sub_exact(at.saturating_add(2), n.saturating_mul(6))?;
    let data = cx.read(entries).await?;
    for (i, e) in data.as_chunks::<6>().0.iter().enumerate() {
        let [s0, s1, s2, o0, o1, o2] = *e;
        let size = u32::from_be_bytes([0, s0, s1, s2]);
        let offset = u32::from_be_bytes([0, o0, o1, o2]);
        cx.push(Node::new(format!("Logical font {i}")).span(entries.sub(to_u64(i).saturating_mul(6), 6)).summary(format!("{size} bytes")).target(file.sub(offset.into(), size.into()))).await;
    }
    cx.annotate(format!("Bitstream PFR, {n} logical fonts, {phys} physical fonts, up to {max_chars} characters"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Borland BGI stroked fonts (.chr)

declare_format!(pub BGI = "bgi-font", "Borland BGI stroked font", ["chr"], "application/x-bgi-font",
    Probe::Magic(&[(0, b"PK\x08\x08BGI ")]), bgi);

async fn bgi(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 256)).await?;
    let eof = head.iter().position(|&b| b == 0x1a).ok_or_else(|| Diagnostic::malformed("no end of description (0x1a)").at(file.sub(0, 256)))?;
    let desc = String::from_utf8_lossy(head.get(4..eof).unwrap_or_default()).trim().to_owned();
    cx.emit(Node::new("Description").span(file.sub(0, to_u64(eof).saturating_add(1))).value(text(desc.clone())));
    let at = to_u64(eof).saturating_add(1);
    let h = cx.read(file.sub_exact(at, 12)?).await?;
    let hsize = u16_le(&h, 0).unwrap_or(0);
    let name = String::from_utf8_lossy(h.get(2..6).unwrap_or_default()).into_owned();
    let size = u16_le(&h, 6).unwrap_or(0);
    cx.emit(Node::new("Header size").span(file.sub(at, 2)).value(uint(hsize, 16)));
    cx.emit(Node::new("Font name").span(file.sub(at.saturating_add(2), 4)).value(text(name.clone())));
    cx.emit(Node::new("Font data size").span(file.sub(at.saturating_add(6), 2)).value(uint(size, 16)));
    cx.emit(Node::new("Version").span(file.sub(at.saturating_add(8), 2)).value(text(format!("{}.{}", h.get(8).copied().unwrap_or(0), h.get(9).copied().unwrap_or(0)))));
    // The font header proper: '+', character count, first character,
    // stroke offset, scan flag, origin-to-cap/base/descender.
    let base = u64::from(hsize);
    let fh = cx.read(file.sub_exact(base, 16)?).await?;
    if fh.first() != Some(&b'+') {
        cx.emit(Node::new("Font").span(file.tail(base)).diag(Diagnostic::malformed("font header does not start with '+'")));
        cx.annotate(format!("BGI font {name}"));
        return Ok(());
    }
    let count = u16_le(&fh, 1).unwrap_or(0);
    let first = fh.get(4).copied().unwrap_or(0);
    let strokes = u16_le(&fh, 5).unwrap_or(0);
    let signed = |i: usize| int(i8::from_ne_bytes([fh.get(i).copied().unwrap_or(0)]), 8);
    cx.emit(Node::new("Characters").span(file.sub(base.saturating_add(1), 2)).value(uint(count, 16)));
    cx.emit(Node::new("First character").span(file.sub(base.saturating_add(4), 1)).value(uint(first, 8)));
    cx.emit(Node::new("Stroke data offset").span(file.sub(base.saturating_add(5), 2)).value(hex(strokes, 16)));
    cx.emit(Node::new("Origin to capital").span(file.sub(base.saturating_add(8), 1)).value(signed(8)));
    cx.emit(Node::new("Origin to baseline").span(file.sub(base.saturating_add(9), 1)).value(signed(9)));
    cx.emit(Node::new("Origin to descender").span(file.sub(base.saturating_add(10), 1)).value(signed(10)));
    let offsets = file.sub_exact(base.saturating_add(16), u64::from(count).saturating_mul(2))?;
    let widths = file.sub_exact(offsets.offset.saturating_sub(file.offset).saturating_add(offsets.len), count.into())?;
    cx.emit(Node::new("Stroke offsets").span(offsets).summary(format!("{count} entries")));
    cx.emit(Node::new("Widths").span(widths).summary(format!("{count} entries")));
    cx.emit(Node::new("Stroke data").span(file.tail(base.saturating_add(strokes.into()))));
    cx.annotate(format!("BGI stroked font {name}, {count} characters from {first}"));
    Ok(())
}

// ---------------------------------------------------------------------------
// FontLab Studio 5 (VFB)

declare_format!(pub VFB = "fontlab-vfb", "FontLab Studio 5 font source", ["vfb"], "application/x-fontlab-vfb",
    Probe::Magic(&[(0, b"\x1aWLF10")]), vfb);

async fn vfb(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("Signature").span(file.sub(0, 6)).value(text("WLF10")));
    let v = cx.read(file.sub_exact(6, 2)?).await?;
    cx.emit(Node::new("Version").span(file.sub(6, 2)).value(uint(u16_le(&v, 0).unwrap_or(0), 16)));
    cx.emit(Node::new("Records").span(file.tail(8)).diag(Diagnostic::unsupported("VFB records")));
    cx.annotate("FontLab Studio 5 font source");
    Ok(())
}

// ---------------------------------------------------------------------------
// FontForge spline font database (SFD)

declare_format!(pub SFD = "fontforge-sfd", "FontForge spline font database", ["sfd"], "application/x-fontforge-sfd",
    Probe::Custom(|h| h.starts_with(b"SplineFontDB:")), sfd);

async fn sfd(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let (mut font, mut glyphs) = (String::new(), 0u32);
    while let Some(line) = lines.next().await? {
        let t = line.text();
        let (key, value) = t.split_once(':').map_or((t.as_str(), ""), |(k, v)| (k, v.trim()));
        match key {
            "StartChar" => {
                let start = line.start;
                let name = value.to_owned();
                let mut encoding = String::new();
                while let Some(l) = lines.next().await? {
                    let t = l.text();
                    if let Some(e) = t.strip_prefix("Encoding:") {
                        encoding = e.trim().split(' ').next().unwrap_or("").to_owned();
                    }
                    if t == "EndChar" {
                        break;
                    }
                }
                let span = lines.since(start);
                glyphs = glyphs.saturating_add(1);
                cx.push(Node::new(name).span(span).summary(format!("encoding {encoding}")).lazy(sfd_glyph, span)).await;
            }
            "BeginChars" => cx.push(Node::new("BeginChars").span(line.span).value(text(value))).await,
            _ if !value.is_empty() && !key.contains(' ') && lines.number() <= 400 => {
                if key == "FontName" {
                    font = value.to_owned();
                }
                cx.push(Node::new(key.to_owned()).span(line.span).value(text(value))).await;
            }
            _ => {}
        }
    }
    cx.annotate(format!("FontForge font {font}, {glyphs} glyphs"));
    Ok(())
}

async fn sfd_glyph(cx: Cx, span: Span) -> Result<()> {
    let mut lines = Lines::new(&cx, span);
    while let Some(line) = lines.next().await? {
        let t = line.text();
        if t == "Fore" || t == "SplineSet" {
            let start = line.start;
            let mut points = 0u32;
            while let Some(l) = lines.next().await? {
                let t = l.text();
                if t == "EndSplineSet" {
                    break;
                }
                points = points.saturating_add(1);
            }
            cx.push(Node::new("Outline").span(lines.since(start)).summary(format!("{points} points"))).await;
        } else if let Some((k, v)) = t.split_once(':') {
            cx.push(Node::new(k.to_owned()).span(line.span).value(text(v.trim()))).await;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Glyphs (OpenStep-style property list)

fn glyphs_probe(h: &Head<'_>) -> bool {
    let head = h.data.get(..512).unwrap_or(h.data);
    probe::trim_start(head).starts_with(b"{")
        && (probe::contains(head, b".appVersion = ") || probe::contains(head, b".formatVersion = "))
}

declare_format!(pub GLYPHS = "glyphs", "Glyphs font source", ["glyphs", "glyphspackage"], "application/x-glyphs",
    Probe::Custom(glyphs_probe), glyphs);

/// Deepest property-list nesting shown.
const MAX_PLIST_DEPTH: u32 = 24;

async fn glyphs(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 4096)).await?;
    let open = head.iter().position(|&b| b == b'{').ok_or_else(|| Diagnostic::malformed("no top-level dictionary").at(file))?;
    let tail_at = file.len.saturating_sub(64);
    let tail = cx.read_avail(file.sub(tail_at, 64)).await?;
    let close = tail.iter().rposition(|&b| b == b'}').map_or(file.len, |p| tail_at.saturating_add(to_u64(p)));
    let body = file.sub(to_u64(open).saturating_add(1), close.saturating_sub(to_u64(open)).saturating_sub(1));
    let family = probe::find(&head, b"familyName = ").map(|p| {
        let rest = head.get(p.saturating_add(13)..).unwrap_or_default();
        let end = rest.iter().position(|&b| b == b';').unwrap_or(0);
        unquote(&String::from_utf8_lossy(rest.get(..end).unwrap_or_default()))
    });
    cx.annotate(match family {
        Some(f) => format!("Glyphs font source, {f}"),
        None => "Glyphs font source".to_owned(),
    });
    plist_items(cx, (body, true, 0)).await
}

fn unquote(s: &str) -> String {
    let s = s.trim();
    s.strip_prefix('"').and_then(|s| s.strip_suffix('"')).map_or_else(|| s.to_owned(), |s| s.replace("\\\"", "\"").replace("\\n", "\n"))
}

/// The entries of a dictionary (`key = value;`) or array (`a, b`) whose
/// interior is `span`: containers become lazy nodes over their interior.
async fn plist_items(cx: Cx, (span, dict, depth): (Span, bool, u32)) -> Result<()> {
    const WINDOW: u64 = 0x10000;
    let sep = if dict { b';' } else { b',' };
    let mut item_start = 0u64;
    let mut eq: Option<u64> = None;
    let mut open: Option<(u64, u8)> = None;
    let mut close: Option<u64> = None;
    let mut level = 0u32;
    let (mut in_str, mut escape) = (false, false);
    let mut index = 0u32;
    let mut pos = 0u64;
    while pos < span.len {
        let window = cx.read(span.sub(pos, WINDOW)).await?;
        if window.is_empty() {
            break;
        }
        for (i, &b) in window.iter().enumerate() {
            let at = pos.saturating_add(to_u64(i));
            if in_str {
                match (escape, b) {
                    (true, _) => escape = false,
                    (false, b'\\') => escape = true,
                    (false, b'"') => in_str = false,
                    _ => {}
                }
                continue;
            }
            match b {
                b'"' => in_str = true,
                b'{' | b'(' => {
                    if level == 0 && open.is_none() {
                        open = Some((at, b));
                    }
                    level = level.saturating_add(1);
                }
                b'}' | b')' => {
                    level = level.saturating_sub(1);
                    if level == 0 {
                        close = Some(at);
                    }
                }
                b'=' if level == 0 && dict && eq.is_none() => eq = Some(at),
                _ if b == sep && level == 0 => {
                    plist_emit(&cx, span, (item_start, at), eq, open, close, dict, depth, index).await?;
                    index = index.saturating_add(1);
                    item_start = at.saturating_add(1);
                    (eq, open, close) = (None, None, None);
                }
                _ => {}
            }
        }
        pos = pos.saturating_add(to_u64(window.len()));
        cx.checkpoint().await;
    }
    // A last array item has no separator.
    if !dict && item_start < span.len {
        let rest = cx.read(span.sub(item_start, 64)).await?;
        if rest.iter().any(|b| !b.is_ascii_whitespace()) {
            plist_emit(&cx, span, (item_start, span.len), eq, open, close, dict, depth, index).await?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn plist_emit(cx: &Cx, span: Span, (a, b): (u64, u64), eq: Option<u64>, open: Option<(u64, u8)>, close: Option<u64>, dict: bool, depth: u32, index: u32) -> Result<()> {
    let whole = span.sub(a, b.saturating_sub(a));
    let lead = cx.read(whole.sub(0, 256)).await?;
    let skip = to_u64(lead.iter().take_while(|b| b.is_ascii_whitespace()).count());
    let whole = whole.tail(skip);
    let (name, value_at) = match (dict, eq) {
        (true, Some(e)) => {
            let k = cx.read(span.sub(a, e.saturating_sub(a).min(256))).await?;
            (unquote(&String::from_utf8_lossy(&k)), e.saturating_add(1))
        }
        _ => (format!("[{index}]"), a),
    };
    let node = Node::new(name).span(whole);
    let node = match (open, close) {
        (Some((o, kind)), Some(c)) if c > o && o >= value_at => {
            let inner = span.sub(o.saturating_add(1), c.saturating_sub(o).saturating_sub(1));
            let is_dict = kind == b'{';
            // Name array entries after a recognisable key inside them.
            let peek = cx.read(inner.sub(0, 512)).await?;
            let label = [&b"glyphname = "[..], b"name = ", b"layerId = "].iter().filter(|_| is_dict).find_map(|k| {
                let p = probe::find(&peek, k)?;
                let rest = peek.get(p.saturating_add(k.len())..)?;
                let end = rest.iter().position(|&c| c == b';')?;
                Some(unquote(&String::from_utf8_lossy(rest.get(..end)?)))
            });
            let summary = if is_dict { "dictionary" } else { "array" };
            let node = node.summary(match label {
                Some(l) => format!("{summary}: {l}"),
                None => summary.to_owned(),
            });
            match depth.checked_add(1).filter(|&d| d <= MAX_PLIST_DEPTH) {
                Some(d) => node.lazy(crate::expander!(self::plist_items: (Span, bool, u32)), (inner, is_dict, d)),
                None => node.diag(Diagnostic::limit(format!("nested deeper than {MAX_PLIST_DEPTH}"))),
            }
        }
        _ => {
            let v = cx.read(span.sub(value_at, b.saturating_sub(value_at).min(4096))).await?;
            node.value(text(unquote(&String::from_utf8_lossy(&v))))
        }
    };
    cx.push(node).await;
    Ok(())
}

// ---------------------------------------------------------------------------
// UFO glyphs and designspace documents (XML)

fn glif_probe(h: &Head<'_>) -> bool {
    probe::is_text(h) && xml::root(h).is_some_and(|r| r.is(b"glyph") && r.mentions(b"name=") && r.mentions(b"format="))
}

fn designspace_probe(h: &Head<'_>) -> bool {
    probe::is_text(h) && xml::root(h).is_some_and(|r| r.is(b"designspace"))
}

declare_format!(pub GLIF = "ufo-glif", "UFO glyph (GLIF)", ["glif"], "application/x-ufo-glif",
    Probe::Custom(glif_probe), glif);
declare_format!(pub DESIGNSPACE = "designspace", "Font designspace document", ["designspace"], "application/x-designspace+xml",
    Probe::Custom(designspace_probe), designspace);

/// The value of attribute `name` in the first start tag of `head`.
fn attr(head: &[u8], name: &str) -> Option<String> {
    let needle = format!(" {name}=\"");
    let p = probe::find(head, needle.as_bytes())?.saturating_add(needle.len());
    let rest = head.get(p..)?;
    let end = rest.iter().position(|&b| b == b'"')?;
    Some(String::from_utf8_lossy(rest.get(..end)?).into_owned())
}

async fn glif(cx: Cx, input: Input) -> Result<()> {
    let head = cx.read_avail(input.span.sub(0, 1024)).await?;
    let tag = probe::find(&head, b"<glyph").and_then(|p| head.get(p..)).unwrap_or_default();
    let name = attr(tag, "name").unwrap_or_default();
    let format = attr(tag, "format").unwrap_or_default();
    xml::dissect(cx.clone(), input).await?;
    cx.annotate(format!("UFO glyph {name:?} (GLIF format {format})"));
    Ok(())
}

async fn designspace(cx: Cx, input: Input) -> Result<()> {
    let head = cx.read_avail(input.span.sub(0, 1024)).await?;
    let tag = probe::find(&head, b"<designspace").and_then(|p| head.get(p..)).unwrap_or_default();
    let format = attr(tag, "format").unwrap_or_default();
    xml::dissect(cx.clone(), input).await?;
    cx.annotate(format!("Font designspace document, format {format}"));
    Ok(())
}
