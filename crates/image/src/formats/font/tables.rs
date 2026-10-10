//! Decoders for individual sfnt tables (`head`, `hhea`, `maxp`, `OS/2`,
//! `post`, `name`, `cmap`, `fvar`), shared by TrueType/OpenType, collections
//! and WOFF. Each works on the table's own span, which may lie in a derived
//! (decompressed) source.

use crate::bytes::{to_u64, u16_be, u32_be};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::util::fmt::{clip, fourcc};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, field, flag, lookup};

const BE: Endian = Endian::Big;

pub const TABLE_NAMES: &[(&str, &str)] = &[
    ("avar", "Axis variations"),
    ("BASE", "Baseline data"),
    ("CBDT", "Colour bitmap data"),
    ("CBLC", "Colour bitmap location"),
    ("CFF ", "Compact Font Format"),
    ("CFF2", "Compact Font Format 2"),
    ("cmap", "Character to glyph mapping"),
    ("COLR", "Colour table"),
    ("CPAL", "Colour palette"),
    ("cvar", "CVT variations"),
    ("cvt ", "Control value table"),
    ("DSIG", "Digital signature"),
    ("EBDT", "Embedded bitmap data"),
    ("EBLC", "Embedded bitmap location"),
    ("EBSC", "Embedded bitmap scaling"),
    ("feat", "Feature name (AAT)"),
    ("fpgm", "Font program"),
    ("fvar", "Font variations"),
    ("gasp", "Grid-fitting and scan-conversion procedure"),
    ("GDEF", "Glyph definition"),
    ("glyf", "Glyph data"),
    ("GPOS", "Glyph positioning"),
    ("GSUB", "Glyph substitution"),
    ("gvar", "Glyph variations"),
    ("hdmx", "Horizontal device metrics"),
    ("head", "Font header"),
    ("hhea", "Horizontal header"),
    ("hmtx", "Horizontal metrics"),
    ("HVAR", "Horizontal metrics variations"),
    ("JSTF", "Justification"),
    ("kern", "Kerning"),
    ("loca", "Index to location"),
    ("LTSH", "Linear threshold"),
    ("MATH", "Mathematical typesetting"),
    ("maxp", "Maximum profile"),
    ("MERG", "Merge"),
    ("meta", "Metadata"),
    ("morx", "Extended glyph metamorphosis (AAT)"),
    ("MVAR", "Metrics variations"),
    ("name", "Naming table"),
    ("OS/2", "OS/2 and Windows metrics"),
    ("PCLT", "PCL 5"),
    ("post", "PostScript"),
    ("prep", "Control value program"),
    ("sbix", "Standard bitmap graphics"),
    ("STAT", "Style attributes"),
    ("SVG ", "SVG glyphs"),
    ("trak", "Tracking (AAT)"),
    ("VDMX", "Vertical device metrics"),
    ("vhea", "Vertical header"),
    ("vmtx", "Vertical metrics"),
    ("VORG", "Vertical origin"),
    ("VVAR", "Vertical metrics variations"),
];

pub fn table_name(tag: &str) -> Option<&'static str> {
    TABLE_NAMES.iter().find(|(t, _)| *t == tag).map(|(_, n)| *n)
}

pub const NAME_IDS: EnumTable = &[
    (0, "Copyright"),
    (1, "Font family"),
    (2, "Font subfamily"),
    (3, "Unique identifier"),
    (4, "Full name"),
    (5, "Version"),
    (6, "PostScript name"),
    (7, "Trademark"),
    (8, "Manufacturer"),
    (9, "Designer"),
    (10, "Description"),
    (11, "Vendor URL"),
    (12, "Designer URL"),
    (13, "License"),
    (14, "License URL"),
    (16, "Typographic family"),
    (17, "Typographic subfamily"),
    (18, "Compatible full name (Mac)"),
    (19, "Sample text"),
    (20, "PostScript CID findfont name"),
    (21, "WWS family"),
    (22, "WWS subfamily"),
    (23, "Light background palette"),
    (24, "Dark background palette"),
    (25, "Variations PostScript name prefix"),
];

pub const PLATFORMS: EnumTable = &[
    (0, "Unicode"),
    (1, "Macintosh"),
    (2, "ISO (deprecated)"),
    (3, "Windows"),
    (4, "Custom"),
];

const WINDOWS_ENCODINGS: EnumTable = &[
    (0, "Symbol"),
    (1, "Unicode BMP"),
    (2, "ShiftJIS"),
    (3, "PRC"),
    (4, "Big5"),
    (5, "Wansung"),
    (6, "Johab"),
    (10, "Unicode full repertoire"),
];

const UNICODE_ENCODINGS: EnumTable = &[
    (0, "Unicode 1.0"),
    (1, "Unicode 1.1"),
    (2, "ISO/IEC 10646"),
    (3, "Unicode 2.0 BMP"),
    (4, "Unicode 2.0 full"),
    (5, "Variation sequences"),
    (6, "Unicode full"),
];

const MAC_ENCODINGS: EnumTable = &[
    (0, "Roman"),
    (1, "Japanese"),
    (2, "Chinese (Traditional)"),
    (3, "Korean"),
];

pub fn encoding_name(platform: u16, encoding: u16) -> String {
    let table = match platform {
        0 => UNICODE_ENCODINGS,
        1 => MAC_ENCODINGS,
        3 => WINDOWS_ENCODINGS,
        _ => &[],
    };
    lookup(table, encoding.into()).map_or_else(|| format!("encoding {encoding}"), str::to_owned)
}

const WINDOWS_LANGUAGES: EnumTable = &[
    (0x0409, "en-US"),
    (0x0809, "en-GB"),
    (0x0407, "de-DE"),
    (0x040c, "fr-FR"),
    (0x0410, "it-IT"),
    (0x0411, "ja-JP"),
    (0x0412, "ko-KR"),
    (0x0413, "nl-NL"),
    (0x0415, "pl-PL"),
    (0x0416, "pt-BR"),
    (0x0419, "ru-RU"),
    (0x041d, "sv-SE"),
    (0x0424, "sl-SI"),
    (0x0804, "zh-CN"),
    (0x0404, "zh-TW"),
    (0x0c0a, "es-ES"),
];

fn language_name(platform: u16, language: u16) -> String {
    match platform {
        3 => lookup(WINDOWS_LANGUAGES, language.into())
            .map_or_else(|| format!("LCID {language:#06x}"), str::to_owned),
        1 if language == 0 => "English".to_owned(),
        _ => format!("language {language}"),
    }
}

/// Decodes a `name` string for its platform and encoding.
pub fn decode_name(platform: u16, encoding: u16, bytes: &[u8]) -> String {
    match (platform, encoding) {
        (0, _) | (3, _) => crate::text::utf16(bytes, BE),
        (1, 0) => crate::codec::charset::Charset::MacRoman.decode(bytes),
        _ => crate::text::latin1(bytes),
    }
}

/// Fixed 16.16.
fn fixed(v: u32) -> f64 {
    f64::from(v as i32) / 65536.0
}

/// F2DOT14 is not needed; `Fixed` is shown as a number.
fn fixed_field(f: &mut Fields<'_>, name: &'static str) -> Result<u32> {
    f.u32(name)
        .with(|&v, n| n.value(Value::Float(fixed(v))))
        .emit()
}

/// The checksum of a table: the sum of its big-endian words.
pub fn checksum(data: &[u8], head: bool) -> u32 {
    let mut sum = 0u32;
    for (i, chunk) in data.chunks(4).enumerate() {
        if head && i == 2 {
            continue; // checkSumAdjustment
        }
        let mut word = [0u8; 4];
        for (dst, src) in word.iter_mut().zip(chunk) {
            *dst = *src;
        }
        sum = sum.wrapping_add(u32::from_be_bytes(word));
    }
    sum
}

/// [`checksum`] over a whole table, in budgeted pieces (a table can be as
/// large as a read).
pub async fn table_checksum(cx: &Cx, data: &[u8], head: bool) -> u32 {
    // A multiple of 4, so the words of each piece are the table's words.
    const PIECE: usize = 1 << 16;
    let mut sum = 0u32;
    for (i, piece) in data.chunks(PIECE).enumerate() {
        if i > 0 {
            cx.checkpoint().await;
        }
        sum = sum.wrapping_add(checksum(piece, head && i == 0));
    }
    sum
}

const HEAD_FLAGS: FlagTable = &[
    flag(0x0001, "Baseline at y=0"),
    flag(0x0002, "Left sidebearing at x=0"),
    flag(0x0004, "Instructions depend on point size"),
    flag(0x0008, "Integer ppem"),
    flag(0x0010, "Instructions may alter advance width"),
    flag(0x0020, "Vertical layout (AAT)"),
    flag(0x0080, "Requires layout (AAT)"),
    flag(0x0100, "Metamorphosis effects (AAT)"),
    flag(0x0200, "Strong right-to-left glyphs (AAT)"),
    flag(0x0400, "Indic rearrangement (AAT)"),
    flag(0x0800, "Lossless font data"),
    flag(0x1000, "Converted font"),
    flag(0x2000, "Optimized for ClearType"),
    flag(0x4000, "Last resort font"),
];

const MAC_STYLE: FlagTable = &[
    flag(0x01, "Bold"),
    flag(0x02, "Italic"),
    flag(0x04, "Underline"),
    flag(0x08, "Outline"),
    flag(0x10, "Shadow"),
    flag(0x20, "Condensed"),
    flag(0x40, "Extended"),
];

const WEIGHTS: EnumTable = &[
    (100, "Thin"),
    (200, "Extra-light"),
    (300, "Light"),
    (400, "Normal"),
    (500, "Medium"),
    (600, "Semi-bold"),
    (700, "Bold"),
    (800, "Extra-bold"),
    (900, "Black"),
];

const WIDTHS: EnumTable = &[
    (1, "Ultra-condensed"),
    (2, "Extra-condensed"),
    (3, "Condensed"),
    (4, "Semi-condensed"),
    (5, "Medium"),
    (6, "Semi-expanded"),
    (7, "Expanded"),
    (8, "Extra-expanded"),
    (9, "Ultra-expanded"),
];

const FS_TYPE: FlagTable = &[
    field(0x000f, 0x0002, "Restricted license"),
    field(0x000f, 0x0004, "Preview & print"),
    field(0x000f, 0x0008, "Editable"),
    flag(0x0100, "No subsetting"),
    flag(0x0200, "Bitmap embedding only"),
];

const FS_SELECTION: FlagTable = &[
    flag(0x0001, "ITALIC"),
    flag(0x0002, "UNDERSCORE"),
    flag(0x0004, "NEGATIVE"),
    flag(0x0008, "OUTLINED"),
    flag(0x0010, "STRIKEOUT"),
    flag(0x0020, "BOLD"),
    flag(0x0040, "REGULAR"),
    flag(0x0080, "USE_TYPO_METRICS"),
    flag(0x0100, "WWS"),
    flag(0x0200, "OBLIQUE"),
];

fn head(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u16("Major version").emit()?;
    f.u16("Minor version").emit()?;
    fixed_field(f, "Font revision")?;
    f.u32("Checksum adjustment").hex().emit()?;
    f.u32("Magic number")
        .hex()
        .check(|&m| (m != 0x5f0f_3cf5).then(|| Diagnostic::malformed("expected 0x5f0f3cf5")))
        .emit()?;
    f.u16("Flags").flags(HEAD_FLAGS).emit()?;
    f.u16("Units per em").emit()?;
    f.u64("Created").mac_time().emit()?;
    f.u64("Modified").mac_time().emit()?;
    for name in ["xMin", "yMin", "xMax", "yMax"] {
        f.int::<i16>(name).emit()?;
    }
    f.u16("Mac style").flags(MAC_STYLE).emit()?;
    f.u16("Smallest readable size (ppem)").emit()?;
    f.int::<i16>("Font direction hint").emit()?;
    f.int::<i16>("Index to location format")
        .with(|&v, n| {
            n.summary(if v == 0 {
                "short offsets"
            } else {
                "long offsets"
            })
        })
        .emit()?;
    f.int::<i16>("Glyph data format").emit()?;
    Ok(())
}

fn hhea(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u16("Major version").emit()?;
    f.u16("Minor version").emit()?;
    for name in ["Ascender", "Descender", "Line gap"] {
        f.int::<i16>(name).emit()?;
    }
    f.u16("Advance width max").emit()?;
    for name in [
        "Min left side bearing",
        "Min right side bearing",
        "x max extent",
        "Caret slope rise",
        "Caret slope run",
        "Caret offset",
    ] {
        f.int::<i16>(name).emit()?;
    }
    f.bytes("Reserved", 8).emit()?;
    f.int::<i16>("Metric data format").emit()?;
    f.u16("Number of h metrics").emit()?;
    Ok(())
}

fn maxp(f: &mut Fields<'_>, _: &()) -> Result<()> {
    let version = f
        .u32("Version")
        .hex()
        .with(|&v, n| {
            n.summary(if v == 0x5000 {
                "0.5 (CFF)"
            } else {
                "1.0 (TrueType)"
            })
        })
        .emit()?;
    f.u16("Number of glyphs").emit()?;
    if version == 0x0001_0000 {
        for name in [
            "Max points",
            "Max contours",
            "Max composite points",
            "Max composite contours",
            "Max zones",
            "Max twilight points",
            "Max storage",
            "Max function defs",
            "Max instruction defs",
            "Max stack elements",
            "Max size of instructions",
            "Max component elements",
            "Max component depth",
        ] {
            f.u16(name).emit()?;
        }
    }
    Ok(())
}

fn os2(f: &mut Fields<'_>, _: &()) -> Result<()> {
    let version = f.u16("Version").emit()?;
    f.int::<i16>("Average char width").emit()?;
    f.u16("Weight class").enumeration(WEIGHTS).emit()?;
    f.u16("Width class").enumeration(WIDTHS).emit()?;
    f.u16("Embedding (fsType)")
        .flags(FS_TYPE)
        .with(|&v, n| {
            if v & 0x000f == 0 {
                n.summary("Installable")
            } else {
                n
            }
        })
        .emit()?;
    for name in [
        "Subscript x size",
        "Subscript y size",
        "Subscript x offset",
        "Subscript y offset",
        "Superscript x size",
        "Superscript y size",
        "Superscript x offset",
        "Superscript y offset",
        "Strikeout size",
        "Strikeout position",
    ] {
        f.int::<i16>(name).emit()?;
    }
    f.int::<i16>("Family class")
        .with(|&v, n| n.summary(format!("class {}, subclass {}", v >> 8, v & 0xff)))
        .emit()?;
    f.bytes("PANOSE", 10).emit()?;
    for name in [
        "Unicode range 1",
        "Unicode range 2",
        "Unicode range 3",
        "Unicode range 4",
    ] {
        f.u32(name).hex().emit()?;
    }
    f.ascii("Vendor ID", 4).emit()?;
    f.u16("Selection").flags(FS_SELECTION).emit()?;
    f.u16("First char index").hex().emit()?;
    f.u16("Last char index").hex().emit()?;
    for name in ["Typo ascender", "Typo descender", "Typo line gap"] {
        f.int::<i16>(name).emit()?;
    }
    f.u16("Win ascent").emit()?;
    f.u16("Win descent").emit()?;
    if version >= 1 {
        f.u32("Code page range 1").hex().emit()?;
        f.u32("Code page range 2").hex().emit()?;
    }
    if version >= 2 {
        f.int::<i16>("x height").emit()?;
        f.int::<i16>("Cap height").emit()?;
        f.u16("Default char").hex().emit()?;
        f.u16("Break char").hex().emit()?;
        f.u16("Max context").emit()?;
    }
    if version >= 5 {
        f.u16("Lower optical point size").emit()?;
        f.u16("Upper optical point size").emit()?;
    }
    Ok(())
}

fn post(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("Version")
        .hex()
        .with(|&v, n| n.summary(format!("{}", fixed(v))))
        .emit()?;
    fixed_field(f, "Italic angle")?;
    f.int::<i16>("Underline position").emit()?;
    f.int::<i16>("Underline thickness").emit()?;
    f.u32("Is fixed pitch").emit()?;
    for name in [
        "Min memory (Type 42)",
        "Max memory (Type 42)",
        "Min memory (Type 1)",
        "Max memory (Type 1)",
    ] {
        f.u32(name).emit()?;
    }
    if f.remaining() > 0 {
        let rest = f.remaining();
        f.node(
            Node::new("Glyph names")
                .span(f.peek_span(rest))
                .summary(format!("{rest} bytes")),
        );
    }
    Ok(())
}

/// Emits the decoded fields of table `tag` at `span`.
pub async fn decode(cx: &Cx, tag: &str, span: Span) -> Result<()> {
    let layout: Option<crate::fields::Layout<(), ()>> = match tag {
        "head" => Some(head),
        "hhea" | "vhea" => Some(hhea),
        "maxp" => Some(maxp),
        "OS/2" => Some(os2),
        "post" => Some(post),
        _ => None,
    };
    if let Some(layout) = layout {
        let block = cx.block(span).await?;
        return layout(&mut Fields::emitting(cx, &block, BE), &());
    }
    match tag {
        "name" => name_table(cx, span).await,
        "cmap" => cmap(cx, span).await,
        "fvar" => fvar(cx, span).await,
        _ => {
            cx.emit(
                Node::new("Data")
                    .span(span)
                    .summary(format!("{} bytes", span.len)),
            );
            Ok(())
        }
    }
}

async fn name_table(cx: &Cx, span: Span) -> Result<()> {
    let head = cx.read(span.sub_exact(0, 6)?).await?;
    let count = u16_be(&head, 2).unwrap_or(0);
    let strings = u64::from(u16_be(&head, 4).unwrap_or(0));
    cx.emit(struct_node("Header", span.sub(0, 6), BE, (), |f, _| {
        f.u16("Format").emit()?;
        f.u16("Count").emit()?;
        f.u16("String offset").hex().emit()?;
        Ok(())
    }));
    let records = span.sub(6, u64::from(count).saturating_mul(12));
    cx.emit(
        Node::new("Name records")
            .span(records)
            .summary(format!("{count} records"))
            .lazy(name_records, (span, count, strings)),
    );
    Ok(())
}

async fn name_records(cx: Cx, (span, count, strings): (Span, u16, u64)) -> Result<()> {
    let table = span.sub_exact(6, u64::from(count).saturating_mul(12))?;
    cx.set_count(Count::Exact(count.into()));
    for i in 0..u64::from(count) {
        let rspan = table.sub(i.saturating_mul(12), 12);
        let r = cx.read(rspan).await?;
        let get = |at: usize| u16_be(&r, at).unwrap_or(0);
        let (platform, encoding, language, id, len, offset) =
            (get(0), get(2), get(4), get(6), get(8), get(10));
        let text_span = span.sub(strings.saturating_add(offset.into()), len.into());
        let bytes = cx.read_avail(text_span).await?;
        let text = decode_name(platform, encoding, &bytes);
        let name = lookup(NAME_IDS, id.into()).map_or_else(|| format!("Name {id}"), str::to_owned);
        cx.push(
            Node::new(name)
                .span(text_span)
                .value(Value::Text(text))
                .summary(format!(
                    "{}, {}, {}",
                    lookup(PLATFORMS, platform.into()).unwrap_or("?"),
                    encoding_name(platform, encoding),
                    language_name(platform, language)
                ))
                .lazy(name_record, rspan),
        )
        .await;
    }
    Ok(())
}

async fn name_record(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    f.u16("Platform ID").enumeration(PLATFORMS).emit()?;
    f.u16("Encoding ID").emit()?;
    f.u16("Language ID").hex().emit()?;
    f.u16("Name ID").enumeration(NAME_IDS).emit()?;
    f.u16("Length").emit()?;
    f.u16("String offset").hex().emit()?;
    Ok(())
}

/// The best name for `wanted` (Windows English first, then anything).
pub async fn find_name(cx: &Cx, span: Span, wanted: u16) -> Option<String> {
    let head = cx.read(span.sub(0, 6)).await.ok()?;
    let count = u16_be(&head, 2)?;
    let strings = u64::from(u16_be(&head, 4)?);
    let table = cx
        .read_avail(span.sub(6, u64::from(count).saturating_mul(12)))
        .await
        .ok()?;
    let mut best: Option<(u8, u16, u16, u16, u16)> = None;
    for r in table.as_chunks::<12>().0 {
        let get = |at: usize| u16_be(r, at).unwrap_or(0);
        if get(6) != wanted {
            continue;
        }
        let rank = match (get(0), get(4)) {
            (3, 0x0409) => 3,
            (3, _) | (0, _) => 2,
            (1, 0) => 1,
            _ => 0,
        };
        if best.is_none_or(|b| rank > b.0) {
            best = Some((rank, get(0), get(2), get(8), get(10)));
        }
    }
    let (_, platform, encoding, len, offset) = best?;
    let bytes = cx
        .read_avail(span.sub(strings.saturating_add(offset.into()), len.into()))
        .await
        .ok()?;
    Some(decode_name(platform, encoding, &bytes))
}

async fn cmap(cx: &Cx, span: Span) -> Result<()> {
    let head = cx.read(span.sub_exact(0, 4)?).await?;
    let count = u16_be(&head, 2).unwrap_or(0);
    cx.emit(struct_node("Header", span.sub(0, 4), BE, (), |f, _| {
        f.u16("Version").emit()?;
        f.u16("Number of encoding records").emit()?;
        Ok(())
    }));
    let records = span.sub_exact(4, u64::from(count).saturating_mul(8))?;
    for i in 0..u64::from(count) {
        let r = cx.read(records.sub(i.saturating_mul(8), 8)).await?;
        let platform = u16_be(&r, 0).unwrap_or(0);
        let encoding = u16_be(&r, 2).unwrap_or(0);
        let offset = u64::from(u32_be(&r, 4).unwrap_or(0));
        let sub = span.tail(offset);
        let sh = cx.read_avail(sub.sub(0, 16)).await?;
        let format = u16_be(&sh, 0).unwrap_or(0);
        let length = match format {
            8 | 10 | 12 | 13 => u64::from(u32_be(&sh, 4).unwrap_or(0)),
            14 => u64::from(u32_be(&sh, 2).unwrap_or(0)),
            _ => u64::from(u16_be(&sh, 2).unwrap_or(0)),
        };
        let sub = sub.sub(0, length);
        let detail = match format {
            4 => format!(", {} segments", u16_be(&sh, 6).unwrap_or(0) / 2),
            12 | 13 => format!(", {} groups", u32_be(&sh, 12).unwrap_or(0)),
            _ => String::new(),
        };
        cx.push(
            Node::new(format!(
                "{} / {}",
                lookup(PLATFORMS, platform.into()).unwrap_or("?"),
                encoding_name(platform, encoding)
            ))
            .span(sub)
            .summary(format!("format {format}{detail}"))
            .lazy(cmap_subtable, (sub, format)),
        )
        .await;
    }
    Ok(())
}

async fn cmap_subtable(cx: Cx, (span, format): (Span, u16)) -> Result<()> {
    match format {
        4 => {
            let head = cx.block(span.sub(0, 14)).await?;
            let mut f = Fields::emitting(&cx, &head, BE);
            f.u16("Format").emit()?;
            f.u16("Length").emit()?;
            f.u16("Language").emit()?;
            let seg2 = f.u16("Segment count × 2").emit()?;
            f.u16("Search range").emit()?;
            f.u16("Entry selector").emit()?;
            f.u16("Range shift").emit()?;
            let segs = u64::from(seg2 / 2);
            cx.emit(
                Node::new("Segments")
                    .span(span.sub(14, segs.saturating_mul(8).saturating_add(2)))
                    .summary(format!("{segs}"))
                    .lazy(format4_segments, (span, segs)),
            );
        }
        12 | 13 => {
            let head = cx.block(span.sub(0, 16)).await?;
            let mut f = Fields::emitting(&cx, &head, BE);
            f.u16("Format").emit()?;
            f.u16("Reserved").emit()?;
            f.u32("Length").emit()?;
            f.u32("Language").emit()?;
            let groups = f.u32("Number of groups").emit()?;
            cx.emit(
                Node::new("Groups")
                    .span(span.sub(16, u64::from(groups).saturating_mul(12)))
                    .summary(format!("{groups}"))
                    .lazy(format12_groups, (span, groups, format)),
            );
        }
        _ => {
            let head = cx.block(span.sub(0, 6)).await?;
            let mut f = Fields::emitting(&cx, &head, BE);
            f.u16("Format").emit()?;
            f.u16("Length").emit()?;
            f.u16("Language").emit()?;
            cx.emit(Node::new("Data").span(span.tail(6)));
        }
    }
    Ok(())
}

fn codepoint(c: u32) -> String {
    format!("U+{c:04X}")
}

async fn format4_segments(cx: Cx, (span, segs): (Span, u64)) -> Result<()> {
    let n = segs.saturating_mul(2);
    let ends = cx.read(span.sub_exact(14, n)?).await?;
    let starts = cx.read(span.sub_exact(16u64.saturating_add(n), n)?).await?;
    let deltas = cx
        .read(span.sub_exact(16u64.saturating_add(n.saturating_mul(2)), n)?)
        .await?;
    let offsets = cx
        .read(span.sub_exact(16u64.saturating_add(n.saturating_mul(3)), n)?)
        .await?;
    cx.set_count(Count::Exact(segs));
    for i in 0..crate::bytes::to_usize(segs) {
        let at = i.saturating_mul(2);
        let end = u16_be(&ends, at).unwrap_or(0);
        let start = u16_be(&starts, at).unwrap_or(0);
        let delta = u16_be(&deltas, at).unwrap_or(0);
        let range = u16_be(&offsets, at).unwrap_or(0);
        let mapping = if range == 0 {
            format!("glyph {} + index", start.wrapping_add(delta))
        } else {
            "via glyph index array".to_owned()
        };
        cx.push(
            Node::new(format!(
                "{}–{}",
                codepoint(start.into()),
                codepoint(end.into())
            ))
            .span(span.sub(14u64.saturating_add(to_u64(at)), 2))
            .summary(mapping),
        )
        .await;
    }
    Ok(())
}

async fn format12_groups(cx: Cx, (span, groups, format): (Span, u32, u16)) -> Result<()> {
    let table = span.sub_exact(16, u64::from(groups).saturating_mul(12))?;
    cx.set_count(Count::Exact(groups.into()));
    for i in 0..u64::from(groups) {
        let gspan = table.sub(i.saturating_mul(12), 12);
        let g = cx.read(gspan).await?;
        let start = u32_be(&g, 0).unwrap_or(0);
        let end = u32_be(&g, 4).unwrap_or(0);
        let glyph = u32_be(&g, 8).unwrap_or(0);
        let summary = if format == 13 {
            format!("all → glyph {glyph}")
        } else {
            format!(
                "→ glyphs {glyph}–{}",
                glyph.saturating_add(end.saturating_sub(start))
            )
        };
        cx.push(
            Node::new(format!("{}–{}", codepoint(start), codepoint(end)))
                .span(gspan)
                .summary(summary),
        )
        .await;
    }
    Ok(())
}

async fn fvar(cx: &Cx, span: Span) -> Result<()> {
    let block = cx.block(span.sub(0, 16)).await?;
    let mut f = Fields::emitting(cx, &block, BE);
    f.u16("Major version").emit()?;
    f.u16("Minor version").emit()?;
    let axes_offset = f.u16("Axes array offset").hex().emit()?;
    f.u16("Reserved").emit()?;
    let axis_count = f.u16("Axis count").emit()?;
    let axis_size = f.u16("Axis size").emit()?;
    let instance_count = f.u16("Instance count").emit()?;
    let instance_size = f.u16("Instance size").emit()?;
    let axes = span.sub(
        axes_offset.into(),
        u64::from(axis_count).saturating_mul(axis_size.into()),
    );
    cx.emit(
        Node::new("Axes")
            .span(axes)
            .summary(format!("{axis_count}"))
            .lazy(fvar_axes, (axes, axis_count, axis_size)),
    );
    let instances_at = u64::from(axes_offset).saturating_add(axes.len);
    let instances = span.sub(
        instances_at,
        u64::from(instance_count).saturating_mul(instance_size.into()),
    );
    cx.emit(
        Node::new("Instances")
            .span(instances)
            .summary(format!("{instance_count}"))
            .lazy(
                fvar_instances,
                (instances, instance_count, instance_size, axis_count),
            ),
    );
    Ok(())
}

async fn fvar_axes(cx: Cx, (span, count, size): (Span, u16, u16)) -> Result<()> {
    let span = span.sub_exact(0, u64::from(count).saturating_mul(size.into()))?;
    if size < 20 {
        return Err(Diagnostic::malformed(format!(
            "axis records of {size} bytes"
        )));
    }
    for i in 0..u64::from(count) {
        let aspan = span.sub(i.saturating_mul(size.into()), size.into());
        let a = cx.read(aspan).await?;
        let tag = a.get(..4).map(fourcc).unwrap_or_default();
        let min = fixed(u32_be(&a, 4).unwrap_or(0));
        let default = fixed(u32_be(&a, 8).unwrap_or(0));
        let max = fixed(u32_be(&a, 12).unwrap_or(0));
        let name = match tag.as_str() {
            "wght" => "Weight",
            "wdth" => "Width",
            "ital" => "Italic",
            "slnt" => "Slant",
            "opsz" => "Optical size",
            _ => "Axis",
        };
        cx.push(
            struct_node(format!("'{tag}' ({name})"), aspan, BE, (), axis_record)
                .summary(format!("{min} … {default} … {max}")),
        )
        .await;
    }
    Ok(())
}

fn axis_record(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.ascii("Tag", 4).emit()?;
    fixed_field(f, "Minimum")?;
    fixed_field(f, "Default")?;
    fixed_field(f, "Maximum")?;
    f.u16("Flags").hex().desc("0x0001 = hidden axis").emit()?;
    f.u16("Axis name ID").emit()?;
    Ok(())
}

async fn fvar_instances(cx: Cx, (span, count, size, axes): (Span, u16, u16, u16)) -> Result<()> {
    let span = span.sub_exact(0, u64::from(count).saturating_mul(size.into()))?;
    if size < 4 {
        return Err(Diagnostic::malformed(format!(
            "instance records of {size} bytes"
        )));
    }
    for i in 0..u64::from(count) {
        let ispan = span.sub(i.saturating_mul(size.into()), size.into());
        let data = cx.read(ispan).await?;
        let name_id = u16_be(&data, 0).unwrap_or(0);
        let coords: Vec<String> = (0..usize::from(axes))
            .map(|a| {
                u32_be(&data, 4usize.saturating_add(a.saturating_mul(4)))
                    .map_or_else(String::new, |v| format!("{}", fixed(v)))
            })
            .collect();
        cx.push(
            Node::new(format!("Instance {i}"))
                .span(ispan)
                .summary(format!(
                    "name ID {name_id}, coordinates ({})",
                    coords.join(", ")
                )),
        )
        .await;
    }
    Ok(())
}

/// Short descriptions for the table list, from a table's first bytes.
pub fn short(tag: &str, head: &[u8]) -> Option<String> {
    match tag {
        "head" => Some(format!("{} units/em", u16_be(head, 18)?)),
        "maxp" => Some(format!("{} glyphs", u16_be(head, 4)?)),
        "hhea" => Some(format!("{} h-metrics", u16_be(head, 34)?)),
        "OS/2" => Some(format!(
            "weight {}, vendor {:?}",
            u16_be(head, 4)?,
            clip(&String::from_utf8_lossy(head.get(58..62)?), 4)
        )),
        "name" => Some(format!("{} records", u16_be(head, 2)?)),
        "cmap" => Some(format!("{} subtables", u16_be(head, 2)?)),
        "fvar" => Some(format!(
            "{} axes, {} instances",
            u16_be(head, 8)?,
            u16_be(head, 12)?
        )),
        "post" => Some(format!("version {}", fixed(u32_be(head, 0)?))),
        _ => None,
    }
}
