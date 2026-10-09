//! Ericsson PKM textures, color swatches, GIMP brushes and patterns, and
//! Paint.NET images.
//!
//! (Metafiles are in `metafile`, film frames in `dpx`, the other GPU
//! textures in `texture`, BPG and FLIF in `modern`; JPEG XR is a TIFF
//! variant in `tiff`.)

use crate::bytes::u16_be;
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, emit_record};
use crate::error::Result;
use crate::fields::Endian;
use crate::formats::{Head, Input, Probe, embedded};
use crate::node::Node;
use crate::record;
use crate::value::{EnumTable, Value, lookup};

const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// Ericsson PKM (ETC textures)

declare_format!(pub PKM = "pkm", "Ericsson ETC texture (PKM)", ["pkm"], "image/x-pkm",
    Probe::Magic(&[(0, b"PKM 10"), (0, b"PKM 20")]), pkm);

record! {
    pub struct PkmHeader {
        magic: ascii[4] "Magic",
        version: ascii[2] "Version",
        format: u16 "Format" .enumeration(&[(0, "ETC1 RGB"), (1, "ETC2 RGB"), (3, "ETC2 RGBA"), (4, "ETC2 RGBA1"), (5, "EAC R11"), (6, "EAC RG11")]),
        padded_width: u16 "Padded width",
        padded_height: u16 "Padded height",
        width: u16 "Width",
        height: u16 "Height",
    }
}

async fn pkm(cx: Cx, input: Input) -> Result<()> {
    let h: PkmHeader = emit_record(&cx, input.span.sub(0, PkmHeader::SIZE), BE).await?;
    cx.emit(Node::new("Texture data").span(input.span.tail(PkmHeader::SIZE)));
    cx.annotate(format!("PKM {}, {}×{}", h.version, h.width, h.height));
    Ok(())
}

// ---------------------------------------------------------------------------
// Colour swatches: Adobe ASE and ACO

declare_format!(pub ASE = "ase", "Adobe swatch exchange", ["ase"], "application/x-adobe-swatch-exchange",
    Probe::Magic(&[(0, b"ASEF")]), ase);

async fn ase(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 12)).await?;
    let mut f = crate::fields::Fields::emitting(&cx, &head, BE);
    f.ascii("Signature", 4).emit()?;
    f.u16("Version major").emit()?;
    f.u16("Version minor").emit()?;
    let blocks = f.u32("Blocks").emit()?;
    let mut cur = Cursor::new(&cx, file, BE);
    cur.seek(12);
    let mut colors = 0u32;
    for _ in 0..blocks.min(100_000) {
        if cur.remaining() < 6 {
            break;
        }
        let start = cur.pos();
        let kind = cur.u16().await?;
        let len = cur.u32().await?;
        let body = cur.span(len.into());
        cur.skip(len.into());
        let label = match kind {
            0xc001 => "Group start",
            0xc002 => "Group end",
            0x0001 => "Color",
            _ => "Block",
        };
        let mut node = Node::new(label).span(cur.since(start));
        if kind == 0x0001 || kind == 0xc001 {
            let data = cx.read_avail(body).await?;
            let units = usize::from(u16_be(&data, 0).unwrap_or(0));
            let name_bytes = data
                .get(2..2usize.saturating_add(units.saturating_mul(2)))
                .unwrap_or_default();
            let name = crate::text::utf16z(name_bytes, BE).0;
            if kind == 0x0001 {
                colors = colors.saturating_add(1);
                let model = String::from_utf8_lossy(
                    data.get(2usize.saturating_add(units.saturating_mul(2))..)
                        .and_then(|r| r.get(..4))
                        .unwrap_or_default(),
                )
                .into_owned();
                node = node.summary(format!("{name} ({})", model.trim()));
            } else {
                node = node.summary(name);
            }
        }
        cx.push(node).await;
    }
    cx.annotate(format!("{colors} colours"));
    Ok(())
}

fn aco_probe(h: &Head<'_>) -> bool {
    // Version 1 or 2, then a plausible count, then colour space ids.
    u16_be(h.data, 0).is_some_and(|v| v == 1 || v == 2)
        && u16_be(h.data, 2)
            .is_some_and(|n| n > 0 && u64::from(n).saturating_mul(10).saturating_add(4) <= h.len)
        && u16_be(h.data, 4).is_some_and(|space| matches!(space, 0..=2 | 7..=9))
        && h.len.saturating_sub(4).is_multiple_of(10)
}

declare_format!(pub ACO = "aco", "Adobe Photoshop colour swatches", ["aco"], "application/x-adobe-color-swatches",
    Probe::Custom(aco_probe), aco);

const ACO_SPACES: EnumTable = &[
    (0, "RGB"),
    (1, "HSB"),
    (2, "CMYK"),
    (7, "Lab"),
    (8, "Grayscale"),
    (9, "Wide CMYK"),
];

async fn aco(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, BE);
    let version = cur.u16().await?;
    let count = cur.u16().await?;
    cx.emit(
        Node::new("Header")
            .span(file.sub(0, 4))
            .summary(format!("version {version}, {count} colours")),
    );
    for i in 0..count {
        let start = cur.pos();
        let space = cur.u16().await?;
        let a = cur.u16().await?;
        let b = cur.u16().await?;
        let c = cur.u16().await?;
        let _d = cur.u16().await?;
        let space_name = lookup(ACO_SPACES, space.into()).unwrap_or("unknown");
        cx.push(
            Node::new(format!("Colour {i}"))
                .span(cur.since(start))
                .summary(format!("{space_name} {} {} {}", a >> 8, b >> 8, c >> 8)),
        )
        .await;
    }
    cx.annotate(format!("{count} colours"));
    Ok(())
}

// ---------------------------------------------------------------------------
// GIMP brushes and patterns, Paint.NET

fn gbr_probe(h: &Head<'_>) -> bool {
    h.at(20, b"GIMP")
}

fn gpat_probe(h: &Head<'_>) -> bool {
    h.at(20, b"GPAT")
}

declare_format!(pub GBR = "gbr", "GIMP brush", ["gbr"], "image/x-gimp-gbr",
    Probe::Custom(gbr_probe), gimp_brush);
declare_format!(pub GPAT = "pat", "GIMP pattern", ["pat"], "image/x-gimp-pat",
    Probe::Custom(gpat_probe), gimp_brush);

async fn gimp_brush(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 28)).await?;
    let mut f = crate::fields::Fields::emitting(&cx, &head, BE);
    let header = f.u32("Header size").emit()?;
    f.u32("Version").emit()?;
    let w = f.u32("Width").emit()?;
    let h = f.u32("Height").emit()?;
    let bytes = f.u32("Bytes per pixel").emit()?;
    let magic = f.ascii("Magic", 4).emit()?;
    let rest = file.sub(24, u64::from(header).saturating_sub(24));
    let (name, name_span) = if magic == "GIMP" {
        f.u32("Spacing").emit()?;
        (cx.read_avail(rest.tail(4)).await?, rest.tail(4))
    } else {
        (cx.read_avail(rest).await?, rest)
    };
    let name = crate::text::until_nul(&name);
    cx.emit(
        Node::new("Name")
            .span(name_span)
            .value(Value::Text(name.clone())),
    );
    cx.emit(Node::new("Pixels").span(file.tail(header.into())));
    cx.annotate(format!("{name:?}, {w}×{h}, {bytes} byte(s) per pixel"));
    Ok(())
}

declare_format!(pub PDN = "pdn", "Paint.NET image", ["pdn"], "image/x-paintnet",
    Probe::Magic(&[(0, b"PDN3")]), pdn);

async fn pdn(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 7)).await?;
    let len = u64::from(crate::bytes::u24_le(&head, 4).unwrap_or(0));
    cx.emit(Node::new("Magic").span(file.sub(0, 4)));
    let xml = file.sub(7, len);
    cx.emit(embedded("Header (XML)", input.nested(xml)));
    let text = String::from_utf8_lossy(&cx.read_avail(xml.sub(0, 512)).await?).into_owned();
    let attr = |name: &str| {
        text.find(&format!("{name}=\""))
            .and_then(|at| text.get(at.saturating_add(name.len()).saturating_add(2)..))
            .and_then(|r| r.split('"').next())
            .map(str::to_owned)
    };
    cx.emit(Node::new("Document (.NET serialized)").span(file.tail(7u64.saturating_add(len))));
    cx.annotate(format!(
        "Paint.NET, {}×{}",
        attr("width").unwrap_or_default(),
        attr("height").unwrap_or_default()
    ));
    Ok(())
}
