//! Electronic design automation: IC layout (GDSII, OASIS), PCB fabrication
//! (Gerber, Excellon), S-expression design files (KiCad, EDIF, SDF timing),
//! simulation and measurement (VCD, Touchstone, CITIfile, SPICE raw), models
//! and parasitics (IBIS, SPEF), and programmable logic (Xilinx bitstreams,
//! JEDEC fuse maps).

use crate::bytes::{to_u64, to_usize, u16_be, u32_be};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::lines::{Line, Lines, contains, head_lines, hex, is_text, number, preview, summarize, tally, text, uint};
use crate::formats::{Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, Value, lookup};

const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// GDSII stream format

declare_format!(pub GDSII = "gdsii", "GDSII stream (IC layout)", ["gds", "gds2", "gdsii", "sf"], "application/vnd.gds",
    Probe::Custom(|h| h.at(0, b"\x00\x06\x00\x02") && h.at(6, b"\x00\x1c\x01\x02")), gdsii);

const GDS_RECORDS: [&str; 60] = [
    "HEADER", "BGNLIB", "LIBNAME", "UNITS", "ENDLIB", "BGNSTR", "STRNAME", "ENDSTR", "BOUNDARY", "PATH", "SREF", "AREF", "TEXT", "LAYER", "DATATYPE", "WIDTH", "XY", "ENDEL", "SNAME", "COLROW", "TEXTNODE",
    "NODE", "TEXTTYPE", "PRESENTATION", "SPACING", "STRING", "STRANS", "MAG", "ANGLE", "UINTEGER", "USTRING", "REFLIBS", "FONTS", "PATHTYPE", "GENERATIONS", "ATTRTABLE", "STYPTABLE", "STRTYPE", "ELFLAGS",
    "ELKEY", "LINKTYPE", "LINKKEYS", "NODETYPE", "PROPATTR", "PROPVALUE", "BOX", "BOXTYPE", "PLEX", "BGNEXTN", "ENDEXTN", "TAPENUM", "TAPECODE", "STRCLASS", "RESERVED", "FORMAT", "MASK", "ENDMASKS", "LIBDIRSIZE",
    "SRFNAME", "LIBSECUR",
];

fn gds_name(kind: u8) -> String {
    GDS_RECORDS.get(usize::from(kind)).map_or_else(|| format!("record {kind:#04x}"), |s| (*s).to_owned())
}

/// GDSII 8-byte real: sign, excess-64 base-16 exponent, 56-bit mantissa.
fn gds_real8(b: &[u8]) -> f64 {
    let Some(v) = crate::bytes::u64_be(b, 0) else { return 0.0 };
    let sign = if v >> 63 == 0 { 1.0 } else { -1.0 };
    let exponent = i32::try_from((v >> 56) & 0x7f).unwrap_or(64).saturating_sub(64);
    #[allow(clippy::cast_precision_loss)]
    let mantissa = (v & 0x00ff_ffff_ffff_ffff) as f64 / 72_057_594_037_927_936.0;
    sign * mantissa * 16f64.powi(exponent)
}

/// Renders a record's payload by data type.
fn gds_value(kind: u8, datatype: u8, b: &[u8]) -> Value {
    match datatype {
        1 => hex(u16_be(b, 0).unwrap_or(0).into(), 16),
        2 if matches!(kind, 0x01 | 0x05) && b.len() >= 24 => {
            let w: Vec<i16> = b.as_chunks::<2>().0.iter().map(|c| i16::from_be_bytes(*c)).collect();
            let g = |i: usize| w.get(i).copied().unwrap_or(0);
            text(format!("modified {:04}-{:02}-{:02} {:02}:{:02}:{:02}, accessed {:04}-{:02}-{:02} {:02}:{:02}:{:02}", year(g(0)), g(1), g(2), g(3), g(4), g(5), year(g(6)), g(7), g(8), g(9), g(10), g(11)))
        }
        2 => {
            let w: Vec<String> = b.as_chunks::<2>().0.iter().take(16).map(|c| i16::from_be_bytes(*c).to_string()).collect();
            if w.len() == 1 { number(w.first().map_or("0", String::as_str)) } else { text(w.join(", ")) }
        }
        3 if kind == 0x10 => {
            let w: Vec<i32> = b.as_chunks::<4>().0.iter().map(|c| i32::from_be_bytes(*c)).collect();
            let pts: Vec<String> = w.chunks(2).take(8).map(|p| format!("({}, {})", p.first().unwrap_or(&0), p.get(1).unwrap_or(&0))).collect();
            text(format!("{}{}", pts.join(" "), if w.len() > 16 { " …" } else { "" }))
        }
        3 => {
            let w: Vec<String> = b.as_chunks::<4>().0.iter().take(16).map(|c| i32::from_be_bytes(*c).to_string()).collect();
            if w.len() == 1 { number(w.first().map_or("0", String::as_str)) } else { text(w.join(", ")) }
        }
        5 => {
            let w: Vec<String> = b.as_chunks::<8>().0.iter().map(|c| real_text(gds_real8(c))).collect();
            text(w.join(", "))
        }
        6 => text(crate::text::until_nul(b)),
        _ => text(""),
    }
}

/// Plain notation for ordinary magnitudes, scientific for tiny or huge ones.
fn real_text(v: f64) -> String {
    if v == 0.0 || (1e-3..1e7).contains(&v.abs()) { v.to_string() } else { format!("{v:e}") }
}

/// Two-digit years in old files mean 19xx.
fn year(y: i16) -> i32 {
    let y = i32::from(y);
    if y < 1900 { y.saturating_add(1900) } else { y }
}

/// One record: type, data type, header+payload span.
#[derive(Clone, Copy, Debug)]
struct GdsRecord {
    kind: u8,
    datatype: u8,
    span: Span,
}

async fn gds_next(cur: &mut Cursor<'_>) -> Result<Option<GdsRecord>> {
    if cur.remaining() < 4 {
        return Ok(None);
    }
    let start = cur.pos();
    let len = cur.u16().await?;
    let kind = cur.u8().await?;
    let datatype = cur.u8().await?;
    if len < 4 {
        // Zero-length records are tape padding at the end.
        return Ok(None);
    }
    cur.seek(start.saturating_add(len.into()));
    Ok(Some(GdsRecord { kind, datatype, span: cur.region().sub(start, len.into()) }))
}

async fn gds_record_node(cx: &Cx, r: GdsRecord) -> Result<Node> {
    let payload = r.span.tail(4);
    let b = cx.read_avail(payload.sub(0, 4096)).await?;
    let node = Node::new(gds_name(r.kind)).span(r.span);
    Ok(if r.datatype == 0 { node } else { node.value(gds_value(r.kind, r.datatype, &b)) })
}

async fn gdsii(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, BE);
    let (mut lib, mut version, mut units) = (String::new(), 0i64, String::new());
    let mut structures = 0u32;
    while let Some(r) = gds_next(&mut cur).await? {
        match r.kind {
            0x05 => {
                // A structure runs to its ENDSTR.
                let start = r.span;
                let mut name = String::new();
                let mut elements = 0u32;
                while let Some(e) = gds_next(&mut cur).await? {
                    if e.kind == 0x06 {
                        name = crate::text::until_nul(&cx.read_avail(e.span.tail(4)).await?);
                    }
                    if e.kind == 0x11 {
                        elements = elements.saturating_add(1);
                    }
                    if e.kind == 0x07 {
                        break;
                    }
                }
                let span = file.sub(start.offset.saturating_sub(file.offset), cur.pos().saturating_sub(start.offset.saturating_sub(file.offset)));
                cx.push(Node::new(format!("Structure {name}")).span(span).summary(format!("{elements} element(s)")).lazy(gds_structure, span)).await;
                structures = structures.saturating_add(1);
            }
            _ => {
                let b = cx.read_avail(r.span.tail(4).sub(0, 64)).await?;
                match r.kind {
                    0x00 => version = i64::from(u16_be(&b, 0).unwrap_or(0).cast_signed()),
                    0x02 => lib = crate::text::until_nul(&b),
                    0x03 => units = format!("{:e} user units/db unit, {:e} m/db unit", gds_real8(&b), gds_real8(b.get(8..).unwrap_or_default())),
                    _ => {}
                }
                cx.push(gds_record_node(&cx, r).await?).await;
            }
        }
    }
    cx.annotate(format!("GDSII v{version} library {lib:?}, {structures} structure(s){}", if units.is_empty() { String::new() } else { format!(", {units}") }));
    Ok(())
}

async fn gds_structure(cx: Cx, span: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, BE);
    while let Some(r) = gds_next(&mut cur).await? {
        if matches!(r.kind, 0x08..=0x0c | 0x15 | 0x2d) {
            // An element runs to its ENDEL.
            let start = r.span.offset.saturating_sub(span.offset);
            let mut summary = Vec::new();
            let mut points = 0u64;
            while let Some(e) = gds_next(&mut cur).await? {
                let b = cx.read_avail(e.span.tail(4).sub(0, 64)).await?;
                match e.kind {
                    0x0d => summary.push(format!("layer {}", u16_be(&b, 0).unwrap_or(0).cast_signed())),
                    0x0e => summary.push(format!("datatype {}", u16_be(&b, 0).unwrap_or(0).cast_signed())),
                    0x12 => summary.push(format!("→ {}", crate::text::until_nul(&b))),
                    0x19 => summary.push(format!("{:?}", crate::text::until_nul(&b))),
                    0x10 => points = e.span.len.saturating_sub(4) / 8,
                    _ => {}
                }
                if e.kind == 0x11 {
                    break;
                }
            }
            if points > 0 {
                summary.push(format!("{points} point(s)"));
            }
            let s = span.sub(start, cur.pos().saturating_sub(start));
            cx.push(Node::new(gds_name(r.kind)).span(s).summary(summary.join(", ")).lazy(gds_records, s)).await;
        } else {
            cx.push(gds_record_node(&cx, r).await?).await;
        }
    }
    Ok(())
}

async fn gds_records(cx: Cx, span: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, BE);
    while let Some(r) = gds_next(&mut cur).await? {
        cx.push(gds_record_node(&cx, r).await?).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// OASIS

declare_format!(pub OASIS = "oasis", "OASIS (Open Artwork System Interchange Standard)", ["oas", "oasis"], "application/x-oasis",
    Probe::Magic(&[(0, b"%SEMI-OASIS\r\n")]), oasis);

/// A cursor over an in-memory OASIS byte stream.
struct Oasis<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Oasis<'_> {
    fn byte(&mut self) -> Result<u8> {
        let b = self.data.get(self.pos).copied().ok_or_else(|| Diagnostic::malformed("record truncated"))?;
        self.pos = self.pos.saturating_add(1);
        Ok(b)
    }

    fn uint(&mut self) -> Result<u64> {
        let (v, n) = crate::bytes::uleb128(self.data.get(self.pos..).unwrap_or_default()).ok_or_else(|| Diagnostic::malformed("bad unsigned integer"))?;
        self.pos = self.pos.saturating_add(n);
        Ok(v)
    }

    fn sint(&mut self) -> Result<i64> {
        let v = self.uint()?;
        let m = (v >> 1).cast_signed();
        Ok(if v & 1 == 1 { m.saturating_neg() } else { m })
    }

    fn bytes(&mut self, n: u64) -> Result<&[u8]> {
        let end = self.pos.saturating_add(to_usize(n));
        let b = self.data.get(self.pos..end).ok_or_else(|| Diagnostic::malformed("string truncated"))?;
        self.pos = end;
        Ok(b)
    }

    fn string(&mut self) -> Result<String> {
        let n = self.uint()?;
        Ok(String::from_utf8_lossy(self.bytes(n)?).into_owned())
    }

    fn real(&mut self) -> Result<f64> {
        #[allow(clippy::cast_precision_loss)]
        let f = |v: u64| v as f64;
        Ok(match self.uint()? {
            0 => f(self.uint()?),
            1 => -f(self.uint()?),
            2 => 1.0 / f(self.uint()?),
            3 => -1.0 / f(self.uint()?),
            4 => f(self.uint()?) / f(self.uint()?),
            5 => -f(self.uint()?) / f(self.uint()?),
            6 => f64::from(f32::from_le_bytes(crate::bytes::array(self.bytes(4)?, 0).unwrap_or_default())),
            7 => f64::from_le_bytes(crate::bytes::array(self.bytes(8)?, 0).unwrap_or_default()),
            t => return Err(Diagnostic::malformed(format!("real type {t}"))),
        })
    }

    /// A g-delta (general displacement).
    fn gdelta(&mut self) -> Result<(i64, i64)> {
        let v = self.uint()?;
        if v & 1 == 0 {
            let m = (v >> 4).cast_signed();
            let n = m.saturating_neg();
            Ok(match (v >> 1) & 7 {
                0 => (m, 0),
                1 => (0, m),
                2 => (n, 0),
                3 => (0, n),
                4 => (m, m),
                5 => (n, m),
                6 => (n, n),
                _ => (m, n),
            })
        } else {
            let x = (v >> 2).cast_signed();
            let x = if v & 2 != 0 { x.saturating_neg() } else { x };
            Ok((x, self.sint()?))
        }
    }

    fn repetition(&mut self) -> Result<String> {
        let t = self.uint()?;
        let s = |v: u64| v.saturating_add(2);
        Ok(match t {
            0 => "reuse previous".to_owned(),
            1 => {
                let (nx, ny, dx, dy) = (self.uint()?, self.uint()?, self.uint()?, self.uint()?);
                format!("{}×{} grid, pitch {dx}×{dy}", s(nx), s(ny))
            }
            2 | 3 => {
                let (n, d) = (self.uint()?, self.uint()?);
                format!("{} along {}, pitch {d}", s(n), if t == 2 { "x" } else { "y" })
            }
            4 | 6 => {
                let n = self.uint()?;
                for _ in 0..n.saturating_add(1).min(1 << 20) {
                    self.uint()?;
                }
                format!("{} irregular along {}", s(n), if t == 4 { "x" } else { "y" })
            }
            5 | 7 => {
                let n = self.uint()?;
                self.uint()?;
                for _ in 0..n.saturating_add(1).min(1 << 20) {
                    self.uint()?;
                }
                format!("{} irregular along {} (gridded)", s(n), if t == 5 { "x" } else { "y" })
            }
            8 => {
                let (n, m) = (self.uint()?, self.uint()?);
                self.gdelta()?;
                self.gdelta()?;
                format!("{}×{} skewed grid", s(n), s(m))
            }
            9 => {
                let n = self.uint()?;
                self.gdelta()?;
                format!("{} along a diagonal", s(n))
            }
            10 | 11 => {
                let n = self.uint()?;
                if t == 11 {
                    self.uint()?;
                }
                for _ in 0..n.saturating_add(1).min(1 << 20) {
                    self.gdelta()?;
                }
                format!("{} arbitrary", s(n))
            }
            _ => return Err(Diagnostic::malformed(format!("repetition type {t}"))),
        })
    }

    fn point_list(&mut self) -> Result<u64> {
        let t = self.uint()?;
        let n = self.uint()?;
        for _ in 0..n.min(1 << 24) {
            match t {
                0 | 1 => {
                    self.sint()?;
                }
                2 | 3 => {
                    self.uint()?;
                }
                4 | 5 => {
                    self.gdelta()?;
                }
                _ => return Err(Diagnostic::malformed(format!("point list type {t}"))),
            }
        }
        Ok(n)
    }

    fn property_value(&mut self) -> Result<String> {
        Ok(match self.uint()? {
            t @ 0..=7 => {
                // Values 0–7 are reals whose type is the value type.
                self.pos = self.pos.saturating_sub(1);
                let _ = t;
                self.real()?.to_string()
            }
            8 => self.uint()?.to_string(),
            9 => self.sint()?.to_string(),
            10..=12 => format!("{:?}", self.string()?),
            13..=15 => format!("propstring #{}", self.uint()?),
            t => return Err(Diagnostic::malformed(format!("property value type {t}"))),
        })
    }
}

const OASIS_RECORDS: [&str; 35] = [
    "PAD", "START", "END", "CELLNAME", "CELLNAME", "TEXTSTRING", "TEXTSTRING", "PROPNAME", "PROPNAME", "PROPSTRING", "PROPSTRING", "LAYERNAME", "LAYERNAME (text)", "CELL", "CELL", "XYABSOLUTE", "XYRELATIVE",
    "PLACEMENT", "PLACEMENT", "TEXT", "RECTANGLE", "POLYGON", "PATH", "TRAPEZOID", "TRAPEZOID", "TRAPEZOID", "CTRAPEZOID", "CIRCLE", "PROPERTY", "PROPERTY", "XNAME", "XNAME", "XELEMENT", "XGEOMETRY", "CBLOCK",
];

/// Parses one record; returns its description (and a CBLOCK payload span).
/// A CBLOCK payload: offset, compressed and uncompressed sizes.
type CBlock = (u64, u64, u64);

fn oasis_record(p: &mut Oasis<'_>, id: u64, offset_flag: &mut u64) -> Result<(String, Option<CBlock>)> {
    let mut parts: Vec<String> = Vec::new();
    let mut cblock = None;
    // Geometry records: optional fields guarded by an info byte.
    let xy = |p: &mut Oasis<'_>, info: u8, parts: &mut Vec<String>| -> Result<()> {
        if info & 0x10 != 0 {
            parts.push(format!("x={}", p.sint()?));
        }
        if info & 0x08 != 0 {
            parts.push(format!("y={}", p.sint()?));
        }
        if info & 0x04 != 0 {
            parts.push(format!("repetition: {}", p.repetition()?));
        }
        Ok(())
    };
    let layer = |p: &mut Oasis<'_>, info: u8, parts: &mut Vec<String>| -> Result<()> {
        if info & 0x01 != 0 {
            parts.push(format!("layer {}", p.uint()?));
        }
        if info & 0x02 != 0 {
            parts.push(format!("datatype {}", p.uint()?));
        }
        Ok(())
    };
    match id {
        0 => {}
        1 => {
            parts.push(format!("version {}", p.string()?));
            parts.push(format!("unit {} per µm", p.real()?));
            *offset_flag = p.uint()?;
            if *offset_flag == 0 {
                for _ in 0..12 {
                    p.uint()?;
                }
                parts.push("table offsets here".to_owned());
            }
        }
        2 => {
            if *offset_flag != 0 {
                for _ in 0..12 {
                    p.uint()?;
                }
            }
            let pad = p.string()?;
            let scheme = p.uint()?;
            if scheme != 0 {
                p.bytes(4)?;
            }
            parts.push(format!("validation {}", ["none", "CRC32", "checksum32"].get(to_usize(scheme)).copied().unwrap_or("?")));
            let _ = pad;
        }
        3 | 5 | 7 | 9 => parts.push(format!("{:?}", p.string()?)),
        4 | 6 | 8 | 10 => {
            let s = p.string()?;
            parts.push(format!("{s:?} = #{}", p.uint()?));
        }
        11 | 12 => {
            let name = p.string()?;
            let interval = |p: &mut Oasis<'_>| -> Result<String> {
                Ok(match p.uint()? {
                    0 => "any".to_owned(),
                    1 => format!("≤{}", p.uint()?),
                    2 => format!("≥{}", p.uint()?),
                    3 => p.uint()?.to_string(),
                    4 => format!("{}–{}", p.uint()?, p.uint()?),
                    t => return Err(Diagnostic::malformed(format!("interval type {t}"))),
                })
            };
            let l = interval(p)?;
            let t = interval(p)?;
            parts.push(format!("{name:?}: layer {l}, type {t}"));
        }
        13 => parts.push(format!("#{}", p.uint()?)),
        14 => parts.push(format!("{:?}", p.string()?)),
        15 => parts.push("absolute".to_owned()),
        16 => parts.push("relative".to_owned()),
        17 | 18 => {
            let info = p.byte()?;
            if info & 0x80 != 0 {
                parts.push(if info & 0x40 != 0 { format!("cell #{}", p.uint()?) } else { format!("cell {:?}", p.string()?) });
            }
            if id == 18 {
                if info & 0x04 != 0 {
                    parts.push(format!("magnification {}", p.real()?));
                }
                if info & 0x02 != 0 {
                    parts.push(format!("angle {}", p.real()?));
                }
            } else if info & 0x06 != 0 {
                parts.push(format!("angle {}", u32::from((info >> 1) & 3).saturating_mul(90)));
            }
            if info & 0x01 != 0 {
                parts.push("flipped".to_owned());
            }
            if info & 0x20 != 0 {
                parts.push(format!("x={}", p.sint()?));
            }
            if info & 0x10 != 0 {
                parts.push(format!("y={}", p.sint()?));
            }
            if info & 0x08 != 0 {
                parts.push(format!("repetition: {}", p.repetition()?));
            }
        }
        19 => {
            let info = p.byte()?;
            if info & 0x40 != 0 {
                parts.push(if info & 0x20 != 0 { format!("text #{}", p.uint()?) } else { format!("{:?}", p.string()?) });
            }
            if info & 0x01 != 0 {
                parts.push(format!("textlayer {}", p.uint()?));
            }
            if info & 0x02 != 0 {
                parts.push(format!("texttype {}", p.uint()?));
            }
            xy(p, info, &mut parts)?;
        }
        20 => {
            let info = p.byte()?;
            layer(p, info, &mut parts)?;
            if info & 0x40 != 0 {
                parts.push(format!("w={}", p.uint()?));
            }
            if info & 0x20 != 0 && info & 0x80 == 0 {
                parts.push(format!("h={}", p.uint()?));
            }
            if info & 0x80 != 0 {
                parts.push("square".to_owned());
            }
            xy(p, info, &mut parts)?;
        }
        21 => {
            let info = p.byte()?;
            layer(p, info, &mut parts)?;
            if info & 0x20 != 0 {
                parts.push(format!("{} point(s)", p.point_list()?));
            }
            xy(p, info, &mut parts)?;
        }
        22 => {
            let info = p.byte()?;
            layer(p, info, &mut parts)?;
            if info & 0x40 != 0 {
                parts.push(format!("half-width {}", p.uint()?));
            }
            if info & 0x80 != 0 {
                let scheme = p.uint()?;
                if (scheme >> 2) & 3 == 3 {
                    p.sint()?;
                }
                if scheme & 3 == 3 {
                    p.sint()?;
                }
            }
            if info & 0x20 != 0 {
                parts.push(format!("{} point(s)", p.point_list()?));
            }
            xy(p, info, &mut parts)?;
        }
        23..=25 => {
            let info = p.byte()?;
            layer(p, info, &mut parts)?;
            if info & 0x40 != 0 {
                parts.push(format!("w={}", p.uint()?));
            }
            if info & 0x20 != 0 {
                parts.push(format!("h={}", p.uint()?));
            }
            if id == 23 || id == 24 {
                parts.push(format!("Δa={}", p.sint()?));
            }
            if id == 23 || id == 25 {
                parts.push(format!("Δb={}", p.sint()?));
            }
            xy(p, info, &mut parts)?;
        }
        26 => {
            let info = p.byte()?;
            layer(p, info, &mut parts)?;
            if info & 0x80 != 0 {
                parts.push(format!("type {}", p.uint()?));
            }
            if info & 0x40 != 0 {
                parts.push(format!("w={}", p.uint()?));
            }
            if info & 0x20 != 0 {
                parts.push(format!("h={}", p.uint()?));
            }
            xy(p, info, &mut parts)?;
        }
        27 => {
            let info = p.byte()?;
            layer(p, info, &mut parts)?;
            if info & 0x20 != 0 {
                parts.push(format!("r={}", p.uint()?));
            }
            xy(p, info, &mut parts)?;
        }
        28 => {
            let info = p.byte()?;
            if info & 0x04 != 0 {
                parts.push(if info & 0x02 != 0 { format!("name #{}", p.uint()?) } else { format!("{:?}", p.string()?) });
            }
            if info & 0x08 == 0 {
                let mut count = u64::from(info >> 4);
                if count == 15 {
                    count = p.uint()?;
                }
                let mut values = Vec::new();
                for _ in 0..count.min(4096) {
                    values.push(p.property_value()?);
                }
                parts.push(format!("= {}", values.join(", ")));
            }
        }
        29 => parts.push("repeat last".to_owned()),
        30 | 31 => {
            let attr = p.uint()?;
            let s = p.string()?;
            parts.push(format!("attribute {attr}: {s:?}"));
            if id == 31 {
                p.uint()?;
            }
        }
        32 => {
            let attr = p.uint()?;
            parts.push(format!("attribute {attr}: {} bytes", p.string()?.len()));
        }
        33 => {
            let info = p.byte()?;
            let attr = p.uint()?;
            layer(p, info, &mut parts)?;
            parts.push(format!("attribute {attr}: {} bytes", p.string()?.len()));
            xy(p, info, &mut parts)?;
        }
        34 => {
            let method = p.uint()?;
            let raw = p.uint()?;
            let compressed = p.uint()?;
            let at = to_u64(p.pos);
            p.bytes(compressed)?;
            parts.push(format!("{} {compressed} → {raw} bytes", if method == 0 { "deflate" } else { "unknown method" }));
            cblock = Some((at, compressed, raw));
        }
        _ => return Err(Diagnostic::unsupported(format!("record type {id}"))),
    }
    Ok((parts.join(", "), cblock))
}

async fn oasis(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("Magic").span(file.sub(0, 13)).value(text("%SEMI-OASIS")));
    let body = file.tail(13);
    let data = cx.read_avail(body.sub(0, cx.limits().max_read)).await?;
    if to_u64(data.len()) < body.len {
        cx.diag(Diagnostic::limit("only the beginning of the file was parsed"));
    }
    let (summary, version) = oasis_list(&cx, input, body, data).await?;
    cx.annotate(format!("OASIS {version}, {summary}"));
    Ok(())
}

/// Lists the records in `data` (the bytes of `span`); returns a summary.
async fn oasis_list(cx: &Cx, input: Input, span: Span, data: Vec<u8>) -> Result<(String, String)> {
    let mut p = Oasis { data: &data, pos: 0 };
    let mut offset_flag = 1u64;
    let mut counts: Vec<(String, u64)> = Vec::new();
    let mut version = String::new();
    let mut cells = 0u64;
    while p.pos < data.len() {
        let start = p.pos;
        let id = p.uint()?;
        let name = OASIS_RECORDS.get(to_usize(id)).copied().unwrap_or("?");
        match oasis_record(&mut p, id, &mut offset_flag) {
            Ok((desc, cblock)) => {
                let s = span.sub(to_u64(start), to_u64(p.pos.saturating_sub(start)));
                if id == 1 {
                    version = desc.split(',').next().unwrap_or_default().trim_start_matches("version ").to_owned();
                }
                if id == 13 || id == 14 {
                    cells = cells.saturating_add(1);
                }
                tally(&mut counts, name, 64);
                let mut node = Node::new(name).span(s);
                node = summarize(node, desc);
                if let Some((at, compressed, raw)) = cblock {
                    node = node.lazy(crate::expander!(self::oasis_cblock: (Input, Span, u64)), (input, span.sub(at, compressed), raw));
                }
                cx.push(node).await;
                if id == 2 {
                    break;
                }
            }
            Err(e) => {
                cx.push(Node::new(name).span(span.tail(to_u64(start))).diag(e)).await;
                break;
            }
        }
    }
    let top: Vec<String> = counts.iter().filter(|(k, _)| k != "PAD").take(8).map(|(k, n)| format!("{n} {k}")).collect();
    Ok((format!("{cells} cell(s); {}", top.join(", ")), version))
}

async fn oasis_cblock(cx: Cx, (input, span, raw): (Input, Span, u64)) -> Result<()> {
    let decoded = crate::codec::inflate_span(&cx, span, false, Some(raw)).await?;
    if let Some(e) = decoded.error.clone() {
        cx.diag(e);
    }
    let data = cx.read_avail(decoded.span.sub(0, cx.limits().max_read)).await?;
    let _ = oasis_list(&cx, input, decoded.span, data).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Gerber (RS-274X) and Excellon drill files

fn gerber_probe(h: &Head<'_>) -> bool {
    if !is_text(h) {
        return false;
    }
    let first = head_lines(h, 32).into_iter().map(<[u8]>::trim_ascii).find(|l| !l.is_empty() && !l.starts_with(b"G04") && !l.starts_with(b"G4 "));
    first.is_some_and(|l| l.starts_with(b"%FS") || l.starts_with(b"%MO") || l.starts_with(b"%TF.") || l.starts_with(b"%TA.") || l.starts_with(b"%IN") || l.starts_with(b"%LP"))
        && contains(h.data, b"%FS")
}

declare_format!(pub GERBER = "gerber", "Gerber RS-274X PCB image", ["gbr", "ger", "gtl", "gbl", "gts", "gbs", "gto", "gbo", "gko", "gm1"], "application/vnd.gerber",
    Probe::Custom(gerber_probe), gerber);

/// Splits Gerber text into statements: `%...%` extended blocks and `*`-terminated words.
fn gerber_statements(data: &[u8]) -> Vec<(usize, usize, bool)> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < data.len() && out.len() < 1_000_000 {
        let Some(&c) = data.get(i) else { break };
        if c.is_ascii_whitespace() {
            i = i.saturating_add(1);
            continue;
        }
        if c == b'%' {
            let end = data.get(i.saturating_add(1)..).and_then(|r| r.iter().position(|&b| b == b'%')).map_or(data.len(), |p| i.saturating_add(1).saturating_add(p).saturating_add(1));
            out.push((i, end, true));
            i = end;
        } else {
            let end = data.get(i..).and_then(|r| r.iter().position(|&b| b == b'*' || b == b'%')).map_or(data.len(), |p| i.saturating_add(p));
            let end = if data.get(end) == Some(&b'*') { end.saturating_add(1) } else { end };
            out.push((i, end.max(i.saturating_add(1)), false));
            i = end.max(i.saturating_add(1));
        }
    }
    out
}

const GERBER_EXTENDED: &[(&str, &str)] = &[
    ("FS", "Format specification"),
    ("MO", "Unit mode"),
    ("AD", "Aperture definition"),
    ("AM", "Aperture macro"),
    ("AB", "Aperture block"),
    ("LP", "Load polarity"),
    ("LM", "Load mirroring"),
    ("LR", "Load rotation"),
    ("LS", "Load scaling"),
    ("SR", "Step and repeat"),
    ("TF", "File attribute"),
    ("TA", "Aperture attribute"),
    ("TO", "Object attribute"),
    ("TD", "Delete attribute"),
    ("IP", "Image polarity (deprecated)"),
    ("IN", "Image name (deprecated)"),
    ("OF", "Offset (deprecated)"),
];

async fn gerber(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let data = cx.read_avail(file.sub(0, cx.limits().max_read)).await?;
    let statements = gerber_statements(&data);
    let (mut apertures, mut draws, mut moves, mut flashes, mut regions) = (0u32, 0u64, 0u64, 0u64, 0u64);
    let (mut unit, mut function) = (String::new(), String::new());
    for &(s, e, extended) in &statements {
        let raw = String::from_utf8_lossy(data.get(s..e).unwrap_or_default()).into_owned();
        let body = raw.trim_matches(['%', '*']).trim().to_owned();
        let span = file.sub(to_u64(s), to_u64(e.saturating_sub(s)));
        if extended {
            let code = body.get(..2).unwrap_or_default().to_owned();
            match code.as_str() {
                "AD" => apertures = apertures.saturating_add(1),
                "MO" => unit = body.get(2..).unwrap_or_default().to_owned(),
                "TF" if body.starts_with("TF.FileFunction") => function = body.trim_start_matches("TF.FileFunction,").trim_end_matches('*').to_owned(),
                _ => {}
            }
            let desc = GERBER_EXTENDED.iter().find(|(c, _)| *c == code).map_or("Extended command", |(_, d)| d);
            cx.push(Node::new(code).span(span).value(text(preview(body.get(2..).unwrap_or_default().trim_end_matches('*'), 120))).desc(desc)).await;
        } else {
            let word = body.trim_end_matches('*');
            if word.ends_with("D01") || word.ends_with("D1") {
                draws = draws.saturating_add(1);
            } else if word.ends_with("D02") || word.ends_with("D2") {
                moves = moves.saturating_add(1);
            } else if word.ends_with("D03") || word.ends_with("D3") {
                flashes = flashes.saturating_add(1);
            }
            if word == "G36" {
                regions = regions.saturating_add(1);
            }
            let name = if word.starts_with("G04") || word.starts_with("G4 ") {
                "Comment"
            } else if word.starts_with('D') && word.get(1..).is_some_and(|d| d.chars().all(|c| c.is_ascii_digit())) && word.len() > 2 {
                "Select aperture"
            } else if word.starts_with('X') || word.starts_with('Y') || word.starts_with('I') || word.starts_with('J') || word.starts_with('D') {
                "Operation"
            } else if word.starts_with('G') {
                "Mode"
            } else if word.starts_with('M') {
                "End of file"
            } else {
                "Statement"
            };
            cx.push(Node::new(name).span(span).value(text(preview(word, 120)))).await;
        }
    }
    cx.annotate(format!(
        "Gerber X2/RS-274X{}{}, {apertures} aperture(s), {draws} draw(s), {moves} move(s), {flashes} flash(es){}",
        if function.is_empty() { String::new() } else { format!(" ({function})") },
        if unit.is_empty() { String::new() } else { format!(", {unit}") },
        if regions > 0 { format!(", {regions} region(s)") } else { String::new() }
    ));
    Ok(())
}

declare_format!(pub EXCELLON = "excellon", "Excellon drill file", ["drl", "xln", "exc", "ncd", "txt"], "application/x-excellon",
    Probe::Custom(|h| is_text(h) && head_lines(h, 4).iter().find(|l| !l.starts_with(b";")).is_some_and(|l| l.trim_ascii() == b"M48")), excellon);

async fn excellon(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut header_end = 0u64;
    let mut tools: Vec<(String, String, u64, Vec<Line>)> = Vec::new();
    let mut units = String::new();
    // Header: up to "%" or "M95".
    while let Some(line) = lines.next().await? {
        let t = line.text();
        let t = t.trim();
        if t == "%" || t == "M95" {
            header_end = lines.pos();
            break;
        }
        if t.starts_with("METRIC") || t.starts_with("INCH") || t == "M71" || t == "M72" {
            units = t.split(',').next().unwrap_or(t).to_owned();
        }
        if let Some(rest) = t.strip_prefix('T')
            && let Some(c) = rest.find('C')
            && tools.len() < 1000
        {
            let id = format!("T{}", rest.get(..c).unwrap_or_default());
            tools.push((id, rest.get(c.saturating_add(1)..).unwrap_or_default().to_owned(), 0, Vec::new()));
        }
        header_end = lines.pos();
    }
    let header = file.sub(0, header_end);
    cx.emit(Node::new("Header").span(header).lazy(text_lines, header));
    let mut current: Option<usize> = None;
    let mut holes = 0u64;
    while let Some(line) = lines.next().await? {
        let t = line.text();
        let t = t.trim();
        if let Some(rest) = t.strip_prefix('T')
            && rest.chars().all(|c| c.is_ascii_digit())
            && !rest.is_empty()
        {
            let id = format!("T{rest}");
            let normalized = |s: &str| s.trim_start_matches('T').trim_start_matches('0').to_owned();
            current = tools.iter().position(|(t, ..)| normalized(t) == normalized(&id));
            if current.is_none() && rest.trim_start_matches('0').is_empty() {
                continue;
            }
            if current.is_none() && tools.len() < 1000 {
                tools.push((id, "?".to_owned(), 0, Vec::new()));
                current = Some(tools.len().saturating_sub(1));
            }
        } else if (t.starts_with('X') || t.starts_with('Y'))
            && let Some(i) = current
            && let Some((_, _, n, list)) = tools.get_mut(i)
        {
            *n = n.saturating_add(1);
            holes = holes.saturating_add(1);
            if list.len() < 100_000 {
                list.push(line.clone());
            }
        }
    }
    let ntools = tools.len();
    for (id, dia, n, list) in tools {
        cx.push(Node::new(id).value(number(&dia)).summary(format!("{n} hole(s)")).desc("Tool diameter").lazy(drill_hits, list)).await;
    }
    cx.annotate(format!("Excellon drill file{}, {ntools} tool(s), {holes} hole(s)", if units.is_empty() { String::new() } else { format!(" ({units})") }));
    Ok(())
}

async fn drill_hits(cx: Cx, list: Vec<Line>) -> Result<()> {
    for l in list {
        cx.push(Node::new("Hit").span(l.content()).value(text(l.text().trim()))).await;
    }
    Ok(())
}

/// Every line of a region as a node.
async fn text_lines(cx: Cx, span: Span) -> Result<()> {
    let mut lines = Lines::new(&cx, span);
    while let Some(line) = lines.next().await? {
        let t = line.text();
        if !t.trim().is_empty() {
            cx.push(Node::new("Line").span(line.content()).value(text(preview(&t, 200)))).await;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// S-expression design files: KiCad, EDIF, SDF timing

fn sexpr_probe(h: &Head<'_>, heads: &[&[u8]]) -> bool {
    let data = h.data.trim_ascii_start();
    is_text(h) && heads.iter().any(|m| data.starts_with(m) && data.get(m.len()).is_some_and(|b| b.is_ascii_whitespace() || *b == b'(' || *b == b')'))
}

declare_format!(pub KICAD_PCB = "kicad-pcb", "KiCad PCB layout", ["kicad_pcb"], "application/x-kicad-pcb",
    Probe::Custom(|h| sexpr_probe(h, &[b"(kicad_pcb"])), sexpr);
declare_format!(pub KICAD_SCH = "kicad-sch", "KiCad schematic", ["kicad_sch"], "application/x-kicad-schematic",
    Probe::Custom(|h| sexpr_probe(h, &[b"(kicad_sch"])), sexpr);
declare_format!(pub KICAD_SYM = "kicad-sym", "KiCad symbol library", ["kicad_sym"], "application/x-kicad-symbol",
    Probe::Custom(|h| sexpr_probe(h, &[b"(kicad_symbol_lib"])), sexpr);
declare_format!(pub KICAD_MOD = "kicad-mod", "KiCad footprint", ["kicad_mod"], "application/x-kicad-footprint",
    Probe::Custom(|h| sexpr_probe(h, &[b"(footprint", b"(module"]) && contains(h.data.get(..4096).unwrap_or(h.data), b"(layer")), sexpr);
declare_format!(pub EDIF = "edif", "Electronic Design Interchange Format (EDIF)", ["edf", "edif", "edn", "edo"], "application/x-edif",
    Probe::Custom(|h| sexpr_probe(h, &[b"(edif", b"(EDIF"])), sexpr);
declare_format!(pub SDF_TIMING = "sdf-timing", "Standard Delay Format (SDF)", ["sdf"], "application/x-sdf-timing",
    Probe::Custom(|h| sexpr_probe(h, &[b"(DELAYFILE", b"(delayfile"])), sexpr);
declare_format!(pub SAIF = "saif", "Switching Activity Interchange Format (SAIF)", ["saif"], "application/x-saif",
    Probe::Custom(|h| sexpr_probe(h, &[b"(SAIFILE", b"(saifile"])), sexpr);
declare_format!(pub SPECCTRA_DSN = "specctra-dsn", "Specctra design (DSN)", ["dsn"], "application/x-specctra-dsn",
    Probe::Custom(|h| sexpr_probe(h, &[b"(pcb", b"(PCB"]) && contains(h.data.get(..8192).unwrap_or(h.data), b"(structure")), sexpr);
declare_format!(pub SPECCTRA_SES = "specctra-ses", "Specctra session (SES)", ["ses"], "application/x-specctra-ses",
    Probe::Custom(|h| sexpr_probe(h, &[b"(session", b"(SESSION"])), sexpr);

/// The elements of one list: atoms and nested lists (`start`, `end` offsets
/// in `data`, exclusive of the list's parentheses).
fn sexpr_elements(data: &[u8]) -> Vec<(usize, usize, bool)> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while let Some(&c) = data.get(i) {
        if out.len() > 1_000_000 {
            break;
        }
        match c {
            b' ' | b'\t' | b'\r' | b'\n' => i = i.saturating_add(1),
            b'(' => {
                let mut depth = 0u32;
                let mut j = i;
                let mut in_str = false;
                while let Some(&d) = data.get(j) {
                    match d {
                        b'\\' if in_str => j = j.saturating_add(1),
                        // A lone `"` before `)` is an atom (Specctra's string_quote), not a string.
                        b'"' if in_str => in_str = false,
                        b'"' if data.get(j.saturating_add(1)) != Some(&b')') => in_str = true,
                        b'(' if !in_str => depth = depth.saturating_add(1),
                        b')' if !in_str => {
                            depth = depth.saturating_sub(1);
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                    j = j.saturating_add(1);
                }
                let end = j.saturating_add(1).min(data.len());
                out.push((i, end, true));
                i = end;
            }
            b')' => i = i.saturating_add(1),
            b'"' if data.get(i.saturating_add(1)) != Some(&b')') => {
                let mut j = i.saturating_add(1);
                while let Some(&d) = data.get(j) {
                    if d == b'\\' {
                        j = j.saturating_add(2);
                        continue;
                    }
                    if d == b'"' {
                        break;
                    }
                    j = j.saturating_add(1);
                }
                let end = j.saturating_add(1).min(data.len());
                out.push((i, end, false));
                i = end;
            }
            _ => {
                let mut j = i;
                while data.get(j).is_some_and(|d| !d.is_ascii_whitespace() && *d != b'(' && *d != b')') {
                    j = j.saturating_add(1);
                }
                out.push((i, j.max(i.saturating_add(1)), false));
                i = j.max(i.saturating_add(1));
            }
        }
    }
    out
}

fn atom(b: &[u8]) -> String {
    let s = String::from_utf8_lossy(b);
    s.strip_prefix('"').and_then(|t| t.strip_suffix('"')).map_or_else(|| s.clone().into_owned(), str::to_owned)
}

async fn sexpr(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let data = cx.read_avail(file.sub(0, cx.limits().max_read)).await?;
    if to_u64(data.len()) < file.len {
        cx.diag(Diagnostic::limit("only the beginning of the file was parsed"));
    }
    let top = sexpr_elements(&data);
    let Some(&(s, e, true)) = top.first() else {
        return Err(Diagnostic::malformed("expected a list"));
    };
    let root = file.sub(to_u64(s), to_u64(e.saturating_sub(s)));
    let inner = data.get(s.saturating_add(1)..e.saturating_sub(1)).unwrap_or_default();
    let elements = sexpr_elements(inner);
    let head = elements.first().map(|&(a, b, _)| atom(inner.get(a..b).unwrap_or_default())).unwrap_or_default();
    // Summary: count child lists by head, and pick out a few well-known values.
    let mut counts: Vec<(String, u64)> = Vec::new();
    let mut facts: Vec<String> = Vec::new();
    for &(a, b, list) in elements.iter().skip(1) {
        let child = inner.get(a..b).unwrap_or_default();
        if !list {
            continue;
        }
        let kids = sexpr_elements(child.get(1..child.len().saturating_sub(1)).unwrap_or_default());
        let name = kids.first().map(|&(x, y, _)| atom(child.get(1..).and_then(|c| c.get(x..y)).unwrap_or_default())).unwrap_or_default();
        let first_value = kids.get(1).map(|&(x, y, _)| atom(child.get(1..).and_then(|c| c.get(x..y)).unwrap_or_default())).unwrap_or_default();
        if matches!(name.as_str(), "version" | "generator" | "SDFVERSION" | "DESIGN" | "edifVersion" | "TIMESCALE" | "paper" | "SAIFVERSION" | "DURATION" | "resolution") && facts.len() < 6 {
            facts.push(format!("{name} {first_value}"));
        }
        tally(&mut counts, &name, 256);
        cx.checkpoint().await;
    }
    cx.emit(Node::new(format!("({head}")).span(root).summary(format!("{} element(s)", elements.len().saturating_sub(1))).lazy(sexpr_list, (root, 0u32)));
    counts.sort_by_key(|c| std::cmp::Reverse(c.1));
    let top: Vec<String> = counts.iter().take(6).map(|(k, n)| format!("{n} {k}")).collect();
    let kind = match head.as_str() {
        "kicad_pcb" => "KiCad PCB",
        "kicad_sch" => "KiCad schematic",
        "kicad_symbol_lib" => "KiCad symbol library",
        "footprint" | "module" => "KiCad footprint",
        "DELAYFILE" | "delayfile" => "SDF timing",
        "SAIFILE" | "saifile" => "SAIF switching activity",
        "pcb" | "PCB" => "Specctra design",
        "session" | "SESSION" => "Specctra session",
        _ => "EDIF",
    };
    cx.annotate(format!("{kind}{}; {}", if facts.is_empty() { String::new() } else { format!(" ({})", facts.join(", ")) }, top.join(", ")));
    Ok(())
}

async fn sexpr_list(cx: Cx, (span, depth): (Span, u32)) -> Result<()> {
    if depth > 200 {
        return Err(Diagnostic::limit("lists nested too deeply"));
    }
    let data = cx.read_avail(span.sub(0, cx.limits().max_read)).await?;
    let inner = data.get(1..data.len().saturating_sub(1)).unwrap_or_default();
    let mut atoms = 0usize;
    for (i, &(a, b, list)) in sexpr_elements(inner).iter().enumerate() {
        let s = span.sub(to_u64(a).saturating_add(1), to_u64(b.saturating_sub(a)));
        let child = inner.get(a..b).unwrap_or_default();
        if i == 0 && !list {
            continue;
        }
        // The first atoms are already shown as the list's value.
        if !list {
            atoms = atoms.saturating_add(1);
            if atoms <= 6 && depth > 0 {
                continue;
            }
        }
        if list {
            let kids = sexpr_elements(child.get(1..child.len().saturating_sub(1)).unwrap_or_default());
            let body = child.get(1..).unwrap_or_default();
            let name = kids.first().filter(|k| !k.2).map(|&(x, y, _)| atom(body.get(x..y).unwrap_or_default())).unwrap_or_default();
            let atoms: Vec<String> = kids.iter().skip(1).filter(|k| !k.2).take(6).map(|&(x, y, _)| atom(body.get(x..y).unwrap_or_default())).collect();
            let lists = kids.iter().filter(|k| k.2).count();
            let mut node = Node::new(format!("({name}")).span(s);
            if !atoms.is_empty() {
                node = node.value(text(atoms.join(" ")));
            }
            if lists > 0 {
                node = node.summary(format!("{lists} sub-list(s)")).lazy(crate::expander!(self::sexpr_list: (Span, u32)), (s, depth.saturating_add(1)));
            }
            cx.push(node).await;
        } else {
            cx.push(Node::new("atom").span(s).value(text(atom(child)))).await;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Value Change Dump

fn vcd_probe(h: &Head<'_>) -> bool {
    let data = h.data.trim_ascii_start();
    is_text(h)
        && [&b"$date"[..], b"$version", b"$timescale", b"$comment", b"$scope"].iter().any(|k| data.starts_with(k))
        && contains(h.data, b"$end")
}

declare_format!(pub VCD = "vcd", "Value Change Dump (VCD)", ["vcd"], "text/x-vcd",
    Probe::Custom(vcd_probe), vcd);

/// A scope with its variables and nested scopes.
#[derive(Clone, Debug, Default)]
struct VcdScope {
    kind: String,
    name: String,
    vars: Vec<(String, String, String, String)>,
    children: Vec<VcdScope>,
}

async fn vcd(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut tokens: Vec<String> = Vec::new();
    let mut stack: Vec<VcdScope> = vec![VcdScope::default()];
    let mut command: Option<(String, u64)> = None;
    let mut defs_end = None;
    let mut timescale = String::new();
    let mut version = String::new();
    let mut vars = 0u64;
    'outer: while let Some(line) = lines.next().await? {
        for (word, wspan) in line.words() {
            if let Some((cmd, start)) = command.as_ref() {
                if word == "$end" {
                    let body = tokens.join(" ");
                    let span = file.sub(*start, wspan.end().saturating_sub(file.offset).saturating_sub(*start));
                    match cmd.as_str() {
                        "$scope" => {
                            if stack.len() < 256 {
                                stack.push(VcdScope { kind: tokens.first().cloned().unwrap_or_default(), name: tokens.get(1).cloned().unwrap_or_default(), ..VcdScope::default() });
                            }
                        }
                        "$upscope" => {
                            if stack.len() > 1
                                && let Some(done) = stack.pop()
                                && let Some(top) = stack.last_mut()
                            {
                                top.children.push(done);
                            }
                        }
                        "$var" => {
                            vars = vars.saturating_add(1);
                            if let Some(top) = stack.last_mut()
                                && top.vars.len() < 100_000
                            {
                                let g = |i: usize| tokens.get(i).cloned().unwrap_or_default();
                                top.vars.push((g(0), g(1), g(2), tokens.get(3..).map(|t| t.join(" ")).unwrap_or_default()));
                            }
                        }
                        "$enddefinitions" => {
                            cx.emit(Node::new(cmd.clone()).span(span));
                            defs_end = Some(lines.pos());
                            break 'outer;
                        }
                        other => {
                            if other == "$timescale" {
                                timescale.clone_from(&body);
                            }
                            if other == "$version" {
                                version.clone_from(&body);
                            }
                            cx.emit(Node::new(cmd.clone()).span(span).value(text(preview(&body, 200))));
                        }
                    }
                    tokens.clear();
                    command = None;
                } else if tokens.len() < 4096 {
                    tokens.push(word);
                }
            } else if word.starts_with('$') {
                command = Some((word, wspan.offset.saturating_sub(file.offset)));
            }
        }
    }
    while stack.len() > 1 {
        if let Some(done) = stack.pop()
            && let Some(top) = stack.last_mut()
        {
            top.children.push(done);
        }
    }
    let root = stack.pop().unwrap_or_default();
    let scopes = root.children.len();
    cx.emit(Node::new("Scopes").value(uint(to_u64(scopes))).lazy(vcd_scopes, root.children));
    let Some(start) = defs_end else {
        return Err(Diagnostic::malformed("no $enddefinitions"));
    };
    let changes = file.tail(start);
    cx.emit(Node::new("Value changes").span(changes).lazy(vcd_changes, changes));
    // The time range: the first and last timestamps.
    let tail = cx.read_avail(file.sub(file.len.saturating_sub(4096), 4096)).await?;
    let last = String::from_utf8_lossy(&tail).lines().rev().find_map(|l| l.trim().strip_prefix('#').map(str::to_owned)).unwrap_or_default();
    cx.annotate(format!(
        "VCD{}, timescale {}, {vars} variable(s) in {scopes} top scope(s), until #{last}",
        if version.is_empty() { String::new() } else { format!(" ({})", preview(&version, 40)) },
        if timescale.is_empty() { "?".to_owned() } else { timescale }
    ));
    Ok(())
}

async fn vcd_scopes(cx: Cx, scopes: Vec<VcdScope>) -> Result<()> {
    for s in scopes {
        let n = s.vars.len();
        let m = s.children.len();
        cx.push(Node::new(format!("{} {}", s.kind, s.name)).summary(format!("{n} variable(s), {m} scope(s)")).lazy(vcd_scope, s)).await;
    }
    Ok(())
}

async fn vcd_scope(cx: Cx, s: VcdScope) -> Result<()> {
    for (kind, width, id, name) in s.vars {
        cx.push(Node::new(name).value(text(format!("{kind} [{width}]"))).summary(format!("id {id}"))).await;
    }
    for c in s.children {
        let n = c.vars.len();
        let m = c.children.len();
        cx.push(Node::new(format!("{} {}", c.kind, c.name)).summary(format!("{n} variable(s), {m} scope(s)")).lazy(crate::expander!(self::vcd_scope: VcdScope), c)).await;
    }
    Ok(())
}

async fn vcd_changes(cx: Cx, span: Span) -> Result<()> {
    let mut lines = Lines::new(&cx, span);
    let mut current: Option<(String, u64, u64)> = None;
    loop {
        let next = lines.next().await?;
        let starts = next.as_ref().is_none_or(|l| l.bytes.starts_with(b"#"));
        if starts && let Some((time, start, n)) = current.take() {
            let end = next.as_ref().map_or(lines.pos(), |l| l.pos);
            let s = span.sub(start, end.saturating_sub(start));
            cx.push(Node::new(format!("#{time}")).span(s).summary(format!("{n} change(s)")).lazy(text_lines, s)).await;
        }
        let Some(line) = next else { break };
        let t = line.text();
        if let Some(time) = t.trim().strip_prefix('#') {
            current = Some((time.to_owned(), line.pos, 0));
        } else if let Some((_, _, n)) = current.as_mut()
            && !t.trim().is_empty()
            && !t.trim().starts_with('$')
        {
            *n = n.saturating_add(1);
        } else if current.is_none() && !t.trim().is_empty() {
            cx.push(Node::new("Initial").span(line.content()).value(text(preview(&t, 120)))).await;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Touchstone and CITIfile network parameters

fn touchstone_option(l: &[u8]) -> bool {
    let t = String::from_utf8_lossy(l).to_ascii_lowercase();
    let Some(rest) = t.trim().strip_prefix('#') else { return false };
    let words: Vec<&str> = rest.split('!').next().unwrap_or_default().split_whitespace().collect();
    words.iter().all(|w| matches!(*w, "hz" | "khz" | "mhz" | "ghz" | "s" | "y" | "z" | "h" | "g" | "db" | "ma" | "ri" | "r") || w.parse::<f64>().is_ok())
        && words.iter().any(|w| matches!(*w, "s" | "y" | "z" | "h" | "g" | "db" | "ma" | "ri"))
}

fn touchstone_probe(h: &Head<'_>) -> bool {
    is_text(h) && {
        let lines = head_lines(h, 64);
        let first = lines.iter().map(|l| l.trim_ascii()).find(|l| !l.is_empty() && !l.starts_with(b"!"));
        first.is_some_and(|l| touchstone_option(l) || l.eq_ignore_ascii_case(b"[Version] 2.0") || l.eq_ignore_ascii_case(b"[Version] 2.1"))
    }
}

declare_format!(pub TOUCHSTONE = "touchstone", "Touchstone network parameters", ["s1p", "s2p", "s3p", "s4p", "snp", "ts"], "application/x-touchstone",
    Probe::Custom(touchstone_probe), touchstone);

async fn touchstone(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut options = String::new();
    let mut points = 0u64;
    let (mut first, mut last) = (String::new(), String::new());
    let mut values_per_point = 0usize;
    let mut data_start = None;
    while let Some(line) = lines.next().await? {
        let t = line.text();
        let body = t.split('!').next().unwrap_or_default().trim().to_owned();
        if t.trim_start().starts_with('!') {
            cx.push(Node::new("Comment").span(line.content()).value(text(t.trim_start().trim_start_matches('!').trim()))).await;
        } else if body.starts_with('#') {
            options = body.trim_start_matches('#').trim().to_owned();
            cx.push(Node::new("Option line").span(line.content()).value(text(options.clone())).lazy(touchstone_options, (options.clone(), line.content()))).await;
        } else if body.starts_with('[') {
            let (k, v) = body.split_once(']').unwrap_or((body.as_str(), ""));
            cx.push(Node::new(format!("{k}]")).span(line.content()).value(number(v.trim()))).await;
        } else if !body.is_empty() {
            let words = body.split_whitespace().count();
            // Lines with an odd number of values start a new frequency point.
            if words % 2 == 1 {
                points = points.saturating_add(1);
                let f = body.split_whitespace().next().unwrap_or_default().to_owned();
                if first.is_empty() {
                    first.clone_from(&f);
                    values_per_point = words;
                }
                last = f;
            }
            data_start.get_or_insert(line.pos);
        }
    }
    if let Some(start) = data_start {
        let data = file.tail(start);
        cx.emit(Node::new("Network data").span(data).value(uint(points)).lazy(touchstone_points, data));
    }
    let ports = match values_per_point {
        3 => "1-port",
        9 => "2-port",
        _ => "multi-port",
    };
    let unit = options.split_whitespace().next().unwrap_or("GHz").to_owned();
    cx.annotate(format!("Touchstone {ports} ({options}), {points} frequency point(s), {first}–{last} {unit}"));
    Ok(())
}

async fn touchstone_options(cx: Cx, (options, span): (String, Span)) -> Result<()> {
    let mut words = options.split_whitespace();
    let names = ["Frequency unit", "Parameter", "Format", "R", "Reference impedance (Ω)"];
    for name in names {
        let Some(w) = words.next() else { break };
        let v = match w.to_ascii_lowercase().as_str() {
            "db" => "dB/angle".to_owned(),
            "ma" => "magnitude/angle".to_owned(),
            "ri" => "real/imaginary".to_owned(),
            _ => w.to_owned(),
        };
        if name != "R" {
            cx.emit(Node::new(name).span(span).value(number(&v)));
        }
    }
    Ok(())
}

async fn touchstone_points(cx: Cx, span: Span) -> Result<()> {
    let mut lines = Lines::new(&cx, span);
    while let Some(line) = lines.next().await? {
        let t = line.text();
        let body = t.split('!').next().unwrap_or_default().trim().to_owned();
        if body.is_empty() || body.starts_with('[') || body.starts_with('#') {
            continue;
        }
        let mut words = body.split_whitespace();
        let f = words.next().unwrap_or_default().to_owned();
        let rest: Vec<&str> = words.collect();
        cx.push(Node::new(f).span(line.content()).value(text(rest.join(" ")))).await;
    }
    Ok(())
}

declare_format!(pub CITI = "citifile", "CITIfile network data", ["cti", "citi"], "application/x-citifile",
    Probe::Custom(|h| h.starts_with(b"CITIFILE ")), citi);

async fn citi(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut block: Option<(String, u64, u64)> = None;
    let (mut name, mut vars, mut datas) = (String::new(), Vec::new(), Vec::new());
    let mut blocks = 0usize;
    while let Some(line) = lines.next().await? {
        let t = line.text();
        let t = t.trim();
        if let Some((kind, start, n)) = block.as_mut() {
            if t.starts_with("END") || t.ends_with("_END") {
                let s = file.sub(*start, lines.pos().saturating_sub(*start));
                cx.push(Node::new(kind.clone()).span(s).summary(format!("{n} value(s)"))).await;
                block = None;
            } else {
                *n = n.saturating_add(1);
            }
            continue;
        }
        let (k, v) = t.split_once(char::is_whitespace).unwrap_or((t, ""));
        match k {
            "BEGIN" | "SEG_LIST_BEGIN" | "VAR_LIST_BEGIN" => {
                let label = if k == "BEGIN" { datas.get(blocks).map_or_else(|| format!("Data {blocks}"), |d: &String| format!("Data {d}")) } else { k.to_owned() };
                if k == "BEGIN" {
                    blocks = blocks.saturating_add(1);
                }
                block = Some((label, line.pos, 0));
                continue;
            }
            "NAME" => name = v.trim().to_owned(),
            "VAR" => vars.push(v.trim().to_owned()),
            "DATA" => datas.push(v.trim().to_owned()),
            _ => {}
        }
        if !t.is_empty() {
            cx.push(Node::new(k.to_owned()).span(line.content()).value(text(v.trim()))).await;
        }
    }
    cx.annotate(format!("CITIfile {name}, variable(s) {}, data {}", vars.join("; "), preview(&datas.join(", "), 80)));
    Ok(())
}

// ---------------------------------------------------------------------------
// SPICE raw output (ngspice ASCII header, LTspice UTF-16 header)

declare_format!(pub SPICE_RAW = "spice-raw", "SPICE simulation output (raw)", ["raw"], "application/x-spice-raw",
    Probe::Custom(|h| (h.starts_with(b"Title:") && contains(h.data.get(..2048).unwrap_or(h.data), b"\nPlotname:")) || (h.starts_with(b"T\0i\0t\0l\0e\0:\0") && contains(h.data.get(..4096).unwrap_or(h.data), b"P\0l\0o\0t\0n\0a\0m\0e\0"))), spice_raw);

async fn spice_raw(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 0x10000)).await?;
    let utf16 = head.get(1) == Some(&0);
    // The header ends with "Binary:\n" or "Values:\n".
    let (header_text, header_len) = if utf16 {
        let s = crate::text::utf16(&head, Endian::Little);
        let end = s.find("Binary:\n").map(|p| p.saturating_add(8)).or_else(|| s.find("Values:\n").map(|p| p.saturating_add(8))).unwrap_or(s.len());
        let text = s.get(..end).unwrap_or_default().to_owned();
        let bytes = to_u64(text.encode_utf16().count()).saturating_mul(2);
        (text, bytes)
    } else {
        let s = String::from_utf8_lossy(&head).into_owned();
        let end = s.find("Binary:\n").map(|p| p.saturating_add(8)).or_else(|| s.find("Values:\n").map(|p| p.saturating_add(8))).unwrap_or(s.len());
        let text = s.get(..end).unwrap_or_default().to_owned();
        let n = to_u64(text.len());
        (text, n)
    };
    let get = |k: &str| header_text.lines().find_map(|l| l.strip_prefix(k)).map(|v| v.trim().to_owned()).unwrap_or_default();
    let mut variables = Vec::new();
    let mut in_vars = false;
    for l in header_text.lines() {
        if l.starts_with("Variables:") {
            in_vars = true;
            continue;
        }
        if in_vars {
            if !l.starts_with(['\t', ' ']) {
                in_vars = false;
            } else if variables.len() < 4096 {
                let w: Vec<&str> = l.split_whitespace().collect();
                variables.push((w.get(1).copied().unwrap_or_default().to_owned(), w.get(2).copied().unwrap_or_default().to_owned()));
            }
        }
        if !in_vars
            && let Some((k, v)) = l.split_once(':')
            && !k.is_empty()
            && !v.trim().is_empty()
        {
            let node = Node::new(k.trim().to_owned()).value(number(v.trim()));
            // Header lines are ASCII (or UTF-16) text; locate them for the span.
            let at = header_text.find(l).map(to_u64).unwrap_or(0);
            let (at, len) = if utf16 { (at.saturating_mul(2), to_u64(l.len()).saturating_mul(2)) } else { (at, to_u64(l.len())) };
            cx.emit(node.span(file.sub(at, len)));
        }
    }
    let nvars = variables.len();
    cx.emit(Node::new("Variables").value(uint(to_u64(nvars))).lazy(spice_vars, variables.clone()));
    cx.emit(Node::new("Header").span(file.sub(0, header_len)));
    let flags = get("Flags:");
    let points: u64 = get("No. Points:").parse().unwrap_or(0);
    let binary = header_text.ends_with("Binary:\n");
    let complex = flags.contains("complex");
    // LTspice stores the time axis as double and the rest as single precision.
    let point_size = if !binary {
        0
    } else if complex {
        to_u64(nvars).saturating_mul(16)
    } else if utf16 && !flags.contains("double") {
        8u64.saturating_add(to_u64(nvars.saturating_sub(1)).saturating_mul(4))
    } else {
        to_u64(nvars).saturating_mul(8)
    };
    let data = file.tail(header_len);
    let mut node = Node::new("Data").span(data).summary(format!("{points} point(s), {}", if binary { "binary" } else { "ASCII" }));
    if point_size > 0 {
        node = node.lazy(spice_points, (data, point_size, variables.clone(), complex, utf16 && !flags.contains("double")));
    }
    cx.emit(node);
    let names: Vec<&str> = variables.iter().map(|(n, _)| n.as_str()).collect();
    cx.annotate(format!("{} raw file: {} \"{}\", {nvars} variable(s) ({}), {points} point(s)", if utf16 { "LTspice" } else { "SPICE" }, get("Plotname:"), get("Title:"), preview(&names.join(", "), 80)));
    Ok(())
}

async fn spice_vars(cx: Cx, vars: Vec<(String, String)>) -> Result<()> {
    for (i, (name, kind)) in vars.into_iter().enumerate() {
        cx.push(Node::new(name).value(text(kind)).summary(format!("index {i}"))).await;
    }
    Ok(())
}

async fn spice_points(cx: Cx, (data, size, vars, complex, mixed): (Span, u64, Vec<(String, String)>, bool, bool)) -> Result<()> {
    let count = data.len.checked_div(size).unwrap_or(0);
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let s = data.sub(i.saturating_mul(size), size);
        let b = cx.read(s).await?;
        let mut values = Vec::new();
        let mut at = 0usize;
        for (j, (name, _)) in vars.iter().enumerate().take(8) {
            let v = if complex {
                let re = f64::from_le_bytes(crate::bytes::array(&b, at).unwrap_or_default());
                let im = f64::from_le_bytes(crate::bytes::array(&b, at.saturating_add(8)).unwrap_or_default());
                at = at.saturating_add(16);
                format!("{re}{im:+}j")
            } else if mixed && j > 0 {
                let v = f32::from_le_bytes(crate::bytes::array(&b, at).unwrap_or_default());
                at = at.saturating_add(4);
                v.to_string()
            } else {
                let v = f64::from_le_bytes(crate::bytes::array(&b, at).unwrap_or_default());
                at = at.saturating_add(8);
                if mixed { v.abs().to_string() } else { v.to_string() }
            };
            values.push(format!("{name}={v}"));
        }
        cx.push(Node::new(format!("Point {i}")).span(s).value(text(values.join(" ")))).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// IBIS models and SPEF parasitics

declare_format!(pub IBIS = "ibis", "I/O Buffer Information Specification (IBIS)", ["ibs", "ibis", "pkg", "ebd"], "text/x-ibis",
    Probe::Custom(|h| is_text(h) && head_lines(h, 32).iter().find(|l| !l.starts_with(b"|") && !l.trim_ascii().is_empty()).is_some_and(|l| l.len() >= 10 && l.get(..10).is_some_and(|k| k.eq_ignore_ascii_case(b"[IBIS Ver]")))), ibis);

async fn ibis(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut current: Option<(String, String, u64, u64)> = None;
    let (mut version, mut components, mut models) = (String::new(), Vec::new(), 0u64);
    loop {
        let next = lines.next().await?;
        let starts = next.as_ref().is_none_or(|l| l.bytes.starts_with(b"["));
        if starts && let Some((key, value, start, n)) = current.take() {
            let end = next.as_ref().map_or(lines.pos(), |l| l.pos);
            let s = file.sub(start, end.saturating_sub(start));
            let node = Node::new(key).span(s).value(text(value));
            cx.push(if n > 0 { node.summary(format!("{n} line(s)")).lazy(text_lines, s) } else { node }).await;
        }
        let Some(line) = next else { break };
        if starts {
            let t = line.text();
            let (k, v) = t.split_once(']').unwrap_or((t.as_str(), ""));
            let key = format!("{k}]");
            let value = v.split('|').next().unwrap_or_default().trim().to_owned();
            match key.to_ascii_lowercase().as_str() {
                "[ibis ver]" => version.clone_from(&value),
                "[component]" if components.len() < 32 => components.push(value.clone()),
                "[model]" => models = models.saturating_add(1),
                _ => {}
            }
            if key.eq_ignore_ascii_case("[End]") {
                cx.push(Node::new(key).span(line.content())).await;
                break;
            }
            current = Some((key, value, line.pos, 0));
        } else if let Some((_, _, _, n)) = current.as_mut()
            && !line.bytes.starts_with(b"|")
            && !line.bytes.trim_ascii().is_empty()
        {
            *n = n.saturating_add(1);
        }
    }
    cx.annotate(format!("IBIS {version}, component(s) {}, {models} model(s)", components.join(", ")));
    Ok(())
}

declare_format!(pub SPEF = "spef", "Standard Parasitic Exchange Format (SPEF)", ["spef"], "text/x-spef",
    Probe::Magic(&[(0, b"*SPEF")]), spef);

async fn spef(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    // The open net: name, capacitance, start, and its sections with line counts.
    type Net = (String, String, u64, Vec<(String, u64)>);
    let mut net: Option<Net> = None;
    let (mut design, mut nets, mut names) = (String::new(), 0u64, 0u64);
    let mut section = String::new();
    while let Some(line) = lines.next().await? {
        let t = line.text();
        let t = t.trim();
        if let Some((name, cap, start, sections)) = net.as_mut() {
            if t == "*END" {
                let s = file.sub(*start, lines.pos().saturating_sub(*start));
                let parts: Vec<String> = sections.iter().map(|(k, n)| format!("{n} {}", k.trim_start_matches('*'))).collect();
                cx.push(Node::new(std::mem::take(name)).span(s).value(number(cap)).summary(parts.join(", ")).lazy(text_lines, s)).await;
                net = None;
                nets = nets.saturating_add(1);
            } else if matches!(t, "*CONN" | "*CAP" | "*RES" | "*INDUC") {
                sections.push((t.to_owned(), 0));
            } else if let Some((_, n)) = sections.last_mut()
                && !t.is_empty()
            {
                *n = n.saturating_add(1);
            }
            continue;
        }
        if t.starts_with("*D_NET") || t.starts_with("*R_NET") {
            let w: Vec<&str> = t.split_whitespace().collect();
            net = Some((w.get(1).copied().unwrap_or_default().to_owned(), w.get(2).copied().unwrap_or_default().to_owned(), line.pos, Vec::new()));
            continue;
        }
        if t.starts_with('*') && !t.starts_with("*SPEF") && t.split_whitespace().count() > 1 && !t.chars().nth(1).is_some_and(|c| c.is_ascii_digit()) {
            let (k, v) = t.split_once(char::is_whitespace).unwrap_or((t, ""));
            if k == "*DESIGN" {
                design = v.trim().trim_matches('"').to_owned();
            }
            cx.push(Node::new(k.to_owned()).span(line.content()).value(text(v.trim().trim_matches('"')))).await;
            section.clear();
        } else if t.starts_with('*') && t.chars().nth(1).is_some_and(|c| c.is_ascii_digit()) && section == "*NAME_MAP" {
            names = names.saturating_add(1);
        } else if t.starts_with('*') {
            section = t.to_owned();
            if t != "*NAME_MAP" {
                cx.push(Node::new(t.to_owned()).span(line.content())).await;
            }
        }
    }
    cx.annotate(format!("SPEF for {design:?}, {names} name map entr(ies), {nets} net(s)"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Xilinx bitstreams and JEDEC fuse maps

declare_format!(pub XILINX_BIT = "xilinx-bit", "Xilinx FPGA bitstream (.bit)", ["bit"], "application/x-xilinx-bit",
    Probe::Magic(&[(0, b"\x00\x09\x0f\xf0\x0f\xf0\x0f\xf0\x0f\xf0\x00\x00\x01\x61")]), xilinx_bit);

const XILINX_REGISTERS: EnumTable = &[
    (0, "CRC"),
    (1, "FAR"),
    (2, "FDRI"),
    (3, "FDRO"),
    (4, "CMD"),
    (5, "CTL0"),
    (6, "MASK"),
    (7, "STAT"),
    (8, "LOUT"),
    (9, "COR0"),
    (10, "MFWR"),
    (11, "CBC"),
    (12, "IDCODE"),
    (13, "AXSS"),
    (14, "COR1"),
    (16, "WBSTAR"),
    (17, "TIMER"),
    (22, "BOOTSTS"),
    (24, "CTL1"),
    (31, "BSPI"),
];

const XILINX_COMMANDS: EnumTable = &[
    (0, "NULL"),
    (1, "WCFG"),
    (2, "MFW"),
    (3, "LFRM / DGHIGH"),
    (4, "RCFG"),
    (5, "START"),
    (6, "RCAP"),
    (7, "RCRC"),
    (8, "AGHIGH"),
    (9, "SWITCH"),
    (10, "GRESTORE"),
    (11, "SHUTDOWN"),
    (12, "GCAPTURE"),
    (13, "DESYNC"),
    (15, "IPROG"),
    (16, "CRCC"),
    (17, "LTIMER"),
];

async fn xilinx_bit(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, BE);
    let start = cur.pos();
    cur.skip(13);
    cx.emit(Node::new("Header magic").span(cur.since(start)));
    let mut fields = Vec::new();
    let mut data = None;
    while cur.remaining() >= 3 {
        let at = cur.pos();
        let key = cur.u8().await?;
        if key == b'e' {
            let len = cur.u32().await?;
            cx.emit(Node::new("e: Bitstream length").span(cur.since(at)).value(uint(len.into())));
            data = Some(cur.span(len.into()));
            break;
        }
        let len = cur.u16().await?;
        let value = crate::text::until_nul(&cur.bytes(len.into()).await?);
        let name = match key {
            b'a' => "a: Design name",
            b'b' => "b: Part",
            b'c' => "c: Date",
            b'd' => "d: Time",
            _ => "Field",
        };
        cx.emit(Node::new(name).span(cur.since(at)).value(text(value.clone())));
        fields.push(value);
        if fields.len() > 16 {
            break;
        }
    }
    let mut idcode = None;
    if let Some(d) = data {
        idcode = xilinx_idcode(&cx, d).await.ok().flatten();
        cx.emit(Node::new("Configuration data").span(d).lazy(xilinx_packets, d));
    }
    let g = |i: usize| fields.get(i).map_or("", String::as_str);
    let design = g(0).split(';').next().unwrap_or_default().to_owned();
    cx.annotate(format!(
        "Xilinx bitstream for {} ({design}), {} {}{}",
        g(1),
        g(2),
        g(3),
        idcode.map(|i| format!(", IDCODE {i:#010x}")).unwrap_or_default()
    ));
    Ok(())
}

/// Finds the sync word and the IDCODE write in the first configuration packets.
async fn xilinx_idcode(cx: &Cx, data: Span) -> Result<Option<u32>> {
    let head = cx.read_avail(data.sub(0, 4096)).await?;
    let Some(sync) = head.windows(4).position(|w| w == b"\xaa\x99\x55\x66") else { return Ok(None) };
    let mut at = sync.saturating_add(4);
    while let Some(word) = u32_be(&head, at) {
        at = at.saturating_add(4);
        if word >> 29 == 1 {
            let reg = (word >> 13) & 0x1f;
            let count = to_usize((word & 0x7ff).into());
            if reg == 12 && count == 1 && (word >> 27) & 3 == 2 {
                return Ok(u32_be(&head, at));
            }
            at = at.saturating_add(count.saturating_mul(4));
        }
    }
    Ok(None)
}

async fn xilinx_packets(cx: Cx, data: Span) -> Result<()> {
    let head = cx.read_avail(data.sub(0, 4096)).await?;
    let Some(sync) = head.windows(4).position(|w| w == b"\xaa\x99\x55\x66") else {
        return Err(Diagnostic::malformed("no sync word"));
    };
    cx.emit(Node::new("Dummy/bus width words").span(data.sub(0, to_u64(sync))));
    cx.emit(Node::new("Sync word").span(data.sub(to_u64(sync), 4)).value(hex(0xaa99_5566, 32)));
    let mut cur = Cursor::new(&cx, data, BE);
    cur.seek(to_u64(sync).saturating_add(4));
    let mut noops = 0u64;
    let mut last_reg = 0u32;
    while cur.remaining() >= 4 {
        let start = cur.pos();
        let word = cur.u32().await?;
        let kind = word >> 29;
        let op = (word >> 27) & 3;
        let opname = ["NOOP", "read", "write", "reserved"].get(to_usize(op.into())).copied().unwrap_or("?");
        if kind == 1 && op == 0 {
            noops = noops.saturating_add(1);
            continue;
        }
        let (reg, count) = match kind {
            1 => ((word >> 13) & 0x1f, u64::from(word & 0x7ff)),
            2 => (last_reg, u64::from(word & 0x07ff_ffff)),
            _ => {
                cx.push(Node::new("Data word").span(cur.since(start)).value(hex(word.into(), 32))).await;
                continue;
            }
        };
        last_reg = reg;
        let payload = cur.span(count.saturating_mul(4));
        let first = cx.read_avail(payload.sub(0, 4)).await?;
        cur.skip(payload.len);
        let regname = lookup(XILINX_REGISTERS, reg.into()).unwrap_or("?");
        let mut node = Node::new(format!("Type {kind} {opname} {regname}")).span(cur.since(start)).value(uint(count)).desc("Word count");
        if count == 1 {
            let v = u32_be(&first, 0).unwrap_or(0);
            node = node.summary(if reg == 4 { lookup(XILINX_COMMANDS, v.into()).unwrap_or("?").to_owned() } else { format!("{v:#010x}") });
        } else if count > 1 {
            node = node.summary(format!("{} bytes", payload.len));
        }
        cx.push(node).await;
    }
    if noops > 0 {
        cx.emit(Node::new("NOOPs").value(uint(noops)));
    }
    Ok(())
}

declare_format!(pub JEDEC = "jedec", "JEDEC fuse map (PLD programming file)", ["jed"], "application/x-jedec",
    Probe::Custom(|h| h.starts_with(b"\x02") && contains(h.data.get(..8192).unwrap_or(h.data), b"*QF") || (h.starts_with(b"\x02") && contains(h.data.get(..8192).unwrap_or(h.data), b"\nQF"))), jedec);

async fn jedec(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let data = cx.read_avail(file.sub(0, cx.limits().max_read)).await?;
    let etx = data.iter().position(|&b| b == 0x03).unwrap_or(data.len());
    let body = data.get(1..etx).unwrap_or_default();
    let mut at = 1usize;
    let (mut fuses, mut pins, mut device, mut lfields, mut vectors) = (String::new(), String::new(), String::new(), 0u64, 0u64);
    for (i, field) in body.split(|&b| b == b'*').enumerate() {
        let len = field.len();
        let t = String::from_utf8_lossy(field).trim().to_owned();
        let span = file.sub(to_u64(at), to_u64(len));
        at = at.saturating_add(len).saturating_add(1);
        if t.is_empty() {
            continue;
        }
        if i == 0 {
            cx.push(Node::new("Design specification").span(span).value(text(preview(&t, 200)))).await;
            continue;
        }
        let (code, name) = match t.get(..2).unwrap_or_default() {
            "QF" => ("QF", "Fuse count"),
            "QP" => ("QP", "Pin count"),
            "QV" => ("QV", "Test vector count"),
            _ => match t.chars().next() {
                Some('N') => ("N", "Note"),
                Some('F') => ("F", "Default fuse state"),
                Some('L') => ("L", "Fuse list"),
                Some('C') => ("C", "Fuse checksum"),
                Some('G') => ("G", "Security fuse"),
                Some('J') => ("J", "Device identification"),
                Some('V') => ("V", "Test vector"),
                Some('X') => ("X", "Default test condition"),
                Some('E') => ("E", "Electrical fuse data"),
                Some('U') => ("U", "User data"),
                Some('D') => ("D", "Device (obsolete)"),
                Some('P') => ("P", "Pin list"),
                _ => ("?", "Field"),
            },
        };
        let value = t.get(code.len()..).unwrap_or_default().trim().to_owned();
        match code {
            "QF" => fuses.clone_from(&value),
            "QP" => pins.clone_from(&value),
            "N" if value.starts_with("DEVICE") && device.is_empty() => device = value.trim_start_matches("DEVICE").trim().to_owned(),
            "L" => lfields = lfields.saturating_add(1),
            "V" => vectors = vectors.saturating_add(1),
            _ => {}
        }
        let shown = if matches!(code, "QF" | "QP" | "QV") {
            cx.push(Node::new(name).span(span).value(number(&value))).await;
            continue;
        } else if code == "L" {
            let (addr, bits) = value.split_once(char::is_whitespace).unwrap_or((value.as_str(), ""));
            let bits: String = bits.chars().filter(|c| *c == '0' || *c == '1').collect();
            format!("@{addr}: {} fuse(s) {}", bits.len(), preview(&bits, 64))
        } else {
            preview(&value, 200)
        };
        cx.push(Node::new(name).span(span).value(text(shown))).await;
    }
    if etx < data.len() {
        let cs = String::from_utf8_lossy(data.get(etx.saturating_add(1)..etx.saturating_add(5)).unwrap_or_default()).into_owned();
        cx.emit(Node::new("Transmission checksum").span(file.sub(to_u64(etx).saturating_add(1), 4)).value(text(cs)));
    }
    cx.annotate(format!("JEDEC fuse map{}, {fuses} fuse(s), {pins} pin(s), {lfields} fuse list field(s){}", if device.is_empty() { String::new() } else { format!(" for {device}") }, if vectors > 0 { format!(", {vectors} test vector(s)") } else { String::new() }));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gds_reals() {
        // 1e-3 and 1e-9 as written by layout tools.
        assert!((gds_real8(&[0x3e, 0x41, 0x89, 0x37, 0x4b, 0xc6, 0xa7, 0xef]) - 1e-3).abs() < 1e-12);
        assert!((gds_real8(&[0x39, 0x44, 0xb8, 0x2f, 0xa0, 0x9b, 0x5a, 0x53]) - 1e-9).abs() < 1e-18);
        assert_eq!(year(98), 1998);
    }

    #[test]
    fn oasis_numbers() {
        let mut p = Oasis { data: &[0x05, 0x81, 0x01, 0x04, 0x03, 0x02], pos: 0 };
        assert_eq!(p.sint().unwrap_or(0), -2);
        assert_eq!(p.uint().unwrap_or(0), 129);
        assert!((p.real().unwrap_or(0.0) - 1.5).abs() < 1e-12);
    }

    #[test]
    fn sexpr_split() {
        let e = sexpr_elements(b"kicad_pcb (version 2021) \"a (b\" x");
        assert_eq!(e.len(), 4);
        assert_eq!(atom(b"\"q\""), "q");
        assert!(touchstone_option(b"# GHz S MA R 50"));
        assert!(!touchstone_option(b"# include <stdio.h>"));
    }

    #[test]
    fn gerber_split() {
        let s = gerber_statements(b"%FSLAX26Y26*%\n%MOMM*%\nD10*\nX0Y0D02*\nM02*\n");
        assert_eq!(s.len(), 5);
    }
}
