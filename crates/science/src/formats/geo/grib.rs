//! GRIB (WMO FM 92) gridded meteorological data, editions 1 and 2.
//!
//! A GRIB file is a sequence of self-delimiting messages, each starting with
//! `GRIB` and ending with `7777`. Edition 1 messages have a 24-bit length
//! and four sections (product definition, optional grid description,
//! optional bit-map, binary data). Edition 2 messages have a 64-bit length
//! and numbered sections 1–7, where 2–7 (or 3–7, 4–7) may repeat for
//! several fields sharing one identification.
//!
//! Layouts and code tables (WMO Manual on Codes, GRIB1 tables 2–5 and GRIB2
//! tables 0.0, 1.x, 3.x, 4.x, 5.x) are from memory, for the common entries
//! only; unknown codes are shown raw. Grid templates 3.0/3.1/3.40, product
//! templates 4.0/4.1/4.8/4.11 and data representation templates 5.0 and 5.4
//! (and the 5.x prefixes they share) are decoded field by field; values
//! are decoded for simple packing and IEEE floats. The fixtures written by
//! ecCodes agree with every value shown.

use crate::bytes::{to_u64, u32_be, u64_be};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::Input;
use crate::formats::science::numarray::num;
use crate::formats::util::floats::ibm;
use crate::formats::util::val::uint;
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, Value, lookup};

const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// Code tables

const DISCIPLINES: EnumTable = &[
    (0, "meteorological"),
    (1, "hydrological"),
    (2, "land surface"),
    (3, "satellite remote sensing"),
    (4, "space weather"),
    (10, "oceanographic"),
];

/// Originating centres (WMO Common Code Table C-11), shared with BUFR.
pub(super) const CENTRES: EnumTable = &[
    (7, "US NCEP"),
    (34, "Japan JMA"),
    (54, "Canada CMC"),
    (74, "UK Met Office"),
    (78, "Germany DWD"),
    (85, "Météo-France"),
    (98, "ECMWF"),
];

const REF_SIGNIFICANCE: EnumTable = &[
    (0, "analysis"),
    (1, "start of forecast"),
    (2, "verifying time of forecast"),
    (3, "observation time"),
];

const PRODUCTION_STATUS: EnumTable = &[
    (0, "operational"),
    (1, "operational test"),
    (2, "research"),
    (3, "re-analysis"),
];

const DATA_TYPES: EnumTable = &[
    (0, "analysis"),
    (1, "forecast"),
    (2, "analysis and forecast"),
    (3, "control forecast"),
    (4, "perturbed forecast"),
    (5, "control and perturbed forecast"),
    (6, "processed satellite observations"),
    (7, "processed radar observations"),
    (8, "event probability"),
];

const GRID_TEMPLATES: EnumTable = &[
    (0, "latitude/longitude"),
    (1, "rotated latitude/longitude"),
    (10, "Mercator"),
    (20, "polar stereographic"),
    (30, "Lambert conformal"),
    (40, "Gaussian latitude/longitude"),
    (41, "rotated Gaussian latitude/longitude"),
    (50, "spherical harmonic coefficients"),
    (90, "space view perspective"),
    (101, "general unstructured grid"),
];

const EARTH_SHAPES: EnumTable = &[
    (0, "sphere, radius 6 367 470 m"),
    (1, "sphere, radius given"),
    (2, "oblate spheroid, IAU 1965"),
    (3, "oblate spheroid, axes given (km)"),
    (4, "oblate spheroid, IAG-GRS80"),
    (5, "WGS 84"),
    (6, "sphere, radius 6 371 229 m"),
    (7, "oblate spheroid, axes given (m)"),
    (8, "sphere, radius 6 371 200 m"),
    (9, "OSGB 1936"),
];

const PRODUCT_TEMPLATES: EnumTable = &[
    (0, "analysis or forecast at a point in time"),
    (1, "individual ensemble forecast"),
    (2, "derived ensemble forecast"),
    (8, "statistically processed over a time interval"),
    (11, "individual ensemble forecast, statistically processed"),
];

const GENERATING_PROCESSES: EnumTable = &[
    (0, "analysis"),
    (1, "initialization"),
    (2, "forecast"),
    (3, "bias corrected forecast"),
    (4, "ensemble forecast"),
    (5, "probability forecast"),
    (6, "forecast error"),
    (7, "analysis error"),
    (8, "observation"),
];

const TIME_UNITS: EnumTable = &[
    (0, "minute"),
    (1, "hour"),
    (2, "day"),
    (3, "month"),
    (4, "year"),
    (5, "decade"),
    (6, "normal (30 years)"),
    (7, "century"),
    (10, "3 hours"),
    (11, "6 hours"),
    (12, "12 hours"),
    (13, "second"),
];

const SURFACES: EnumTable = &[
    (1, "ground or water surface"),
    (2, "cloud base"),
    (3, "cloud top"),
    (4, "0 °C isotherm"),
    (6, "maximum wind level"),
    (7, "tropopause"),
    (8, "nominal top of atmosphere"),
    (10, "entire atmosphere"),
    (100, "isobaric surface"),
    (101, "mean sea level"),
    (102, "altitude above mean sea level"),
    (103, "height above ground"),
    (104, "sigma level"),
    (105, "hybrid level"),
    (106, "depth below land surface"),
    (107, "isentropic level"),
    (108, "pressure difference from ground"),
    (109, "potential vorticity surface"),
    (111, "eta level"),
    (160, "depth below sea level"),
    (255, "missing"),
];

const STATISTICS: EnumTable = &[
    (0, "average"),
    (1, "accumulation"),
    (2, "maximum"),
    (3, "minimum"),
    (4, "difference (end − start)"),
    (5, "root mean square"),
    (6, "standard deviation"),
    (7, "covariance"),
    (8, "difference (start − end)"),
    (9, "ratio"),
];

const DATA_TEMPLATES: EnumTable = &[
    (0, "grid point, simple packing"),
    (2, "grid point, complex packing"),
    (3, "grid point, complex packing and spatial differencing"),
    (4, "grid point, IEEE floating point"),
    (40, "grid point, JPEG 2000"),
    (41, "grid point, PNG"),
    (42, "grid point, CCSDS"),
    (50, "spectral, simple packing"),
    (51, "spectral, complex packing"),
    (
        61,
        "grid point, simple packing with logarithm pre-processing",
    ),
    (200, "run length packing with level values"),
];

const BITMAP_INDICATORS: EnumTable = &[
    (0, "bit-map follows"),
    (254, "previously defined bit-map"),
    (255, "no bit-map"),
];

const CATEGORIES_0: EnumTable = &[
    (0, "temperature"),
    (1, "moisture"),
    (2, "momentum"),
    (3, "mass"),
    (4, "short-wave radiation"),
    (5, "long-wave radiation"),
    (6, "cloud"),
    (7, "thermodynamic stability indices"),
    (13, "aerosols"),
    (14, "trace gases"),
    (15, "radar"),
    (16, "forecast radar imagery"),
    (17, "electrodynamics"),
    (18, "nuclear/radiology"),
    (19, "physical atmospheric properties"),
    (190, "CCITT IA5 string"),
    (191, "miscellaneous"),
];

/// GRIB2 parameter names (code table 4.2) for common parameters.
fn parameter2(discipline: u8, category: u8, number: u8) -> Option<&'static str> {
    Some(match (discipline, category, number) {
        (0, 0, 0) => "Temperature",
        (0, 0, 1) => "Virtual temperature",
        (0, 0, 2) => "Potential temperature",
        (0, 0, 4) => "Maximum temperature",
        (0, 0, 5) => "Minimum temperature",
        (0, 0, 6) => "Dew point temperature",
        (0, 0, 7) => "Dew point depression",
        (0, 0, 17) => "Skin temperature",
        (0, 1, 0) => "Specific humidity",
        (0, 1, 1) => "Relative humidity",
        (0, 1, 2) => "Humidity mixing ratio",
        (0, 1, 3) => "Precipitable water",
        (0, 1, 7) => "Precipitation rate",
        (0, 1, 8) => "Total precipitation",
        (0, 1, 11) => "Snow depth",
        (0, 1, 13) => "Water equivalent of accumulated snow depth",
        (0, 1, 52) => "Total precipitation rate",
        (0, 2, 0) => "Wind direction",
        (0, 2, 1) => "Wind speed",
        (0, 2, 2) => "u-component of wind",
        (0, 2, 3) => "v-component of wind",
        (0, 2, 8) => "Vertical velocity (pressure)",
        (0, 2, 9) => "Vertical velocity (geometric)",
        (0, 2, 10) => "Absolute vorticity",
        (0, 2, 12) => "Relative vorticity",
        (0, 2, 22) => "Wind speed (gust)",
        (0, 3, 0) => "Pressure",
        (0, 3, 1) => "Pressure reduced to MSL",
        (0, 3, 2) => "Pressure tendency",
        (0, 3, 4) => "Geopotential",
        (0, 3, 5) => "Geopotential height",
        (0, 3, 6) => "Geometric height",
        (0, 6, 1) => "Total cloud cover",
        (0, 6, 3) => "Low cloud cover",
        (0, 6, 4) => "Medium cloud cover",
        (0, 6, 5) => "High cloud cover",
        (0, 7, 6) => "Convective available potential energy",
        (0, 7, 7) => "Convective inhibition",
        _ => return None,
    })
}

/// GRIB1 parameter names: WMO table 2 (versions 1–3) and ECMWF table 128.
fn parameter1(table: u8, centre: u8, number: u8) -> Option<&'static str> {
    if table < 128 {
        return Some(match number {
            1 => "Pressure",
            2 => "Pressure reduced to MSL",
            6 => "Geopotential",
            7 => "Geopotential height",
            11 => "Temperature",
            15 => "Maximum temperature",
            16 => "Minimum temperature",
            17 => "Dew point temperature",
            33 => "u-component of wind",
            34 => "v-component of wind",
            39 => "Vertical velocity (pressure)",
            51 => "Specific humidity",
            52 => "Relative humidity",
            61 => "Total precipitation",
            65 => "Water equivalent of accumulated snow depth",
            66 => "Snow depth",
            71 => "Total cloud cover",
            _ => return None,
        });
    }
    if centre == 98 && table == 128 {
        return Some(match number {
            129 => "Geopotential",
            130 => "Temperature",
            131 => "U component of wind",
            132 => "V component of wind",
            133 => "Specific humidity",
            134 => "Surface pressure",
            151 => "Mean sea level pressure",
            157 => "Relative humidity",
            164 => "Total cloud cover",
            165 => "10 metre U wind component",
            166 => "10 metre V wind component",
            167 => "2 metre temperature",
            168 => "2 metre dewpoint temperature",
            228 => "Total precipitation",
            235 => "Skin temperature",
            _ => return None,
        });
    }
    None
}

const LEVELS1: EnumTable = &[
    (1, "surface"),
    (4, "0 °C isotherm"),
    (8, "nominal top of atmosphere"),
    (100, "isobaric level"),
    (102, "mean sea level"),
    (103, "altitude above MSL"),
    (105, "height above ground"),
    (107, "sigma level"),
    (109, "hybrid level"),
    (111, "depth below land surface"),
    (112, "layer between depths below land surface"),
    (200, "entire atmosphere"),
];

const TIME_UNITS1: EnumTable = &[
    (0, "minute"),
    (1, "hour"),
    (2, "day"),
    (3, "month"),
    (4, "year"),
    (10, "3 hours"),
    (11, "6 hours"),
    (12, "12 hours"),
    (254, "second"),
];

const TIME_RANGES1: EnumTable = &[
    (0, "forecast valid at reference time + P1"),
    (1, "analysis or initialized product"),
    (2, "valid between reference + P1 and reference + P2"),
    (3, "average from P1 to P2"),
    (4, "accumulation from P1 to P2"),
    (5, "difference P2 − P1"),
    (10, "P1 occupies octets 19 and 20"),
];

const GRID_TYPES1: EnumTable = &[
    (0, "latitude/longitude"),
    (1, "Mercator"),
    (3, "Lambert conformal"),
    (4, "Gaussian latitude/longitude"),
    (5, "polar stereographic"),
    (10, "rotated latitude/longitude"),
    (50, "spherical harmonic coefficients"),
    (90, "space view perspective"),
];

fn unit_suffix(unit: u8, edition: u8) -> &'static str {
    match (unit, edition) {
        (0, _) => " min",
        (1, _) => " h",
        (2, _) => " d",
        (3, _) => " months",
        (4, _) => " years",
        (10, _) => " × 3 h",
        (11, _) => " × 6 h",
        (12, _) => " × 12 h",
        (13, 2) | (254, 1) => " s",
        _ => "",
    }
}

// ---------------------------------------------------------------------------
// Bit and number helpers

/// A sign-and-magnitude integer of `bits` bits (GRIB's signed fields).
fn signed(raw: u64, bits: u32) -> i64 {
    let sign = 1u64.checked_shl(bits.saturating_sub(1)).unwrap_or(0);
    let magnitude = i64::try_from(raw & sign.wrapping_sub(1)).unwrap_or(i64::MAX);
    if raw & sign != 0 {
        magnitude.saturating_neg()
    } else {
        magnitude
    }
}

/// Reads `n` (≤ 64) bits starting at bit `at` of `buf`, MSB first.
fn bits_at(buf: &[u8], at: u64, n: u8) -> Option<u64> {
    let mut bits = crate::formats::util::vidutil::Bits::new(buf);
    bits.skip(usize::try_from(at).ok()?)?;
    bits.bits(n.into())
}

fn date(y: u64, mo: u64, d: u64, h: u64, mi: u64) -> String {
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}")
}

fn timestamp(y: u64, mo: u64, d: u64, h: u64, mi: u64, s: u64) -> Value {
    let c = |v: u64| u32::try_from(v).unwrap_or(0);
    Value::Timestamp {
        unix_seconds: crate::formats::util::civil::civil_to_unix(
            i64::try_from(y).unwrap_or(0),
            c(mo),
            c(d),
            c(h),
            c(mi),
            c(s),
        ),
    }
}

// ---------------------------------------------------------------------------
// The message list

#[derive(Clone, Default)]
struct Walk {
    pos: u64,
    index: u64,
    editions: (u64, u64),
    first: Option<String>,
}

const SEARCH_WINDOW: u64 = 64 * 1024;

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut w = cx.resume::<Walk>().unwrap_or_default();
    while w.pos < file.len {
        cx.progress_in(file, file.offset.saturating_add(w.pos));
        let head = cx.read_avail(file.sub(w.pos, 16)).await?;
        if !head.starts_with(b"GRIB") {
            // Padding or a bulletin header between messages: look ahead
            // for the next message.
            let window = cx.read_avail(file.sub(w.pos, SEARCH_WINDOW)).await?;
            let next = crate::bytes::find(&window, b"GRIB", 0);
            match next {
                Some(off) if off > 0 => {
                    let off = to_u64(off);
                    cx.push(
                        Node::new("Gap")
                            .span(file.sub(w.pos, off))
                            .summary(format!("{off} bytes between messages")),
                    )
                    .await;
                    w.pos = w.pos.saturating_add(off);
                    continue;
                }
                _ => {
                    cx.push(Node::new("Trailing data").span(file.tail(w.pos)))
                        .await;
                    break;
                }
            }
        }
        let edition = head.get(7).copied().unwrap_or(0);
        let len = match edition {
            2 => u64_be(&head, 8).unwrap_or(0),
            _ => u64::from(crate::bytes::u24_be(&head, 4).unwrap_or(0)),
        };
        let min = if edition == 2 { 16 } else { 12 };
        let index = w.index.saturating_add(1);
        if len < min {
            cx.push(
                Node::new(format!("Message {index}"))
                    .span(file.sub(w.pos, 8))
                    .diag(Diagnostic::malformed(format!("message length {len}"))),
            )
            .await;
            break;
        }
        let span = file.sub(w.pos, len);
        let mut node = Node::new(format!("Message {index}")).span(span);
        if edition == 1 || edition == 2 {
            let summary = match summarize(&cx, span, edition).await {
                Ok(s) => s,
                Err(e) => {
                    node = node.diag(e);
                    format!("GRIB{edition}")
                }
            };
            if w.first.is_none() {
                w.first = Some(summary.clone());
            }
            node = node.summary(summary).lazy(message, (span, edition));
        } else {
            node = node.diag(Diagnostic::unsupported(format!("GRIB edition {edition}")));
        }
        if span.len < len {
            node = node.diag(Diagnostic::truncated(
                Span::new(file.source, span.offset, len),
                span.len,
            ));
        } else if cx.read(span.sub(len.saturating_sub(4), 4)).await? != b"7777" {
            node = node.diag(Diagnostic::malformed("message does not end with 7777"));
        }
        let state = w.clone();
        cx.mark(move || state);
        cx.push(node).await;
        match edition {
            1 => w.editions.0 = w.editions.0.saturating_add(1),
            _ => w.editions.1 = w.editions.1.saturating_add(1),
        }
        w.index = index;
        w.pos = w.pos.saturating_add(len);
    }
    let edition = match w.editions {
        (0, _) => "GRIB2",
        (_, 0) => "GRIB1",
        _ => "GRIB1/GRIB2",
    };
    cx.annotate(match (w.index, w.first) {
        (1, Some(first)) => format!("{edition}, {first}"),
        (n, Some(first)) => format!("{n} {edition} messages, first: {first}"),
        (n, None) => format!("{n} GRIB messages"),
    });
    Ok(())
}

// ---------------------------------------------------------------------------
// Summaries

#[derive(Default)]
struct Summary2 {
    discipline: u8,
    reference: String,
    parameter: Option<(u8, u8)>,
    level: String,
    forecast: String,
    grid: String,
    fields: u32,
}

fn level2(kind: u8, factor: u8, value: u32) -> String {
    let v = if factor == 255 && value == u32::MAX {
        None
    } else {
        Some(f64::from(value) / 10f64.powi(i32::try_from(signed(factor.into(), 8)).unwrap_or(0)))
    };
    let v = |unit: &str| v.map_or(String::new(), |v| format!("{} {unit}", num(v)));
    match kind {
        1 => "surface".to_owned(),
        8 => "top of atmosphere".to_owned(),
        10 => "entire atmosphere".to_owned(),
        100 => v("Pa")
            .strip_suffix(" Pa")
            .and_then(|p| p.parse::<f64>().ok())
            .map_or_else(
                || "isobaric".to_owned(),
                |p| format!("{} hPa", num(p / 100.0)),
            ),
        101 => "mean sea level".to_owned(),
        102 => format!("{} above MSL", v("m")),
        103 => format!("{} above ground", v("m")),
        106 => format!("{} below ground", v("m")),
        160 => format!("{} below sea level", v("m")),
        _ => lookup(SURFACES, kind.into()).map_or_else(
            || format!("level type {kind}"),
            |name| {
                let value = v("");
                if value.is_empty() {
                    name.to_owned()
                } else {
                    format!("{name} {}", value.trim_end())
                }
            },
        ),
    }
}

fn grid_summary2(template: u16, b: &[u8], points: u32) -> String {
    let at = |o: usize| u32_be(b, o).unwrap_or(0);
    let name = lookup(GRID_TEMPLATES, template.into()).unwrap_or("grid");
    match template {
        0 | 1 => {
            // Offsets within the section: Ni 30, Nj 34, Di 63, Dj 67.
            let (ni, nj, di) = (at(30), at(34), at(63));
            let inc = f64::from(di) / 1e6;
            let global = di != u32::MAX && u64::from(ni).saturating_mul(di.into()) >= 359_000_000;
            format!(
                "{}{}° {ni}×{nj} {name} grid",
                if global { "global " } else { "" },
                num(inc)
            )
        }
        40 | 41 => format!("Gaussian N{} {} grid, {points} points", at(67), name),
        _ => format!("{name} grid, {points} points"),
    }
}

async fn summarize(cx: &Cx, span: Span, edition: u8) -> Result<String> {
    if edition == 1 {
        return summarize1(cx, span).await;
    }
    let head = cx.read(span.sub(0, 16)).await?;
    let mut s = Summary2 {
        discipline: head.get(6).copied().unwrap_or(0),
        ..Summary2::default()
    };
    let mut pos = 16u64;
    let end = span.len.saturating_sub(4);
    while pos.saturating_add(5) <= end {
        let h = cx.read(span.sub(pos, 5)).await?;
        let len = u64::from(u32_be(&h, 0).unwrap_or(0));
        let number = h.get(4).copied().unwrap_or(0);
        if len < 5 {
            break;
        }
        let body = cx.read_avail(span.sub(pos, len.min(80))).await?;
        let b = |o: usize| u64::from(body.get(o).copied().unwrap_or(0));
        let w = |o: usize| u64::from(crate::bytes::u16_be(&body, o).unwrap_or(0));
        let d = |o: usize| u64::from(u32_be(&body, o).unwrap_or(0));
        match number {
            1 if s.reference.is_empty() => {
                s.reference = date(w(12), b(14), b(15), b(16), b(17));
            }
            3 if s.grid.is_empty() => {
                let template = u16::try_from(w(12)).unwrap_or(0);
                s.grid = grid_summary2(template, &body, u32::try_from(d(6)).unwrap_or(0));
            }
            4 => {
                s.fields = s.fields.saturating_add(1);
                let template = w(7);
                if s.fields == 1 && matches!(template, 0..=15) {
                    let (cat, par) = (b(9), b(10));
                    s.parameter = Some((
                        u8::try_from(cat).unwrap_or(0),
                        u8::try_from(par).unwrap_or(0),
                    ));
                    let unit = u8::try_from(b(17)).unwrap_or(255);
                    let ft = d(18);
                    s.level = level2(
                        u8::try_from(b(22)).unwrap_or(255),
                        u8::try_from(b(23)).unwrap_or(255),
                        u32::try_from(d(24)).unwrap_or(u32::MAX),
                    );
                    s.forecast = format!("+{ft}{}", unit_suffix(unit, 2));
                    if matches!(template, 8 | 11) {
                        // The first time range of the statistical process.
                        let base: usize = if template == 11 { 37 } else { 34 };
                        let process = b(base.saturating_add(12));
                        let length = d(base.saturating_add(15));
                        let range_unit = u8::try_from(b(base.saturating_add(14))).unwrap_or(255);
                        if range_unit == unit {
                            s.forecast = format!(
                                "+{ft}–{}{}",
                                ft.saturating_add(length),
                                unit_suffix(unit, 2)
                            );
                        }
                        if let Some(p) = lookup(STATISTICS, process) {
                            s.forecast.push(' ');
                            s.forecast.push_str(p);
                        }
                    }
                }
            }
            _ => {}
        }
        pos = pos.saturating_add(len);
    }
    let parameter = match s.parameter {
        Some((cat, par)) => parameter2(s.discipline, cat, par).map_or_else(
            || format!("parameter {}/{cat}/{par}", s.discipline),
            str::to_owned,
        ),
        None => "no product".to_owned(),
    };
    let mut out = parameter;
    for part in [
        &s.level,
        &format!("{} {}", s.reference, s.forecast),
        &s.grid,
    ] {
        if !part.trim().is_empty() {
            out.push_str(", ");
            out.push_str(part.trim());
        }
    }
    if s.fields > 1 {
        out.push_str(&format!(" ({} fields)", s.fields));
    }
    Ok(out)
}

async fn summarize1(cx: &Cx, span: Span) -> Result<String> {
    let pds = cx.read_avail(span.sub(8, 40)).await?;
    let b = |o: usize| pds.get(o).copied().unwrap_or(0);
    let table = b(3);
    let centre = b(4);
    let param = b(8);
    let mut out = parameter1(table, centre, param)
        .map_or_else(|| format!("parameter {table}/{param}"), str::to_owned);
    let level_type = b(9);
    let level = crate::bytes::u16_be(&pds, 10).unwrap_or(0);
    out.push_str(", ");
    out.push_str(&match level_type {
        1 => "surface".to_owned(),
        100 => format!("{level} hPa"),
        102 => "mean sea level".to_owned(),
        105 => format!("{level} m above ground"),
        t => lookup(LEVELS1, t.into()).map_or_else(
            || format!("level type {t} {level}"),
            |n| format!("{n} {level}"),
        ),
    });
    let century = u64::from(b(24));
    let year = century
        .saturating_sub(1)
        .saturating_mul(100)
        .saturating_add(b(12).into());
    let unit = b(17);
    let (p1, p2) = (b(18), b(19));
    let range = match b(20) {
        0 | 1 => format!("+{p1}{}", unit_suffix(unit, 1)),
        10 => format!(
            "+{}{}",
            crate::bytes::u16_be(&pds, 18).unwrap_or(0),
            unit_suffix(unit, 1)
        ),
        t => format!(
            "+{p1}–{p2}{} {}",
            unit_suffix(unit, 1),
            match t {
                3 => "average",
                4 => "accumulation",
                5 => "difference",
                _ => "range",
            }
        ),
    };
    out.push_str(&format!(
        ", {} {range}",
        date(year, b(13).into(), b(14).into(), b(15).into(), b(16).into())
    ));
    if b(7) & 0x80 != 0 {
        let pds_len = u64::from(crate::bytes::u24_be(&pds, 0).unwrap_or(0));
        let gds = cx
            .read_avail(span.sub(8u64.saturating_add(pds_len), 32))
            .await?;
        let kind = gds.get(5).copied().unwrap_or(255);
        let w = |o: usize| crate::bytes::u16_be(&gds, o).unwrap_or(0);
        let name = lookup(GRID_TYPES1, kind.into()).unwrap_or("grid");
        out.push_str(&match kind {
            0 | 10 => {
                let (ni, nj, di) = (w(6), w(8), w(23));
                let global = di != 0xffff && u32::from(ni).saturating_mul(di.into()) >= 359_000;
                format!(
                    ", {}{}° {ni}×{nj} {name} grid",
                    if global { "global " } else { "" },
                    num(f64::from(di) / 1000.0)
                )
            }
            4 => format!(", Gaussian N{} grid", w(25)),
            _ => format!(", {name} grid"),
        });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// GRIB2 sections

const SECTION_NAMES: [&str; 9] = [
    "Indicator",
    "Identification",
    "Local use",
    "Grid definition",
    "Product definition",
    "Data representation",
    "Bit-map",
    "Data",
    "End",
];

/// Context for decoding values: what the most recent sections 3, 5 and 6
/// said.
#[derive(Clone, Default)]
struct Context {
    points: u64,
    grid: Option<Grid>,
    packing: Option<Packing>,
    bitmap: Option<Span>,
}

#[derive(Clone, Copy, Debug)]
struct Grid {
    ni: u64,
    nj: u64,
    la1: f64,
    lo1: f64,
    di: f64,
    dj: f64,
    scan: u8,
}

#[derive(Clone, Copy, Debug)]
enum Packing {
    Simple {
        reference: f64,
        binary: i32,
        decimal: i32,
        bits: u8,
    },
    Ieee {
        bytes: u8,
    },
}

async fn message(cx: Cx, (span, edition): (Span, u8)) -> Result<()> {
    if edition == 1 {
        return message1(cx, span).await;
    }
    cx.emit(struct_node(
        "Section 0: Indicator",
        span.sub(0, 16),
        BE,
        (),
        indicator2,
    ));
    let head = cx.read(span.sub(0, 16)).await?;
    let discipline = head.get(6).copied().unwrap_or(0);
    let mut pos = 16u64;
    let end = span.len.saturating_sub(4);
    let mut ctx = Context::default();
    let mut field = 0u32;
    while pos.saturating_add(5) <= end {
        let h = cx.read(span.sub(pos, 5)).await?;
        let len = u64::from(u32_be(&h, 0).unwrap_or(0));
        let number = h.get(4).copied().unwrap_or(0);
        let sec = span.sub(pos, len);
        let name = format!(
            "Section {number}: {}",
            SECTION_NAMES.get(usize::from(number)).unwrap_or(&"unknown")
        );
        if len < 5 || pos.saturating_add(len) > end {
            cx.push(
                Node::new(name)
                    .span(sec)
                    .diag(Diagnostic::malformed(format!("section length {len}"))),
            )
            .await;
            break;
        }
        let node = match number {
            1 => struct_node(name, sec, BE, (), identification2),
            2 => struct_node(name, sec, BE, (), local2),
            3 => {
                let body = cx.read_avail(sec.sub(0, 72)).await?;
                ctx.points = u64::from(u32_be(&body, 6).unwrap_or(0));
                ctx.grid = grid2(&body);
                struct_node(name, sec, BE, (), grid_definition2)
            }
            4 => {
                field = field.saturating_add(1);
                struct_node(name, sec, BE, discipline, product2)
            }
            5 => {
                let body = cx.read_avail(sec.sub(0, 22)).await?;
                ctx.packing = packing2(&body);
                struct_node(name, sec, BE, (), representation2)
            }
            6 => {
                let indicator = cx
                    .read(sec.sub(5, 1))
                    .await?
                    .first()
                    .copied()
                    .unwrap_or(255);
                match indicator {
                    0 => ctx.bitmap = Some(sec.tail(6)),
                    254 => {}
                    _ => ctx.bitmap = None,
                }
                struct_node(name, sec, BE, (), bitmap2)
            }
            7 => struct_node(name, sec, BE, (), data2),
            _ => Node::new(name).span(sec),
        };
        cx.push(node.summary(format!("{len} bytes"))).await;
        if number == 7 {
            let label = if field > 1 {
                format!("Values (field {field})")
            } else {
                "Values".to_owned()
            };
            cx.push(values_node(label, &ctx, sec.tail(5))).await;
        }
        pos = pos.saturating_add(len);
    }
    cx.push(
        Node::new("Section 8: End")
            .span(span.sub(pos, 4))
            .value(Value::Text("7777".into())),
    )
    .await;
    Ok(())
}

fn grid2(b: &[u8]) -> Option<Grid> {
    let template = crate::bytes::u16_be(b, 12)?;
    if !matches!(template, 0 | 40) {
        return None;
    }
    let d = |o: usize| u32_be(b, o).unwrap_or(0);
    let angle = d(38);
    let unit = if angle == 0 || angle == u32::MAX {
        1e-6
    } else {
        f64::from(angle) / f64::from(d(42).max(1))
    };
    let sdeg = |o: usize| signed(d(o).into(), 32) as f64 * unit;
    Some(Grid {
        ni: d(30).into(),
        nj: d(34).into(),
        la1: sdeg(46),
        lo1: sdeg(50),
        di: f64::from(d(63)) * unit,
        // Template 3.40 stores N (parallels between pole and equator) here;
        // Gaussian latitudes are not evenly spaced, so they are not labelled.
        dj: if template == 0 {
            f64::from(d(67)) * unit
        } else {
            f64::NAN
        },
        scan: b.get(71).copied().unwrap_or(0),
    })
}

fn packing2(b: &[u8]) -> Option<Packing> {
    let template = crate::bytes::u16_be(b, 9)?;
    match template {
        0 => Some(Packing::Simple {
            reference: f64::from(f32::from_bits(u32_be(b, 11)?)),
            binary: i32::try_from(signed(crate::bytes::u16_be(b, 15)?.into(), 16)).ok()?,
            decimal: i32::try_from(signed(crate::bytes::u16_be(b, 17)?.into(), 16)).ok()?,
            bits: *b.get(19)?,
        }),
        4 => match b.get(11)? {
            1 => Some(Packing::Ieee { bytes: 4 }),
            2 => Some(Packing::Ieee { bytes: 8 }),
            _ => None,
        },
        _ => None,
    }
}

fn section_head(f: &mut Fields<'_>) -> Result<()> {
    f.u32("Section length").emit()?;
    f.u8("Section number").emit()?;
    Ok(())
}

fn indicator2(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.ascii("Magic", 4).emit()?;
    f.u16("Reserved").emit()?;
    f.u8("Discipline").enumeration(DISCIPLINES).emit()?;
    f.u8("Edition").emit()?;
    f.u64("Total length").emit()?;
    Ok(())
}

fn identification2(f: &mut Fields<'_>, _: &()) -> Result<()> {
    section_head(f)?;
    f.u16("Originating centre").enumeration(CENTRES).emit()?;
    f.u16("Sub-centre").emit()?;
    f.u8("Master tables version").emit()?;
    f.u8("Local tables version").emit()?;
    f.u8("Significance of reference time")
        .enumeration(REF_SIGNIFICANCE)
        .emit()?;
    let at = f.peek_span(7);
    let year = f.u16("Year").get()?;
    let month = f.u8("Month").get()?;
    let day = f.u8("Day").get()?;
    let hour = f.u8("Hour").get()?;
    let minute = f.u8("Minute").get()?;
    let second = f.u8("Second").get()?;
    f.node(Node::new("Reference time").span(at).value(timestamp(
        year.into(),
        month.into(),
        day.into(),
        hour.into(),
        minute.into(),
        second.into(),
    )));
    f.u8("Production status")
        .enumeration(PRODUCTION_STATUS)
        .emit()?;
    f.u8("Type of data").enumeration(DATA_TYPES).emit()?;
    rest(f, "Reserved")
}

/// The rest of a section as bytes (shared with BUFR).
pub(super) fn rest(f: &mut Fields<'_>, name: &'static str) -> Result<()> {
    let n = f.remaining();
    if n > 0 {
        f.bytes(name, n).emit()?;
    }
    Ok(())
}

fn local2(f: &mut Fields<'_>, _: &()) -> Result<()> {
    section_head(f)?;
    rest(f, "Local data")
}

fn latitude(f: &mut Fields<'_>, name: &'static str, unit: f64) -> Result<()> {
    f.u32(name)
        .with(|&v, n| n.value(Value::Float(signed(v.into(), 32) as f64 * unit)))
        .emit()?;
    Ok(())
}

fn longitude(f: &mut Fields<'_>, name: &'static str, unit: f64) -> Result<()> {
    latitude(f, name, unit)
}

fn earth(f: &mut Fields<'_>) -> Result<()> {
    f.u8("Shape of the earth")
        .enumeration(EARTH_SHAPES)
        .emit()?;
    f.u8("Scale factor of radius").emit()?;
    f.u32("Scaled value of radius").emit()?;
    f.u8("Scale factor of major axis").emit()?;
    f.u32("Scaled value of major axis").emit()?;
    f.u8("Scale factor of minor axis").emit()?;
    f.u32("Scaled value of minor axis").emit()?;
    Ok(())
}

const RESOLUTION_FLAGS: crate::value::FlagTable = &[
    crate::value::flag(0x20, "i increments given"),
    crate::value::flag(0x10, "j increments given"),
    crate::value::flag(0x08, "u/v relative to grid"),
];

const SCANNING_FLAGS: crate::value::FlagTable = &[
    crate::value::flag(0x80, "i negative"),
    crate::value::flag(0x40, "j positive"),
    crate::value::flag(0x20, "j consecutive"),
    crate::value::flag(0x10, "alternate rows reversed"),
];

fn grid_definition2(f: &mut Fields<'_>, _: &()) -> Result<()> {
    section_head(f)?;
    f.u8("Source of grid definition").emit()?;
    f.u32("Number of data points").emit()?;
    let list = f.u8("Octets per optional list item").emit()?;
    f.u8("Interpretation of list").emit()?;
    let template = f
        .u16("Grid definition template")
        .enumeration(GRID_TEMPLATES)
        .emit()?;
    match template {
        0 | 1 | 40 | 41 => {
            earth(f)?;
            f.u32("Ni (points along a parallel)").emit()?;
            f.u32("Nj (points along a meridian)").emit()?;
            let angle = f.u32("Basic angle").emit()?;
            let sub = f.u32("Subdivisions of basic angle").emit()?;
            let unit = if angle == 0 || angle == u32::MAX {
                1e-6
            } else {
                f64::from(angle) / f64::from(sub.max(1))
            };
            latitude(f, "La1 (first latitude, °)", unit)?;
            longitude(f, "Lo1 (first longitude, °)", unit)?;
            f.u8("Resolution and component flags")
                .flags(RESOLUTION_FLAGS)
                .emit()?;
            latitude(f, "La2 (last latitude, °)", unit)?;
            longitude(f, "Lo2 (last longitude, °)", unit)?;
            f.u32("Di (i increment, °)")
                .with(|&v, n| n.value(Value::Float(f64::from(v) * unit)))
                .emit()?;
            if template == 0 || template == 1 {
                f.u32("Dj (j increment, °)")
                    .with(|&v, n| n.value(Value::Float(f64::from(v) * unit)))
                    .emit()?;
            } else {
                f.u32("N (parallels between a pole and the equator)")
                    .emit()?;
            }
            f.u8("Scanning mode").flags(SCANNING_FLAGS).emit()?;
            if template == 1 || template == 41 {
                latitude(f, "Latitude of the southern pole (°)", unit)?;
                longitude(f, "Longitude of the southern pole (°)", unit)?;
                f.f32("Angle of rotation").emit()?;
            }
        }
        _ => {}
    }
    let n = f.remaining();
    if n > 0 {
        f.bytes(
            if list > 0 && template <= 41 {
                "List of points per row"
            } else {
                "Template data"
            },
            n,
        )
        .emit()?;
    }
    Ok(())
}

fn surface(f: &mut Fields<'_>, which: u8) -> Result<()> {
    let (t, s, v) = if which == 1 {
        (
            "Type of first fixed surface",
            "Scale factor of first fixed surface",
            "Scaled value of first fixed surface",
        )
    } else {
        (
            "Type of second fixed surface",
            "Scale factor of second fixed surface",
            "Scaled value of second fixed surface",
        )
    };
    f.u8(t).enumeration(SURFACES).emit()?;
    f.u8(s)
        .with(|&v, n| {
            if v == 255 {
                n.summary("missing")
            } else {
                n.value(Value::Int {
                    value: signed(v.into(), 8),
                    bits: 8,
                })
            }
        })
        .emit()?;
    f.u32(v).emit()?;
    Ok(())
}

fn product2(f: &mut Fields<'_>, discipline: &u8) -> Result<()> {
    section_head(f)?;
    let nv = f.u16("Number of coordinate values").emit()?;
    let template = f
        .u16("Product definition template")
        .enumeration(PRODUCT_TEMPLATES)
        .emit()?;
    if matches!(template, 0 | 1 | 8 | 11) {
        let category = if *discipline == 0 {
            f.u8("Parameter category")
                .enumeration(CATEGORIES_0)
                .emit()?
        } else {
            f.u8("Parameter category").emit()?
        };
        let d = *discipline;
        f.u8("Parameter number")
            .with(|&v, n| match parameter2(d, category, v) {
                Some(name) => n.summary(name),
                None if v >= 192 => n.summary("local use"),
                None => n,
            })
            .emit()?;
        f.u8("Type of generating process")
            .enumeration(GENERATING_PROCESSES)
            .emit()?;
        f.u8("Background generating process").emit()?;
        f.u8("Generating process identifier").emit()?;
        f.u16("Hours of observational data cut-off").emit()?;
        f.u8("Minutes of observational data cut-off").emit()?;
        f.u8("Unit of time range").enumeration(TIME_UNITS).emit()?;
        f.u32("Forecast time").emit()?;
        surface(f, 1)?;
        surface(f, 2)?;
        if template == 1 || template == 11 {
            f.u8("Type of ensemble forecast").emit()?;
            f.u8("Perturbation number").emit()?;
            f.u8("Number of forecasts in ensemble").emit()?;
        }
        if template == 8 || template == 11 {
            let at = f.peek_span(7);
            let year = f.u16("Year").get()?;
            let month = f.u8("Month").get()?;
            let day = f.u8("Day").get()?;
            let hour = f.u8("Hour").get()?;
            let minute = f.u8("Minute").get()?;
            let second = f.u8("Second").get()?;
            f.node(
                Node::new("End of overall time interval")
                    .span(at)
                    .value(timestamp(
                        year.into(),
                        month.into(),
                        day.into(),
                        hour.into(),
                        minute.into(),
                        second.into(),
                    )),
            );
            let ranges = f.u8("Number of time ranges").emit()?;
            f.u32("Values missing from the statistical process")
                .emit()?;
            for _ in 0..ranges {
                if f.remaining() < 12 {
                    break;
                }
                f.u8("Statistical process").enumeration(STATISTICS).emit()?;
                f.u8("Type of time increment").emit()?;
                f.u8("Unit of time range").enumeration(TIME_UNITS).emit()?;
                f.u32("Length of time range").emit()?;
                f.u8("Unit of time increment")
                    .enumeration(TIME_UNITS)
                    .emit()?;
                f.u32("Time increment").emit()?;
            }
        }
    }
    let coords = u64::from(nv).saturating_mul(4);
    let n = f.remaining();
    if n > coords {
        f.bytes("Template data", n.saturating_sub(coords)).emit()?;
    }
    if coords > 0 {
        let len = coords.min(f.remaining());
        f.bytes("Coordinate values", len).emit()?;
    }
    Ok(())
}

fn representation2(f: &mut Fields<'_>, _: &()) -> Result<()> {
    section_head(f)?;
    f.u32("Number of data values").emit()?;
    let template = f
        .u16("Data representation template")
        .enumeration(DATA_TEMPLATES)
        .emit()?;
    match template {
        0 | 2 | 3 | 40 | 41 | 42 | 61 => {
            f.f32("Reference value (R)").emit()?;
            f.u16("Binary scale factor (E)")
                .with(|&v, n| {
                    n.value(Value::Int {
                        value: signed(v.into(), 16),
                        bits: 16,
                    })
                })
                .emit()?;
            f.u16("Decimal scale factor (D)")
                .with(|&v, n| {
                    n.value(Value::Int {
                        value: signed(v.into(), 16),
                        bits: 16,
                    })
                })
                .emit()?;
            f.u8("Bits per value").emit()?;
            f.u8("Type of original values")
                .enumeration(&[(0, "floating point"), (1, "integer")])
                .emit()?;
        }
        4 => {
            f.u8("Precision")
                .enumeration(&[(1, "32-bit"), (2, "64-bit"), (3, "128-bit")])
                .emit()?;
        }
        _ => {}
    }
    rest(f, "Template data")
}

fn bitmap2(f: &mut Fields<'_>, _: &()) -> Result<()> {
    section_head(f)?;
    f.u8("Bit-map indicator")
        .enumeration(BITMAP_INDICATORS)
        .emit()?;
    rest(f, "Bit-map")
}

fn data2(f: &mut Fields<'_>, _: &()) -> Result<()> {
    section_head(f)?;
    let n = f.remaining();
    f.node(Node::new("Packed data").span(f.peek_span(n)));
    Ok(())
}

// ---------------------------------------------------------------------------
// GRIB1

async fn message1(cx: Cx, span: Span) -> Result<()> {
    cx.emit(struct_node(
        "Section 0: Indicator",
        span.sub(0, 8),
        BE,
        (),
        indicator1,
    ));
    let mut pos = 8u64;
    let end = span.len.saturating_sub(4);
    let pds_head = cx.read(span.sub(pos, 8)).await?;
    let pds_len = u64::from(crate::bytes::u24_be(&pds_head, 0).unwrap_or(0));
    let flags = pds_head.get(7).copied().unwrap_or(0);
    if pds_len < 28 {
        return Err(Diagnostic::malformed(format!("PDS length {pds_len}")).at(span.sub(pos, 3)));
    }
    let pds = span.sub(pos, pds_len);
    let pds_bytes = cx.read_avail(pds.sub(0, 28)).await?;
    let decimal = i32::try_from(signed(
        crate::bytes::u16_be(&pds_bytes, 26).unwrap_or(0).into(),
        16,
    ))
    .unwrap_or(0);
    cx.emit(
        struct_node("Section 1: Product definition", pds, BE, (), pds1)
            .summary(format!("{pds_len} bytes")),
    );
    pos = pos.saturating_add(pds_len);
    let mut ctx = Context::default();
    for (present, number, name) in [
        (flags & 0x80 != 0, 2u8, "Section 2: Grid description"),
        (flags & 0x40 != 0, 3, "Section 3: Bit-map"),
        (true, 4, "Section 4: Binary data"),
    ] {
        if !present {
            continue;
        }
        if pos.saturating_add(3) > end {
            cx.diag(Diagnostic::truncated(span.sub(pos, 3), 0));
            break;
        }
        let h = cx.read(span.sub(pos, 3)).await?;
        let len = u64::from(crate::bytes::u24_be(&h, 0).unwrap_or(0));
        let sec = span.sub(pos, len);
        if len < 3 || pos.saturating_add(len) > end {
            cx.emit(
                Node::new(name)
                    .span(sec)
                    .diag(Diagnostic::malformed(format!("section length {len}"))),
            );
            break;
        }
        let node = match number {
            2 => {
                let b = cx.read_avail(sec.sub(0, 32)).await?;
                ctx.grid = grid1(&b);
                if let Some(g) = ctx.grid {
                    ctx.points = g.ni.saturating_mul(g.nj);
                }
                struct_node(name, sec, BE, (), gds1)
            }
            3 => {
                let b = cx.read(sec.sub(4, 2)).await?;
                if crate::bytes::u16_be(&b, 0) == Some(0) {
                    ctx.bitmap = Some(sec.tail(6));
                }
                struct_node(name, sec, BE, (), bms1)
            }
            _ => {
                let b = cx.read_avail(sec.sub(0, 11)).await?;
                let bflags = b.get(3).copied().unwrap_or(0);
                if bflags & 0xc0 == 0 {
                    ctx.packing = Some(Packing::Simple {
                        reference: ibm(b.get(6..10).unwrap_or(&[0; 4])).unwrap_or(0.0),
                        binary: i32::try_from(signed(
                            crate::bytes::u16_be(&b, 4).unwrap_or(0).into(),
                            16,
                        ))
                        .unwrap_or(0),
                        decimal,
                        bits: b.get(10).copied().unwrap_or(0),
                    });
                }
                if ctx.points == 0 {
                    // No grid description: the number of values follows
                    // from the section length and the unused bits.
                    let unused = u64::from(bflags & 0x0f);
                    let bits = u64::from(b.get(10).copied().unwrap_or(0));
                    ctx.points = len
                        .saturating_sub(11)
                        .saturating_mul(8)
                        .saturating_sub(unused)
                        .checked_div(bits)
                        .unwrap_or(0);
                }
                struct_node(name, sec, BE, (), bds1)
            }
        };
        cx.emit(node.summary(format!("{len} bytes")));
        if number == 4 {
            cx.emit(values_node("Values".to_owned(), &ctx, sec.tail(11)));
        }
        pos = pos.saturating_add(len);
    }
    cx.emit(
        Node::new("Section 5: End")
            .span(span.sub(end, 4))
            .value(Value::Text("7777".into())),
    );
    Ok(())
}

fn grid1(b: &[u8]) -> Option<Grid> {
    let kind = *b.get(5)?;
    if !matches!(kind, 0 | 4) {
        return None;
    }
    let w = |o: usize| u64::from(crate::bytes::u16_be(b, o).unwrap_or(0));
    let t = |o: usize| u64::from(crate::bytes::u24_be(b, o).unwrap_or(0));
    let deg = |o: usize| signed(t(o), 24) as f64 / 1000.0;
    Some(Grid {
        ni: w(6),
        nj: w(8),
        la1: deg(10),
        lo1: deg(13),
        di: w(23) as f64 / 1000.0,
        dj: if kind == 0 {
            w(25) as f64 / 1000.0
        } else {
            f64::NAN
        },
        scan: *b.get(27)?,
    })
}

/// A 24-bit big-endian unsigned field (shared with BUFR).
pub(super) fn u24(f: &mut Fields<'_>, name: &'static str) -> Result<u64> {
    let raw = f
        .bytes(name, 3)
        .with(|b, n| n.value(uint(crate::formats::util::datakit::be_uint(b), 24)))
        .emit()?;
    Ok(crate::formats::util::datakit::be_uint(&raw))
}

fn s24(f: &mut Fields<'_>, name: &'static str, scale: f64) -> Result<()> {
    f.bytes(name, 3)
        .with(|b, n| {
            let v = signed(crate::formats::util::datakit::be_uint(b), 24);
            n.value(Value::Float(v as f64 / scale))
        })
        .emit()?;
    Ok(())
}

/// The GRIB1 indicator section; BUFR's has the same layout.
pub(super) fn indicator1(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.ascii("Magic", 4).emit()?;
    u24(f, "Total length")?;
    f.u8("Edition").emit()?;
    Ok(())
}

const PDS_FLAGS: crate::value::FlagTable = &[
    crate::value::flag(0x80, "grid description included"),
    crate::value::flag(0x40, "bit-map included"),
];

fn pds1(f: &mut Fields<'_>, _: &()) -> Result<()> {
    u24(f, "Section length")?;
    let table = f.u8("Parameter table version").emit()?;
    let centre = f.u8("Originating centre").enumeration(CENTRES).emit()?;
    f.u8("Generating process").emit()?;
    f.u8("Grid identification").emit()?;
    f.u8("Flags").flags(PDS_FLAGS).emit()?;
    f.u8("Indicator of parameter")
        .with(|&v, n| match parameter1(table, centre, v) {
            Some(name) => n.summary(name),
            None => n,
        })
        .emit()?;
    f.u8("Indicator of type of level")
        .enumeration(LEVELS1)
        .emit()?;
    f.u16("Level").emit()?;
    let at = f.peek_span(5);
    let year = f.u8("Year of century").get()?;
    let month = f.u8("Month").get()?;
    let day = f.u8("Day").get()?;
    let hour = f.u8("Hour").get()?;
    let minute = f.u8("Minute").get()?;
    f.u8("Unit of time range").enumeration(TIME_UNITS1).emit()?;
    f.u8("P1").emit()?;
    f.u8("P2").emit()?;
    f.u8("Time range indicator")
        .enumeration(TIME_RANGES1)
        .emit()?;
    f.u16("Number included in average").emit()?;
    f.u8("Number missing from average").emit()?;
    let century = f.u8("Century").emit()?;
    let full = u64::from(century)
        .saturating_sub(1)
        .saturating_mul(100)
        .saturating_add(year.into());
    f.node(Node::new("Reference time").span(at).value(timestamp(
        full,
        month.into(),
        day.into(),
        hour.into(),
        minute.into(),
        0,
    )));
    f.u8("Sub-centre").emit()?;
    f.u16("Decimal scale factor (D)")
        .with(|&v, n| {
            n.value(Value::Int {
                value: signed(v.into(), 16),
                bits: 16,
            })
        })
        .emit()?;
    let reserved = f.remaining().min(12);
    if reserved > 0 {
        f.bytes("Reserved", reserved).emit()?;
    }
    rest(f, "Local extension")
}

fn gds1(f: &mut Fields<'_>, _: &()) -> Result<()> {
    u24(f, "Section length")?;
    f.u8("Number of vertical coordinate parameters").emit()?;
    f.u8("Location of vertical parameters or points list")
        .emit()?;
    let kind = f
        .u8("Data representation type")
        .enumeration(GRID_TYPES1)
        .emit()?;
    if matches!(kind, 0 | 4 | 10) {
        f.u16("Ni (points along a parallel)").emit()?;
        f.u16("Nj (points along a meridian)").emit()?;
        s24(f, "La1 (first latitude, °)", 1000.0)?;
        s24(f, "Lo1 (first longitude, °)", 1000.0)?;
        f.u8("Resolution and component flags").hex().emit()?;
        s24(f, "La2 (last latitude, °)", 1000.0)?;
        s24(f, "Lo2 (last longitude, °)", 1000.0)?;
        f.u16("Di (i increment, °)")
            .with(|&v, n| n.value(Value::Float(f64::from(v) / 1000.0)))
            .emit()?;
        if kind == 4 {
            f.u16("N (parallels between a pole and the equator)")
                .emit()?;
        } else {
            f.u16("Dj (j increment, °)")
                .with(|&v, n| n.value(Value::Float(f64::from(v) / 1000.0)))
                .emit()?;
        }
        f.u8("Scanning mode").flags(SCANNING_FLAGS).emit()?;
    }
    rest(f, "Grid parameters")
}

fn bms1(f: &mut Fields<'_>, _: &()) -> Result<()> {
    u24(f, "Section length")?;
    f.u8("Unused bits at end").emit()?;
    f.u16("Predefined bit-map").emit()?;
    rest(f, "Bit-map")
}

fn bds1(f: &mut Fields<'_>, _: &()) -> Result<()> {
    u24(f, "Section length")?;
    f.u8("Flags and unused bits")
        .hex()
        .with(|&v, n| {
            n.summary(format!(
                "{}, {}, {}{}; {} unused bits at end",
                if v & 0x80 != 0 {
                    "spherical harmonic coefficients"
                } else {
                    "grid point"
                },
                if v & 0x40 != 0 {
                    "complex packing"
                } else {
                    "simple packing"
                },
                if v & 0x20 != 0 {
                    "integer"
                } else {
                    "floating point"
                },
                if v & 0x10 != 0 {
                    ", additional flags"
                } else {
                    ""
                },
                v & 0x0f
            ))
        })
        .emit()?;
    f.u16("Binary scale factor (E)")
        .with(|&v, n| {
            n.value(Value::Int {
                value: signed(v.into(), 16),
                bits: 16,
            })
        })
        .emit()?;
    f.u32("Reference value (R)")
        .with(|&v, n| {
            n.value(Value::Float(ibm(&v.to_be_bytes()).unwrap_or(0.0)))
                .summary("IBM single precision")
        })
        .emit()?;
    f.u8("Bits per value").emit()?;
    let n = f.remaining();
    f.node(Node::new("Packed data").span(f.peek_span(n)));
    Ok(())
}

// ---------------------------------------------------------------------------
// Values

#[derive(Clone)]
struct Values {
    data: Span,
    packing: Packing,
    bitmap: Option<Span>,
    points: u64,
    grid: Option<Grid>,
}

fn values_node(label: String, ctx: &Context, data: Span) -> Node {
    let node = Node::new(label).span(data);
    match ctx.packing {
        Some(Packing::Simple { bits, .. }) if bits > 32 => {
            node.diag(Diagnostic::unsupported(format!("{bits} bits per value")))
        }
        Some(packing) => {
            // Never list more points than the bit-map or the data can hold
            // (a constant field, 0 bits per value, has no data at all).
            let bits = match packing {
                Packing::Simple { bits, .. } => u64::from(bits),
                Packing::Ieee { bytes } => u64::from(bytes).saturating_mul(8),
            };
            let capacity = match (ctx.bitmap, bits) {
                (Some(b), _) => b.len.saturating_mul(8),
                (None, 0) => MAX_CONSTANT_POINTS,
                (None, b) => data.len.saturating_mul(8).checked_div(b).unwrap_or(0),
            };
            let points = ctx.points.min(capacity);
            let mut node = node;
            if points < ctx.points {
                node = node.diag(Diagnostic::warning(format!(
                    "{} grid points, values for only {points}",
                    ctx.points
                )));
            }
            let summary = format!(
                "{} points{}",
                points,
                if ctx.bitmap.is_some() {
                    ", with bit-map"
                } else {
                    ""
                }
            );
            node.summary(summary).lazy(
                values,
                Values {
                    data,
                    packing,
                    bitmap: ctx.bitmap,
                    points,
                    grid: ctx.grid,
                },
            )
        }
        None => node.diag(Diagnostic::unsupported(
            "values packed other than simple packing or IEEE floats",
        )),
    }
}

impl Grid {
    fn label(&self, n: u64) -> Option<String> {
        if self.ni == 0 || self.nj == 0 || !self.dj.is_finite() {
            return None;
        }
        let (i, j) = if self.scan & 0x20 != 0 {
            (n.checked_div(self.nj)?, n.checked_rem(self.nj)?)
        } else {
            (n.checked_rem(self.ni)?, n.checked_div(self.ni)?)
        };
        let di = if self.scan & 0x80 != 0 {
            -self.di
        } else {
            self.di
        };
        let dj = if self.scan & 0x40 != 0 {
            self.dj
        } else {
            -self.dj
        };
        let lat = self.la1 + j as f64 * dj;
        let mut lon = self.lo1 + i as f64 * di;
        if lon >= 360.0 {
            lon -= 360.0;
        }
        Some(format!("({}, {})", num(lat), num(lon)))
    }
}

const PAGE: u64 = 256;
const MAX_CONSTANT_POINTS: u64 = 1 << 24;

async fn values(cx: Cx, v: Values) -> Result<()> {
    cx.set_count(Count::Exact(v.points));
    let (mut n, mut k) = cx.resume::<(u64, u64)>().unwrap_or((0, 0));
    let (bits, size) = match v.packing {
        Packing::Simple { bits, .. } => (u64::from(bits), 0u64),
        Packing::Ieee { bytes } => (u64::from(bytes).saturating_mul(8), u64::from(bytes)),
    };
    while n < v.points {
        let chunk = PAGE.min(v.points.saturating_sub(n));
        let bitmap = match v.bitmap {
            Some(b) => Some(
                cx.read_avail(b.sub(n / 8, chunk.saturating_add(15) / 8))
                    .await?,
            ),
            None => None,
        };
        let present = |m: u64| -> bool {
            match &bitmap {
                None => true,
                Some(bm) => {
                    let off = m.saturating_sub(n.saturating_sub(n % 8));
                    bits_at(bm, off, 1) == Some(1)
                }
            }
        };
        let needed = (n..n.saturating_add(chunk)).filter(|&m| present(m)).count();
        let first_bit = k.saturating_mul(bits);
        let byte0 = first_bit / 8;
        let packed = cx
            .read_avail(v.data.sub(
                byte0,
                to_u64(needed).saturating_mul(bits).saturating_add(15) / 8,
            ))
            .await?;
        for m in n..n.saturating_add(chunk) {
            let state = (m, k);
            cx.mark(move || state);
            let label = v
                .grid
                .and_then(|g| g.label(m))
                .map_or_else(|| format!("#{m}"), |l| format!("#{m} {l}"));
            let mut node = Node::new(label);
            if present(m) {
                let bit = k
                    .saturating_mul(bits)
                    .saturating_sub(byte0.saturating_mul(8));
                let at = byte0.saturating_add(bit / 8);
                let width = (bit % 8).saturating_add(bits).div_ceil(8);
                node = node.span(v.data.sub(at, width));
                let value = match v.packing {
                    Packing::Simple {
                        reference,
                        binary,
                        decimal,
                        bits: b,
                    } => bits_at(&packed, bit, b)
                        .map(|x| (reference + x as f64 * 2f64.powi(binary)) / 10f64.powi(decimal)),
                    Packing::Ieee { .. } => {
                        let o = usize::try_from(bit / 8).unwrap_or(usize::MAX);
                        match size {
                            4 => u32_be(&packed, o).map(|b| f64::from(f32::from_bits(b))),
                            _ => u64_be(&packed, o).map(f64::from_bits),
                        }
                    }
                };
                match value {
                    Some(x) => node = node.value(Value::Float(x)),
                    None => {
                        node = node.diag(Diagnostic::truncated(v.data.sub(at, width), 0));
                    }
                }
                k = k.saturating_add(1);
            } else {
                node = node.value(Value::Text("missing".into()));
            }
            cx.push(node).await;
        }
        n = n.saturating_add(chunk);
    }
    Ok(())
}
