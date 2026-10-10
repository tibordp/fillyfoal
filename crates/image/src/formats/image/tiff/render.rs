//! Values of TIFF, Exif, GPS and Interoperability tags as a person reads
//! them: f-numbers, exposure times, APEX values, coordinates in degrees,
//! character-coded comments, CFA patterns, matrices.

use crate::cx::Cx;
use crate::fields::Endian;
use crate::formats::util::val::uint;
use crate::value::{EnumTable, Value, decode_flags, lookup};

use super::super::tiff_tags::{
    EXTRA_SAMPLES, FILE_SOURCE, FLASH_FLAGS, GPS_ALTITUDE_REF, GPS_DIFFERENTIAL, SAMPLE_FORMAT,
    SCENE_TYPE, SUBFILE_FLAGS, T4_FLAGS, T6_FLAGS, enumeration,
};
use super::{Dir, Entry, Ifd, Ns, Num, Tiff, is_offset_tag, num, type_size};

/// How many values an entry's summary shows.
const PREVIEW: u64 = 16;
/// How much of a text value is read for the entry's value.
const TEXT_CAP: u64 = 1024;

/// The reference tags of a GPS IFD (hemispheres, units), and the CFA
/// pattern dimensions of a TIFF/EP IFD, which other tags' values need.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Refs {
    gps: [Option<u8>; 32],
    cfa: Option<(u64, u64)>,
}

impl Refs {
    fn gps(&self, tag: u16) -> Option<u8> {
        self.gps.get(usize::from(tag)).copied().flatten()
    }
}

pub(super) async fn refs(cx: &Cx, t: Tiff, dir: Dir, ifd: &Ifd) -> Refs {
    let mut r = Refs::default();
    for (i, e) in ifd.entries.iter().enumerate() {
        if i % 1024 == 1023 {
            cx.checkpoint().await;
        }
        match (dir, e.tag) {
            (Dir::Gps, 0x01 | 0x03 | 0x05 | 0x0c | 0x0e | 0x10 | 0x13 | 0x15 | 0x17 | 0x19) => {
                if let Ok(b) = cx.read_avail(e.data.sub(0, 1)).await
                    && let Some(&c) = b.first()
                    && let Some(slot) = r.gps.get_mut(usize::from(e.tag))
                    && slot.is_none()
                {
                    *slot = Some(c);
                }
            }
            (Dir::Main | Dir::Exif, 0x828d) => {
                let v = super::values_of(cx, t, e, 2).await;
                if let (Some(rows), Some(cols)) = (
                    v.first().and_then(|n| n.as_u64()),
                    v.get(1).and_then(|n| n.as_u64()),
                ) {
                    r.cfa = Some((rows, cols));
                }
            }
            _ => {}
        }
    }
    r
}

/// An entry's value and summary.
#[derive(Default)]
pub(super) struct Shown {
    pub(super) value: Option<Value>,
    pub(super) summary: Option<String>,
}

impl Shown {
    fn new(value: Value, summary: impl Into<String>) -> Shown {
        Shown {
            value: Some(value),
            summary: Some(summary.into()),
        }
    }

    fn text(text: impl Into<String>, summary: Option<String>) -> Shown {
        Shown {
            value: Some(Value::Text(text.into())),
            summary,
        }
    }
}

pub(super) async fn describe(cx: &Cx, t: Tiff, dir: Dir, e: &Entry, refs: &Refs) -> Shown {
    let preview_len = match e.kind {
        1 | 2 | 6 | 7 => e.size.min(TEXT_CAP),
        _ => type_size(e.kind).saturating_mul(e.count.min(PREVIEW)),
    };
    let Ok(bytes) = cx.read_avail(e.data.sub(0, preview_len)).await else {
        return Shown::default();
    };
    render(t, dir.ns(e.tag), e, &bytes, refs)
}

fn render(t: Tiff, ns: Ns, e: &Entry, bytes: &[u8], refs: &Refs) -> Shown {
    let values: Vec<Num> = (0..usize::try_from(e.count.min(PREVIEW)).unwrap_or(0))
        .map_while(|i| num(t, e.kind, bytes, i))
        .collect();
    let special = match ns {
        Ns::Main => main(t, e, bytes, &values, refs),
        Ns::Gps => gps(e, bytes, &values, refs),
        Ns::Interop => interop(e, bytes),
        Ns::Other(_) => None,
    };
    if let Some(shown) = special {
        return shown;
    }
    if e.kind == 2 {
        return Shown::text(ascii_text(bytes), None);
    }
    generic(ns, e, bytes, &values)
}

/// ASCII values: NUL-separated strings, UTF-8 when valid.
pub fn ascii_text(bytes: &[u8]) -> String {
    let parts: Vec<String> = bytes
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| match std::str::from_utf8(s) {
            Ok(text) => text.to_owned(),
            Err(_) => crate::text::latin1(s),
        })
        .collect();
    parts.join("; ")
}

/// A number with at most `decimals` decimals, trailing zeros removed.
pub fn trim(v: f64, decimals: usize) -> String {
    let s = format!("{v:.decimals$}");
    let s = if s.contains('.') {
        s.trim_end_matches('0').trim_end_matches('.').to_owned()
    } else {
        s
    };
    if s == "-0" { "0".to_owned() } else { s }
}

/// "1/250 s", "0.5 s", "30 s".
pub fn exposure_time(secs: f64) -> String {
    if !secs.is_finite() || secs <= 0.0 {
        return format!("{} s", trim(secs, 3));
    }
    if secs < 0.25001 {
        format!("1/{} s", trim((1.0 / secs).round(), 0))
    } else {
        format!("{} s", trim(secs, 1))
    }
}

/// "f/2.8", "f/4".
pub fn fnumber(f: f64) -> String {
    format!("f/{}", trim(f, 1))
}

/// An exposure value as a fraction of stops where it is one ("+1/3 EV",
/// "-1 2/3 EV", "0 EV").
fn ev(n: i64, d: i64) -> Option<String> {
    if d == 0 {
        return None;
    }
    if n == 0 {
        return Some("0 EV".to_owned());
    }
    let negative = (n < 0) != (d < 0);
    let (mut a, mut b) = (n.unsigned_abs(), d.unsigned_abs());
    let g = gcd(a, b);
    a = a.checked_div(g).unwrap_or(a);
    b = b.checked_div(g).unwrap_or(b);
    let sign = if negative { "-" } else { "+" };
    if b == 1 {
        return Some(format!("{sign}{a} EV"));
    }
    if b <= 3 {
        let whole = a.checked_div(b).unwrap_or(0);
        let rest = a.checked_rem(b).unwrap_or(0);
        return Some(if whole == 0 {
            format!("{sign}{rest}/{b} EV")
        } else {
            format!("{sign}{whole} {rest}/{b} EV")
        });
    }
    let v = super::f64_of(a) / super::f64_of(b);
    Some(format!("{sign}{} EV", trim(v, 2)))
}

fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let r = a.checked_rem(b).unwrap_or(0);
        a = b;
        b = r;
    }
    a.max(1)
}

/// "24-105mm f/4", "18-55mm f/3.5-5.6", "50mm f/1.8".
pub(super) fn lens_spec(v: &[Num]) -> Option<String> {
    let get = |i: usize| v.get(i).and_then(|n| n.f64()).filter(|x| *x > 0.0);
    let (min, max) = (get(0)?, get(1).unwrap_or(get(0)?));
    let focal = if (max - min).abs() < 0.05 {
        format!("{}mm", trim(min, 1))
    } else {
        format!("{}-{}mm", trim(min, 1), trim(max, 1))
    };
    Some(match (get(2), get(3)) {
        (Some(a), Some(b)) if (a - b).abs() >= 0.05 => {
            format!("{focal} f/{}-{}", trim(a, 1), trim(b, 1))
        }
        (Some(a), _) | (None, Some(a)) => format!("{focal} {}", fnumber(a)),
        (None, None) => focal,
    })
}

/// Degrees, minutes and seconds to a signed decimal and its text
/// ("48° 51' 29.64\" N").
pub(super) fn dms(v: &[Num], hemisphere: Option<u8>) -> Option<(f64, String)> {
    let d = v.first()?.f64()?;
    let m = v.get(1).and_then(|n| n.f64()).unwrap_or(0.0);
    let s = v.get(2).and_then(|n| n.f64()).unwrap_or(0.0);
    let decimal = d + m / 60.0 + s / 3600.0;
    let negative = matches!(hemisphere, Some(b'S' | b'W'));
    let letter = hemisphere
        .filter(u8::is_ascii_alphabetic)
        .map(|h| format!(" {}", char::from(h)))
        .unwrap_or_default();
    let text = if d.fract() == 0.0 && m.fract() == 0.0 {
        format!("{}° {}' {}\"{letter}", trim(d, 0), trim(m, 0), trim(s, 2))
    } else {
        format!("{}°{letter}", trim(decimal, 6))
    };
    Some((if negative { -decimal } else { decimal }, text))
}

/// "48.85823° N, 2.29450° E".
pub fn position(lat: f64, lon: f64) -> String {
    format!(
        "{:.5}° {}, {:.5}° {}",
        lat.abs(),
        if lat < 0.0 { 'S' } else { 'N' },
        lon.abs(),
        if lon < 0.0 { 'W' } else { 'E' }
    )
}

/// Text with an 8-byte character code in front (UserComment,
/// GPSProcessingMethod, GPSAreaInformation).
fn coded_text(bytes: &[u8], endian: Endian) -> (String, &'static str) {
    let (code, rest) = bytes.split_at_checked(8).unwrap_or((bytes, &[]));
    let trimmed = |s: String| s.trim_end_matches([' ', '\0']).to_owned();
    match code {
        b"ASCII\0\0\0" => (trimmed(crate::text::until_nul(rest)), "ASCII"),
        b"UNICODE\0" => {
            let (body, endian) = match rest {
                [0xfe, 0xff, body @ ..] => (body, Endian::Big),
                [0xff, 0xfe, body @ ..] => (body, Endian::Little),
                _ => (rest, endian),
            };
            (trimmed(crate::text::utf16z(body, endian).0), "Unicode")
        }
        b"JIS\0\0\0\0\0" => (trimmed(crate::text::latin1(rest)), "JIS"),
        _ if code.iter().all(|&b| b == 0) => (
            trimmed(String::from_utf8_lossy(rest).replace('\0', "")),
            "undefined character code",
        ),
        _ => (
            trimmed(String::from_utf8_lossy(bytes).replace('\0', "")),
            "no character code",
        ),
    }
}

fn cfa_colour(c: u64) -> char {
    match c {
        0 => 'R',
        1 => 'G',
        2 => 'B',
        3 => 'C',
        4 => 'M',
        5 => 'Y',
        6 => 'W',
        _ => '?',
    }
}

/// "RGGB", or rows separated by slashes for larger patterns.
fn cfa_pattern(rows: u64, cols: u64, colours: &[u8]) -> Option<String> {
    let n = usize::try_from(rows.checked_mul(cols)?).ok()?;
    if n == 0 || n > 64 || colours.len() < n {
        return None;
    }
    let cols = usize::try_from(cols).ok()?;
    let rows_text: Vec<String> = colours
        .get(..n)?
        .chunks(cols)
        .map(|row| row.iter().map(|&c| cfa_colour(c.into())).collect())
        .collect();
    Some(if rows == 2 && cols == 2 {
        rows_text.concat()
    } else {
        rows_text.join("/")
    })
}

/// "Fired, auto mode, return detected, red-eye reduction".
fn flash_text(v: u64) -> String {
    if v & 0x20 != 0 {
        return "No flash function".to_owned();
    }
    let mut parts = vec![if v & 1 != 0 { "Fired" } else { "Did not fire" }];
    match v & 0x18 {
        0x08 => parts.push("compulsory flash firing"),
        0x10 => parts.push("compulsory flash suppression"),
        0x18 => parts.push("auto mode"),
        _ => {}
    }
    match v & 0x06 {
        0x04 => parts.push("return not detected"),
        0x06 => parts.push("return detected"),
        _ => {}
    }
    if v & 0x40 != 0 {
        parts.push("red-eye reduction");
    }
    parts.join(", ")
}

/// "0232" → "2.32".
fn version_text(b: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(b.get(..4)?).ok()?;
    if !s.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let major: u32 = s.get(..2)?.parse().ok()?;
    Some(format!("{major}.{}", s.get(2..)?))
}

fn floats(values: &[Num], decimals: usize) -> Vec<String> {
    values
        .iter()
        .map(|n| n.f64().map_or_else(|| n.to_string(), |v| trim(v, decimals)))
        .collect()
}

/// Matrices (DNG colour matrices) as rows of three.
fn matrix(values: &[Num], count: u64) -> String {
    let cells = floats(values, 4);
    let rows: Vec<String> = cells.chunks(3).map(|r| r.join(" ")).collect();
    let more = if count > super::to_u64(values.len()) {
        " …"
    } else {
        ""
    };
    format!("[{}{more}]", rows.join("; "))
}

fn u(values: &[Num], i: usize) -> Option<u64> {
    values.get(i).and_then(|n| n.as_u64())
}

fn f(values: &[Num], i: usize) -> Option<f64> {
    values.get(i).and_then(|n| n.f64())
}

/// The first value as a float, for single-valued tags.
fn single(values: &[Num]) -> Option<(Value, f64)> {
    let v = *values.first()?;
    Some((v.to_value(false), v.f64()?))
}

fn main(t: Tiff, e: &Entry, bytes: &[u8], values: &[Num], refs: &Refs) -> Option<Shown> {
    let one = e.count == 1;
    Some(match e.tag {
        0x829a if one => {
            let (v, x) = single(values)?;
            Shown::new(v, exposure_time(x))
        }
        0x829d if one => {
            let (v, x) = single(values)?;
            Shown::new(v, fnumber(x))
        }
        // APEX values.
        0x9202 | 0x9205 if one => {
            let (v, x) = single(values)?;
            Shown::new(
                v,
                format!("{} (APEX {})", fnumber(2f64.powf(x / 2.0)), trim(x, 2)),
            )
        }
        0x9201 if one => {
            let (v, x) = single(values)?;
            Shown::new(
                v,
                format!("{} (APEX {})", exposure_time(2f64.powf(-x)), trim(x, 2)),
            )
        }
        0x9203 if one => {
            let (v, x) = single(values)?;
            Shown::new(v, format!("{} EV", trim(x, 2)))
        }
        0x9204 if one => {
            let (v, _) = single(values)?;
            let text = match values.first()? {
                Num::S(n, d) => ev(*n, *d)?,
                Num::R(n, d) => ev(i64::try_from(*n).ok()?, i64::try_from(*d).ok()?)?,
                other => format!("{} EV", other.short()),
            };
            Shown::new(v, text)
        }
        0xc62a | 0xc7a5 if one => {
            let (v, x) = single(values)?;
            Shown::new(
                v,
                format!("{}{} EV", if x > 0.0 { "+" } else { "" }, trim(x, 2)),
            )
        }
        0x9206 if one => {
            let v = *values.first()?;
            let text = match v {
                Num::R(0, _) => "unknown".to_owned(),
                Num::R(0xffff_ffff, _) => "infinity".to_owned(),
                _ => format!("{} m", trim(v.f64()?, 2)),
            };
            Shown::new(v.to_value(false), text)
        }
        0x920a if one => {
            let (v, x) = single(values)?;
            Shown::new(v, format!("{} mm", trim(x, 1)))
        }
        0xa405 if one => {
            let (v, x) = single(values)?;
            Shown::new(v, format!("{} mm (35 mm equivalent)", trim(x, 1)))
        }
        0xa404 if one => {
            let v = *values.first()?;
            let text = match v.f64() {
                Some(x) if x > 0.0 => format!("{}×", trim(x, 2)),
                _ => "not used".to_owned(),
            };
            Shown::new(v.to_value(false), text)
        }
        0x8827 | 0x8831 | 0x8832 | 0x8833 if one => {
            let v = *values.first()?;
            Shown::new(v.to_value(false), format!("ISO {}", v.short()))
        }
        0x9400 if one => unit(values, "°C")?,
        0x9401 if one => unit(values, "%")?,
        0x9402 if one => unit(values, "hPa")?,
        0x9403 if one => unit(values, "m")?,
        0x9404 if one => unit(values, "mGal")?,
        0x9405 if one => unit(values, "°")?,
        0x9000 | 0xa000 => Shown::text(crate::text::latin1(bytes), version_text(bytes)),
        0xc612 | 0xc613 | 0xc7a1 if e.kind == 1 && e.count == 4 => Shown::text(
            bytes
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join("."),
            None,
        ),
        0x9101 => {
            let names: String = bytes
                .iter()
                .take(4)
                .filter_map(|&c| match c {
                    1 => Some("Y"),
                    2 => Some("Cb"),
                    3 => Some("Cr"),
                    4 => Some("R"),
                    5 => Some("G"),
                    6 => Some("B"),
                    _ => None,
                })
                .collect();
            Shown::new(Value::Bytes(bytes.to_vec()), names)
        }
        0x9214 => {
            let text = match (values.len(), e.count) {
                (2, 2) => format!("point ({}, {})", u(values, 0)?, u(values, 1)?),
                (3, 3) => format!(
                    "circle at ({}, {}), diameter {}",
                    u(values, 0)?,
                    u(values, 1)?,
                    u(values, 2)?
                ),
                (4, 4) => format!(
                    "rectangle at ({}, {}), {}",
                    u(values, 0)?,
                    u(values, 1)?,
                    super::dims(u(values, 2)?, u(values, 3)?)
                ),
                _ => return None,
            };
            Shown {
                value: None,
                summary: Some(text),
            }
        }
        0xa214 if e.count == 2 => Shown {
            value: None,
            summary: Some(format!("({}, {})", u(values, 0)?, u(values, 1)?)),
        },
        0xa432 | 0xc630 => Shown {
            value: lens_spec(values).map(Value::Text),
            summary: Some(format!("[{}]", floats(values, 2).join(", "))),
        },
        0x9286 => {
            let (text, code) = coded_text(bytes, t.endian);
            Shown::text(text, Some(code.to_owned()))
        }
        0x9c9b..=0x9c9f => Shown::text(crate::text::utf16z(bytes, Endian::Little).0, None),
        0xa300 if one => enumerated(bytes.first().copied()?.into(), 8, FILE_SOURCE),
        0xa301 if one => enumerated(bytes.first().copied()?.into(), 8, SCENE_TYPE),
        0xa302 => {
            // Two SHORTs (repeat dimensions) in the stream's byte order,
            // then one byte per cell; some writers swap the SHORTs' order.
            let dim = |at: usize, endian| {
                bytes
                    .get(at..at.checked_add(2)?)
                    .and_then(|b| <u16 as crate::fields::Prim>::decode(b, endian))
            };
            let colours = bytes.get(4..).unwrap_or_default();
            let other = if t.endian == Endian::Little {
                Endian::Big
            } else {
                Endian::Little
            };
            let fits =
                |c: u16, r: u16| usize::from(c).saturating_mul(usize::from(r)) == colours.len();
            let (cols, rows) = match (dim(0, t.endian), dim(2, t.endian)) {
                (Some(c), Some(r)) if fits(c, r) => (c, r),
                _ => (dim(0, other)?, dim(2, other)?),
            };
            Shown {
                value: Some(Value::Bytes(bytes.to_vec())),
                summary: cfa_pattern(rows.into(), cols.into(), colours),
            }
        }
        0x828e => {
            let (rows, cols) = refs.cfa.unwrap_or((2, 2));
            Shown {
                value: Some(Value::Bytes(bytes.to_vec())),
                summary: cfa_pattern(rows, cols, bytes),
            }
        }
        0xc616 => Shown::new(
            Value::Bytes(bytes.to_vec()),
            bytes
                .iter()
                .map(|&c| cfa_colour(c.into()))
                .collect::<String>(),
        ),
        0x9209 if one => {
            let raw = values.first()?.as_u64()?;
            let (set, unknown) = decode_flags(FLASH_FLAGS, raw);
            Shown::new(
                Value::Flags {
                    raw,
                    bits: 16,
                    set,
                    unknown,
                },
                flash_text(raw),
            )
        }
        0x00fe | 0x0124 | 0x0125 if one => {
            let raw = values.first()?.as_u64()?;
            let table = match e.tag {
                0x00fe => SUBFILE_FLAGS,
                0x0124 => T4_FLAGS,
                _ => T6_FLAGS,
            };
            let (set, unknown) = decode_flags(table, raw);
            Shown {
                value: Some(Value::Flags {
                    raw,
                    bits: 32,
                    set,
                    unknown,
                }),
                summary: None,
            }
        }
        0x0212 if e.count == 2 => {
            let text = match (u(values, 0)?, u(values, 1)?) {
                (1, 1) => "4:4:4",
                (2, 1) => "4:2:2",
                (2, 2) => "4:2:0",
                (4, 1) => "4:1:1",
                (4, 2) => "4:1:0",
                _ => return None,
            };
            Shown {
                value: None,
                summary: Some(format!("{text} ({}, {})", u(values, 0)?, u(values, 1)?)),
            }
        }
        0x0129 if e.count == 2 => Shown {
            value: None,
            summary: Some(match u(values, 1)? {
                0 => format!("page {}", u(values, 0)?.saturating_add(1)),
                total => format!("page {} of {total}", u(values, 0)?.saturating_add(1)),
            }),
        },
        0x4746 if one => {
            let v = u(values, 0)?;
            Shown::new(uint(v, 64), format!("{v} of 5 stars"))
        }
        0xc621..=0xc626 | 0xc714 | 0xc715 | 0xcd32..=0xcd34 | 0xcd3a | 0xc690 | 0xc692 => Shown {
            value: None,
            summary: Some(matrix(values, e.count)),
        },
        0xc627..=0xc629 => Shown {
            value: None,
            summary: Some(format!("[{}]", floats(values, 4).join(", "))),
        },
        0xc68d if e.count == 4 => {
            let (top, left, bottom, right) =
                (u(values, 0)?, u(values, 1)?, u(values, 2)?, u(values, 3)?);
            Shown {
                value: None,
                summary: Some(format!(
                    "{} at ({left}, {top})",
                    super::dims(right.saturating_sub(left), bottom.saturating_sub(top))
                )),
            }
        }
        0xc620 | 0xc791..=0xc793 if e.count == 2 => Shown {
            value: None,
            summary: Some(super::dims(trim(f(values, 0)?, 2), trim(f(values, 1)?, 2))),
        },
        0xc61f if e.count == 2 => Shown {
            value: None,
            summary: Some(format!(
                "({}, {})",
                trim(f(values, 0)?, 2),
                trim(f(values, 1)?, 2)
            )),
        },
        0x87af if e.count >= 4 => Shown {
            value: None,
            summary: Some(format!(
                "GeoTIFF {}.{}.{}, {} keys",
                u(values, 0)?,
                u(values, 1)?,
                u(values, 2)?,
                u(values, 3)?
            )),
        },
        _ => return None,
    })
}

fn unit(values: &[Num], unit: &str) -> Option<Shown> {
    let (v, x) = single(values)?;
    Some(Shown::new(v, format!("{} {unit}", trim(x, 2))))
}

fn enumerated(raw: u64, bits: u8, table: EnumTable) -> Shown {
    Shown {
        value: Some(Value::Enum {
            raw,
            bits,
            name: lookup(table, raw),
        }),
        summary: None,
    }
}

fn gps(e: &Entry, bytes: &[u8], values: &[Num], refs: &Refs) -> Option<Shown> {
    let one = e.count == 1;
    let letter = |tag: u16| refs.gps(tag);
    Some(match e.tag {
        0x00 => Shown::text(
            bytes
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join("."),
            None,
        ),
        0x02 | 0x04 | 0x14 | 0x16 => {
            let reference = letter(e.tag.saturating_sub(1));
            let (decimal, text) = dms(values, reference)?;
            Shown::new(Value::Float(decimal), text)
        }
        0x05 if one => enumerated(u(values, 0)?, 8, GPS_ALTITUDE_REF),
        0x06 if one => {
            let x = f(values, 0)?;
            let below = matches!(letter(0x05), Some(1 | 3));
            let text = match letter(0x05) {
                Some(1) => format!("{} m below sea level", trim(x, 2)),
                Some(2) => format!("{} m above the ellipsoid", trim(x, 2)),
                Some(3) => format!("{} m below the ellipsoid", trim(x, 2)),
                _ => format!("{} m above sea level", trim(x, 2)),
            };
            Shown::new(Value::Float(if below { -x } else { x }), text)
        }
        0x07 if e.count == 3 => {
            let (h, m, s) = (f(values, 0)?, f(values, 1)?, f(values, 2)?);
            let seconds = if s.fract() == 0.0 {
                format!("{:0>2}", trim(s, 0))
            } else {
                format!("{:0>5}", trim(s, 3))
            };
            Shown::text(
                format!("{:0>2}:{:0>2}:{seconds}", trim(h, 0), trim(m, 0)),
                Some("UTC".to_owned()),
            )
        }
        0x0d if one => {
            let unit = match letter(0x0c) {
                Some(b'M') => "mph",
                Some(b'N') => "knots",
                _ => "km/h",
            };
            unit_of(values, unit)?
        }
        0x0f | 0x11 | 0x18 if one => {
            let north = match letter(e.tag.saturating_sub(1)) {
                Some(b'M') => " (magnetic)",
                Some(b'T') => " (true)",
                _ => "",
            };
            let (v, x) = single(values)?;
            Shown::new(v, format!("{}°{north}", trim(x, 2)))
        }
        0x1a if one => {
            let unit = match letter(0x19) {
                Some(b'M') => "miles",
                Some(b'N') => "nautical miles",
                _ => "km",
            };
            unit_of(values, unit)?
        }
        0x1f if one => unit_of(values, "m")?,
        0x1b | 0x1c => {
            let (text, code) = coded_text(bytes, Endian::Big);
            Shown::text(text, Some(code.to_owned()))
        }
        0x1e if one => enumerated(u(values, 0)?, 16, GPS_DIFFERENTIAL),
        _ if e.kind == 2 => {
            let text = ascii_text(bytes);
            let meaning = match (e.tag, text.as_str()) {
                (0x01 | 0x13, "N") => Some("North"),
                (0x01 | 0x13, "S") => Some("South"),
                (0x03 | 0x15, "E") => Some("East"),
                (0x03 | 0x15, "W") => Some("West"),
                (0x09, "A") => Some("Measurement in progress"),
                (0x09, "V") => Some("Measurement interrupted"),
                (0x0a, "2") => Some("2-dimensional"),
                (0x0a, "3") => Some("3-dimensional"),
                (0x0c, "K") => Some("km/h"),
                (0x0c, "M") => Some("mph"),
                (0x0c, "N") => Some("knots"),
                (0x0e | 0x10 | 0x17, "T") => Some("True north"),
                (0x0e | 0x10 | 0x17, "M") => Some("Magnetic north"),
                (0x19, "K") => Some("Kilometres"),
                (0x19, "M") => Some("Miles"),
                (0x19, "N") => Some("Nautical miles"),
                _ => None,
            };
            Shown::text(text, meaning.map(str::to_owned))
        }
        _ => return None,
    })
}

fn unit_of(values: &[Num], unit: &str) -> Option<Shown> {
    let (v, x) = single(values)?;
    Some(Shown::new(v, format!("{} {unit}", trim(x, 2))))
}

fn interop(e: &Entry, bytes: &[u8]) -> Option<Shown> {
    Some(match e.tag {
        0x0001 if e.kind == 2 => {
            let text = ascii_text(bytes);
            let meaning = match text.as_str() {
                "R98" => Some("Exif R98: DCF basic file (sRGB)"),
                "THM" => Some("DCF thumbnail file"),
                "R03" => Some("DCF option file (Adobe RGB)"),
                _ => None,
            };
            Shown::text(text, meaning.map(str::to_owned))
        }
        0x0002 => Shown::text(crate::text::latin1(bytes), version_text(bytes)),
        _ => return None,
    })
}

/// Anything else: text for printable byte strings, enumerations and flags,
/// numbers.
fn generic(ns: Ns, e: &Entry, bytes: &[u8], values: &[Num]) -> Shown {
    let main = ns == Ns::Main;
    if matches!(e.kind, 1 | 7) && e.count > 1 {
        let printable = bytes
            .iter()
            .all(|&b| b.is_ascii_graphic() || b == b' ' || b == 0);
        if printable && e.count <= 64 && bytes.first().is_some_and(u8::is_ascii_graphic) {
            return Shown::text(crate::text::until_nul(bytes), None);
        }
        let shown = bytes
            .get(..bytes.len().min(32))
            .unwrap_or_default()
            .to_vec();
        return Shown::new(Value::Bytes(shown), format!("{} bytes", e.count));
    }
    let table = if main { enumeration(e.tag) } else { None };
    if e.count == 1
        && let Some(&v) = values.first()
    {
        if let (Some(table), Some(raw)) = (table, v.as_u64()) {
            let bits = u8::try_from(type_size(e.kind).saturating_mul(8)).unwrap_or(64);
            return enumerated(raw, bits, table);
        }
        let summary = match v {
            Num::R(_, d) if d != 1 => Some(v.to_string()),
            Num::S(_, d) if d != 1 => Some(v.to_string()),
            _ => None,
        };
        return Shown {
            value: Some(v.to_value((main && is_offset_tag(e.tag)) || e.kind == 13)),
            summary,
        };
    }
    let table = table.or(match e.tag {
        0x0153 if main => Some(SAMPLE_FORMAT),
        0x0152 if main => Some(EXTRA_SAMPLES),
        _ => None,
    });
    let mut list: Vec<String> = values
        .iter()
        .map(|v| match (table, v.as_u64()) {
            (Some(table), Some(raw)) => {
                lookup(table, raw).map_or_else(|| raw.to_string(), str::to_owned)
            }
            _ if main && is_offset_tag(e.tag) => {
                v.as_u64().map_or_else(|| v.short(), |o| format!("{o:#x}"))
            }
            _ => v.short(),
        })
        .collect();
    if e.count > PREVIEW {
        list.push(format!("… ({} values)", e.count));
    }
    Shown {
        value: None,
        summary: Some(format!("[{}]", list.join(", "))),
    }
}
