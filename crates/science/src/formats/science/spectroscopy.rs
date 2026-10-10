//! Spectroscopy and diffraction data: Thermo Galactic SPC spectra, NMRPipe
//! and Sparky NMR spectra, and Rigaku RAS diffraction scans.

use super::{field_text, kv_spans};
use crate::bytes::{to_u64, to_usize, u32_be, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Record, read_record};
use crate::error::Result;
use crate::fields::{Endian, Fields};
use crate::formats::util::lines::{Lines, float32, text, uint};
use crate::formats::{Head, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, flag, lookup};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// Thermo Galactic SPC spectra

fn spc_probe(h: &Head<'_>) -> bool {
    let (Some(&version), Some(&exper)) = (h.data.get(1), h.data.get(2)) else {
        return false;
    };
    let npts = u32_le(h.data, 4).unwrap_or(u32::MAX);
    version == 0x4b
        && exper <= 14
        && h.len >= 512
        && u64::from(npts).saturating_mul(2) <= h.len
        && h.data.get(28).is_some_and(|&x| x < 64)
        && h.data.get(29).is_some_and(|&y| !(64..128).contains(&y))
}

declare_format!(pub GALACTIC_SPC = "galactic-spc", "Thermo Galactic SPC spectrum", ["spc"], "chemical/x-galactic-spc",
    Probe::Custom(spc_probe), galactic_spc);

const SPC_FLAGS: FlagTable = &[
    flag(0x01, "TSPREC (16-bit Y)"),
    flag(0x02, "TCGRAM"),
    flag(0x04, "TMULTI (multiple subfiles)"),
    flag(0x08, "TRANDM"),
    flag(0x10, "TORDRD"),
    flag(0x20, "TALABS (axis labels)"),
    flag(0x40, "TXYXYS (separate X per subfile)"),
    flag(0x80, "TXVALS (X array)"),
];
const SPC_EXPERIMENTS: EnumTable = &[
    (0, "general"),
    (1, "gas chromatogram"),
    (2, "chromatogram"),
    (3, "HPLC chromatogram"),
    (4, "FT-IR, FT-NIR, FT-Raman"),
    (5, "NIR"),
    (7, "UV-VIS"),
    (8, "X-ray diffraction"),
    (9, "mass spectrum"),
    (10, "NMR"),
    (11, "Raman"),
    (12, "fluorescence"),
    (13, "atomic"),
    (14, "chromatography diode array"),
];
const SPC_XUNITS: EnumTable = &[
    (0, "arbitrary"),
    (1, "wavenumber (cm⁻¹)"),
    (2, "micrometers"),
    (3, "nanometers"),
    (4, "seconds"),
    (5, "minutes"),
    (6, "hertz"),
    (7, "kilohertz"),
    (8, "megahertz"),
    (9, "mass (m/z)"),
    (10, "ppm"),
    (11, "days"),
    (12, "years"),
    (13, "Raman shift (cm⁻¹)"),
    (14, "electron volts"),
    (16, "diode number"),
    (17, "channel"),
    (18, "degrees"),
    (19, "°F"),
    (20, "°C"),
    (21, "K"),
    (22, "data points"),
    (23, "milliseconds"),
    (24, "microseconds"),
    (25, "nanoseconds"),
    (26, "gigahertz"),
    (27, "centimeters"),
    (28, "meters"),
    (29, "millimeters"),
    (30, "hours"),
];
const SPC_YUNITS: EnumTable = &[
    (0, "arbitrary intensity"),
    (1, "interferogram"),
    (2, "absorbance"),
    (3, "Kubelka-Munk"),
    (4, "counts"),
    (5, "volts"),
    (6, "degrees"),
    (7, "milliamps"),
    (8, "millimeters"),
    (9, "millivolts"),
    (10, "log(1/R)"),
    (11, "percent"),
    (12, "intensity"),
    (13, "relative intensity"),
    (14, "energy"),
    (16, "decibel"),
    (19, "°F"),
    (20, "°C"),
    (21, "K"),
    (22, "index of refraction"),
    (23, "extinction coefficient"),
    (24, "real"),
    (25, "imaginary"),
    (26, "complex"),
    (128, "transmission"),
    (129, "reflectance"),
    (130, "arbitrary (valley peaks)"),
    (131, "emission"),
];

record! {
    pub struct SpcHeader {
        flags: u8 "ftflgs" .flags(SPC_FLAGS),
        version: u8 "fversn" .hex(),
        experiment: u8 "fexper" .enumeration(SPC_EXPERIMENTS),
        exponent: i8 "fexp" .desc("Y exponent; -128 means IEEE floats"),
        points: u32 "fnpts",
        first: f64 "ffirst",
        last: f64 "flast",
        subfiles: u32 "fnsub",
        xtype: u8 "fxtype" .enumeration(SPC_XUNITS),
        ytype: u8 "fytype" .enumeration(SPC_YUNITS),
        ztype: u8 "fztype" .enumeration(SPC_XUNITS),
        post: u8 "fpost",
        date: u32 "fdate" .hex().desc("Packed: year<<20 | month<<16 | day<<11 | hour<<6 | minute"),
        resolution: ascii[9] "fres",
        source: ascii[9] "fsource",
        peak: u16 "fpeakpt",
        spare: bytes[32] "fspare",
        comment: ascii[130] "fcmnt",
        axis_labels: ascii[30] "fcatxt",
        log_offset: u32 "flogoff" .hex(),
        mods: u32 "fmods" .hex(),
        procs: u8 "fprocs",
        level: u8 "flevel",
        sampin: u16 "fsampin",
        factor: f32 "ffactor",
        method: ascii[48] "fmethod",
        zinc: f32 "fzinc",
        wplanes: u32 "fwplanes",
        winc: f32 "fwinc",
        wtype: u8 "fwtype",
    }
}

async fn galactic_spc(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let hs = file.sub(0, SpcHeader::SIZE);
    let h: SpcHeader = read_record(&cx, hs, LE).await?;
    cx.emit(SpcHeader::node("Header", hs, LE));
    let mut at = 512u64;
    let points = u64::from(h.points);
    if h.flags & 0x80 != 0 && h.flags & 0x40 == 0 {
        cx.emit(
            Node::new("X values")
                .span(file.sub(at, points.saturating_mul(4)))
                .summary(format!("{points} float32")),
        );
        at = at.saturating_add(points.saturating_mul(4));
    }
    let ysize: u64 = if h.flags & 0x01 != 0 { 2 } else { 4 };
    let subs = if h.flags & 0x04 != 0 {
        u64::from(h.subfiles.max(1))
    } else {
        1
    };
    let mut list = Vec::new();
    for i in 0..subs.min(100_000) {
        if at.saturating_add(32) > file.len {
            break;
        }
        let sub = cx.read(file.sub(at, 32)).await?;
        let sub_points = match u32_le(&sub, 16) {
            Some(n) if n > 0 && h.flags & 0x40 != 0 => u64::from(n),
            _ => points,
        };
        let xs = if h.flags & 0x40 != 0 {
            sub_points.saturating_mul(4)
        } else {
            0
        };
        let len = 32u64
            .saturating_add(xs)
            .saturating_add(sub_points.saturating_mul(ysize));
        list.push((i, file.sub(at, len), sub_points));
        at = at.saturating_add(len);
        cx.checkpoint().await;
    }
    let n = to_u64(list.len());
    cx.emit(
        Node::new("Subfiles")
            .value(uint(n))
            .lazy(spc_subfiles, (list, h.exponent, ysize, h.flags & 0x40 != 0)),
    );
    if h.log_offset != 0 {
        cx.emit(Node::new("Log block").span(file.tail(h.log_offset.into())));
    }
    let date = h.date;
    cx.annotate(format!(
        "Galactic SPC, {} ({}), {points} point(s) from {} to {}{}, {n} subfile(s){}",
        lookup(SPC_EXPERIMENTS, h.experiment.into()).unwrap_or("experiment"),
        lookup(SPC_YUNITS, h.ytype.into()).unwrap_or("?"),
        h.first,
        h.last,
        lookup(SPC_XUNITS, h.xtype.into())
            .map(|u| format!(" {u}"))
            .unwrap_or_default(),
        if date == 0 {
            String::new()
        } else {
            format!(
                ", {:04}-{:02}-{:02}",
                date >> 20,
                (date >> 16) & 0xf,
                (date >> 11) & 0x1f
            )
        }
    ));
    Ok(())
}

async fn spc_subfiles(
    cx: Cx,
    (list, exponent, ysize, xy): (Vec<(u64, Span, u64)>, i8, u64, bool),
) -> Result<()> {
    for (i, span, points) in list {
        let ydata = span.tail(32u64.saturating_add(if xy { points.saturating_mul(4) } else { 0 }));
        let b = cx.read_avail(ydata.sub(0, ysize.saturating_mul(6))).await?;
        let shown: Vec<String> = b
            .chunks(to_usize(ysize))
            .filter(|c| to_u64(c.len()) == ysize)
            .map(|c| {
                if ysize == 2 {
                    i16::from_le_bytes([
                        c.first().copied().unwrap_or(0),
                        c.get(1).copied().unwrap_or(0),
                    ])
                    .to_string()
                } else if exponent == -128 {
                    f32::from_le_bytes(crate::bytes::array(c, 0).unwrap_or_default()).to_string()
                } else {
                    // Fixed point: value × 2^(exponent − 32).
                    let raw = f64::from(i32::from_le_bytes(
                        crate::bytes::array(c, 0).unwrap_or_default(),
                    ));
                    (raw * 2f64.powi(i32::from(exponent).saturating_sub(32))).to_string()
                }
            })
            .collect();
        cx.push(
            Node::new(format!("Subfile {i}"))
                .span(span)
                .summary(format!(
                    "{points} point(s): {}{}",
                    shown.join(", "),
                    if points > 6 { ", …" } else { "" }
                ))
                .lazy(spc_subheader, span.sub(0, 32)),
        )
        .await;
    }
    Ok(())
}

async fn spc_subheader(cx: Cx, span: Span) -> Result<()> {
    let b = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &b, LE);
    f.u8("subflgs").hex().emit()?;
    f.int::<i8>("subexp").emit()?;
    f.u16("subindx").emit()?;
    f.f32("subtime").emit()?;
    f.f32("subnext").emit()?;
    f.f32("subnois").emit()?;
    f.u32("subnpts").emit()?;
    f.u32("subscan").emit()?;
    f.f32("subwlevel").emit()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// NMRPipe and Sparky NMR spectra

fn nmrpipe_order(h: &[u8]) -> Option<Endian> {
    let near = |v: f32| (v - 2.345).abs() < 1e-4;
    if u32_le(h, 8).is_some_and(|v| near(f32::from_bits(v))) {
        Some(LE)
    } else if u32_be(h, 8).is_some_and(|v| near(f32::from_bits(v))) {
        Some(BE)
    } else {
        None
    }
}

declare_format!(pub NMRPIPE = "nmrpipe", "NMRPipe spectrum", ["fid", "ft", "ft1", "ft2", "ft3", "pipe", "dat"], "chemical/x-nmrpipe",
    Probe::Custom(|h| h.at(0, b"\0\0\0\0") && nmrpipe_order(h.data).is_some() && h.len >= 2048), nmrpipe);

/// (name, float index) of notable NMRPipe header fields.
const NMRPIPE_FIELDS: &[(&str, usize)] = &[
    ("FDDIMCOUNT", 9),
    ("FDDIMORDER1", 24),
    ("FDDIMORDER2", 25),
    ("FDF2SW (Hz)", 100),
    ("FDF2OBS (MHz)", 119),
    ("FDF2ORIG (Hz)", 101),
    ("FDF2CAR (ppm)", 66),
    ("FDF2FTFLAG", 220),
    ("FDF2QUADFLAG", 56),
    ("FDF1SW (Hz)", 229),
    ("FDF1OBS (MHz)", 218),
    ("FDF1ORIG (Hz)", 249),
    ("FDF1CAR (ppm)", 67),
    ("FDF1FTFLAG", 222),
    ("FDSIZE (points)", 99),
    ("FDSPECNUM (traces)", 219),
    ("FDQUADFLAG", 106),
    ("FDTRANSPOSED", 221),
    ("FDPIPEFLAG", 57),
    ("FDYEAR", 296),
    ("FDMONTH", 294),
    ("FDDAY", 295),
];

async fn nmrpipe(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 2048)).await?;
    let endian = nmrpipe_order(&head).unwrap_or(LE);
    let get = |i: usize| {
        let o = i.saturating_mul(4);
        f32::from_bits(
            match endian {
                Endian::Little => u32_le(&head, o),
                Endian::Big => u32_be(&head, o),
            }
            .unwrap_or(0),
        )
    };
    let label = |i: usize| {
        field_text(
            head.get(i.saturating_mul(4)..i.saturating_mul(4).saturating_add(8))
                .unwrap_or_default(),
        )
    };
    cx.emit(
        Node::new("FDFLTORDER")
            .span(file.sub(8, 4))
            .value(float32(get(2)))
            .desc("2.345, for byte order detection"),
    );
    for &(name, i) in NMRPIPE_FIELDS {
        cx.emit(
            Node::new(name)
                .span(file.sub(to_u64(i).saturating_mul(4), 4))
                .value(float32(get(i))),
        );
    }
    cx.emit(
        Node::new("FDF2LABEL")
            .span(file.sub(64, 8))
            .value(text(label(16))),
    );
    cx.emit(
        Node::new("FDF1LABEL")
            .span(file.sub(72, 8))
            .value(text(label(18))),
    );
    cx.emit(Node::new("Data").span(file.tail(2048)));
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let dims = get(9) as u32;
    cx.annotate(format!(
        "NMRPipe {dims}D spectrum ({} endian), {} × {} points, F2 {} {} MHz{}",
        if endian == LE { "little" } else { "big" },
        get(99),
        get(219),
        label(16),
        get(119),
        if get(220) != 0.0 {
            ", frequency domain"
        } else {
            ", time domain"
        }
    ));
    Ok(())
}

declare_format!(pub SPARKY = "sparky-ucsf", "Sparky/UCSF NMR spectrum", ["ucsf"], "chemical/x-ucsf-nmr",
    Probe::Magic(&[(0, b"UCSF NMR\0")]), sparky);

record! {
    pub struct SparkyAxis {
        nucleus: ascii[6] "Nucleus",
        pad: bytes[2] "Padding",
        points: u32 "Points",
        pad2: bytes[4] "Padding",
        tile: u32 "Tile size",
        frequency: f32 "Spectrometer frequency (MHz)",
        width: f32 "Spectral width (Hz)",
        center: f32 "Center (ppm)",
    }
}

async fn sparky(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 14)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Magic", 10).emit()?;
    let dims = f.u8("Dimensions").emit()?;
    f.u8("Components").emit()?;
    f.u8("Padding").emit()?;
    f.u8("Format version").emit()?;
    let mut axes = Vec::new();
    for i in 0..u64::from(dims.min(8)) {
        let s = file.sub(180u64.saturating_add(i.saturating_mul(128)), 128);
        let a: SparkyAxis = read_record(&cx, s.sub(0, SparkyAxis::SIZE), BE).await?;
        cx.emit(
            SparkyAxis::node(format!("Axis {}", i.saturating_add(1)), s, BE).summary(format!(
                "{} {} points, {} MHz",
                a.nucleus.trim_end_matches('\0'),
                a.points,
                a.frequency
            )),
        );
        axes.push(format!("{} {}", a.nucleus.trim_end_matches('\0'), a.points));
    }
    let data = 180u64.saturating_add(u64::from(dims).saturating_mul(128));
    cx.emit(Node::new("Data (tiles)").span(file.tail(data)));
    cx.annotate(format!("Sparky {dims}D NMR spectrum: {}", axes.join(" × ")));
    Ok(())
}

// ---------------------------------------------------------------------------
// Rigaku RAS diffraction data

declare_format!(pub RIGAKU_RAS = "rigaku-ras", "Rigaku RAS diffraction data", ["ras"], "text/x-rigaku-ras",
    Probe::Custom(|h| h.starts_with(b"*RAS_DATA_START")), rigaku_ras);

async fn rigaku_ras(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut header: Vec<(String, String, Span)> = Vec::new();
    let mut in_header = false;
    let mut data_start = None;
    let mut points = 0u64;
    let mut scans = 0u32;
    let (mut first, mut last) = (String::new(), String::new());
    while let Some(line) = lines.next().await? {
        cx.progress_in(file, file.offset.saturating_add(lines.pos()));
        let t = line.text();
        let t = t.trim();
        match t {
            "*RAS_HEADER_START" => in_header = true,
            "*RAS_HEADER_END" => in_header = false,
            "*RAS_INT_START" => data_start = Some((line.pos, 0u64)),
            "*RAS_INT_END" => {
                if let Some((start, n)) = data_start.take() {
                    let span = file.sub(start, lines.pos().saturating_sub(start));
                    cx.push(
                        Node::new(format!("Scan {scans}"))
                            .span(span)
                            .value(uint(n))
                            .summary(format!("{first}–{last}")),
                    )
                    .await;
                    scans = scans.saturating_add(1);
                    points = points.saturating_add(n);
                }
            }
            _ if in_header => {
                if let Some(rest) = t.strip_prefix('*') {
                    let (k, v) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
                    if header.len() < 4096 {
                        header.push((
                            k.to_owned(),
                            v.trim().trim_matches('"').to_owned(),
                            line.content(),
                        ));
                    }
                }
            }
            _ => {
                if let Some((_, n)) = data_start.as_mut()
                    && !t.is_empty()
                {
                    let x = t.split_whitespace().next().unwrap_or_default().to_owned();
                    if *n == 0 {
                        first.clone_from(&x);
                    }
                    last = x;
                    *n = n.saturating_add(1);
                }
            }
        }
    }
    let get = |k: &str| {
        header
            .iter()
            .find(|(a, _, _)| a == k)
            .map_or(String::new(), |(_, v, _)| v.clone())
    };
    let n = header.len();
    cx.emit(
        Node::new("Header")
            .value(uint(to_u64(n)))
            .lazy(kv_spans, header.clone()),
    );
    cx.annotate(format!(
        "Rigaku RAS, {scans} scan(s), {points} point(s){}{}",
        if get("MEAS_SCAN_AXIS_X").is_empty() {
            String::new()
        } else {
            format!(", axis {}", get("MEAS_SCAN_AXIS_X"))
        },
        if get("HW_XG_TARGET_NAME").is_empty() {
            String::new()
        } else {
            format!(", {} target", get("HW_XG_TARGET_NAME"))
        }
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(
            nmrpipe_order(&[0, 0, 0, 0, 0, 0, 0, 0, 0x7b, 0x14, 0x16, 0x40]),
            Some(LE)
        );
    }
}
