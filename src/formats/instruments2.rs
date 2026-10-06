//! More instrument and lab formats: spectroscopy (Galactic SPC, NMRPipe,
//! Sparky), diffraction (Rigaku RAS), imaging (ImageJ ROI, Bio-Rad PIC,
//! Princeton SPE, ICS, IMOD models), neuroimaging (Analyze 7.5, FreeSurfer
//! MGH and surfaces), physiology (Spike2, Axon ATF), lab software (Igor
//! text, LabVIEW LVM) and oscilloscopes / logic analysers (Keysight,
//! Tektronix, LeCroy, FST waveforms).

use crate::bytes::{to_u64, to_usize, u16_be, u16_le, u32_be, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::lines::{
    Lines, contains, float32, head_lines, int, is_text, number, preview, summarize, text, uint,
};
use crate::formats::{Head, Input, Probe, embedded};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

fn field_text(b: &[u8]) -> String {
    String::from_utf8_lossy(b)
        .trim_matches(['\0', ' '])
        .to_owned()
}

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

async fn kv_spans(cx: Cx, items: Vec<(String, String, Span)>) -> Result<()> {
    for (k, v, span) in items {
        cx.push(Node::new(k).span(span).value(number(&v))).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ImageJ ROI

declare_format!(pub IMAGEJ_ROI = "imagej-roi", "ImageJ region of interest", ["roi"], "application/x-imagej-roi",
    Probe::Custom(|h| h.at(0, b"Iout") && u16_be(h.data, 4).is_some_and(|v| v < 1000) && h.data.get(6).is_some_and(|&t| t <= 10)), imagej_roi);

const ROI_TYPES: EnumTable = &[
    (0, "polygon"),
    (1, "rectangle"),
    (2, "oval"),
    (3, "line"),
    (4, "freeline"),
    (5, "polyline"),
    (6, "no ROI"),
    (7, "freehand"),
    (8, "traced"),
    (9, "angle"),
    (10, "point"),
];

record! {
    pub struct RoiHeader {
        magic: ascii[4] "Magic",
        version: u16 "Version",
        kind: u8 "Type" .enumeration(ROI_TYPES),
        pad: u8 "Padding",
        top: i16 "Top",
        left: i16 "Left",
        bottom: i16 "Bottom",
        right: i16 "Right",
        points: u16 "Coordinates",
        x1: f32 "X1",
        y1: f32 "Y1",
        x2: f32 "X2",
        y2: f32 "Y2",
        stroke_width: u16 "Stroke width",
        shape_size: u32 "Shape ROI size",
        stroke_color: u32 "Stroke color" .hex(),
        fill_color: u32 "Fill color" .hex(),
        subtype: u16 "Subtype",
        options: u16 "Options" .hex(),
        arrow_style: u8 "Arrow style / aspect ratio",
        point_type: u8 "Point type",
        arrow_size: u16 "Arrow head size / arc size",
        position: u32 "Position",
        header2: u32 "Header 2 offset" .hex(),
    }
}

async fn imagej_roi(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let hs = file.sub(0, RoiHeader::SIZE);
    let h: RoiHeader = read_record(&cx, hs, BE).await?;
    cx.emit(RoiHeader::node("Header", hs, BE));
    let n = u64::from(h.points);
    if n > 0 && h.kind != 1 && h.kind != 2 {
        let xs = file.sub(64, n.saturating_mul(2));
        let ys = file.sub(
            64u64.saturating_add(n.saturating_mul(2)),
            n.saturating_mul(2),
        );
        cx.emit(
            Node::new("Coordinates")
                .span(file.sub(64, n.saturating_mul(4)))
                .value(uint(n))
                .lazy(roi_points, (xs, ys, h.left, h.top)),
        );
    }
    let mut name = String::new();
    if h.header2 > 0 {
        let b = cx.block(file.sub(h.header2.into(), 64)).await?;
        let mut f = Fields::new(&b, BE);
        f.skip(4);
        let c = f.u32("C position").get()?;
        let z = f.u32("Z position").get()?;
        let t = f.u32("T position").get()?;
        let name_offset = f.u32("Name offset").get()?;
        let name_len = f.u32("Name length").get()?;
        cx.emit(
            Node::new("Header 2")
                .span(file.sub(h.header2.into(), 64))
                .summary(format!("C {c}, Z {z}, T {t}")),
        );
        if name_offset > 0 && name_len > 0 {
            let ns = file.sub(
                name_offset.into(),
                u64::from(name_len.min(1024)).saturating_mul(2),
            );
            name = crate::text::utf16(&cx.read_avail(ns).await?, BE);
            cx.emit(Node::new("Name").span(ns).value(text(name.clone())));
        }
    }
    cx.annotate(format!(
        "ImageJ ROI v{}, {} ({}, {})–({}, {}){}{}",
        h.version,
        lookup(ROI_TYPES, h.kind.into()).unwrap_or("?"),
        h.left,
        h.top,
        h.right,
        h.bottom,
        if n > 0 {
            format!(", {n} point(s)")
        } else {
            String::new()
        },
        if name.is_empty() {
            String::new()
        } else {
            format!(", {name:?}")
        }
    ));
    Ok(())
}

async fn roi_points(cx: Cx, (xs, ys, left, top): (Span, Span, i16, i16)) -> Result<()> {
    let x = cx.read(xs).await?;
    let y = cx.read(ys).await?;
    for (i, (a, b)) in x
        .as_chunks::<2>()
        .0
        .iter()
        .zip(y.as_chunks::<2>().0.iter())
        .enumerate()
    {
        let (px, py) = (i16::from_be_bytes(*a), i16::from_be_bytes(*b));
        cx.push(Node::new(format!("Point {i}")).value(text(format!(
            "({}, {})",
            i32::from(px).saturating_add(left.into()),
            i32::from(py).saturating_add(top.into())
        ))))
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Bio-Rad PIC confocal images

declare_format!(pub BIORAD_PIC = "biorad-pic", "Bio-Rad PIC confocal image", ["pic"], "image/x-biorad-pic",
    Probe::Custom(|h| u16_le(h.data, 54) == Some(12345) && u16_le(h.data, 0).is_some_and(|x| x > 0) && u16_le(h.data, 2).is_some_and(|y| y > 0) && u16_le(h.data, 14).is_some_and(|b| b <= 1)), biorad_pic);

record! {
    pub struct PicHeader {
        nx: u16 "Width",
        ny: u16 "Height",
        npic: u16 "Images",
        ramp1_min: u16 "Ramp 1 min",
        ramp1_max: u16 "Ramp 1 max",
        notes: u32 "Notes flag",
        byte_format: u16 "Byte format" .desc("1 = 8-bit, 0 = 16-bit"),
        image: u16 "Image number",
        name: ascii[32] "Name",
        merged: u16 "Merged",
        color1: u16 "Color 1",
        file_id: u16 "File ID" .desc("Always 12345"),
        ramp2_min: u16 "Ramp 2 min",
        ramp2_max: u16 "Ramp 2 max",
        color2: u16 "Color 2",
        edited: u16 "Edited",
        lens: u16 "Lens magnification",
        mag_factor: f32 "Magnification factor",
        reserved: bytes[6] "Reserved",
    }
}

async fn biorad_pic(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let hs = file.sub(0, PicHeader::SIZE);
    let h: PicHeader = read_record(&cx, hs, LE).await?;
    cx.emit(PicHeader::node("Header", hs, LE));
    let bytes = if h.byte_format == 1 { 1u64 } else { 2 };
    let plane = u64::from(h.nx)
        .saturating_mul(h.ny.into())
        .saturating_mul(bytes);
    let images = file.sub(76, plane.saturating_mul(h.npic.into()));
    cx.emit(
        Node::new("Images")
            .span(images)
            .value(uint(h.npic.into()))
            .summary(format!("{}×{} {}-bit", h.nx, h.ny, bytes.saturating_mul(8))),
    );
    let notes = file.tail(76u64.saturating_add(images.len));
    let mut count = 0u64;
    if notes.len >= 96 {
        count = notes.len / 96;
        cx.emit(
            Node::new("Notes")
                .span(notes)
                .value(uint(count))
                .lazy(pic_notes, notes),
        );
    }
    cx.annotate(format!(
        "Bio-Rad PIC {:?}, {}×{}×{} {}-bit, {count} note(s)",
        h.name.trim_end_matches('\0'),
        h.nx,
        h.ny,
        h.npic,
        bytes.saturating_mul(8)
    ));
    Ok(())
}

async fn pic_notes(cx: Cx, span: Span) -> Result<()> {
    let mut at = 0u64;
    while at.saturating_add(96) <= span.len {
        let b = cx.read(span.sub(at, 96)).await?;
        let kind = u16_le(&b, 10).unwrap_or(0);
        let t = field_text(b.get(16..96).unwrap_or_default());
        cx.push(
            Node::new(format!("Note (type {kind})"))
                .span(span.sub(at, 96))
                .value(text(t)),
        )
        .await;
        at = at.saturating_add(96);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Princeton Instruments / Roper SPE

declare_format!(pub PRINCETON_SPE = "princeton-spe", "Princeton Instruments SPE image", ["spe"], "image/x-spe",
    Probe::Custom(|h| u16_le(h.data, 4098) == Some(0x5555) && h.len >= 4100), princeton_spe);

const SPE_TYPES: EnumTable = &[
    (0, "float32"),
    (1, "int32"),
    (2, "int16"),
    (3, "uint16"),
    (5, "float64"),
    (6, "uint8"),
    (8, "uint32"),
];

async fn princeton_spe(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h = cx.read(file.sub(0, 4100)).await?;
    let emit = |name: &'static str, at: u64, len: u64, v: Value| {
        cx.emit(Node::new(name).span(file.sub(at, len)).value(v))
    };
    let exposure = f32::from_le_bytes(crate::bytes::array(&h, 10).unwrap_or_default());
    emit("Exposure (s)", 10, 4, float32(exposure));
    emit(
        "Date",
        20,
        10,
        text(field_text(h.get(20..30).unwrap_or_default())),
    );
    let xdim = u16_le(&h, 42).unwrap_or(0);
    emit("X dimension", 42, 2, uint(xdim.into()));
    let dtype = u16_le(&h, 108).unwrap_or(0);
    emit(
        "Data type",
        108,
        2,
        crate::formats::util::lines::enumeration(SPE_TYPES, dtype.into(), 16),
    );
    let comments: Vec<String> = (0..5usize)
        .map(|i| {
            field_text(
                h.get(
                    200usize.saturating_add(i.saturating_mul(80))
                        ..280usize.saturating_add(i.saturating_mul(80)),
                )
                .unwrap_or_default(),
            )
        })
        .filter(|c| !c.is_empty())
        .collect();
    emit("Comments", 200, 400, text(comments.join(" / ")));
    let ydim = u16_le(&h, 656).unwrap_or(0);
    emit("Y dimension", 656, 2, uint(ydim.into()));
    let xml = crate::bytes::u64_le(&h, 678).unwrap_or(0);
    emit(
        "XML footer offset",
        678,
        8,
        crate::formats::util::lines::hex(xml, 64),
    );
    let frames = crate::bytes::i32_le(&h, 1446).unwrap_or(0);
    emit("Frames", 1446, 4, int(frames.into()));
    let version = f32::from_le_bytes(crate::bytes::array(&h, 1992).unwrap_or_default());
    emit("File header version", 1992, 4, float32(version));
    emit(
        "Last value",
        4098,
        2,
        crate::formats::util::lines::hex(0x5555, 16),
    );
    let size: u64 = match dtype {
        0 | 1 | 8 => 4,
        2 | 3 => 2,
        5 => 8,
        _ => 1,
    };
    let frame = u64::from(xdim)
        .saturating_mul(ydim.into())
        .saturating_mul(size);
    let data = file.sub(
        4100,
        frame.saturating_mul(u64::try_from(frames).unwrap_or(0)),
    );
    cx.emit(Node::new("Frames").span(data).value(int(frames.into())));
    if xml > 0 {
        let x = file.tail(xml);
        let head = cx.read_avail(x.sub(0, 512)).await?;
        cx.emit(
            Node::new("XML footer")
                .span(x)
                .value(text(preview(&String::from_utf8_lossy(&head), 200))),
        );
    }
    cx.annotate(format!(
        "Princeton SPE {version}, {xdim}×{ydim} {} × {frames} frame(s), exposure {exposure} s",
        lookup(SPE_TYPES, dtype.into()).unwrap_or("?")
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Image Cytometry Standard (ICS)

declare_format!(pub ICS = "ics", "Image Cytometry Standard header", ["ics", "ids"], "image/x-ics",
    Probe::Custom(|h| is_text(h) && h.data.get(2..13) == Some(b"ics_version") && h.data.first().is_some_and(|b| !b.is_ascii_alphanumeric())), ics);

async fn ics(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut items: Vec<(String, String, Span)> = Vec::new();
    let mut data_at = None;
    while let Some(line) = lines.next().await? {
        if line.pos == 0 {
            cx.emit(
                Node::new("Separators")
                    .span(line.span)
                    .desc("Field and line separator characters"),
            );
            continue;
        }
        let t = line.text();
        if t.trim() == "end" {
            data_at = Some(lines.pos());
            break;
        }
        let fields: Vec<&str> = t.split(['\t', ' ']).filter(|f| !f.is_empty()).collect();
        let (key, value) = match fields.as_slice() {
            [cat, key, rest @ ..] if !matches!(*cat, "ics_version" | "filename") => {
                (format!("{cat} {key}"), rest.join(" "))
            }
            [cat, rest @ ..] => ((*cat).to_owned(), rest.join(" ")),
            [] => continue,
        };
        if items.len() < 4096 {
            items.push((key, value, line.content()));
        }
    }
    let get = |k: &str| {
        items
            .iter()
            .find(|(a, _, _)| a == k)
            .map_or(String::new(), |(_, v, _)| v.clone())
    };
    let n = items.len();
    cx.emit(
        Node::new("Parameters")
            .value(uint(to_u64(n)))
            .lazy(kv_spans, items.clone()),
    );
    if let Some(at) = data_at
        && at < file.len
    {
        cx.emit(Node::new("Image data").span(file.tail(at)));
    }
    cx.annotate(format!(
        "ICS {} image, order {}, sizes {}, {} {}",
        get("ics_version"),
        get("layout order"),
        get("layout sizes"),
        get("representation format"),
        get("representation compression")
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// IMOD models

declare_format!(pub IMOD = "imod-model", "IMOD model", ["mod", "fid"], "application/x-imod",
    Probe::Magic(&[(0, b"IMODV1.2")]), imod);

async fn imod(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 232)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Magic", 8).emit()?;
    let name = f.ascii("Name", 128).emit()?;
    let xmax = f.u32("X max").emit()?;
    let ymax = f.u32("Y max").emit()?;
    let zmax = f.u32("Z max").emit()?;
    let objects = f.u32("Objects").emit()?;
    f.u32("Flags").hex().emit()?;
    f.u32("Draw mode").emit()?;
    f.u32("Mouse mode").emit()?;
    f.u32("Black level").emit()?;
    f.u32("White level").emit()?;
    for n in [
        "X offset", "Y offset", "Z offset", "X scale", "Y scale", "Z scale",
    ] {
        f.f32(n).emit()?;
    }
    for n in [
        "Current object",
        "Current contour",
        "Current point",
        "Resolution",
        "Threshold",
    ] {
        f.u32(n).emit()?;
    }
    f.f32("Pixel size").emit()?;
    f.u32("Units").emit()?;
    let mut cur = Cursor::new(&cx, file, BE);
    cur.seek(232);
    let (mut contours, mut points) = (0u64, 0u64);
    while cur.remaining() >= 4 {
        let start = cur.pos();
        let id = String::from_utf8_lossy(&cur.bytes(4).await?).into_owned();
        let (summary, len) = match id.as_str() {
            "IEOF" => {
                cx.push(Node::new("IEOF").span(cur.since(start))).await;
                break;
            }
            "OBJT" => {
                let b = cx.read_avail(file.sub(cur.pos(), 176)).await?;
                (
                    format!(
                        "{:?}, {} contour(s)",
                        field_text(b.get(..64).unwrap_or_default()),
                        u32_be(&b, 128).unwrap_or(0)
                    ),
                    176u64,
                )
            }
            "CONT" => {
                let n = u64::from(cur.u32().await?);
                contours = contours.saturating_add(1);
                points = points.saturating_add(n);
                cur.seek(start.saturating_add(4));
                (
                    format!("{n} point(s)"),
                    16u64.saturating_add(n.saturating_mul(12)),
                )
            }
            "MESH" => {
                let v = u64::from(cur.u32().await?);
                let l = u64::from(cur.u32().await?);
                cur.seek(start.saturating_add(4));
                (
                    format!("{v} vertices, {l} indices"),
                    20u64
                        .saturating_add(v.saturating_mul(12))
                        .saturating_add(l.saturating_mul(4)),
                )
            }
            _ => {
                let size = u64::from(cur.u32().await?);
                cur.seek(start.saturating_add(4));
                (format!("{size} bytes"), 4u64.saturating_add(size))
            }
        };
        cur.skip(len);
        cx.push(Node::new(id).span(cur.since(start)).summary(summary))
            .await;
    }
    cx.annotate(format!("IMOD model {:?}, {xmax}×{ymax}×{zmax}, {objects} object(s), {contours} contour(s), {points} point(s)", name.trim_end_matches('\0')));
    Ok(())
}

// ---------------------------------------------------------------------------
// Analyze 7.5 headers

fn analyze_probe(h: &Head<'_>) -> bool {
    (u32_le(h.data, 0) == Some(348) || u32_be(h.data, 0) == Some(348))
        && !h.at(344, b"n+1\0")
        && !h.at(344, b"ni1\0")
        && !h.at(344, b"n+2\0")
        && (h.len == 348 || h.data.get(38) == Some(&b'r'))
}

declare_format!(pub ANALYZE = "analyze-hdr", "Analyze 7.5 image header", ["hdr"], "application/x-analyze",
    Probe::Custom(analyze_probe), analyze);

const ANALYZE_TYPES: EnumTable = &[
    (0, "unknown"),
    (1, "binary"),
    (2, "uint8"),
    (4, "int16"),
    (8, "int32"),
    (16, "float32"),
    (32, "complex64"),
    (64, "float64"),
    (128, "RGB24"),
];

record! {
    pub struct AnalyzeHeader {
        sizeof_hdr: u32 "sizeof_hdr",
        data_type: ascii[10] "data_type",
        db_name: ascii[18] "db_name",
        extents: u32 "extents",
        session_error: u16 "session_error",
        regular: ascii[1] "regular",
        hkey_un0: u8 "hkey_un0",
        dim0: u16 "dim[0] (dimensions)",
        dim1: u16 "dim[1]",
        dim2: u16 "dim[2]",
        dim3: u16 "dim[3]",
        dim4: u16 "dim[4]",
        dim5: u16 "dim[5]",
        dim6: u16 "dim[6]",
        dim7: u16 "dim[7]",
        vox_units: ascii[4] "vox_units",
        cal_units: ascii[8] "cal_units",
        unused1: u16 "unused1",
        datatype: u16 "datatype" .enumeration(ANALYZE_TYPES),
        bitpix: u16 "bitpix",
        dim_un0: u16 "dim_un0",
        pixdim0: f32 "pixdim[0]",
        pixdim1: f32 "pixdim[1]",
        pixdim2: f32 "pixdim[2]",
        pixdim3: f32 "pixdim[3]",
        pixdim4: f32 "pixdim[4]",
        pixdim5: f32 "pixdim[5]",
        pixdim6: f32 "pixdim[6]",
        pixdim7: f32 "pixdim[7]",
        vox_offset: f32 "vox_offset",
        funused: bytes[12] "funused",
        cal_max: f32 "cal_max",
        cal_min: f32 "cal_min",
        compressed: f32 "compressed",
        verified: f32 "verified",
        glmax: i32 "glmax",
        glmin: i32 "glmin",
        descrip: ascii[80] "descrip",
        aux_file: ascii[24] "aux_file",
        orient: u8 "orient",
        originator: bytes[10] "originator",
        generated: ascii[10] "generated",
        scannum: ascii[10] "scannum",
        patient_id: ascii[10] "patient_id",
        exp_date: ascii[10] "exp_date",
        exp_time: ascii[10] "exp_time",
        hist_un0: bytes[3] "hist_un0",
        views: i32 "views",
        vols_added: i32 "vols_added",
        start_field: i32 "start_field",
        field_skip: i32 "field_skip",
        omax: i32 "omax",
        omin: i32 "omin",
        smax: i32 "smax",
        smin: i32 "smin",
    }
}

async fn analyze(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let endian = if u32_le(&cx.read(file.sub(0, 4)).await?, 0) == Some(348) {
        LE
    } else {
        BE
    };
    let hs = file.sub(0, AnalyzeHeader::SIZE);
    let h: AnalyzeHeader = read_record(&cx, hs, endian).await?;
    cx.emit(AnalyzeHeader::node("Header", hs, endian));
    let dims: Vec<String> = [h.dim1, h.dim2, h.dim3, h.dim4]
        .iter()
        .take(usize::from(h.dim0.min(4)))
        .map(u16::to_string)
        .collect();
    cx.annotate(format!(
        "Analyze 7.5 header, {} {}, voxels {}×{}×{} {}{}",
        dims.join("×"),
        lookup(ANALYZE_TYPES, h.datatype.into()).unwrap_or("?"),
        h.pixdim1,
        h.pixdim2,
        h.pixdim3,
        h.vox_units.trim_end_matches('\0'),
        if h.descrip.trim_end_matches('\0').is_empty() {
            String::new()
        } else {
            format!(", {:?}", h.descrip.trim_end_matches('\0'))
        }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// FreeSurfer MGH volumes and surfaces

fn mgh_size(t: u32) -> u64 {
    match t {
        0 => 1,
        4 => 2,
        1 | 3 => 4,
        _ => 0,
    }
}

fn mgh_probe(h: &Head<'_>) -> bool {
    let g = |o: usize| u32_be(h.data, o).map(u64::from);
    let (Some(1), Some(w), Some(hh), Some(d), Some(f), Some(t)) =
        (g(0), g(4), g(8), g(12), g(16), u32_be(h.data, 20))
    else {
        return false;
    };
    let size = mgh_size(t);
    size > 0
        && w > 0
        && hh > 0
        && d > 0
        && f > 0
        && 284u64.saturating_add(
            w.saturating_mul(hh)
                .saturating_mul(d)
                .saturating_mul(f)
                .saturating_mul(size),
        ) <= h.len
        && u16_be(h.data, 28).is_some_and(|r| r <= 1)
}

declare_format!(pub MGH = "mgh", "FreeSurfer MGH volume", ["mgh"], "application/x-mgh",
    Probe::Custom(mgh_probe), mgh);

const MGH_TYPES: EnumTable = &[(0, "uint8"), (1, "int32"), (3, "float32"), (4, "int16")];

async fn mgh(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 90)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.u32("Version").emit()?;
    let w = f.u32("Width").emit()?;
    let h = f.u32("Height").emit()?;
    let d = f.u32("Depth").emit()?;
    let frames = f.u32("Frames").emit()?;
    let t = f.u32("Type").enumeration(MGH_TYPES).emit()?;
    f.u32("Degrees of freedom").emit()?;
    let ras = f.u16("Good RAS flag").emit()?;
    let mut voxel = (0.0, 0.0, 0.0);
    if ras == 1 {
        voxel = (
            f.f32("Voxel size X").emit()?,
            f.f32("Voxel size Y").emit()?,
            f.f32("Voxel size Z").emit()?,
        );
        for n in [
            "x_r", "x_a", "x_s", "y_r", "y_a", "y_s", "z_r", "z_a", "z_s", "c_r", "c_a", "c_s",
        ] {
            f.f32(n).emit()?;
        }
    }
    let size = u64::from(w)
        .saturating_mul(h.into())
        .saturating_mul(d.into())
        .saturating_mul(frames.into())
        .saturating_mul(mgh_size(t));
    cx.emit(Node::new("Voxels").span(file.sub(284, size)));
    let tail = file.tail(284u64.saturating_add(size));
    if tail.len > 0 {
        let b = cx.block(tail.sub(0, 20)).await?;
        let mut g = Fields::new(&b, BE);
        let tr = g.f32("TR").get().unwrap_or(0.0);
        cx.emit(
            Node::new("Scan parameters and tags")
                .span(tail)
                .summary(format!("TR {tr} ms")),
        );
    }
    cx.annotate(format!(
        "FreeSurfer MGH, {w}×{h}×{d}×{frames} {}, voxels {}×{}×{} mm",
        lookup(MGH_TYPES, t.into()).unwrap_or("?"),
        voxel.0,
        voxel.1,
        voxel.2
    ));
    Ok(())
}

declare_format!(pub FREESURFER_SURF = "freesurfer-surf", "FreeSurfer triangle surface", ["white", "pial", "inflated", "sphere", "orig", "smoothwm"], "application/x-freesurfer-surface",
    Probe::Custom(|h| h.at(0, b"\xff\xff\xfe") && h.at(3, b"created by")), freesurfer_surf);

async fn freesurfer_surf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(
        Node::new("Magic")
            .span(file.sub(0, 3))
            .value(crate::formats::util::lines::hex(0xff_fffe, 24)),
    );
    let head = cx.read_avail(file.sub(3, 1024)).await?;
    // The comment ends with two newlines.
    let end = head
        .windows(2)
        .position(|w| w == b"\n\n")
        .map_or(0, |p| p.saturating_add(2));
    let comment = String::from_utf8_lossy(head.get(..end).unwrap_or_default())
        .trim()
        .to_owned();
    cx.emit(
        Node::new("Comment")
            .span(file.sub(3, to_u64(end)))
            .value(text(comment.clone())),
    );
    let at = 3u64.saturating_add(to_u64(end));
    let b = cx.read(file.sub(at, 8)).await?;
    let v = u64::from(u32_be(&b, 0).unwrap_or(0));
    let faces = u64::from(u32_be(&b, 4).unwrap_or(0));
    cx.emit(Node::new("Vertices").span(file.sub(at, 4)).value(uint(v)));
    cx.emit(
        Node::new("Faces")
            .span(file.sub(at.saturating_add(4), 4))
            .value(uint(faces)),
    );
    let vs = file.sub(at.saturating_add(8), v.saturating_mul(12));
    cx.emit(
        Node::new("Vertex coordinates")
            .span(vs)
            .lazy(surf_vertices, vs),
    );
    cx.emit(Node::new("Face indices").span(file.sub(
        vs.end().saturating_sub(file.offset),
        faces.saturating_mul(12),
    )));
    cx.annotate(format!(
        "FreeSurfer surface, {v} vertices, {faces} triangles ({})",
        preview(&comment, 60)
    ));
    Ok(())
}

async fn surf_vertices(cx: Cx, span: Span) -> Result<()> {
    let count = span.len / 12;
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let s = span.sub(i.saturating_mul(12), 12);
        let b = cx.read(s).await?;
        let c = |o: usize| f32::from_bits(u32_be(&b, o).unwrap_or(0));
        cx.push(Node::new(format!("Vertex {i}")).span(s).value(text(format!(
            "({}, {}, {})",
            c(0),
            c(4),
            c(8)
        ))))
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// CED Spike2 (SON) data files

declare_format!(pub SPIKE2 = "spike2-smr", "CED Spike2 data file (SON)", ["smr", "srf"], "application/x-spike2",
    Probe::Magic(&[(2, b"(C) CED 87")]), spike2);

const SON_KINDS: EnumTable = &[
    (0, "off"),
    (1, "waveform (ADC)"),
    (2, "event (falling)"),
    (3, "event (rising)"),
    (4, "event (both)"),
    (5, "marker"),
    (6, "ADC marker"),
    (7, "real marker"),
    (8, "text marker"),
    (9, "real wave"),
];

async fn spike2(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 512)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    let version = f.u16("System ID").emit()?;
    f.ascii("Copyright", 10).emit()?;
    f.ascii("Creator", 8).emit()?;
    let us = f.u16("µs per time unit").emit()?;
    f.u16("Time units per ADC").emit()?;
    f.u16("File state").emit()?;
    f.u32("First data block").hex().emit()?;
    let channels = f.u16("Channels").emit()?;
    f.u16("Channel header size").emit()?;
    f.u16("Extra data").emit()?;
    f.u16("Buffer size").emit()?;
    f.u16("OS format").emit()?;
    let max = f.u32("Maximum time").emit()?;
    let base = f.f64("Time base (s)").emit()?;
    f.bytes("Date/time", 8).emit()?;
    f.skip(52);
    let mut comments = Vec::new();
    for _ in 0..5 {
        let span = f.peek_span(80);
        let b = f.bytes("Comment", 80).get()?;
        let n = usize::from(b.first().copied().unwrap_or(0)).min(79);
        let c =
            String::from_utf8_lossy(b.get(1..n.saturating_add(1)).unwrap_or_default()).into_owned();
        if !c.is_empty() {
            cx.emit(Node::new("Comment").span(span).value(text(c.clone())));
            comments.push(c);
        }
    }
    let chans = file.sub(512, u64::from(channels).saturating_mul(140));
    cx.emit(
        Node::new("Channels")
            .span(chans)
            .value(uint(channels.into()))
            .lazy(son_channels, chans),
    );
    cx.emit(Node::new("Data blocks").span(file.tail(chans.end().saturating_sub(file.offset))));
    let seconds = f64::from(max) * f64::from(us) * if base > 0.0 { base } else { 1e-6 };
    cx.annotate(format!(
        "Spike2 v{version}, {channels} channel slot(s), {seconds:.3} s{}",
        comments
            .first()
            .map(|c| format!(", {c}"))
            .unwrap_or_default()
    ));
    Ok(())
}

async fn son_channels(cx: Cx, span: Span) -> Result<()> {
    let mut at = 0u64;
    let mut i = 0u32;
    while at.saturating_add(140) <= span.len {
        let s = span.sub(at, 140);
        let b = cx.read(s).await?;
        let kind = b.get(122).copied().unwrap_or(0);
        let pstr = |o: usize, max: usize| {
            let n = usize::from(b.get(o).copied().unwrap_or(0)).min(max);
            String::from_utf8_lossy(
                b.get(o.saturating_add(1)..o.saturating_add(1).saturating_add(n))
                    .unwrap_or_default(),
            )
            .into_owned()
        };
        let title = pstr(108, 9);
        let comment = pstr(26, 71);
        let rate = f32::from_le_bytes(crate::bytes::array(&b, 118).unwrap_or_default());
        let blocks = u16_le(&b, 14).unwrap_or(0);
        if kind != 0 {
            let node = Node::new(format!("{i}: {title}")).span(s).value(
                crate::formats::util::lines::enumeration(SON_KINDS, kind.into(), 8),
            );
            cx.push(summarize(
                node,
                format!(
                    "{blocks} block(s), ideal rate {rate} Hz{}",
                    if comment.is_empty() {
                        String::new()
                    } else {
                        format!(", {comment}")
                    }
                ),
            ))
            .await;
        }
        at = at.saturating_add(140);
        i = i.saturating_add(1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Axon text files, Igor text, LabVIEW measurement files

declare_format!(pub AXON_ATF = "axon-atf", "Axon Text File (ATF)", ["atf"], "text/x-axon-atf",
    Probe::Custom(|h| h.starts_with(b"ATF\t") || h.starts_with(b"ATF ")), axon_atf);

async fn axon_atf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut header_lines = 0usize;
    let mut columns = 0usize;
    let mut index = 0usize;
    let mut items = Vec::new();
    let mut titles = String::new();
    let mut rows = 0u64;
    let mut data_start = None;
    while let Some(line) = lines.next().await? {
        let t = line.text();
        match index {
            0 => cx.emit(
                Node::new("Version")
                    .span(line.content())
                    .value(text(t.trim())),
            ),
            1 => {
                let w: Vec<usize> = t
                    .split_whitespace()
                    .filter_map(|x| x.parse().ok())
                    .collect();
                header_lines = w.first().copied().unwrap_or(0);
                columns = w.get(1).copied().unwrap_or(0);
                cx.emit(
                    Node::new("Header records / columns")
                        .span(line.content())
                        .value(text(t.trim())),
                );
            }
            _ if index < header_lines.saturating_add(2) => {
                let body = t.trim().trim_matches('"');
                let (k, v) = body.split_once('=').unwrap_or((body, ""));
                items.push((k.to_owned(), v.to_owned(), line.content()));
            }
            _ if index == header_lines.saturating_add(2) => {
                titles = t
                    .split('\t')
                    .map(|c| c.trim().trim_matches('"'))
                    .collect::<Vec<_>>()
                    .join(", ");
                cx.emit(
                    Node::new("Column titles")
                        .span(line.content())
                        .value(text(titles.clone())),
                );
                data_start = Some(lines.pos());
            }
            _ => {
                if !t.trim().is_empty() {
                    rows = rows.saturating_add(1);
                }
            }
        }
        index = index.saturating_add(1);
    }
    let n = items.len();
    cx.emit(
        Node::new("Header records")
            .value(uint(to_u64(n)))
            .lazy(kv_spans, items),
    );
    if let Some(at) = data_start {
        cx.emit(
            Node::new("Data")
                .span(file.tail(at))
                .value(uint(rows))
                .summary(format!("{columns} column(s)")),
        );
    }
    cx.annotate(format!(
        "Axon ATF, {columns} column(s) ({}), {rows} row(s)",
        preview(&titles, 80)
    ));
    Ok(())
}

declare_format!(pub IGOR_ITX = "igor-itx", "Igor Pro text wave file", ["itx", "awav"], "text/x-igor-itx",
    Probe::Custom(|h| head_lines(h, 1).first().is_some_and(|l| l.trim_ascii() == b"IGOR") && is_text(h)), igor_itx);

async fn igor_itx(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut block: Option<(String, u64, u64)> = None;
    let mut waves = Vec::new();
    let mut commands = 0u64;
    while let Some(line) = lines.next().await? {
        let t = line.text();
        let t = t.trim();
        if let Some((decl, start, n)) = block.as_mut() {
            if t == "END" {
                let s = file.sub(*start, lines.pos().saturating_sub(*start));
                cx.push(
                    Node::new(decl.clone())
                        .span(s)
                        .value(uint(*n))
                        .desc("Data rows"),
                )
                .await;
                block = None;
            } else if t != "BEGIN" {
                *n = n.saturating_add(1);
            }
            continue;
        }
        if t.starts_with("WAVES") {
            let names = t
                .split_once(char::is_whitespace)
                .map_or("", |(_, r)| r)
                .trim();
            waves.push(names.to_owned());
            block = Some((t.to_owned(), line.pos, 0));
        } else if let Some(cmd) = t.strip_prefix("X ") {
            commands = commands.saturating_add(1);
            cx.push(Node::new("Command").span(line.content()).value(text(cmd)))
                .await;
        }
    }
    cx.annotate(format!(
        "Igor Pro text, wave(s) {}, {commands} command(s)",
        preview(&waves.join("; "), 100)
    ));
    Ok(())
}

declare_format!(pub LABVIEW_LVM = "labview-lvm", "LabVIEW measurement file (LVM)", ["lvm"], "text/x-labview-lvm",
    Probe::Custom(|h| h.starts_with(b"LabVIEW Measurement")), labview_lvm);

async fn labview_lvm(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut items = Vec::new();
    let mut segments = 0u32;
    let mut channels = String::new();
    let mut in_header = true;
    let mut seg_start = None;
    let mut rows = 0u64;
    loop {
        let next = lines.next().await?;
        let ends = next
            .as_ref()
            .is_none_or(|l| l.text().starts_with("***End_of_Header***"));
        if ends && let Some(start) = seg_start.take() {
            let end = next.as_ref().map_or(lines.pos(), |l| l.pos);
            cx.push(
                Node::new(format!("Segment {segments}"))
                    .span(file.sub(start, end.saturating_sub(start)))
                    .value(uint(rows)),
            )
            .await;
            segments = segments.saturating_add(1);
            rows = 0;
        }
        let Some(line) = next else { break };
        let t = line.text();
        if t.starts_with("***End_of_Header***") {
            if in_header {
                in_header = false;
                cx.emit(
                    Node::new("File header")
                        .value(uint(to_u64(items.len())))
                        .lazy(kv_spans, std::mem::take(&mut items)),
                );
            } else {
                seg_start = Some(lines.pos());
            }
            continue;
        }
        let fields: Vec<&str> = t.split('\t').collect();
        if in_header {
            if let (Some(k), Some(v)) = (fields.first(), fields.get(1)) {
                items.push(((*k).to_owned(), (*v).to_owned(), line.content()));
            }
        } else if seg_start.is_some() {
            if fields.first() == Some(&"X_Value") && channels.is_empty() {
                channels = fields
                    .iter()
                    .skip(1)
                    .filter(|f| !f.is_empty() && **f != "Comment")
                    .copied()
                    .collect::<Vec<_>>()
                    .join(", ");
            } else if fields.first().is_some_and(|f| f.parse::<f64>().is_ok()) {
                rows = rows.saturating_add(1);
            }
        } else {
            seg_start = Some(line.pos);
        }
    }
    cx.annotate(format!(
        "LabVIEW measurement file, {segments} segment(s), channel(s) {}",
        preview(&channels, 80)
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Oscilloscope waveforms: Keysight/Agilent .bin, Tektronix .isf, LeCroy .trc

declare_format!(pub KEYSIGHT_BIN = "keysight-bin", "Keysight/Agilent oscilloscope waveform (.bin)", ["bin"], "application/x-keysight-bin",
    Probe::Custom(|h| (h.at(0, b"AG10") || h.at(0, b"AG01") || h.at(0, b"AG03")) && u32_le(h.data, 4).is_some_and(|s| u64::from(s) == h.len) && u32_le(h.data, 12) == Some(140)), keysight_bin);

const KS_WAVEFORMS: EnumTable = &[
    (0, "unknown"),
    (1, "normal"),
    (2, "peak detect"),
    (3, "average"),
    (4, "horizontal histogram"),
    (5, "vertical histogram"),
    (6, "logic"),
];
const KS_UNITS: EnumTable = &[
    (0, "unknown"),
    (1, "volts"),
    (2, "seconds"),
    (3, "constant"),
    (4, "amps"),
    (5, "decibels"),
    (6, "hertz"),
];

record! {
    pub struct KsWaveform {
        header_size: u32 "Header size",
        kind: u32 "Waveform type" .enumeration(KS_WAVEFORMS),
        buffers: u32 "Buffers",
        points: u32 "Points",
        count: u32 "Count",
        x_range: f32 "X display range",
        x_display_origin: f64 "X display origin",
        x_increment: f64 "X increment",
        x_origin: f64 "X origin",
        x_units: u32 "X units" .enumeration(KS_UNITS),
        y_units: u32 "Y units" .enumeration(KS_UNITS),
        date: ascii[16] "Date",
        time: ascii[16] "Time",
        frame: ascii[24] "Frame",
        label: ascii[16] "Label",
        time_tag: f64 "Time tag",
        segment: u32 "Segment index",
    }
}

async fn keysight_bin(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 12)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    let cookie = f.ascii("Cookie and version", 4).emit()?;
    f.u32("File size").emit()?;
    let waveforms = f.u32("Waveforms").emit()?;
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(12);
    let mut labels = Vec::new();
    for _ in 0..waveforms.min(64) {
        let start = cur.pos();
        let size = u64::from(cur.u32().await?);
        cur.seek(start);
        let w: KsWaveform = read_record(&cx, file.sub(start, KsWaveform::SIZE), LE).await?;
        cur.skip(size.max(4));
        let mut buffers = Vec::new();
        for _ in 0..w.buffers.min(16) {
            let bstart = cur.pos();
            let hsize = u64::from(cur.u32().await?);
            let btype = cur.u16().await?;
            let bpp = cur.u16().await?;
            let bsize = u64::from(cur.u32().await?);
            cur.seek(bstart.saturating_add(hsize.max(12)));
            buffers.push((file.sub(bstart, hsize.max(12)), cur.span(bsize), btype, bpp));
            cur.skip(bsize);
        }
        let label = w.label.trim_end_matches('\0').to_owned();
        labels.push(label.clone());
        cx.push(
            KsWaveform::node(
                format!("Waveform {label}"),
                file.sub(start, KsWaveform::SIZE),
                LE,
            )
            .summary(format!(
                "{} points, Δx {} s, {} {}",
                w.points,
                w.x_increment,
                w.date.trim_end_matches('\0'),
                w.time.trim_end_matches('\0')
            ))
            .target(file.sub(start, cur.pos().saturating_sub(start))),
        )
        .await;
        for (h, data, btype, bpp) in buffers {
            cx.push(
                Node::new(format!("Buffer of waveform {label}"))
                    .span(data)
                    .summary(format!("type {btype}, {bpp} byte(s)/point"))
                    .target(h),
            )
            .await;
        }
    }
    cx.annotate(format!(
        "Keysight waveform file {cookie}, {waveforms} waveform(s): {}",
        labels.join(", ")
    ));
    Ok(())
}

declare_format!(pub TEKTRONIX_ISF = "tektronix-isf", "Tektronix internal save file (ISF)", ["isf"], "application/x-tektronix-isf",
    Probe::Custom(|h| (h.starts_with(b":WFMPRE:") || h.starts_with(b":WFMP:") || h.starts_with(b":WFMOUTPRE:")) && contains(h.data.get(..4096).unwrap_or(h.data), b"CURVE")), tektronix_isf);

async fn tektronix_isf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 0x4000)).await?;
    let curve = head
        .windows(7)
        .position(|w| w == b":CURVE ")
        .or_else(|| head.windows(6).position(|w| w == b"CURVE "))
        .ok_or_else(|| Diagnostic::malformed("no CURVE block"))?;
    let text_part = String::from_utf8_lossy(head.get(..curve).unwrap_or_default()).into_owned();
    let mut items = Vec::new();
    let mut at = 0u64;
    for part in text_part.split(';') {
        let len = to_u64(part.len());
        let body = part.trim().rsplit(':').next().unwrap_or_default();
        let (k, v) = body.split_once(char::is_whitespace).unwrap_or((body, ""));
        if !k.is_empty() {
            items.push((
                k.to_owned(),
                v.trim().trim_matches('"').to_owned(),
                file.sub(at, len),
            ));
        }
        at = at.saturating_add(len).saturating_add(1);
    }
    let get = |key: &str| {
        items
            .iter()
            .find(|(a, _, _)| a.eq_ignore_ascii_case(key))
            .map_or(String::new(), |(_, v, _)| v.clone())
    };
    let n = items.len();
    cx.emit(
        Node::new("Preamble")
            .span(file.sub(0, to_u64(curve)))
            .value(uint(to_u64(n)))
            .lazy(kv_spans, items.clone()),
    );
    // IEEE 488.2 definite-length block: '#', digit count, length digits.
    let hash = head
        .get(curve..)
        .and_then(|r| r.iter().position(|&b| b == b'#'))
        .map(|p| curve.saturating_add(p));
    if let Some(h) = hash {
        let digits = usize::from(
            head.get(h.saturating_add(1))
                .copied()
                .unwrap_or(b'0')
                .saturating_sub(b'0'),
        );
        let len: u64 = String::from_utf8_lossy(
            head.get(h.saturating_add(2)..h.saturating_add(2).saturating_add(digits))
                .unwrap_or_default(),
        )
        .parse()
        .unwrap_or(0);
        let data_at = to_u64(h.saturating_add(2).saturating_add(digits));
        cx.emit(
            Node::new("Curve block header")
                .span(file.sub(to_u64(h), data_at.saturating_sub(to_u64(h))))
                .value(uint(len)),
        );
        cx.emit(
            Node::new("Curve data")
                .span(file.sub(data_at, len))
                .summary(format!("{} {}-byte point(s)", get("NR_PT"), get("BYT_NR"))),
        );
    }
    cx.annotate(format!(
        "Tektronix ISF, {} point(s), {}, Δx {} {}",
        get("NR_PT"),
        preview(&get("WFID"), 60),
        get("XINCR"),
        get("XUNIT")
    ));
    Ok(())
}

declare_format!(pub LECROY_TRC = "lecroy-trc", "Teledyne LeCroy waveform (.trc)", ["trc"], "application/x-lecroy-trc",
    Probe::Custom(|h| (h.at(0, b"WAVEDESC") && h.at(16, b"LECROY_")) || (h.at(11, b"WAVEDESC") && h.at(27, b"LECROY_"))), lecroy_trc);

async fn lecroy_trc(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let start: u64 = if cx.read(file.sub(0, 8)).await? == b"WAVEDESC" {
        0
    } else {
        11
    };
    if start > 0 {
        cx.emit(Node::new("Block header").span(file.sub(0, 11)).value(text(
            String::from_utf8_lossy(&cx.read(file.sub(0, 11)).await?).into_owned(),
        )));
    }
    let d = file.sub(start, 346);
    let raw = cx.read(d).await?;
    let little = u16_le(&raw, 34) == Some(1);
    let endian = if little { LE } else { BE };
    let b = cx.block(d).await?;
    let mut f = Fields::emitting(&cx, &b, endian);
    f.ascii("DESCRIPTOR_NAME", 16).emit()?;
    let template = f.ascii("TEMPLATE_NAME", 16).emit()?;
    let comm_type = f.u16("COMM_TYPE").desc("0 = byte, 1 = word").emit()?;
    f.u16("COMM_ORDER")
        .desc("0 = big endian, 1 = little endian")
        .emit()?;
    let desc_len = f.u32("WAVE_DESCRIPTOR").emit()?;
    let user = f.u32("USER_TEXT").emit()?;
    f.u32("RES_DESC1").emit()?;
    let trig = f.u32("TRIGTIME_ARRAY").emit()?;
    let ris = f.u32("RIS_TIME_ARRAY").emit()?;
    f.u32("RES_ARRAY1").emit()?;
    let wave1 = f.u32("WAVE_ARRAY_1").emit()?;
    let wave2 = f.u32("WAVE_ARRAY_2").emit()?;
    f.u32("RES_ARRAY2").emit()?;
    f.u32("RES_ARRAY3").emit()?;
    let instrument = f.ascii("INSTRUMENT_NAME", 16).emit()?;
    f.u32("INSTRUMENT_NUMBER").emit()?;
    let label = f.ascii("TRACE_LABEL", 16).emit()?;
    f.u16("RESERVED1").emit()?;
    f.u16("RESERVED2").emit()?;
    let count = f.u32("WAVE_ARRAY_COUNT").emit()?;
    for n in [
        "PNTS_PER_SCREEN",
        "FIRST_VALID_PNT",
        "LAST_VALID_PNT",
        "FIRST_POINT",
        "SPARSING_FACTOR",
        "SEGMENT_INDEX",
        "SUBARRAY_COUNT",
        "SWEEPS_PER_ACQ",
    ] {
        f.u32(n).emit()?;
    }
    f.u16("POINTS_PER_PAIR").emit()?;
    f.u16("PAIR_OFFSET").emit()?;
    let gain = f.f32("VERTICAL_GAIN").emit()?;
    f.f32("VERTICAL_OFFSET").emit()?;
    f.f32("MAX_VALUE").emit()?;
    f.f32("MIN_VALUE").emit()?;
    f.u16("NOMINAL_BITS").emit()?;
    f.u16("NOM_SUBARRAY_COUNT").emit()?;
    let interval = f.f32("HORIZ_INTERVAL").emit()?;
    f.f64("HORIZ_OFFSET").emit()?;
    f.f64("PIXEL_OFFSET").emit()?;
    let vunit = f.ascii("VERTUNIT", 48).emit()?;
    let hunit = f.ascii("HORUNIT", 48).emit()?;
    f.f32("HORIZ_UNCERTAINTY").emit()?;
    let seconds = f.f64("TRIGGER_TIME seconds").emit()?;
    let minutes = f.u8("TRIGGER_TIME minutes").emit()?;
    let hours = f.u8("TRIGGER_TIME hours").emit()?;
    let days = f.u8("TRIGGER_TIME days").emit()?;
    let months = f.u8("TRIGGER_TIME months").emit()?;
    let year = f.u16("TRIGGER_TIME year").emit()?;
    f.u16("TRIGGER_TIME unused").emit()?;
    f.f32("ACQ_DURATION").emit()?;
    for n in [
        "RECORD_TYPE",
        "PROCESSING_DONE",
        "RESERVED5",
        "RIS_SWEEPS",
        "TIMEBASE",
        "VERT_COUPLING",
    ] {
        f.u16(n).emit()?;
    }
    f.f32("PROBE_ATT").emit()?;
    f.u16("FIXED_VERT_GAIN").emit()?;
    f.u16("BANDWIDTH_LIMIT").emit()?;
    f.f32("VERTICAL_VERNIER").emit()?;
    f.f32("ACQ_VERT_OFFSET").emit()?;
    f.u16("WAVE_SOURCE").emit()?;
    let mut at = start.saturating_add(desc_len.into());
    for (name, len) in [
        ("User text", user),
        ("Trigger time array", trig),
        ("RIS time array", ris),
        ("Wave array 1", wave1),
        ("Wave array 2", wave2),
    ] {
        if len > 0 {
            cx.emit(Node::new(name).span(file.sub(at, len.into())));
        }
        at = at.saturating_add(len.into());
    }
    cx.annotate(format!(
        "LeCroy {} waveform {}{}, {count} {}-byte point(s), Δt {interval} {}, gain {gain} {}, triggered {year:04}-{months:02}-{days:02} {hours:02}:{minutes:02}:{seconds:06.3}",
        template.trim_end_matches('\0'),
        label.trim_end_matches(['\0', ' ']),
        if instrument.trim_end_matches('\0').is_empty() { String::new() } else { format!(" from {}", instrument.trim_end_matches('\0')) },
        if comm_type == 0 { 1 } else { 2 },
        hunit.trim_end_matches('\0'),
        vunit.trim_end_matches('\0')
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// FST (GTKWave Fast Signal Trace)

declare_format!(pub FST = "fst", "Fast Signal Trace (FST) waveform", ["fst"], "application/x-fst",
    Probe::Magic(&[(0, b"\x00\x00\x00\x00\x00\x00\x00\x01\x49")]), fst);

const FST_BLOCKS: EnumTable = &[
    (0, "HDR"),
    (1, "VCDATA"),
    (2, "BLACKOUT"),
    (3, "GEOM"),
    (4, "HIER"),
    (5, "VCDATA_DYN_ALIAS"),
    (6, "HIER_LZ4"),
    (7, "HIER_LZ4DUO"),
    (8, "VCDATA_DYN_ALIAS2"),
    (254, "ZWRAPPER"),
    (255, "SKIP"),
];
const FST_FILETYPES: EnumTable = &[(0, "Verilog"), (1, "VHDL"), (2, "Verilog/VHDL")];

async fn fst(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, BE);
    let mut blocks = 0u32;
    let mut summary = String::new();
    while cur.remaining() >= 9 {
        let start = cur.pos();
        let kind = cur.u8().await?;
        let len = cur.u64().await?;
        let body = file.sub(start.saturating_add(9), len.saturating_sub(8));
        let name = lookup(FST_BLOCKS, kind.into()).unwrap_or("unknown");
        let mut node = Node::new(name)
            .span(file.sub(start, len.saturating_add(1)))
            .value(uint(len));
        if kind == 0 {
            let b = cx.block(body.sub(0, 321)).await?;
            let mut f = Fields::new(&b, BE);
            let st = f.u64("Start time").get()?;
            let et = f.u64("End time").get()?;
            f.skip(16);
            let scopes = f.u64("Scopes").get()?;
            let vars = f.u64("Hierarchy vars").get()?;
            f.skip(16);
            let ts = f.int::<i8>("Timescale").get()?;
            let version = f.ascii("Version", 128).get()?;
            summary = format!(
                "{}, time {st}–{et} ×10^{ts} s, {scopes} scope(s), {vars} variable(s)",
                version.trim_end_matches('\0'),
            );
            node = node.lazy(fst_header, body);
        } else if kind == 4 {
            // HIER: uncompressed length, then a gzip stream.
            node = node.lazy(fst_hier, (input, body));
        }
        cx.push(node).await;
        blocks = blocks.saturating_add(1);
        cur.seek(start.saturating_add(1).saturating_add(len.max(8)));
    }
    cx.annotate(format!("FST waveform, {blocks} block(s); {summary}"));
    Ok(())
}

async fn fst_header(cx: Cx, body: Span) -> Result<()> {
    let b = cx.block(body.sub(0, 321)).await?;
    let mut f = Fields::emitting(&cx, &b, BE);
    f.u64("Start time").emit()?;
    f.u64("End time").emit()?;
    f.f64("Endianness test (e)")
        .desc("2.718281828… in the writer's byte order")
        .emit()?;
    f.u64("Writer memory use").emit()?;
    f.u64("Scopes").emit()?;
    f.u64("Hierarchy variables").emit()?;
    f.u64("Variables").emit()?;
    f.u64("Value change sections").emit()?;
    f.int::<i8>("Timescale (10^n s)").emit()?;
    f.ascii("Writer version", 128).emit()?;
    f.ascii("Date", 119).emit()?;
    f.u8("File type").enumeration(FST_FILETYPES).emit()?;
    f.u64("Time zero").emit()?;
    Ok(())
}

async fn fst_hier(cx: Cx, (input, body): (Input, Span)) -> Result<()> {
    let b = cx.read(body.sub(0, 8)).await?;
    cx.emit(
        Node::new("Uncompressed length")
            .span(body.sub(0, 8))
            .value(uint(crate::bytes::u64_be(&b, 0).unwrap_or(0))),
    );
    cx.emit(embedded("Hierarchy (gzip)", input.nested(body.tail(8))));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(mgh_size(3), 4);
        assert_eq!(field_text(b"ab\0\0 "), "ab");
        assert_eq!(
            nmrpipe_order(&[0, 0, 0, 0, 0, 0, 0, 0, 0x7b, 0x14, 0x16, 0x40]),
            Some(LE)
        );
    }
}
