//! Molecular simulation and mass spectrometry: CHARMM/NAMD DCD and GROMACS
//! XTC/TRR trajectories, Tripos MOL2 and CHARMM PSF topologies, and
//! MGF/MSP peak lists.

use crate::bytes::{to_u64, u32_be, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::lines::{
    Line, Lines, head_lines, is_text, number, preview, summarize, text, uint,
};
use crate::formats::{Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// CHARMM/NAMD DCD trajectories (Fortran unformatted records)

declare_format!(pub DCD = "dcd", "CHARMM/NAMD DCD trajectory", ["dcd"], "chemical/x-dcd",
    Probe::Magic(&[(0, b"\x54\x00\x00\x00CORD"), (0, b"\x00\x00\x00\x54CORD")]), dcd);

/// Reads a Fortran record (length, payload, length); returns the payload span.
async fn fortran_record(cur: &mut Cursor<'_>) -> Result<Span> {
    let start = cur.pos();
    let len = cur.u32().await?;
    let body = cur.span(len.into());
    cur.skip(len.into());
    let end = cur.u32().await?;
    if end != len {
        return Err(
            Diagnostic::malformed(format!("record markers differ ({len} vs {end})"))
                .at(cur.since(start)),
        );
    }
    Ok(body)
}

async fn dcd(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let endian = if cx.read(file.sub(0, 1)).await? == [0x54] {
        LE
    } else {
        BE
    };
    let mut cur = Cursor::new(&cx, file, endian);
    let header = fortran_record(&mut cur).await?;
    let b = cx.block(header).await?;
    let mut f = Fields::emitting(&cx, &b, endian);
    f.ascii("Signature", 4).emit()?;
    let frames = f.u32("NSET (frames)").emit()?;
    f.u32("ISTART (first step)").emit()?;
    f.u32("NSAVC (steps between frames)").emit()?;
    f.u32("NSTEP").emit()?;
    f.bytes("Unused", 16).emit()?;
    f.u32("NAMNF (fixed atoms)").emit()?;
    let delta = f.f32("DELTA (time step)").emit()?;
    let cell = f.u32("Unit cell flag").emit()?;
    f.u32("4D flag").emit()?;
    f.bytes("Unused", 28).emit()?;
    let version = f.u32("CHARMM version").emit()?;
    let titles = fortran_record(&mut cur).await?;
    let t = cx.read_avail(titles.sub(0, 4096)).await?;
    let lines: Vec<String> = t
        .get(4..)
        .unwrap_or_default()
        .chunks(80)
        .map(|c| {
            String::from_utf8_lossy(c)
                .trim_end_matches(['\0', ' '])
                .to_owned()
        })
        .collect();
    cx.emit(
        Node::new("Titles")
            .span(titles)
            .value(text(preview(&lines.join(" / "), 200))),
    );
    let natom_rec = fortran_record(&mut cur).await?;
    let n = cx.read(natom_rec.sub(0, 4)).await?;
    let natoms = match endian {
        Endian::Little => u32_le(&n, 0),
        Endian::Big => u32_be(&n, 0),
    }
    .unwrap_or(0);
    cx.emit(
        Node::new("Atoms")
            .span(natom_rec)
            .value(uint(natoms.into())),
    );
    let frames_span = file.tail(cur.pos());
    let has_cell = cell != 0 && version != 0;
    let frame_len = u64::from(natoms)
        .saturating_mul(12)
        .saturating_add(24)
        .saturating_add(if has_cell { 56 } else { 0 });
    cx.emit(
        Node::new("Frames")
            .span(frames_span)
            .value(uint(frames.into()))
            .lazy(dcd_frames, (frames_span, endian, has_cell, frame_len)),
    );
    cx.annotate(format!(
        "DCD trajectory ({}), {natoms} atom(s), {frames} frame(s), Δt {delta}{}",
        if version == 0 { "X-PLOR" } else { "CHARMM" },
        lines
            .first()
            .map(|l| format!("; {}", preview(l, 60)))
            .unwrap_or_default()
    ));
    Ok(())
}

async fn dcd_frames(
    cx: Cx,
    (span, endian, has_cell, frame_len): (Span, Endian, bool, u64),
) -> Result<()> {
    let count = span.len.checked_div(frame_len).unwrap_or(0);
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let fs = span.sub(i.saturating_mul(frame_len), frame_len);
        let mut cur = Cursor::new(&cx, fs, endian);
        if has_cell {
            fortran_record(&mut cur).await?;
        }
        let x = fortran_record(&mut cur).await?;
        let y = fortran_record(&mut cur).await?;
        let z = fortran_record(&mut cur).await?;
        let (fx, fy, fz) = (
            first_f32(&cx, x, endian).await,
            first_f32(&cx, y, endian).await,
            first_f32(&cx, z, endian).await,
        );
        cx.push(
            Node::new(format!("Frame {i}"))
                .span(fs)
                .summary(format!("atom 1 at ({fx}, {fy}, {fz})")),
        )
        .await;
    }
    Ok(())
}

/// The first float32 of a record.
async fn first_f32(cx: &Cx, s: Span, endian: Endian) -> f32 {
    let b = cx.read_avail(s.sub(0, 4)).await.unwrap_or_default();
    f32::from_bits(
        match endian {
            Endian::Little => u32_le(&b, 0),
            Endian::Big => u32_be(&b, 0),
        }
        .unwrap_or(0),
    )
}

// ---------------------------------------------------------------------------
// GROMACS XTC and TRR trajectories

fn xtc_probe(h: &Head<'_>) -> bool {
    u32_be(h.data, 0) == Some(1995)
        && u32_be(h.data, 4).is_some()
        && u32_be(h.data, 4) == u32_be(h.data, 52)
}

declare_format!(pub XTC = "xtc", "GROMACS compressed trajectory (XTC)", ["xtc"], "chemical/x-xtc",
    Probe::Custom(xtc_probe), xtc);
declare_format!(pub TRR = "trr", "GROMACS full-precision trajectory (TRR)", ["trr", "trj"], "chemical/x-trr",
    Probe::Custom(|h| u32_be(h.data, 0) == Some(1993) && h.at(12, b"GMX_trn_file")), trr);

async fn xtc(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, BE);
    let mut frames = 0u64;
    let (mut natoms, mut first, mut last) = (0u32, 0.0f32, 0.0f32);
    while cur.remaining() >= 56 {
        let start = cur.pos();
        let magic = cur.u32().await?;
        if magic != 1995 {
            cx.diag(Diagnostic::malformed(format!("frame magic {magic}")).at(file.sub(start, 4)));
            break;
        }
        natoms = cur.u32().await?;
        let step = cur.u32().await?;
        let time = cur.int::<f32>().await?;
        let b = cur.bytes(36).await?;
        let diag: Vec<f32> = [0usize, 16, 32]
            .iter()
            .map(|&o| f32::from_bits(u32_be(&b, o).unwrap_or(0)))
            .collect();
        cur.skip(4);
        let (precision, size) = if natoms <= 9 {
            (None, u64::from(natoms).saturating_mul(12))
        } else {
            let p = cur.int::<f32>().await?;
            cur.skip(28);
            let n = cur.u32().await?;
            (Some(p), u64::from(n).next_multiple_of(4))
        };
        cur.skip(size);
        if frames == 0 {
            first = time;
        }
        last = time;
        cx.push(
            Node::new(format!("Frame {frames}"))
                .span(cur.since(start))
                .value(uint(step.into()))
                .summary(format!(
                    "t = {time} ps, box {:.3}×{:.3}×{:.3} nm{}",
                    diag.first().unwrap_or(&0.0),
                    diag.get(1).unwrap_or(&0.0),
                    diag.get(2).unwrap_or(&0.0),
                    precision
                        .map(|p| format!(", precision {p}"))
                        .unwrap_or_default()
                ))
                .lazy(xtc_frame, cur.since(start)),
        )
        .await;
        frames = frames.saturating_add(1);
    }
    cx.annotate(format!(
        "GROMACS XTC, {natoms} atom(s), {frames} frame(s), t = {first}–{last} ps"
    ));
    Ok(())
}

async fn xtc_frame(cx: Cx, span: Span) -> Result<()> {
    let b = cx.block(span.sub(0, 92)).await?;
    let mut f = Fields::emitting(&cx, &b, BE);
    f.u32("Magic").emit()?;
    let natoms = f.u32("Atoms").emit()?;
    f.u32("Step").emit()?;
    f.f32("Time (ps)").emit()?;
    for name in [
        "Box ax", "Box ay", "Box az", "Box bx", "Box by", "Box bz", "Box cx", "Box cy", "Box cz",
    ] {
        f.f32(name).emit()?;
    }
    f.u32("Atoms").emit()?;
    if natoms > 9 {
        f.f32("Precision").emit()?;
        for name in ["Min x", "Min y", "Min z", "Max x", "Max y", "Max z"] {
            f.int::<i32>(name).emit()?;
        }
        f.u32("Small index").emit()?;
        let n = f.u32("Compressed bytes").emit()?;
        cx.emit(Node::new("Compressed coordinates").span(span.sub(92, n.into())));
    } else {
        cx.emit(
            Node::new("Coordinates")
                .span(span.tail(56))
                .summary(format!("{natoms} × 3 float32")),
        );
    }
    Ok(())
}

const TRR_SIZES: [&str; 13] = [
    "ir_size",
    "e_size",
    "box_size",
    "vir_size",
    "pres_size",
    "top_size",
    "sym_size",
    "x_size",
    "v_size",
    "f_size",
    "natoms",
    "step",
    "nre",
];

async fn trr(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, BE);
    let mut frames = 0u64;
    let mut natoms = 0u32;
    let mut double = false;
    while cur.remaining() >= 24 {
        let start = cur.pos();
        if cur.u32().await? != 1993 {
            cx.diag(Diagnostic::malformed("frame magic is not 1993").at(file.sub(start, 4)));
            break;
        }
        cur.skip(8);
        cur.skip(12);
        let mut v = [0u32; 13];
        for slot in &mut v {
            *slot = cur.u32().await?;
        }
        natoms = v.get(10).copied().unwrap_or(0);
        let box_size = v.get(2).copied().unwrap_or(0);
        let x_size = v.get(7).copied().unwrap_or(0);
        double = box_size == 72
            || (box_size == 0
                && natoms > 0
                && u64::from(x_size) == u64::from(natoms).saturating_mul(24));
        let real = if double { 8 } else { 4 };
        let t = if double {
            cur.int::<f64>().await?
        } else {
            f64::from(cur.int::<f32>().await?)
        };
        cur.skip(real);
        let data: u64 = v.iter().take(10).map(|&s| u64::from(s)).sum();
        let header = cur.since(start);
        cur.skip(data);
        let parts: Vec<&str> = [(2, "box"), (7, "x"), (8, "v"), (9, "f")]
            .iter()
            .filter(|(i, _)| v.get(*i).copied().unwrap_or(0) > 0)
            .map(|(_, n)| *n)
            .collect();
        cx.push(
            Node::new(format!("Frame {frames}"))
                .span(cur.since(start))
                .value(uint(v.get(11).copied().unwrap_or(0).into()))
                .summary(format!("t = {t} ps, {}", parts.join("+")))
                .lazy(trr_header, (header, v.to_vec())),
        )
        .await;
        frames = frames.saturating_add(1);
    }
    cx.annotate(format!(
        "GROMACS TRR ({} precision), {natoms} atom(s), {frames} frame(s)",
        if double { "double" } else { "single" }
    ));
    Ok(())
}

async fn trr_header(cx: Cx, (span, values): (Span, Vec<u32>)) -> Result<()> {
    cx.emit(Node::new("Magic").span(span.sub(0, 4)).value(uint(1993)));
    cx.emit(
        Node::new("Version string")
            .span(span.sub(4, 20))
            .value(text("GMX_trn_file")),
    );
    for (i, (name, v)) in TRR_SIZES.iter().zip(values).enumerate() {
        cx.emit(
            Node::new(*name)
                .span(span.sub(24u64.saturating_add(to_u64(i).saturating_mul(4)), 4))
                .value(uint(v.into())),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tripos MOL2

declare_format!(pub MOL2 = "mol2", "Tripos MOL2 molecule", ["mol2", "ml2", "sy2"], "chemical/x-mol2",
    Probe::Custom(|h| is_text(h) && head_lines(h, 16).iter().find(|l| !l.starts_with(b"#") && !l.trim_ascii().is_empty()).is_some_and(|l| l.trim_ascii() == b"@<TRIPOS>MOLECULE")), mol2);

async fn mol2(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut section: Option<(String, u64, Vec<Line>)> = None;
    let mut molecules = 0u32;
    let mut first = String::new();
    let (mut atoms, mut bonds) = (0u64, 0u64);
    loop {
        let next = lines.next().await?;
        let starts = next
            .as_ref()
            .is_none_or(|l| l.bytes.starts_with(b"@<TRIPOS>"));
        if starts && let Some((name, start, body)) = section.take() {
            let end = next.as_ref().map_or(lines.pos(), |l| l.pos);
            let span = file.sub(start, end.saturating_sub(start));
            let n = body.len();
            if name == "MOLECULE" {
                molecules = molecules.saturating_add(1);
                if first.is_empty() {
                    first = body.first().map(Line::text).unwrap_or_default();
                }
            } else if name == "ATOM" {
                atoms = atoms.saturating_add(to_u64(n));
            } else if name == "BOND" {
                bonds = bonds.saturating_add(to_u64(n));
            }
            cx.push(
                Node::new(format!("@<TRIPOS>{name}"))
                    .span(span)
                    .summary(format!("{n} line(s)"))
                    .lazy(mol2_section, (name, body)),
            )
            .await;
        }
        let Some(line) = next else { break };
        let t = line.text();
        if let Some(name) = t.trim().strip_prefix("@<TRIPOS>") {
            section = Some((name.to_owned(), line.pos, Vec::new()));
        } else if let Some((_, _, body)) = section.as_mut()
            && !t.trim().is_empty()
            && !t.starts_with('#')
            && body.len() < 1_000_000
        {
            body.push(line);
        }
    }
    cx.annotate(format!(
        "MOL2, {molecules} molecule(s) ({}), {atoms} atom(s), {bonds} bond(s)",
        preview(&first, 40)
    ));
    Ok(())
}

const MOL2_MOLECULE: [&str; 6] = [
    "Name",
    "Counts (atoms bonds substructures features sets)",
    "Molecule type",
    "Charge type",
    "Status bits",
    "Comment",
];

async fn mol2_section(cx: Cx, (name, body): (String, Vec<Line>)) -> Result<()> {
    for (i, l) in body.into_iter().enumerate() {
        let t = l.text();
        let words: Vec<&str> = t.split_whitespace().collect();
        let node = match name.as_str() {
            "MOLECULE" => {
                Node::new(MOL2_MOLECULE.get(i).copied().unwrap_or("Line")).value(text(t.trim()))
            }
            "ATOM" => Node::new(format!("Atom {}", words.first().copied().unwrap_or("?")))
                .value(text(format!(
                    "{} ({})",
                    words.get(1).copied().unwrap_or_default(),
                    words.get(5).copied().unwrap_or_default()
                )))
                .summary(format!(
                    "({}, {}, {}){}",
                    words.get(2).copied().unwrap_or_default(),
                    words.get(3).copied().unwrap_or_default(),
                    words.get(4).copied().unwrap_or_default(),
                    words
                        .get(8)
                        .map(|c| format!(", charge {c}"))
                        .unwrap_or_default()
                )),
            "BOND" => Node::new(format!("Bond {}", words.first().copied().unwrap_or("?")))
                .value(text(format!(
                    "{}–{}",
                    words.get(1).copied().unwrap_or_default(),
                    words.get(2).copied().unwrap_or_default()
                )))
                .summary(match words.get(3).copied().unwrap_or_default() {
                    "1" => "single".to_owned(),
                    "2" => "double".to_owned(),
                    "3" => "triple".to_owned(),
                    "ar" => "aromatic".to_owned(),
                    "am" => "amide".to_owned(),
                    other => other.to_owned(),
                }),
            _ => Node::new("Line").value(text(t.trim())),
        };
        cx.push(node.span(l.content())).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// CHARMM/X-PLOR PSF topology

declare_format!(pub CHARMM_PSF = "charmm-psf", "CHARMM/X-PLOR protein structure file (PSF)", ["psf"], "chemical/x-psf",
    Probe::Custom(|h| is_text(h) && h.starts_with(b"PSF") && head_lines(h, 1).first().is_some_and(|l| l.len() < 40 && l.iter().all(|b| b.is_ascii_uppercase() || *b == b' ')) && crate::formats::util::lines::contains(h.data, b"!NATOM")), charmm_psf);

async fn charmm_psf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut section: Option<(String, u64, u64, u64)> = None;
    let mut counts: Vec<(String, u64)> = Vec::new();
    let mut flags = String::new();
    loop {
        let next = lines.next().await?;
        let header = next.as_ref().is_some_and(|l| l.text().contains(" !N"));
        if (header || next.is_none())
            && let Some((name, count, start, lines_in)) = section.take()
        {
            let end = next.as_ref().map_or(lines.pos(), |l| l.pos);
            let span = file.sub(start, end.saturating_sub(start));
            let node = Node::new(name.clone())
                .span(span)
                .value(uint(count))
                .summary(format!("{lines_in} line(s)"));
            cx.push(
                if name.starts_with("!NATOM") || name.starts_with("!NTITLE") {
                    node.lazy(psf_lines, span)
                } else {
                    node
                },
            )
            .await;
            counts.push((name, count));
        }
        let Some(line) = next else { break };
        let t = line.text();
        if line.pos == 0 {
            flags = t.trim().to_owned();
            cx.emit(
                Node::new("Flags")
                    .span(line.content())
                    .value(text(flags.clone())),
            );
            continue;
        }
        if header {
            let (n, name) = t.trim().split_once(' ').unwrap_or(("0", t.trim()));
            section = Some((
                name.trim().to_owned(),
                n.trim().parse().unwrap_or(0),
                line.pos,
                0,
            ));
        } else if let Some((_, _, _, n)) = section.as_mut()
            && !t.trim().is_empty()
        {
            *n = n.saturating_add(1);
        }
    }
    let get = |k: &str| {
        counts
            .iter()
            .find(|(n, _)| n.starts_with(k))
            .map_or(0, |(_, c)| *c)
    };
    cx.annotate(format!(
        "{flags}: {} atom(s), {} bond(s), {} angle(s), {} dihedral(s)",
        get("!NATOM"),
        get("!NBOND"),
        get("!NTHETA"),
        get("!NPHI")
    ));
    Ok(())
}

async fn psf_lines(cx: Cx, span: Span) -> Result<()> {
    let mut lines = Lines::new(&cx, span);
    let mut first = true;
    while let Some(line) = lines.next().await? {
        if first {
            first = false;
            continue;
        }
        let t = line.text();
        let w: Vec<&str> = t.split_whitespace().collect();
        if w.len() >= 8 {
            let node = Node::new(format!("Atom {}", w.first().copied().unwrap_or_default()))
                .span(line.content())
                .value(text(format!(
                    "{} {}{} {}",
                    w.get(1).copied().unwrap_or_default(),
                    w.get(3).copied().unwrap_or_default(),
                    w.get(2).copied().unwrap_or_default(),
                    w.get(4).copied().unwrap_or_default()
                )));
            cx.push(node.summary(format!(
                "type {}, charge {}, mass {}",
                w.get(5).copied().unwrap_or_default(),
                w.get(6).copied().unwrap_or_default(),
                w.get(7).copied().unwrap_or_default()
            )))
            .await;
        } else if !t.trim().is_empty() {
            cx.push(Node::new("Line").span(line.content()).value(text(t.trim())))
                .await;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Mascot generic format (MGF) and NIST MSP peak lists

fn mgf_probe(h: &Head<'_>) -> bool {
    if !is_text(h) {
        return false;
    }
    for l in head_lines(h, 64) {
        let l = l.trim_ascii();
        if l.is_empty() || l.starts_with(b"#") || l.starts_with(b"!") || l.starts_with(b";") {
            continue;
        }
        if l == b"BEGIN IONS" {
            return true;
        }
        let Some(eq) = l.iter().position(|&b| b == b'=') else {
            return false;
        };
        if !l.get(..eq).is_some_and(|k| {
            !k.is_empty()
                && k.iter()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_')
        }) {
            return false;
        }
    }
    false
}

declare_format!(pub MGF = "mgf", "Mascot Generic Format (MS/MS peak lists)", ["mgf"], "chemical/x-mgf",
    Probe::Custom(mgf_probe), mgf);

async fn mgf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    // The open spectrum: start, parameters, and peak count.
    type Block = (u64, Vec<(String, String)>, u64);
    let mut block: Option<Block> = None;
    let mut spectra = 0u64;
    let mut peaks_total = 0u64;
    while let Some(line) = lines.next().await? {
        let t = line.text();
        let t = t.trim();
        if t == "BEGIN IONS" {
            block = Some((line.pos, Vec::new(), 0));
        } else if t == "END IONS" {
            if let Some((start, params, peaks)) = block.take() {
                let span = file.sub(start, lines.pos().saturating_sub(start));
                let title = params
                    .iter()
                    .find(|(k, _)| k == "TITLE")
                    .map(|(_, v)| v.clone())
                    .unwrap_or_else(|| format!("Spectrum {spectra}"));
                let mass = params
                    .iter()
                    .find(|(k, _)| k == "PEPMASS")
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default();
                let charge = params
                    .iter()
                    .find(|(k, _)| k == "CHARGE")
                    .map(|(_, v)| format!(" {v}"))
                    .unwrap_or_default();
                cx.push(
                    Node::new(title)
                        .span(span)
                        .value(number(mass.split_whitespace().next().unwrap_or_default()))
                        .summary(format!("{peaks} peak(s){charge}"))
                        .lazy(peak_block, span),
                )
                .await;
                spectra = spectra.saturating_add(1);
                peaks_total = peaks_total.saturating_add(peaks);
            }
        } else if let Some((_, params, peaks)) = block.as_mut() {
            if let Some((k, v)) = t.split_once('=') {
                if params.len() < 64 {
                    params.push((k.to_owned(), v.to_owned()));
                }
            } else if t.starts_with(|c: char| c.is_ascii_digit()) {
                *peaks = peaks.saturating_add(1);
            }
        } else if let Some((k, v)) = t.split_once('=') {
            cx.push(
                Node::new(k.to_owned())
                    .span(line.content())
                    .value(number(v))
                    .desc("Global parameter"),
            )
            .await;
        }
    }
    cx.annotate(format!(
        "MGF, {spectra} spectr(um/a), {peaks_total} peak(s)"
    ));
    Ok(())
}

/// Parameters and peaks of one spectrum.
async fn peak_block(cx: Cx, span: Span) -> Result<()> {
    let mut lines = Lines::new(&cx, span);
    while let Some(line) = lines.next().await? {
        let t = line.text();
        let t = t.trim();
        if t.is_empty() || t == "BEGIN IONS" || t == "END IONS" {
            continue;
        }
        if let Some((k, v)) = t
            .split_once(['=', ':'])
            .filter(|(k, _)| !k.trim().starts_with(|c: char| c.is_ascii_digit()))
        {
            cx.push(
                Node::new(k.trim().to_owned())
                    .span(line.content())
                    .value(number(v.trim())),
            )
            .await;
        } else {
            for peak in t.split(';').filter(|p| !p.trim().is_empty()) {
                let mut w = peak.split_whitespace();
                let mz = w.next().unwrap_or_default().to_owned();
                let intensity = w.next().unwrap_or_default().to_owned();
                cx.push(summarize(
                    Node::new(format!("m/z {mz}"))
                        .span(line.content())
                        .value(number(&intensity)),
                    w.collect::<Vec<_>>().join(" "),
                ))
                .await;
            }
        }
    }
    Ok(())
}

fn msp_probe(h: &Head<'_>) -> bool {
    is_text(h)
        && h.data
            .get(..5)
            .is_some_and(|k| k.eq_ignore_ascii_case(b"Name:"))
        && h.data
            .get(..8192)
            .unwrap_or(h.data)
            .windows(10)
            .any(|w| w.eq_ignore_ascii_case(b"Num Peaks:"))
}

declare_format!(pub MSP = "msp", "NIST MSP mass spectral library", ["msp"], "chemical/x-msp",
    Probe::Custom(msp_probe), msp);

async fn msp(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut current: Option<(String, u64, String, u64)> = None;
    let mut spectra = 0u64;
    loop {
        let next = lines.next().await?;
        let starts = next.as_ref().is_none_or(|l| {
            l.bytes
                .get(..5)
                .is_some_and(|k| k.eq_ignore_ascii_case(b"Name:"))
        });
        if starts && let Some((name, start, formula, peaks)) = current.take() {
            let end = next.as_ref().map_or(lines.pos(), |l| l.pos);
            let span = file.sub(start, end.saturating_sub(start));
            cx.push(
                summarize(
                    Node::new(name).span(span).value(text(formula)),
                    format!("{peaks} peak(s)"),
                )
                .lazy(peak_block, span),
            )
            .await;
            spectra = spectra.saturating_add(1);
        }
        let Some(line) = next else { break };
        let t = line.text();
        if starts {
            current = Some((
                t.get(5..).unwrap_or_default().trim().to_owned(),
                line.pos,
                String::new(),
                0,
            ));
        } else if let Some((_, _, formula, peaks)) = current.as_mut() {
            if t.get(..8)
                .is_some_and(|k| k.eq_ignore_ascii_case("Formula:"))
            {
                *formula = t.get(8..).unwrap_or_default().trim().to_owned();
            } else if t.trim().starts_with(|c: char| c.is_ascii_digit()) {
                *peaks = peaks.saturating_add(to_u64(
                    t.split(';').filter(|p| !p.trim().is_empty()).count(),
                ));
            }
        }
    }
    cx.annotate(format!("NIST MSP library, {spectra} spectr(um/a)"));
    Ok(())
}
