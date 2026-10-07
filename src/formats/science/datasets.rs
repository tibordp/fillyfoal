//! Statistics and scientific datasets: SPSS, SAS, Stata, CERN ROOT, NIfTI,
//! NRRD, HDF4 and legacy VTK.

use crate::bytes::{to_u64, u16_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Record, emit_record};
use crate::error::Result;
use crate::fields::{Endian, Fields};
use crate::formats::{Input, Probe};
use crate::node::Node;
use crate::record;
use crate::value::Value;

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

fn text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

// ---------------------------------------------------------------------------
// Statistics and science: SPSS, SAS, Stata, ROOT, NIfTI, NRRD, HDF4, VTK

declare_format!(pub SPSS = "spss-sav", "SPSS data file", ["sav", "zsav"], "application/x-spss-sav",
    Probe::Magic(&[(0, b"$FL2"), (0, b"$FL3")]), spss);

record! {
    pub struct SpssHeader {
        magic: ascii[4] "Record type",
        product: ascii[60] "Product name",
        layout: i32 "Layout code",
        nominal_case_size: i32 "Nominal case size",
        compression: i32 "Compression" .enumeration(&[(0, "none"), (1, "bytecode"), (2, "zlib")]),
        weight: i32 "Weight variable index",
        cases: i32 "Number of cases",
        bias: f64 "Compression bias",
        date: ascii[9] "Creation date",
        time: ascii[8] "Creation time",
        label: ascii[64] "File label",
        _padding: bytes[3] "Padding",
    }
}

async fn spss(cx: Cx, input: Input) -> Result<()> {
    let h: SpssHeader = emit_record(&cx, input.span.sub(0, SpssHeader::SIZE), LE).await?;
    cx.emit(Node::new("Dictionary and data").span(input.span.tail(SpssHeader::SIZE)));
    cx.annotate(format!(
        "SPSS, {} cases, {} ({} {})",
        h.cases,
        h.product.trim().trim_start_matches("@(#) "),
        h.date,
        h.time
    ));
    Ok(())
}

const SAS_MAGIC: &[u8] = b"\0\0\0\0\0\0\0\0\0\0\0\0\xc2\xea\x81\x60\xb3\x14\x11\xcf\xbd\x92\x08\0\x09\xc7\x31\x8c\x18\x1f\x10\x11";

declare_format!(pub SAS7BDAT = "sas7bdat", "SAS data set", ["sas7bdat", "sas7bcat"], "application/x-sas-data",
    Probe::Magic(&[(0, SAS_MAGIC)]), sas7bdat);

async fn sas7bdat(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 0x120)).await?;
    let align = if head.get(32) == Some(&0x33) { 4u64 } else { 0 };
    let little = head.get(37) == Some(&0x01);
    let name = crate::text::until_nul(head.get(92..156).unwrap_or_default());
    let kind = crate::text::until_nul(head.get(156..164).unwrap_or_default());
    cx.emit(Node::new("Magic").span(file.sub(0, 32)));
    cx.emit(
        Node::new("Dataset name")
            .span(file.sub(92, 64))
            .value(text(name.trim())),
    );
    cx.emit(
        Node::new("File type")
            .span(file.sub(156, 8))
            .value(text(kind.trim())),
    );
    let version_at = 216u64
        .saturating_add(align.saturating_mul(2))
        .saturating_add(64);
    let version = crate::text::until_nul(&cx.read_avail(file.sub(version_at, 8)).await?);
    cx.emit(
        Node::new("SAS release")
            .span(file.sub(version_at, 8))
            .value(text(version.trim())),
    );
    cx.annotate(format!(
        "SAS {} {:?}, release {}, {}-bit {}",
        kind.trim(),
        name.trim(),
        version.trim(),
        if align == 4 { 64 } else { 32 },
        if little {
            "little-endian"
        } else {
            "big-endian"
        }
    ));
    Ok(())
}

declare_format!(pub STATA = "stata-dta", "Stata data file", ["dta"], "application/x-stata-dta",
    Probe::Magic(&[(0, b"<stata_dta>")]), stata);

async fn stata(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 512)).await?;
    let text_head = String::from_utf8_lossy(&head).into_owned();
    let tag = |name: &str| {
        let open = format!("<{name}>");
        let start = text_head.find(&open)?.saturating_add(open.len());
        let end = text_head.get(start..)?.find(&format!("</{name}>"))?;
        Some((
            start,
            text_head.get(start..start.saturating_add(end))?.to_owned(),
        ))
    };
    let release = tag("release").map(|(_, r)| r).unwrap_or_default();
    let order = tag("byteorder").map(|(_, r)| r).unwrap_or_default();
    cx.emit(Node::new("Release").value(text(release.clone())));
    cx.emit(Node::new("Byte order").value(text(order.clone())));
    let little = order == "LSF";
    let mut vars = 0u64;
    let mut obs = 0u64;
    if let Some((k_at, _)) = tag("K") {
        let at = crate::bytes::to_u64(k_at);
        let raw = cx.read_avail(file.sub(at, 2)).await?;
        vars = u64::from(
            if little {
                u16_le(&raw, 0)
            } else {
                crate::bytes::u16_be(&raw, 0)
            }
            .unwrap_or(0),
        );
        let n_at = text_head.find("<N>").map_or(0, |p| p.saturating_add(3));
        let raw = cx
            .read_avail(file.sub(crate::bytes::to_u64(n_at), 8))
            .await?;
        obs = if little {
            crate::bytes::u64_le(&raw, 0)
        } else {
            crate::bytes::u64_be(&raw, 0)
        }
        .unwrap_or(0);
    }
    cx.emit(Node::new("Data").span(file));
    cx.annotate(format!(
        "Stata release {release}, {vars} variables, {obs} observations"
    ));
    Ok(())
}

declare_format!(pub ROOT = "cern-root", "CERN ROOT file", ["root"], "application/x-root",
    Probe::Magic(&[(0, b"root\0")]), cern_root);

async fn cern_root(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 64)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Magic", 4).emit()?;
    let version = f.u32("Version").emit()?;
    let begin = f.u32("First data record").hex().emit()?;
    let big = version >= 1_000_000;
    if big {
        f.u64("End of file").hex().emit()?;
        f.u64("First free segment").hex().emit()?;
    } else {
        f.u32("End of file").hex().emit()?;
        f.u32("First free segment").hex().emit()?;
    }
    f.u32("Free segment record length").emit()?;
    f.u32("Deleted free segments").emit()?;
    f.u32("Header length (TFile)").emit()?;
    f.u8("Units (pointer size)").emit()?;
    let compression = f.u32("Compression").emit()?;
    cx.emit(Node::new("Records").span(file.tail(begin.into())));
    let v = version % 1_000_000;
    cx.annotate(format!(
        "ROOT {}.{:02}/{:02}, compression {compression}",
        v / 10000,
        v / 100 % 100,
        v % 100
    ));
    Ok(())
}

declare_format!(pub NIFTI = "nifti", "NIfTI neuroimaging volume", ["nii", "hdr"], "application/x-nifti",
    Probe::Custom(super::nifti::probe), super::nifti::dissect);

declare_format!(pub NRRD = "nrrd", "Nearly raw raster data (NRRD)", ["nrrd", "nhdr"], "application/x-nrrd",
    Probe::Magic(&[(0, b"NRRD000")]), nrrd);

async fn nrrd(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 8192)).await?;
    let end = head
        .windows(2)
        .position(|w| w == b"\n\n")
        .map_or(head.len(), |p| p.saturating_add(2));
    let header = String::from_utf8_lossy(head.get(..end).unwrap_or_default()).into_owned();
    let mut pos = 0u64;
    let mut fields = Vec::new();
    for line in header.lines() {
        let len = to_u64(line.len()).saturating_add(1);
        if let Some((k, v)) = line.split_once(':') {
            fields.push((k.trim().to_owned(), v.trim().to_owned()));
            cx.emit(
                Node::new(k.trim().to_owned())
                    .span(file.sub(pos, len))
                    .value(text(v.trim())),
            );
        } else if !line.starts_with('#') && !line.is_empty() {
            cx.emit(
                Node::new("Magic")
                    .span(file.sub(pos, len))
                    .value(text(line)),
            );
        }
        pos = pos.saturating_add(len);
    }
    cx.emit(Node::new("Data").span(file.tail(to_u64(end))));
    let get = |k: &str| {
        fields
            .iter()
            .find(|(f, _)| f == k)
            .map_or(String::new(), |(_, v)| v.clone())
    };
    cx.annotate(format!(
        "NRRD {} {}, {} encoding",
        get("sizes").replace(' ', "×"),
        get("type"),
        get("encoding")
    ));
    Ok(())
}

declare_format!(pub HDF4 = "hdf4", "HDF4 scientific data", ["hdf", "hdf4", "h4"], "application/x-hdf4",
    Probe::Magic(&[(0, b"\x0e\x03\x13\x01")]), super::hdf4::dissect);

declare_format!(pub VTK = "vtk-legacy", "VTK legacy data file", ["vtk"], "application/x-vtk",
    Probe::Magic(&[(0, b"# vtk DataFile Version")]), vtk);

async fn vtk(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 1024)).await?;
    let mut lines = head.split(|&b| b == b'\n');
    let mut pos = 0u64;
    let mut values = Vec::new();
    for name in ["Version", "Title", "Encoding", "Dataset type"] {
        let line = lines.next().unwrap_or_default();
        let len = to_u64(line.len()).saturating_add(1);
        let s = String::from_utf8_lossy(line).trim().to_owned();
        values.push(s.clone());
        cx.emit(Node::new(name).span(file.sub(pos, len)).value(text(s)));
        pos = pos.saturating_add(len);
    }
    cx.emit(Node::new("Data").span(file.tail(pos)));
    cx.annotate(format!(
        "{} {}, {}",
        values
            .get(3)
            .map_or("", |s| s.trim_start_matches("DATASET ")),
        values.get(2).cloned().unwrap_or_default(),
        values.get(1).cloned().unwrap_or_default()
    ));
    Ok(())
}
