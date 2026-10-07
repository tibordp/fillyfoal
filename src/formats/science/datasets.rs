//! Scientific datasets: CERN ROOT, NIfTI, NRRD, HDF4 and legacy VTK
//! (statistics packages live in `stats`).

use crate::bytes::{to_u64, u16_le, u32_be, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::error::Result;
use crate::fields::{Endian, Fields};
use crate::formats::{Head, Input, Probe};
use crate::node::Node;
use crate::value::{EnumTable, Value, lookup};

const BE: Endian = Endian::Big;

fn text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

// ---------------------------------------------------------------------------
// Science: ROOT, NIfTI, NRRD, HDF4, VTK

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

fn nifti_probe(h: &Head<'_>) -> bool {
    (u32_le(h.data, 0) == Some(348) && (h.at(344, b"n+1\0") || h.at(344, b"ni1\0")))
        || (u32_le(h.data, 0) == Some(540) && (h.at(4, b"n+2\0") || h.at(4, b"ni2\0")))
}

declare_format!(pub NIFTI = "nifti", "NIfTI neuroimaging volume", ["nii", "hdr"], "application/x-nifti",
    Probe::Custom(nifti_probe), nifti);

const NIFTI_TYPES: EnumTable = &[
    (2, "uint8"),
    (4, "int16"),
    (8, "int32"),
    (16, "float32"),
    (64, "float64"),
    (128, "rgb24"),
    (256, "int8"),
    (512, "uint16"),
    (768, "uint32"),
];

async fn nifti(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 348)).await?;
    if u32_le(&head, 0) == Some(540) {
        cx.emit(Node::new("NIfTI-2 header").span(file.sub(0, 540)));
        cx.annotate("NIfTI-2 volume");
        return Ok(());
    }
    let dims: Vec<String> =
        (0..usize::from(crate::bytes::i16_le(&head, 40).unwrap_or(0).clamp(0, 7) as u16))
            .map(|i| {
                crate::bytes::i16_le(&head, 42usize.saturating_add(i.saturating_mul(2)))
                    .unwrap_or(0)
                    .to_string()
            })
            .collect();
    let datatype = u16_le(&head, 70).unwrap_or(0);
    let description = crate::text::until_nul(head.get(148..228).unwrap_or_default());
    let offset = f32::from_le_bytes([
        head.get(108).copied().unwrap_or(0),
        head.get(109).copied().unwrap_or(0),
        head.get(110).copied().unwrap_or(0),
        head.get(111).copied().unwrap_or(0),
    ]);
    cx.emit(
        Node::new("Header")
            .span(file.sub(0, 348))
            .summary(description.clone()),
    );
    cx.emit(
        Node::new("Dimensions")
            .span(file.sub(40, 16))
            .value(text(dims.join("×"))),
    );
    cx.emit(
        Node::new("Data type")
            .span(file.sub(70, 2))
            .value(Value::Enum {
                raw: datatype.into(),
                bits: 16,
                name: lookup(NIFTI_TYPES, datatype.into()),
            }),
    );
    let data_at = if offset.is_finite() && offset >= 348.0 {
        offset as u64
    } else {
        352
    };
    cx.emit(Node::new("Voxel data").span(file.tail(data_at)));
    cx.annotate(format!(
        "NIfTI-1, {} {}{}",
        dims.join("×"),
        lookup(NIFTI_TYPES, datatype.into()).unwrap_or("?"),
        if description.is_empty() {
            String::new()
        } else {
            format!(", {description:?}")
        }
    ));
    Ok(())
}

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
    Probe::Magic(&[(0, b"\x0e\x03\x13\x01")]), hdf4);

async fn hdf4(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("Magic").span(file.sub(0, 4)));
    let mut at = 4u64;
    let mut blocks = 0u32;
    let mut descriptors = 0u32;
    while at != 0 && at < file.len && blocks < 1000 {
        let head = cx.read(file.sub(at, 6)).await?;
        let count = crate::bytes::u16_be(&head, 0).unwrap_or(0);
        let next = u64::from(u32_be(&head, 2).unwrap_or(0));
        blocks = blocks.saturating_add(1);
        descriptors = descriptors.saturating_add(count.into());
        cx.push(
            Node::new(format!("DD block {blocks}"))
                .span(file.sub(at, 6u64.saturating_add(u64::from(count).saturating_mul(12))))
                .summary(format!("{count} descriptors")),
        )
        .await;
        if next <= at {
            break;
        }
        at = next;
    }
    cx.annotate(format!("HDF4, {descriptors} data descriptors"));
    Ok(())
}

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
