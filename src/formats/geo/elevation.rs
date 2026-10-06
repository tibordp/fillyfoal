//! Elevation and imagery: SRTM HGT, DTED and NITF.

use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Record, emit_record};
use crate::error::Result;
use crate::fields::Endian;
use crate::formats::{Head, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::value::Value;

const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// Elevation and imagery: SRTM HGT, DTED, NITF

fn hgt_probe(h: &Head<'_>) -> bool {
    matches!(h.len, 2_884_802 | 25_934_402)
}

declare_format!(pub HGT = "srtm-hgt", "SRTM elevation tile (HGT)", ["hgt"], "application/x-srtm-hgt",
    Probe::Custom(hgt_probe), hgt);

async fn hgt(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let side = if file.len == 2_884_802 { 1201u64 } else { 3601 };
    let row = side.saturating_mul(2);
    // Sample the centre post.
    let centre = (side / 2)
        .saturating_mul(row)
        .saturating_add((side / 2).saturating_mul(2));
    let sample = cx.read(file.sub(centre, 2)).await?;
    let height = i16::from_be_bytes([
        sample.first().copied().unwrap_or(0),
        sample.get(1).copied().unwrap_or(0),
    ]);
    cx.emit(
        Node::new("Grid")
            .span(file)
            .summary(format!("{side}×{side} big-endian 16-bit posts")),
    );
    cx.emit(
        Node::new("Centre elevation")
            .span(file.sub(centre, 2))
            .value(Value::Int {
                value: height.into(),
                bits: 16,
            }),
    );
    cx.annotate(format!(
        "SRTM{} tile, {side}×{side} posts",
        if side == 1201 { 3 } else { 1 }
    ));
    Ok(())
}

declare_format!(pub DTED = "dted", "Digital Terrain Elevation Data", ["dt0", "dt1", "dt2"], "application/x-dted",
    Probe::Magic(&[(0, b"UHL1")]), dted);

record! {
    pub struct DtedUhl {
        sentinel: ascii[4] "Sentinel",
        longitude: ascii[8] "Origin longitude (DDDMMSSH)",
        latitude: ascii[8] "Origin latitude (DDDMMSSH)",
        lon_interval: ascii[4] "Longitude interval (0.1 s)",
        lat_interval: ascii[4] "Latitude interval (0.1 s)",
        accuracy: ascii[4] "Absolute vertical accuracy (m)",
        security: ascii[3] "Security code",
        reference: ascii[12] "Unique reference",
        lon_lines: ascii[4] "Longitude lines",
        lat_points: ascii[4] "Latitude points",
        multiple: ascii[1] "Multiple accuracy",
    }
}

async fn dted(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: DtedUhl = emit_record(&cx, file.sub(0, DtedUhl::SIZE), BE).await?;
    cx.emit(Node::new("Data set identification (DSI)").span(file.sub(80, 648)));
    cx.emit(Node::new("Accuracy (ACC)").span(file.sub(728, 2700)));
    cx.emit(Node::new("Elevation records").span(file.tail(3428)));
    cx.annotate(format!(
        "DTED tile at {} {}, {}×{} posts",
        h.latitude, h.longitude, h.lon_lines, h.lat_points
    ));
    Ok(())
}

declare_format!(pub NITF = "nitf", "National Imagery Transmission Format", ["ntf", "nitf", "nsf"], "image/x-nitf",
    Probe::Magic(&[(0, b"NITF02.10"), (0, b"NITF02.00"), (0, b"NSIF01.00")]), nitf);

record! {
    pub struct NitfHeader {
        profile: ascii[4] "File profile",
        version: ascii[5] "Version",
        complexity: ascii[2] "Complexity level",
        system: ascii[4] "Standard type",
        station: ascii[10] "Originating station",
        datetime: ascii[14] "File date and time",
        title: ascii[80] "File title",
        classification: ascii[1] "Security classification",
    }
}

async fn nitf(cx: Cx, input: Input) -> Result<()> {
    let h: NitfHeader = emit_record(&cx, input.span.sub(0, NitfHeader::SIZE), BE).await?;
    cx.emit(Node::new("Security and segments").span(input.span.tail(NitfHeader::SIZE)));
    cx.annotate(format!(
        "{}{} {:?} from {}",
        h.profile,
        h.version,
        h.title.trim(),
        h.station.trim()
    ));
    Ok(())
}
