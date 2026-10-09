//! GeoTIFF: the GeoKeyDirectory (tag 34735), an array of SHORTs holding a
//! header and `key, location, count, value` quadruples. A key's value is the
//! SHORT itself (location 0), or `count` items at index `value` of the
//! GeoDoubleParams (34736) or GeoAsciiParams (34737) arrays.

use crate::cx::Cx;
use crate::error::Result;
use crate::fields::Fields;
use crate::node::{Count, Node};
use crate::value::{EnumTable, Value, lookup};

use super::super::uint;
use super::render::trim;
use super::{Entry, Num, Tiff, num};

pub fn node(t: Tiff, dir: Entry, doubles: Option<Entry>, ascii: Option<Entry>) -> Node {
    Node::new("GeoKeys")
        .span(dir.data)
        .lazy(keys, (t, dir, doubles, ascii))
}

const KEYS: EnumTable = &[
    (1024, "GTModelTypeGeoKey"),
    (1025, "GTRasterTypeGeoKey"),
    (1026, "GTCitationGeoKey"),
    (2048, "GeographicTypeGeoKey"),
    (2049, "GeogCitationGeoKey"),
    (2050, "GeogGeodeticDatumGeoKey"),
    (2051, "GeogPrimeMeridianGeoKey"),
    (2052, "GeogLinearUnitsGeoKey"),
    (2053, "GeogLinearUnitSizeGeoKey"),
    (2054, "GeogAngularUnitsGeoKey"),
    (2055, "GeogAngularUnitSizeGeoKey"),
    (2056, "GeogEllipsoidGeoKey"),
    (2057, "GeogSemiMajorAxisGeoKey"),
    (2058, "GeogSemiMinorAxisGeoKey"),
    (2059, "GeogInvFlatteningGeoKey"),
    (2060, "GeogAzimuthUnitsGeoKey"),
    (2061, "GeogPrimeMeridianLongGeoKey"),
    (2062, "GeogTOWGS84GeoKey"),
    (3072, "ProjectedCSTypeGeoKey"),
    (3073, "PCSCitationGeoKey"),
    (3074, "ProjectionGeoKey"),
    (3075, "ProjCoordTransGeoKey"),
    (3076, "ProjLinearUnitsGeoKey"),
    (3077, "ProjLinearUnitSizeGeoKey"),
    (3078, "ProjStdParallel1GeoKey"),
    (3079, "ProjStdParallel2GeoKey"),
    (3080, "ProjNatOriginLongGeoKey"),
    (3081, "ProjNatOriginLatGeoKey"),
    (3082, "ProjFalseEastingGeoKey"),
    (3083, "ProjFalseNorthingGeoKey"),
    (3084, "ProjFalseOriginLongGeoKey"),
    (3085, "ProjFalseOriginLatGeoKey"),
    (3086, "ProjFalseOriginEastingGeoKey"),
    (3087, "ProjFalseOriginNorthingGeoKey"),
    (3088, "ProjCenterLongGeoKey"),
    (3089, "ProjCenterLatGeoKey"),
    (3090, "ProjCenterEastingGeoKey"),
    (3091, "ProjCenterNorthingGeoKey"),
    (3092, "ProjScaleAtNatOriginGeoKey"),
    (3093, "ProjScaleAtCenterGeoKey"),
    (3094, "ProjAzimuthAngleGeoKey"),
    (3095, "ProjStraightVertPoleLongGeoKey"),
    (4096, "VerticalCSTypeGeoKey"),
    (4097, "VerticalCitationGeoKey"),
    (4098, "VerticalDatumGeoKey"),
    (4099, "VerticalUnitsGeoKey"),
];

const MODEL_TYPE: EnumTable = &[(1, "Projected"), (2, "Geographic"), (3, "Geocentric")];
const RASTER_TYPE: EnumTable = &[(1, "PixelIsArea"), (2, "PixelIsPoint")];
const LINEAR_UNITS: EnumTable = &[
    (9001, "metre"),
    (9002, "foot"),
    (9003, "US survey foot"),
    (9030, "nautical mile"),
    (9036, "kilometre"),
];
const ANGULAR_UNITS: EnumTable = &[
    (9101, "radian"),
    (9102, "degree"),
    (9103, "arc-minute"),
    (9104, "arc-second"),
    (9105, "grad"),
];
const DATUMS: EnumTable = &[
    (6258, "ETRS89"),
    (6267, "NAD27"),
    (6269, "NAD83"),
    (6326, "WGS 84"),
];
const ELLIPSOIDS: EnumTable = &[(7008, "Clarke 1866"), (7019, "GRS 1980"), (7030, "WGS 84")];
const CRS: EnumTable = &[
    (3857, "WGS 84 / Pseudo-Mercator"),
    (4258, "ETRS89"),
    (4267, "NAD27"),
    (4269, "NAD83"),
    (4326, "WGS 84"),
];
const TRANSFORMS: EnumTable = &[
    (1, "Transverse Mercator"),
    (7, "Mercator"),
    (8, "Lambert conformal conic (2SP)"),
    (9, "Lambert conformal conic (1SP)"),
    (10, "Lambert azimuthal equal area"),
    (11, "Albers equal area"),
    (14, "Stereographic"),
    (15, "Polar stereographic"),
    (17, "Equirectangular"),
];

/// A name for a SHORT key value: EPSG codes and GeoTIFF enumerations.
fn code_name(key: u64, v: u64) -> Option<String> {
    if v == 32767 {
        return Some("user-defined".to_owned());
    }
    if v == 0 {
        return Some("undefined".to_owned());
    }
    let table = match key {
        1024 => MODEL_TYPE,
        1025 => RASTER_TYPE,
        2052 | 3076 | 4099 => LINEAR_UNITS,
        2054 | 2060 => ANGULAR_UNITS,
        2050 => DATUMS,
        2056 => ELLIPSOIDS,
        2051 if v == 8901 => return Some("Greenwich".to_owned()),
        3075 => TRANSFORMS,
        2048 | 3072 => {
            if let Some(name) = lookup(CRS, v) {
                return Some(format!("EPSG:{v} ({name})"));
            }
            let utm = |base: u64, datum: &str, hemisphere: char| {
                let zone = v.checked_sub(base)?;
                (1..=60)
                    .contains(&zone)
                    .then(|| format!("EPSG:{v} ({datum} / UTM zone {zone}{hemisphere})"))
            };
            return utm(32600, "WGS 84", 'N')
                .or_else(|| utm(32700, "WGS 84", 'S'))
                .or_else(|| utm(26900, "NAD83", 'N'))
                .or_else(|| Some(format!("EPSG:{v}")));
        }
        _ => return None,
    };
    lookup(table, v).map(str::to_owned)
}

type State = (Tiff, Entry, Option<Entry>, Option<Entry>);

async fn keys(cx: Cx, (t, dir, doubles, ascii): State) -> Result<()> {
    let block = cx.block(dir.data.sub(0, 8)).await?;
    let mut f = Fields::emitting(&cx, &block, t.endian);
    f.u16("KeyDirectoryVersion").emit()?;
    f.u16("KeyRevision").emit()?;
    f.u16("MinorRevision").emit()?;
    let declared = f.u16("NumberOfKeys").emit()?;
    let n = u64::from(declared).min(dir.count.saturating_sub(4) / 4);
    cx.set_count(Count::AtLeast(n));
    let short = |b: &[u8], i: usize| num(t, 3, b, i).and_then(Num::as_u64).unwrap_or(0);
    for i in 0..n {
        let span = dir.data.sub(i.saturating_add(1).saturating_mul(8), 8);
        let b = cx.read(span).await?;
        let (id, location, count, value) = (short(&b, 0), short(&b, 1), short(&b, 2), short(&b, 3));
        let name = lookup(KEYS, id).map_or_else(|| format!("Key {id}"), str::to_owned);
        let mut node = Node::new(name).span(span);
        match (location, doubles, ascii) {
            (0, _, _) => {
                node = node.value(uint(value));
                if let Some(text) = code_name(id, value) {
                    node = node.summary(text);
                }
            }
            (0x87b0, Some(d), _) => {
                let shown = count.min(16);
                let at = d.data.sub(value.saturating_mul(8), shown.saturating_mul(8));
                let bytes = cx.read_avail(at).await?;
                let v: Vec<f64> = (0..usize::try_from(shown).unwrap_or(0))
                    .map_while(|j| num(t, 12, &bytes, j).and_then(Num::f64))
                    .collect();
                node = node.target(at);
                node = match v.as_slice() {
                    [one] => node.value(Value::Float(*one)),
                    many => node.summary(format!(
                        "[{}]",
                        many.iter()
                            .map(|x| trim(*x, 6))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )),
                };
            }
            (0x87b1, _, Some(a)) => {
                let at = a.data.sub(value, count.min(1024));
                let bytes = cx.read_avail(at).await?;
                let text = crate::text::latin1(&bytes);
                node = node
                    .target(at)
                    .value(Value::Text(text.trim_end_matches(['|', '\0']).to_owned()));
            }
            (0x87af, _, _) => {
                let at = dir
                    .data
                    .sub(value.saturating_mul(2), count.min(64).saturating_mul(2));
                let bytes = cx.read_avail(at).await?;
                let v: Vec<String> = (0..bytes.len() / 2)
                    .map(|j| short(&bytes, j).to_string())
                    .collect();
                node = node.target(at).summary(format!("[{}]", v.join(", ")));
            }
            _ => {
                node = node.summary(format!("{count} values at index {value} of tag {location}"));
            }
        }
        cx.push(node).await;
    }
    Ok(())
}
