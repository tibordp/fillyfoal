//! XML and JSON vocabularies of the geospatial, vehicle and fitness world:
//! Garmin TCX, TrainingPeaks PWX, SportTracks FitLog, Zwift workouts,
//! OpenStreetMap change files, GML, AUTOSAR ARXML and ASAM ODX; TileJSON,
//! Mapbox GL styles and QGroundControl mission plans.
//!
//! These reuse the generic XML and JSON dissectors; the format entry only
//! recognises the vocabulary and annotates the file.

use crate::cx::Cx;
use crate::error::Result;
use crate::formats::text::probe;
use crate::formats::text::xml::{self, Mode, Root};
use crate::formats::{Format, Head, Input, Probe};

/// The root element, when the head is XML text.
fn xml_root(h: &Head<'_>) -> Option<Root> {
    if !probe::is_text(h) {
        return None;
    }
    xml::root(h)
}

macro_rules! xml_format {
    ($id:ident, $f:ident, $name:literal, $title:literal, [$($ext:literal),*], $mime:literal, $probe:expr, $detail:expr) => {
        pub static $id: Format = Format {
            name: $name,
            title: $title,
            extensions: &[$($ext),*],
            mime: $mime,
            probe: Probe::Custom(|h| xml_root(h).is_some_and($probe)),
            dissect: crate::expander!($f: Input),
        };
        async fn $f(cx: Cx, input: Input) -> Result<()> {
            let head = cx.read_avail(input.span.sub(0, 16 * 1024)).await?;
            let detail: Option<String> = ($detail)(head.as_slice());
            cx.annotate(match detail {
                Some(d) => format!("{}, {d}", $title),
                None => $title.to_owned(),
            });
            xml::document(&cx, input, Mode::Xml).await
        }
    };
}

/// How many times `tag` opens in `head` (a lower bound for large files).
fn count(head: &[u8], tag: &[u8]) -> usize {
    let mut open = b"<".to_vec();
    open.extend_from_slice(tag);
    head.windows(open.len())
        .filter(|w| *w == open.as_slice())
        .count()
}

xml_format!(
    TCX,
    tcx,
    "tcx",
    "Garmin Training Center activity",
    ["tcx"],
    "application/vnd.garmin.tcx+xml",
    |r| r.local() == b"TrainingCenterDatabase",
    |head: &[u8]| {
        let sport = probe::find(head, b"Sport=\"").and_then(|i| {
            let rest = head.get(i.saturating_add(7)..)?;
            let end = rest.iter().position(|&b| b == b'"')?;
            Some(String::from_utf8_lossy(rest.get(..end)?).into_owned())
        });
        let id = xml::first_text(head, b"Id");
        match (sport, id) {
            (Some(s), Some(i)) => Some(format!("{s} activity {i}")),
            (Some(s), None) => Some(format!("{s} activity")),
            (None, i) => i.or_else(|| xml::first_text(head, b"Name")),
        }
    }
);
xml_format!(
    PWX,
    pwx,
    "pwx",
    "TrainingPeaks workout (PWX)",
    ["pwx"],
    "application/xml",
    |r| r.local() == b"pwx",
    |head: &[u8]| xml::first_text(head, b"sportType")
);
xml_format!(
    FITLOG,
    fitlog,
    "fitlog",
    "SportTracks fitness log",
    ["fitlog"],
    "application/xml",
    |r| r.local() == b"FitnessWorkbook",
    |head: &[u8]| {
        let n = count(head, b"Activity ");
        (n > 0).then(|| format!("{n} activities in the head"))
    }
);
xml_format!(
    ZWO,
    zwo,
    "zwift-workout",
    "Zwift workout",
    ["zwo"],
    "application/xml",
    |r| r.local() == b"workout_file",
    |head: &[u8]| xml::first_text(head, b"name")
);
xml_format!(
    OSC,
    osc,
    "osm-change",
    "OpenStreetMap change file",
    ["osc"],
    "application/vnd.openstreetmap.osc+xml",
    |r| r.local() == b"osmChange",
    |head: &[u8]| Some(format!(
        "{} create, {} modify, {} delete blocks",
        count(head, b"create"),
        count(head, b"modify"),
        count(head, b"delete")
    ))
);
xml_format!(
    GML,
    gml,
    "gml",
    "Geography Markup Language",
    ["gml", "xml"],
    "application/gml+xml",
    |r| r.mentions(b"http://www.opengis.net/gml") && !matches!(r.local(), b"kml" | b"gpx" | b"osm"),
    |head: &[u8]| {
        let members = count(head, b"gml:featureMember")
            .saturating_add(count(head, b"wfs:member"))
            .saturating_add(count(head, b"cityObjectMember"));
        (members > 0).then(|| format!("{members} feature members in the head"))
    }
);
xml_format!(
    ARXML,
    arxml,
    "arxml",
    "AUTOSAR XML",
    ["arxml"],
    "application/xml",
    |r| r.local() == b"AUTOSAR",
    |head: &[u8]| xml::first_text(head, b"SHORT-NAME")
);
xml_format!(
    ODX,
    odx,
    "odx",
    "ASAM ODX diagnostic data",
    ["odx", "odx-d", "odx-c", "odx-cs", "odx-v", "pdx"],
    "application/xml",
    |r| r.local() == b"ODX",
    |head: &[u8]| xml::first_text(head, b"SHORT-NAME")
);

// ---------------------------------------------------------------------------
// JSON vocabularies

/// The head as text when it is a JSON object.
fn json_object(h: &Head<'_>) -> Option<Vec<u8>> {
    if !probe::is_text(h) {
        return None;
    }
    let data = probe::head(h).into_owned();
    probe::trim_start(&data).starts_with(b"{").then_some(data)
}

/// Whether `"key"` followed by `:` occurs in `data`.
fn has_key(data: &[u8], key: &[u8]) -> bool {
    let mut needle = b"\"".to_vec();
    needle.extend_from_slice(key);
    needle.push(b'"');
    let mut at = 0usize;
    while let Some(i) = data.get(at..).and_then(|d| probe::find(d, &needle)) {
        let after = at.saturating_add(i).saturating_add(needle.len());
        if probe::trim_start(data.get(after..).unwrap_or_default()).starts_with(b":") {
            return true;
        }
        at = after;
    }
    false
}

/// The value of `"key": value` (string or bare token), textually.
fn scrape(data: &[u8], key: &[u8]) -> Option<String> {
    let mut needle = b"\"".to_vec();
    needle.extend_from_slice(key);
    needle.push(b'"');
    let at = probe::find(data, &needle)?;
    let rest =
        probe::trim_start(data.get(at.saturating_add(needle.len())..)?).strip_prefix(b":")?;
    let rest = probe::trim_start(rest);
    if let Some(s) = rest.strip_prefix(b"\"") {
        let end = s.iter().position(|&b| b == b'"')?;
        return Some(String::from_utf8_lossy(s.get(..end)?).into_owned());
    }
    let end = rest
        .iter()
        .position(|b| !(b.is_ascii_alphanumeric() || *b == b'.'))
        .unwrap_or(rest.len());
    Some(String::from_utf8_lossy(rest.get(..end)?).into_owned())
}

macro_rules! json_format {
    ($id:ident, $f:ident, $name:literal, $title:literal, [$($ext:literal),*], $mime:literal, $probe:expr, $detail:expr) => {
        pub static $id: Format = Format {
            name: $name,
            title: $title,
            extensions: &[$($ext),*],
            mime: $mime,
            probe: Probe::Custom(|h| json_object(h).is_some_and(|d| ($probe)(d.as_slice()))),
            dissect: crate::expander!($f: Input),
        };
        async fn $f(cx: Cx, input: Input) -> Result<()> {
            let head = cx.read_avail(input.span.sub(0, 16 * 1024)).await?;
            let detail: Option<String> = ($detail)(head.as_slice());
            let result = crate::formats::text::json::dissect(cx.clone(), input).await;
            cx.annotate(match detail {
                Some(d) => format!("{}, {d}", $title),
                None => $title.to_owned(),
            });
            result
        }
    };
}

json_format!(
    TILEJSON,
    tilejson,
    "tilejson",
    "TileJSON tile set description",
    ["json"],
    "application/json",
    |d: &[u8]| has_key(d, b"tilejson") && has_key(d, b"tiles"),
    |d: &[u8]| scrape(d, b"name")
        .or_else(|| scrape(d, b"tilejson").map(|v| format!("version {v}")))
);
json_format!(
    MAPBOX_STYLE,
    mapbox_style,
    "mapbox-style",
    "Mapbox/MapLibre GL style",
    ["json"],
    "application/json",
    |d: &[u8]| has_key(d, b"version")
        && scrape(d, b"version").as_deref() == Some("8")
        && has_key(d, b"sources")
        && has_key(d, b"layers"),
    |d: &[u8]| scrape(d, b"name")
);
json_format!(
    QGC_PLAN,
    qgc_plan,
    "qgc-plan",
    "QGroundControl mission plan",
    ["plan"],
    "application/json",
    |d: &[u8]| scrape(d, b"fileType").as_deref() == Some("Plan") && has_key(d, b"groundStation"),
    |d: &[u8]| scrape(d, b"groundStation").map(|g| format!("from {g}"))
);
