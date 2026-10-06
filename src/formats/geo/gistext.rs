//! Text GIS and sports formats: IGC flight recorder logs, OziExplorer
//! tracks, waypoints, routes and map calibrations, MapInfo MIF and TAB,
//! GRASS ASCII rasters and vectors, IDRISI documentation files, WKT
//! coordinate reference systems (`.prj`), ESRI BIL/BIP/BSQ headers, Polar
//! HRM exercise files and ERG/MRC trainer workouts; and the binary SRM
//! power-meter file header.

use std::borrow::Cow;

use super::{leaf, text};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::text::piece::Piece;
use crate::formats::text::probe;
use crate::formats::text::scan::{LineBuf, Lines};
use crate::formats::{Head, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::Value;

/// A text line as a leaf.
fn line_leaf(line: &LineBuf) -> Node {
    leaf(format!("Line {}", line.number), line.span, text(line.text()))
}

/// Emits a region's lines as leaves (paged).
async fn region_lines(cx: Cx, span: Span) -> Result<()> {
    let mut lines = Lines::new(&cx, span);
    while let Some(line) = lines.next().await? {
        cx.push(line_leaf(&line)).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// IGC

fn igc_probe(h: &Head<'_>) -> bool {
    let lines = super::head_lines(h, 3);
    let (Some(a), Some(b)) = (lines.first(), lines.get(1)) else { return false };
    a.first() == Some(&b'A') && a.len() >= 4 && a.get(1..4).is_some_and(|m| m.iter().all(u8::is_ascii_alphanumeric)) && b.starts_with(b"H")
        && (b.get(1..5) == Some(b"FDTE") || probe::contains(&probe::head(h), b"\nHFDTE"))
}

declare_format!(pub IGC = "igc", "IGC flight recorder log", ["igc"], "text/x-igc",
    Probe::Custom(igc_probe), igc);

const B_RECORD: super::Columns = &[
    (0, 1, "Record"), (1, 6, "UTC time (HHMMSS)"), (7, 8, "Latitude (DDMMmmmN)"), (15, 9, "Longitude (DDDMMmmmE)"),
    (24, 1, "Fix validity"), (25, 5, "Pressure altitude (m)"), (30, 5, "GNSS altitude (m)"), (35, 64, "Extensions"),
];

/// `DDMMmmmH` / `DDDMMmmmH` as signed degrees.
fn igc_degrees(s: &str, deg_digits: usize) -> Option<f64> {
    let d: f64 = s.get(..deg_digits)?.parse().ok()?;
    let m: f64 = s.get(deg_digits..deg_digits.checked_add(5)?)?.parse().ok()?;
    let v = d + m / 60_000.0;
    Some(if matches!(s.get(deg_digits.checked_add(5)?..)?, "S" | "W") { -v } else { v })
}

async fn igc(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut fixes = 0u64;
    while let Some(line) = lines.next().await? {
        if line.is_blank() {
            continue;
        }
        let t = line.text();
        let node = match t.as_bytes().first() {
            Some(b'A') => {
                cx.annotate(format!("IGC flight log, recorder {}", t.get(1..).unwrap_or_default().trim()));
                leaf("Logger ID", line.span, text(t.get(1..).unwrap_or_default()))
            }
            Some(b'H') => {
                let body = t.get(2..).unwrap_or_default();
                let (k, v) = body.split_once(':').unwrap_or((body.get(..3).unwrap_or_default(), body.get(3..).unwrap_or_default()));
                leaf(format!("Header {}", k.trim()), line.span, text(v.trim()))
            }
            Some(b'B') => {
                fixes = fixes.saturating_add(1);
                let time = t.get(1..7).unwrap_or_default();
                let lat = igc_degrees(t.get(7..15).unwrap_or_default(), 2);
                let lon = igc_degrees(t.get(15..24).unwrap_or_default(), 3);
                let alt = t.get(30..35).unwrap_or_default().trim_start_matches('0');
                let pos = lat.zip(lon).map(|(a, b)| format!(", {a:.5}°, {b:.5}°")).unwrap_or_default();
                super::columns_node("Fix", line.span, B_RECORD).summary(format!("{}:{}:{}{pos}, {} m", time.get(..2).unwrap_or_default(), time.get(2..4).unwrap_or_default(), time.get(4..).unwrap_or_default(), if alt.is_empty() { "0" } else { alt }))
            }
            Some(b'I') => leaf("Fix extensions", line.span, text(t)),
            Some(b'J') => leaf("Data extensions", line.span, text(t)),
            Some(b'C') => leaf("Task", line.span, text(t.get(1..).unwrap_or_default())),
            Some(b'L') => leaf("Comment", line.span, text(t.get(1..).unwrap_or_default())),
            Some(b'E') => leaf("Event", line.span, text(t.get(1..).unwrap_or_default())),
            Some(b'F') => leaf("Satellites", line.span, text(t.get(1..).unwrap_or_default())),
            Some(b'K') => leaf("Data", line.span, text(t.get(1..).unwrap_or_default())),
            Some(b'G') => leaf("Security", line.span, text(t.get(1..).unwrap_or_default())),
            _ => line_leaf(&line),
        };
        cx.push(node).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// OziExplorer

fn ozi(h: &Head<'_>, title: &[u8]) -> bool {
    super::head_lines(h, 1).first().is_some_and(|l| l.starts_with(title))
}

declare_format!(pub OZI_TRACK = "ozi-track", "OziExplorer track", ["plt"], "text/x-ozi-track",
    Probe::Custom(|h| ozi(h, b"OziExplorer Track Point File")), ozi_track);
declare_format!(pub OZI_WAYPOINTS = "ozi-waypoints", "OziExplorer waypoints", ["wpt"], "text/x-ozi-waypoints",
    Probe::Custom(|h| ozi(h, b"OziExplorer Waypoint File")), ozi_waypoints);
declare_format!(pub OZI_ROUTE = "ozi-route", "OziExplorer route", ["rte"], "text/x-ozi-route",
    Probe::Custom(|h| ozi(h, b"OziExplorer Route File")), ozi_route);
declare_format!(pub OZI_MAP = "ozi-map", "OziExplorer map calibration", ["map"], "text/x-ozi-map",
    Probe::Custom(|h| ozi(h, b"OziExplorer Map Data File")), ozi_map);

const TRACK_HEADER: &[&str] = &["File type", "Datum", "Altitude units", "Reserved", "Track info", "Point count"];
const TRACK_POINT: super::Labels = &["Latitude", "Longitude", "New segment", "Altitude (ft)", "Date (days since 1899-12-30)", "Date", "Time"];
const WPT_HEADER: &[&str] = &["File type", "Datum", "Reserved", "GPS symbol set"];
const WAYPOINT: super::Labels = &["Number", "Name", "Latitude", "Longitude", "Date (days since 1899-12-30)", "Symbol", "Status", "Map display format", "Foreground colour", "Background colour", "Description", "Pointer direction", "Garmin display format", "Proximity distance", "Altitude (ft)", "Font size", "Font style", "Symbol size"];
const RTE_HEADER: &[&str] = &["File type", "Datum", "Reserved", "Reserved"];
const ROUTE: super::Labels = &["Record", "Route number", "Name", "Description", "Colour"];
const ROUTE_WAYPOINT: super::Labels = &["Record", "Route number", "Waypoint number", "Waypoint ID", "Name", "Latitude", "Longitude", "Date", "Symbol", "Status", "Map display format", "Foreground colour", "Background colour", "Description"];

/// Walks an Ozi file: a fixed number of header lines, then records.
async fn ozi_walk(cx: &Cx, file: Span, header: &[&'static str], record: fn(&LineBuf) -> Node) -> Result<u64> {
    let mut lines = Lines::new(cx, file);
    let mut n = 0u64;
    while let Some(line) = lines.next().await? {
        let index = usize::try_from(line.number.saturating_sub(1)).unwrap_or(usize::MAX);
        if let Some(name) = header.get(index) {
            cx.push(leaf(*name, line.span, text(line.text().trim()))).await;
            continue;
        }
        if line.is_blank() {
            continue;
        }
        cx.push(record(&line)).await;
        n = n.saturating_add(1);
    }
    Ok(n)
}

fn csv_field(line: &LineBuf, i: usize) -> String {
    line.text().split(',').nth(i).unwrap_or_default().trim().to_owned()
}

async fn ozi_track(cx: Cx, input: Input) -> Result<()> {
    cx.annotate("OziExplorer track");
    ozi_walk(&cx, input.span, TRACK_HEADER, |l| {
        super::delimited_node("Point", l, b',', TRACK_POINT).summary(format!("{}, {}", csv_field(l, 0), csv_field(l, 1)))
    })
    .await?;
    Ok(())
}

async fn ozi_waypoints(cx: Cx, input: Input) -> Result<()> {
    cx.annotate("OziExplorer waypoints");
    ozi_walk(&cx, input.span, WPT_HEADER, |l| {
        super::delimited_node(Cow::Owned(csv_field(l, 1)), l, b',', WAYPOINT).summary(format!("{}, {}", csv_field(l, 2), csv_field(l, 3)))
    })
    .await?;
    Ok(())
}

async fn ozi_route(cx: Cx, input: Input) -> Result<()> {
    cx.annotate("OziExplorer route");
    ozi_walk(&cx, input.span, RTE_HEADER, |l| {
        if l.bytes.starts_with(b"W") {
            super::delimited_node(Cow::Owned(format!("Waypoint {}", csv_field(l, 4))), l, b',', ROUTE_WAYPOINT).summary(format!("{}, {}", csv_field(l, 5), csv_field(l, 6)))
        } else {
            super::delimited_node(Cow::Owned(format!("Route {}", csv_field(l, 2))), l, b',', ROUTE)
        }
    })
    .await?;
    Ok(())
}

const MAP_HEADER: &[&str] = &["File type", "Title", "Image file", "Map code", "Datum", "Reserved", "Reserved", "Magnetic variation", "Projection"];

async fn ozi_map(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut title = String::new();
    while let Some(line) = lines.next().await? {
        let index = usize::try_from(line.number.saturating_sub(1)).unwrap_or(usize::MAX);
        if line.is_blank() {
            continue;
        }
        let t = line.text();
        if index == 1 {
            title = t.trim().to_owned();
        }
        let node = match MAP_HEADER.get(index) {
            Some(name) => leaf(*name, line.span, text(t.trim())),
            None => {
                let key = t.split(',').next().unwrap_or_default().trim().to_owned();
                super::delimited_node(Cow::Owned(key), &line, b',', &[])
            }
        };
        cx.push(node).await;
    }
    cx.annotate(format!("OziExplorer map calibration {title:?}"));
    Ok(())
}

// ---------------------------------------------------------------------------
// MapInfo

fn mif_probe(h: &Head<'_>) -> bool {
    let data = probe::head(h);
    let mut lines = probe::significant(&data, &[]);
    let Some(first) = lines.next() else { return false };
    let first = probe::trim(first);
    probe::starts_with_nocase(first, b"version ")
        && first.get(8..).is_some_and(|v| !v.is_empty() && probe::trim(v).iter().all(u8::is_ascii_digit))
        && probe::find_nocase(&data, b"\ncolumns ").is_some()
        && probe::find_nocase(&data, b"\ndata").is_some()
}

declare_format!(pub MIF = "mapinfo-mif", "MapInfo Interchange Format", ["mif"], "text/x-mapinfo-mif",
    Probe::Custom(mif_probe), mif);

const MIF_OBJECTS: &[&str] = &["point", "line", "pline", "region", "arc", "text", "rect", "roundrect", "ellipse", "multipoint", "collection", "none"];

async fn mif(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut header_end = 0u64;
    let mut columns = 0u64;
    while let Some(line) = lines.next().await? {
        let t = line.text();
        let word = t.split_whitespace().next().unwrap_or_default().to_ascii_lowercase();
        header_end = line.next;
        if word == "columns" {
            columns = t.split_whitespace().nth(1).and_then(|n| n.parse().ok()).unwrap_or(0);
        }
        if word == "data" {
            break;
        }
    }
    let hspan = file.sub(0, header_end);
    cx.emit(Node::new("Header").span(hspan).summary(format!("{columns} columns")).lazy(mif_header, hspan));
    cx.annotate(format!("MapInfo MIF, {columns} attribute columns"));
    let body = file.tail(header_end);
    let mut lines = Lines::new(&cx, body);
    let mut current: Option<(u64, String)> = None;
    let mut n = 0u64;
    loop {
        let Some(line) = lines.peek().await? else { break };
        let t = line.text();
        let word = t.split_whitespace().next().unwrap_or_default().to_ascii_lowercase();
        let starts = MIF_OBJECTS.contains(&word.as_str());
        if starts && let Some((from, first)) = current.take() {
            let span = body.sub(from, line.start.saturating_sub(from));
            cx.push(mif_object(span, &first, n)).await;
            n = n.saturating_add(1);
        }
        let _ = lines.next().await?;
        if starts {
            current = Some((line.start, t.trim().to_owned()));
        }
    }
    if let Some((from, first)) = current {
        cx.push(mif_object(body.tail(from), &first, n)).await;
    }
    Ok(())
}

fn mif_object(span: Span, first: &str, index: u64) -> Node {
    let kind = first.split_whitespace().next().unwrap_or_default();
    Node::new(format!("Object {index}: {kind}")).span(span).summary(first.chars().take(80).collect::<String>()).lazy(region_lines, span)
}

async fn mif_header(cx: Cx, span: Span) -> Result<()> {
    let mut lines = Lines::new(&cx, span);
    while let Some(line) = lines.next().await? {
        if line.is_blank() {
            continue;
        }
        let piece = line.piece().trim();
        let (k, v) = piece.split_word();
        let node = if line.bytes.first().is_some_and(u8::is_ascii_whitespace) {
            leaf(format!("Column {}", k.text()), line.span, text(v.text()))
        } else {
            Node::new(k.text()).span(line.span).value(text(v.text()))
        };
        cx.push(node).await;
    }
    Ok(())
}

fn tab_probe(h: &Head<'_>) -> bool {
    let lines = super::head_lines(h, 2);
    lines.first().is_some_and(|l| probe::starts_with_nocase(probe::trim(l), b"!table"))
        && lines.get(1).is_some_and(|l| probe::starts_with_nocase(probe::trim(l), b"!version"))
}

declare_format!(pub TAB = "mapinfo-tab", "MapInfo table definition", ["tab"], "text/x-mapinfo-tab",
    Probe::Custom(tab_probe), tab);

fn tab_name(first: &str) -> (Cow<'static, str>, Option<String>) {
    let (k, v) = first.split_once(char::is_whitespace).unwrap_or((first, ""));
    (Cow::Owned(k.to_owned()), Some(v.trim().to_owned()).filter(|v| !v.is_empty()))
}

async fn tab(cx: Cx, input: Input) -> Result<()> {
    let head = cx.read(input.span.sub(0, 4096)).await?;
    let raster = probe::find_nocase(&head, b"\"RASTER\"").is_some();
    cx.annotate(if raster { "MapInfo raster table" } else { "MapInfo table definition" });
    super::vehicle::statements(&cx, input.span, tab_name).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// GRASS ASCII raster and vector

fn grass_probe(h: &Head<'_>) -> bool {
    let lines = super::head_lines(h, 6);
    let keys: Vec<String> = lines
        .iter()
        .filter_map(|l| {
            let t = String::from_utf8_lossy(l);
            let (k, v) = t.split_once(':')?;
            (!v.trim().is_empty()).then(|| k.trim().to_ascii_lowercase())
        })
        .collect();
    keys.len() == 6 && ["north", "south", "east", "west", "rows", "cols"].iter().all(|k| keys.iter().any(|x| x == k))
}

declare_format!(pub GRASS_ASCII = "grass-ascii", "GRASS ASCII raster", ["asc", "txt", "grass"], "text/x-grass-ascii",
    Probe::Custom(grass_probe), grass_ascii);

const GRASS_KEYS: &[&str] = &["north", "south", "east", "west", "rows", "cols", "null", "type", "multiplier"];

async fn grass_ascii(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let (mut rows, mut cols) = (String::new(), String::new());
    let mut row = 0u64;
    while let Some(line) = lines.next().await? {
        if line.is_blank() {
            continue;
        }
        let t = line.text();
        if row == 0
            && let Some((k, v)) = t.split_once(':')
            && GRASS_KEYS.contains(&k.trim().to_ascii_lowercase().as_str())
        {
            match k.trim() {
                "rows" => rows = v.trim().to_owned(),
                "cols" => cols = v.trim().to_owned(),
                _ => {}
            }
            if let Some(node) = super::key_value(&line, b':') {
                cx.push(node).await;
            }
            continue;
        }
        if row == 0 {
            cx.annotate(format!("GRASS ASCII raster, {rows} rows × {cols} columns"));
        }
        cx.push(super::words_node(format!("Row {row}"), &line, &[])).await;
        row = row.saturating_add(1);
    }
    Ok(())
}

declare_format!(pub GRASS_VECTOR = "grass-vector", "GRASS ASCII vector", ["txt", "grass"], "text/x-grass-vector",
    Probe::Custom(|h| h.starts_with(b"ORGANIZATION:") && probe::contains(&probe::head(h), b"\nVERTI:")), grass_vector);

async fn grass_vector(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut body = 0u64;
    while let Some(line) = lines.next().await? {
        if line.bytes.starts_with(b"VERTI:") {
            body = line.next;
            cx.push(leaf("VERTI", line.span, text(""))).await;
            break;
        }
        if let Some(node) = super::key_value(&line, b':') {
            cx.push(node).await;
        }
    }
    cx.annotate("GRASS ASCII vector");
    // Each feature: a type line (`L  3 1`) followed by its coordinates.
    let region = file.tail(body);
    let mut lines = Lines::new(&cx, region);
    let mut n = 0u64;
    while let Some(line) = lines.next().await? {
        let t = line.text();
        let mut words = t.split_whitespace();
        let (Some(kind), Some(count)) = (words.next(), words.next().and_then(|c| c.parse::<u64>().ok())) else { continue };
        if !kind.chars().all(|c| c.is_ascii_alphabetic()) {
            continue;
        }
        let start = line.start;
        let mut end = line.next;
        for _ in 0..count.min(1 << 20) {
            match lines.next().await? {
                Some(l) => end = l.next,
                None => break,
            }
        }
        let kind_name = match kind {
            "P" | "p" => "Point",
            "L" | "l" => "Line",
            "B" | "b" => "Boundary",
            "C" | "c" => "Centroid",
            "F" | "f" => "Face",
            "K" | "k" => "Kernel",
            _ => "Feature",
        };
        let span = region.sub(start, end.saturating_sub(start));
        cx.push(Node::new(format!("{kind_name} {n}")).span(span).summary(format!("{count} coordinates")).lazy(region_lines, span)).await;
        n = n.saturating_add(1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// IDRISI documentation files

fn idrisi_probe(h: &Head<'_>) -> bool {
    super::head_lines(h, 1).first().is_some_and(|l| {
        let t = String::from_utf8_lossy(l);
        t.split_once(':').is_some_and(|(k, v)| k.trim() == "file format" && v.trim().starts_with("IDRISI"))
    })
}

declare_format!(pub IDRISI = "idrisi-doc", "IDRISI raster/vector documentation file", ["rdc", "vdc"], "text/x-idrisi",
    Probe::Custom(idrisi_probe), idrisi);

async fn idrisi(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let (mut format, mut cols, mut rows, mut ty) = (String::new(), String::new(), String::new(), String::new());
    while let Some(line) = lines.next().await? {
        let t = line.text();
        if let Some((k, v)) = t.split_once(':') {
            match k.trim() {
                "file format" => format = v.trim().to_owned(),
                "columns" => cols = v.trim().to_owned(),
                "rows" => rows = v.trim().to_owned(),
                "data type" => ty = v.trim().to_owned(),
                _ => {}
            }
        }
        let node = super::key_value(&line, b':').unwrap_or_else(|| line_leaf(&line));
        cx.push(node).await;
        if line.number == 8 {
            let size = if cols.is_empty() { String::new() } else { format!(", {cols}×{rows} {ty}") };
            cx.annotate(format!("{format}{size}"));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// WKT coordinate reference systems

const WKT_ROOTS: &[&[u8]] = &[
    b"PROJCS[", b"GEOGCS[", b"GEOCCS[", b"COMPD_CS[", b"VERT_CS[", b"LOCAL_CS[", b"FITTED_CS[",
    b"PROJCRS[", b"GEOGCRS[", b"GEODCRS[", b"COMPOUNDCRS[", b"VERTCRS[", b"ENGCRS[", b"BOUNDCRS[",
];

fn wkt_probe(h: &Head<'_>) -> bool {
    let data = probe::head(h);
    let t = probe::trim_start(&data);
    WKT_ROOTS.iter().any(|r| t.starts_with(r)) && probe::is_text(h)
}

declare_format!(pub WKT = "wkt-crs", "WKT coordinate reference system", ["prj", "wkt"], "text/x-wkt-crs",
    Probe::Custom(wkt_probe), wkt);

/// The longest WKT read whole.
const WKT_MAX: u64 = 1 << 20;

/// Parses one element `KEYWORD[params]` at `*at`, returning its node.
fn wkt_element(p: Piece<'_>, at: &mut usize, depth: u32) -> Option<Node> {
    let b = p.bytes();
    while b.get(*at).is_some_and(u8::is_ascii_whitespace) {
        *at = at.saturating_add(1);
    }
    let start = *at;
    while b.get(*at).is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_') {
        *at = at.saturating_add(1);
    }
    let keyword = p.slice(start, *at).text();
    if !matches!(b.get(*at), Some(b'[' | b'(')) {
        return None;
    }
    *at = at.saturating_add(1);
    let mut name: Option<String> = None;
    let mut children = Vec::new();
    let mut params = Vec::new();
    loop {
        while b.get(*at).is_some_and(|c| c.is_ascii_whitespace() || *c == b',') {
            *at = at.saturating_add(1);
        }
        match b.get(*at) {
            None => return None,
            Some(b']' | b')') => {
                *at = at.saturating_add(1);
                break;
            }
            Some(b'"') => {
                let s = at.saturating_add(1);
                let mut e = s;
                // "" escapes a quote.
                while let Some(&c) = b.get(e) {
                    if c == b'"' && b.get(e.saturating_add(1)) == Some(&b'"') {
                        e = e.saturating_add(2);
                    } else if c == b'"' {
                        break;
                    } else {
                        e = e.saturating_add(1);
                    }
                }
                let s_text = p.slice(s, e).text().replace("\"\"", "\"");
                if name.is_none() {
                    name = Some(s_text);
                } else {
                    params.push(Node::new("Text").span(p.slice(s, e).span()).value(Value::Text(s_text)));
                }
                *at = e.saturating_add(1);
            }
            Some(c) if c.is_ascii_alphabetic() => {
                let save = *at;
                if depth >= 32 {
                    return None;
                }
                if let Some(child) = wkt_element(p, at, depth.saturating_add(1)) {
                    children.push(child);
                } else {
                    // A bare word (an enumeration such as `NORTH`).
                    *at = save;
                    while b.get(*at).is_some_and(|c| !matches!(c, b',' | b']' | b')')) {
                        *at = at.saturating_add(1);
                    }
                    let w = p.slice(save, *at).trim();
                    params.push(Node::new("Value").span(w.span()).value(Value::Text(w.text())));
                }
            }
            Some(_) => {
                let s = *at;
                while b.get(*at).is_some_and(|c| !matches!(c, b',' | b']' | b')')) {
                    *at = at.saturating_add(1);
                }
                let w = p.slice(s, *at).trim();
                params.push(super::field_node("Value", w));
            }
        }
    }
    let span = p.slice(start, *at).span();
    let mut nodes = params;
    nodes.extend(children);
    let mut node = Node::new(keyword).span(span);
    if let Some(n) = name {
        node = node.value(Value::Text(n));
    }
    Some(if nodes.is_empty() { node } else { node.lazy(super::emit_nodes, nodes) })
}

async fn wkt(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    if file.len > WKT_MAX {
        return Err(Diagnostic::limit("WKT text too large").at(file));
    }
    let data = cx.read(file).await?;
    let piece = Piece::new(&data, file);
    let mut at = 0usize;
    let root = wkt_element(piece, &mut at, 0).ok_or_else(|| Diagnostic::malformed("unbalanced WKT").at(file))?;
    let summary = format!("{}{}", root.name, root.value.as_ref().map(|v| format!(" {}", crate::render::value(v))).unwrap_or_default());
    cx.annotate(format!("WKT CRS: {summary}"));
    cx.emit(root);
    Ok(())
}

// ---------------------------------------------------------------------------
// ESRI BIL/BIP/BSQ header

fn bil_probe(h: &Head<'_>) -> bool {
    let data = probe::head(h);
    let lines: Vec<&[u8]> = probe::significant(&data, &[]).take(24).collect();
    let keys: Vec<String> = lines.iter().map(|l| String::from_utf8_lossy(probe::trim(l)).split_whitespace().next().unwrap_or_default().to_ascii_uppercase()).collect();
    let all_keys = lines.iter().all(|l| {
        let t = probe::trim(l);
        t.iter().take_while(|b| !b.is_ascii_whitespace()).all(|b| b.is_ascii_alphanumeric() || *b == b'_') && t.iter().any(u8::is_ascii_whitespace)
    });
    all_keys
        && keys.iter().any(|k| k == "NROWS")
        && keys.iter().any(|k| k == "NCOLS")
        && keys.iter().any(|k| matches!(k.as_str(), "LAYOUT" | "BYTEORDER" | "NBITS"))
}

declare_format!(pub BIL_HDR = "esri-bil-hdr", "ESRI BIL/BIP/BSQ raster header", ["hdr"], "text/x-esri-hdr",
    Probe::Custom(bil_probe), bil_hdr);

async fn bil_hdr(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut layout = String::from("BIL");
    let (mut rows, mut cols, mut bands) = (String::new(), String::new(), String::from("1"));
    while let Some(line) = lines.next().await? {
        if line.is_blank() {
            continue;
        }
        let piece = line.piece().trim();
        let (k, v) = piece.split_word();
        let key = k.text().to_ascii_uppercase();
        match key.as_str() {
            "LAYOUT" => layout = v.text().to_ascii_uppercase(),
            "NROWS" => rows = v.text(),
            "NCOLS" => cols = v.text(),
            "NBANDS" => bands = v.text(),
            _ => {}
        }
        cx.push(super::field_node(key, v).span(line.span)).await;
    }
    cx.annotate(format!("ESRI {layout} header, {rows}×{cols}, {bands} bands"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Bracketed sections: Polar HRM and ERG/MRC workouts

/// Lists `[Section]` blocks; their lines become `key=value` leaves or
/// whitespace-separated rows.
async fn sections(cx: &Cx, file: Span) -> Result<u64> {
    let mut lines = Lines::new(cx, file);
    let mut current: Option<(u64, String)> = None;
    let mut n = 0u64;
    loop {
        let Some(line) = lines.peek().await? else { break };
        let t = line.text();
        let trimmed = t.trim();
        let starts = trimmed.starts_with('[') && trimmed.ends_with(']') && !trimmed.starts_with("[END");
        if starts && let Some((from, name)) = current.take() {
            push_section(cx, file.sub(from, line.start.saturating_sub(from)), name).await;
            n = n.saturating_add(1);
        }
        let _ = lines.next().await?;
        if starts {
            current = Some((line.start, trimmed.trim_matches(['[', ']']).to_owned()));
        }
    }
    if let Some((from, name)) = current {
        push_section(cx, file.tail(from), name).await;
        n = n.saturating_add(1);
    }
    Ok(n)
}

async fn push_section(cx: &Cx, span: Span, name: String) {
    cx.push(Node::new(name).span(span).lazy(section_lines, span)).await;
}

async fn section_lines(cx: Cx, span: Span) -> Result<()> {
    let mut lines = Lines::new(&cx, span);
    let mut row = 0u64;
    while let Some(line) = lines.next().await? {
        if line.number == 1 || line.is_blank() {
            continue;
        }
        let node = if line.bytes.contains(&b'=') {
            super::key_value(&line, b'=').unwrap_or_else(|| line_leaf(&line))
        } else if line.bytes.starts_with(b"[") {
            line_leaf(&line)
        } else {
            row = row.saturating_add(1);
            super::words_node(format!("Row {row}"), &line, &[])
        };
        cx.push(node).await;
    }
    Ok(())
}

fn hrm_probe(h: &Head<'_>) -> bool {
    let data = probe::head(h);
    probe::trim_start(&data).starts_with(b"[Params]") && probe::contains(&data, b"Version=") && (probe::contains(&data, b"SMode=") || probe::contains(&data, b"Monitor="))
}

declare_format!(pub HRM = "polar-hrm", "Polar HRM exercise file", ["hrm"], "text/x-polar-hrm",
    Probe::Custom(hrm_probe), hrm);

async fn hrm(cx: Cx, input: Input) -> Result<()> {
    let head = cx.read(input.span.sub(0, 2048)).await?;
    let t = String::from_utf8_lossy(&head);
    let get = |k: &str| t.lines().find_map(|l| l.strip_prefix(k)).map(|v| v.trim().to_owned()).unwrap_or_default();
    cx.annotate(format!("Polar HRM v{}, {} {}, duration {}", get("Version="), get("Date="), get("StartTime="), get("Length=")));
    sections(&cx, input.span).await?;
    Ok(())
}

declare_format!(pub ERG = "erg-workout", "ERG/MRC trainer workout", ["erg", "mrc"], "text/x-erg",
    Probe::Custom(|h| probe::trim_start(&probe::head(h)).starts_with(b"[COURSE HEADER]")), erg);

async fn erg(cx: Cx, input: Input) -> Result<()> {
    let head = cx.read(input.span.sub(0, 2048)).await?;
    let t = String::from_utf8_lossy(&head);
    let units = t.lines().find_map(|l| l.trim().split_once(' ').filter(|(a, _)| a.eq_ignore_ascii_case("MINUTES")).map(|(_, b)| b.trim().to_owned())).unwrap_or_default();
    let kind = if units.eq_ignore_ascii_case("PERCENT") { "MRC (% FTP)" } else { "ERG (watts)" };
    cx.annotate(format!("{kind} trainer workout"));
    sections(&cx, input.span).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// SRM power meter files

declare_format!(pub SRM = "srm", "SRM power meter ride file", ["srm"], "application/x-srm",
    Probe::Custom(|h| matches!(h.data.get(..4), Some(b"SRM5" | b"SRM6" | b"SRM7")) && h.data.get(14).is_some_and(|&p| p <= 1)), srm);

record! {
    pub struct SrmHeader {
        magic: ascii[4] "Magic",
        days: u16 "Days since 1880-01-01",
        circumference: u16 "Wheel circumference (mm)",
        recint1: u8 "Recording interval numerator",
        recint2: u8 "Recording interval denominator",
        blocks: u16 "Data blocks",
        markers: u16 "Markers",
        _pad: u8 "Padding",
        comment_len: u8 "Comment length",
        comment: ascii[70] "Comment",
    }
}

async fn srm(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: SrmHeader = read_record(&cx, file.sub(0, SrmHeader::SIZE), Endian::Little).await?;
    cx.emit(SrmHeader::node("Header", file.sub(0, SrmHeader::SIZE), Endian::Little));
    cx.emit(Node::new("Markers, blocks and samples").span(file.tail(SrmHeader::SIZE)));
    // 1880-01-01 is 32,873 days before the Unix epoch.
    let date = i64::from(h.days).saturating_sub(32_873).saturating_mul(86_400);
    cx.emit(leaf("Ride date", file.sub(4, 2), Value::Timestamp { unix_seconds: date }));
    cx.annotate(format!("SRM ride ({}), {} blocks, {} markers, interval {}/{} s", h.magic, h.blocks, h.markers, h.recint1, h.recint2));
    Ok(())
}
