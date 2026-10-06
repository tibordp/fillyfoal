//! More geoscience formats: ESRI projection (WKT) and BIL headers, ER Mapper
//! and IDRISI raster headers, ISO 8211 (S-57 charts, SDTS) and DLIS well logs.

use crate::bytes::{to_u64, to_usize, u16_be};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::lines::{Lines, head_lines, is_text, number, preview, summarize, tally, text};
use crate::formats::{Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, flag, lookup};

const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// WKT coordinate reference systems (ESRI .prj)

const WKT_ROOTS: [&[u8]; 8] = [b"PROJCS[", b"GEOGCS[", b"GEOCCS[", b"COMPD_CS[", b"LOCAL_CS[", b"PROJCRS[", b"GEOGCRS[", b"COMPOUNDCRS["];

declare_format!(pub ESRI_PRJ = "esri-prj", "WKT coordinate reference system (.prj)", ["prj", "wkt"], "text/x-wkt-crs",
    Probe::Custom(|h| is_text(h) && WKT_ROOTS.iter().any(|r| h.data.trim_ascii_start().starts_with(r))), esri_prj);

/// Elements of a WKT node body: (keyword or value, start, end, is node).
fn wkt_elements(data: &[u8]) -> Vec<(usize, usize, bool)> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < data.len() && out.len() < 100_000 {
        let Some(&c) = data.get(i) else { break };
        if c.is_ascii_whitespace() || c == b',' {
            i = i.saturating_add(1);
            continue;
        }
        let start = i;
        if c == b'"' {
            i = i.saturating_add(1);
            while data.get(i).is_some_and(|&b| b != b'"') {
                i = i.saturating_add(1);
            }
            i = i.saturating_add(1).min(data.len());
            out.push((start, i, false));
            continue;
        }
        while data.get(i).is_some_and(|&b| b != b'[' && b != b'(' && b != b',' && b != b']' && b != b')') {
            i = i.saturating_add(1);
        }
        if data.get(i).is_some_and(|&b| b == b'[' || b == b'(') {
            let mut depth = 0u32;
            let mut quoted = false;
            while let Some(&b) = data.get(i) {
                match b {
                    b'"' => quoted = !quoted,
                    b'[' | b'(' if !quoted => depth = depth.saturating_add(1),
                    b']' | b')' if !quoted => {
                        depth = depth.saturating_sub(1);
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
                i = i.saturating_add(1);
            }
            i = i.saturating_add(1).min(data.len());
            out.push((start, i, true));
        } else {
            out.push((start, i.max(start.saturating_add(1)), false));
            i = i.max(start.saturating_add(1));
        }
    }
    out
}

/// Keyword and inner bytes of a WKT node.
fn wkt_split(node: &[u8]) -> (String, &[u8]) {
    let open = node.iter().position(|&b| b == b'[' || b == b'(').unwrap_or(node.len());
    let key = String::from_utf8_lossy(node.get(..open).unwrap_or_default()).trim().to_owned();
    (key, node.get(open.saturating_add(1)..node.len().saturating_sub(1)).unwrap_or_default())
}

fn wkt_name(inner: &[u8]) -> String {
    wkt_elements(inner).first().filter(|e| !e.2).map(|&(a, b, _)| String::from_utf8_lossy(inner.get(a..b).unwrap_or_default()).trim_matches('"').to_owned()).unwrap_or_default()
}

/// Finds the first node named `key` (depth-first).
fn wkt_find(data: &[u8], key: &str, depth: u32) -> Option<String> {
    if depth > 32 {
        return None;
    }
    for (a, b, node) in wkt_elements(data) {
        if !node {
            continue;
        }
        let (k, inner) = wkt_split(data.get(a..b).unwrap_or_default());
        if k == key {
            return Some(wkt_name(inner));
        }
        if let Some(found) = wkt_find(inner, key, depth.saturating_add(1)) {
            return Some(found);
        }
    }
    None
}

async fn esri_prj(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let data = cx.read_avail(file.sub(0, 0x10_0000)).await?;
    let elements = wkt_elements(&data);
    let Some(&(a, b, true)) = elements.first() else {
        return Err(Diagnostic::malformed("expected a WKT node"));
    };
    let root = data.get(a..b).unwrap_or_default();
    let (key, inner) = wkt_split(root);
    let name = wkt_name(inner);
    cx.emit(Node::new(key.clone()).span(file.sub(to_u64(a), to_u64(b.saturating_sub(a)))).value(text(name.clone())).lazy(wkt_node, (file.sub(to_u64(a), to_u64(b.saturating_sub(a))), 0u32)));
    let datum = wkt_find(inner, "DATUM", 0).unwrap_or_default();
    let projection = wkt_find(inner, "PROJECTION", 0).unwrap_or_default();
    // The CRS unit is a direct child; nested ones belong to the base CRS.
    let unit = wkt_elements(inner).into_iter().filter(|e| e.2).map(|(a, b, _)| wkt_split(inner.get(a..b).unwrap_or_default())).find(|(k, _)| k == "UNIT").map(|(_, body)| wkt_name(body)).or_else(|| wkt_find(inner, "UNIT", 0)).unwrap_or_default();
    cx.annotate(format!(
        "WKT {key} {name:?}{}{}{}",
        if projection.is_empty() { String::new() } else { format!(", {projection}") },
        if datum.is_empty() { String::new() } else { format!(", datum {datum}") },
        if unit.is_empty() { String::new() } else { format!(", unit {unit}") }
    ));
    Ok(())
}

async fn wkt_node(cx: Cx, (span, depth): (Span, u32)) -> Result<()> {
    if depth > 64 {
        return Err(Diagnostic::limit("nodes nested too deeply"));
    }
    let data = cx.read_avail(span).await?;
    let open = data.iter().position(|&b| b == b'[' || b == b'(').unwrap_or(0).saturating_add(1);
    let inner = data.get(open..data.len().saturating_sub(1)).unwrap_or_default();
    for (a, b, node) in wkt_elements(inner) {
        let s = span.sub(to_u64(open.saturating_add(a)), to_u64(b.saturating_sub(a)));
        let raw = inner.get(a..b).unwrap_or_default();
        if node {
            let (k, body) = wkt_split(raw);
            let name = wkt_name(body);
            let has_children = wkt_elements(body).iter().any(|e| e.2) || wkt_elements(body).len() > 1;
            let n = Node::new(k).span(s).value(text(name));
            cx.push(if has_children { n.lazy(crate::expander!(self::wkt_node: (Span, u32)), (s, depth.saturating_add(1))) } else { n }).await;
        } else {
            let v = String::from_utf8_lossy(raw).trim_matches('"').to_owned();
            cx.push(Node::new("value").span(s).value(number(&v))).await;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Keyword/value raster headers: ESRI BIL, ER Mapper, IDRISI

const BIL_KEYS: [&str; 16] = ["BYTEORDER", "LAYOUT", "NROWS", "NCOLS", "NBANDS", "NBITS", "BANDROWBYTES", "TOTALROWBYTES", "BANDGAPBYTES", "PIXELTYPE", "ULXMAP", "ULYMAP", "XDIM", "YDIM", "NODATA", "SKIPBYTES"];

fn bil_probe(h: &Head<'_>) -> bool {
    let key = |l: &[u8]| {
        let w = String::from_utf8_lossy(l).split_whitespace().next().unwrap_or_default().to_ascii_uppercase();
        BIL_KEYS.contains(&w.as_str())
    };
    let lines: Vec<&[u8]> = head_lines(h, 8).into_iter().filter(|l| !l.trim_ascii().is_empty()).collect();
    is_text(h) && lines.first().is_some_and(|l| key(l)) && lines.iter().filter(|l| key(l)).count() >= 3
}

declare_format!(pub ESRI_BIL_HDR = "esri-bil-hdr", "ESRI BIL/BIP/BSQ raster header", ["hdr"], "text/x-esri-bil-header",
    Probe::Custom(bil_probe), esri_bil_hdr);

async fn esri_bil_hdr(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut items: Vec<(String, String)> = Vec::new();
    while let Some(line) = lines.next().await? {
        let t = line.text();
        let mut w = t.split_whitespace();
        let (Some(k), v) = (w.next(), w.collect::<Vec<_>>().join(" ")) else { continue };
        cx.push(Node::new(k.to_owned()).span(line.content()).value(number(&v))).await;
        items.push((k.to_ascii_uppercase(), v));
    }
    let get = |k: &str| items.iter().find(|(a, _)| a == k).map_or("?".to_owned(), |(_, v)| v.clone());
    cx.annotate(format!("ESRI {} raster header, {}×{} × {} band(s), {}-bit", get("LAYOUT"), get("NCOLS"), get("NROWS"), get("NBANDS"), get("NBITS")));
    Ok(())
}

declare_format!(pub ERMAPPER_ERS = "ermapper-ers", "ER Mapper raster header (.ers)", ["ers"], "text/x-ermapper",
    Probe::Custom(|h| is_text(h) && h.data.trim_ascii_start().starts_with(b"DatasetHeader Begin")), ermapper);

/// One `X Begin … X End` block: name, span, entries and nested blocks.
#[derive(Clone, Debug)]
struct ErsBlock {
    name: String,
    span: Span,
    items: Vec<(String, String, Span)>,
    children: Vec<ErsBlock>,
}

async fn ermapper(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut stack: Vec<ErsBlock> = vec![ErsBlock { name: String::new(), span: file, items: Vec::new(), children: Vec::new() }];
    while let Some(line) = lines.next().await? {
        let t = line.text();
        let t = t.trim();
        if let Some(name) = t.strip_suffix(" Begin") {
            if stack.len() < 64 {
                stack.push(ErsBlock { name: name.trim().to_owned(), span: line.span, items: Vec::new(), children: Vec::new() });
            }
        } else if t.ends_with(" End") && stack.len() > 1 {
            if let Some(mut done) = stack.pop() {
                done.span = Span::new(done.span.source, done.span.offset, line.span.end().saturating_sub(done.span.offset));
                if let Some(top) = stack.last_mut() {
                    top.children.push(done);
                }
            }
        } else if let Some((k, v)) = t.split_once('=')
            && let Some(top) = stack.last_mut()
            && top.items.len() < 10_000
        {
            top.items.push((k.trim().to_owned(), v.trim().trim_matches('"').to_owned(), line.content()));
        }
    }
    while stack.len() > 1 {
        if let Some(done) = stack.pop()
            && let Some(top) = stack.last_mut()
        {
            top.children.push(done);
        }
    }
    let root = stack.pop().map(|r| r.children).unwrap_or_default();
    let find = |blocks: &[ErsBlock], key: &str| -> String {
        let mut todo: Vec<&ErsBlock> = blocks.iter().collect();
        while let Some(b) = todo.pop() {
            if let Some((_, v, _)) = b.items.iter().find(|(k, _, _)| k == key) {
                return v.clone();
            }
            todo.extend(b.children.iter());
        }
        String::new()
    };
    let summary = format!("ER Mapper header, {}×{} × {} band(s), {}, datum {}", find(&root, "NrOfCellsPerLine"), find(&root, "NrOfLines"), find(&root, "NrOfBands"), find(&root, "CellType"), find(&root, "Datum"));
    ers_emit(&cx, root).await;
    cx.annotate(summary);
    Ok(())
}

async fn ers_emit(cx: &Cx, blocks: Vec<ErsBlock>) {
    for b in blocks {
        let n = b.items.len().saturating_add(b.children.len());
        cx.push(Node::new(b.name.clone()).span(b.span).summary(format!("{n} entr(ies)")).lazy(ers_block, b)).await;
    }
}

async fn ers_block(cx: Cx, b: ErsBlock) -> Result<()> {
    for (k, v, span) in b.items {
        cx.push(Node::new(k).span(span).value(number(&v))).await;
    }
    for c in b.children {
        let n = c.items.len().saturating_add(c.children.len());
        cx.push(Node::new(c.name.clone()).span(c.span).summary(format!("{n} entr(ies)")).lazy(crate::expander!(self::ers_block: ErsBlock), c)).await;
    }
    Ok(())
}

declare_format!(pub IDRISI_RDC = "idrisi-rdc", "IDRISI raster documentation (.rdc)", ["rdc", "vdc"], "text/x-idrisi",
    Probe::Custom(|h| h.starts_with(b"file format : IDRISI")), idrisi);

async fn idrisi(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut items: Vec<(String, String)> = Vec::new();
    while let Some(line) = lines.next().await? {
        let t = line.text();
        let Some((k, v)) = t.split_once(':') else { continue };
        cx.push(Node::new(k.trim().to_owned()).span(line.content()).value(number(v.trim()))).await;
        items.push((k.trim().to_owned(), v.trim().to_owned()));
    }
    let get = |k: &str| items.iter().find(|(a, _)| a == k).map_or("?".to_owned(), |(_, v)| v.clone());
    cx.annotate(format!("{} ({}), {}×{} {}, {}", get("file format"), get("file title"), get("columns"), get("rows"), get("data type"), get("ref. system")));
    Ok(())
}

// ---------------------------------------------------------------------------
// ISO/IEC 8211 (S-57 electronic charts, SDTS)

fn iso8211_probe(h: &Head<'_>) -> bool {
    h.data.get(..5).is_some_and(|d| d.iter().all(u8::is_ascii_digit)) && h.data.get(5..9) == Some(b"3LE1") && h.data.get(12..17).is_some_and(|d| d.iter().all(u8::is_ascii_digit))
}

declare_format!(pub ISO8211 = "iso8211", "ISO 8211 data descriptive file (S-57, SDTS)", ["000", "001", "ddf"], "application/x-iso8211",
    Probe::Custom(iso8211_probe), iso8211);

/// Parses a record leader: (record length, base address, field length size,
/// position size, tag size).
fn leader(b: &[u8]) -> Option<(u64, u64, usize, usize, usize)> {
    let num = |r: std::ops::Range<usize>| -> Option<u64> { std::str::from_utf8(b.get(r)?).ok()?.trim().parse().ok() };
    let len = num(0..5)?;
    let base = num(12..17)?;
    let digit = |i: usize| b.get(i).and_then(|c| char::from(*c).to_digit(10)).map(|d| to_usize(d.into()));
    Some((len, base, digit(20)?, digit(21)?, digit(23)?))
}

async fn iso8211(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut pos = 0u64;
    let mut records = 0u64;
    let mut names: Vec<(String, String)> = Vec::new();
    let mut tags: Vec<(String, u64)> = Vec::new();
    while pos.saturating_add(24) <= file.len {
        let lead = cx.read(file.sub(pos, 24)).await?;
        let Some((len, base, lsize, psize, tsize)) = leader(&lead) else {
            cx.diag(Diagnostic::malformed("bad record leader").at(file.sub(pos, 24)));
            break;
        };
        if len < 24 || tsize == 0 {
            cx.diag(Diagnostic::malformed("bad record length").at(file.sub(pos, 5)));
            break;
        }
        let record = file.sub(pos, len);
        let dir = cx.read_avail(record.sub(24, base.saturating_sub(24))).await?;
        let entry = tsize.saturating_add(lsize).saturating_add(psize);
        let mut fields = Vec::new();
        for e in dir.chunks(entry.max(1)) {
            if e.len() < entry || e.first() == Some(&0x1e) {
                break;
            }
            let tag = String::from_utf8_lossy(e.get(..tsize).unwrap_or_default()).into_owned();
            let flen: u64 = String::from_utf8_lossy(e.get(tsize..tsize.saturating_add(lsize)).unwrap_or_default()).parse().unwrap_or(0);
            let fpos: u64 = String::from_utf8_lossy(e.get(tsize.saturating_add(lsize)..entry).unwrap_or_default()).parse().unwrap_or(0);
            fields.push((tag, record.sub(base.saturating_add(fpos), flen)));
        }
        let ddr = lead.get(6) == Some(&b'L');
        if ddr {
            for (tag, span) in &fields {
                let b = cx.read_avail(span.sub(0, 512)).await?;
                let name = String::from_utf8_lossy(b.get(9..).unwrap_or_default().split(|&c| c == 0x1f).next().unwrap_or_default()).into_owned();
                names.push((tag.clone(), name));
            }
        } else {
            for (tag, _) in &fields {
                tally(&mut tags, tag, 256);
            }
        }
        let first = fields.iter().find(|(t, _)| t != "0001").map(|(t, _)| t.clone()).unwrap_or_default();
        let node = Node::new(if ddr { "Data descriptive record".to_owned() } else { format!("Record {records} ({first})") }).span(record).summary(format!("{} field(s)", fields.len()));
        cx.push(node.lazy(iso8211_fields, (fields, ddr, names.clone()))).await;
        records = records.saturating_add(1);
        pos = pos.saturating_add(len);
    }
    let top: Vec<String> = tags.iter().take(6).map(|(t, n)| format!("{n} {t}")).collect();
    let kind = if names.iter().any(|(t, _)| t == "DSID") { "S-57 chart" } else if names.iter().any(|(t, _)| t == "IDEN") { "SDTS module" } else { "ISO 8211 file" };
    cx.annotate(format!("{kind}, {records} record(s), {} field definition(s); {}", names.len(), top.join(", ")));
    Ok(())
}

/// Fields of one record, whether it is the descriptive record, and field names.
type FieldList = (Vec<(String, Span)>, bool, Vec<(String, String)>);

async fn iso8211_fields(cx: Cx, (fields, ddr, names): FieldList) -> Result<()> {
    for (tag, span) in fields {
        let b = cx.read_avail(span.sub(0, 1024)).await?;
        let node = Node::new(tag.clone()).span(span);
        if ddr {
            let body = b.get(9..).unwrap_or_default();
            let parts: Vec<String> = body.split(|&c| c == 0x1f || c == 0x1e).map(|p| String::from_utf8_lossy(p).into_owned()).filter(|p| !p.is_empty()).collect();
            let controls = String::from_utf8_lossy(b.get(..9.min(b.len())).unwrap_or_default()).into_owned();
            cx.push(summarize(node.value(text(parts.first().cloned().unwrap_or_default())), format!("controls {controls:?}{}", parts.get(1).map(|d| format!(", subfields {}", preview(d, 80))).unwrap_or_default()))).await;
        } else {
            let name = names.iter().find(|(t, _)| *t == tag).map(|(_, n)| n.clone()).unwrap_or_default();
            let shown: String = b.iter().map(|&c| if c == 0x1f { '|' } else if c == 0x1e { ' ' } else if (0x20..0x7f).contains(&c) { char::from(c) } else { '.' }).collect();
            cx.push(summarize(node.value(text(preview(&shown, 120))), name)).await;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// DLIS (RP66 v1) well logs

declare_format!(pub DLIS = "dlis", "Digital Log Interchange Standard (DLIS)", ["dlis", "dls"], "application/x-dlis",
    Probe::Custom(|h| h.data.get(4..9) == Some(b"V1.00") && h.data.get(9..15) == Some(b"RECORD")), dlis);

const DLIS_ATTRS: FlagTable = &[
    flag(0x80, "explicitly formatted"),
    flag(0x40, "has predecessor"),
    flag(0x20, "has successor"),
    flag(0x10, "encrypted"),
    flag(0x08, "encryption packet"),
    flag(0x04, "checksum"),
    flag(0x02, "trailing length"),
    flag(0x01, "padding"),
];
const DLIS_EFLR: EnumTable = &[(0, "FHLR (file header)"), (1, "OLR (origin)"), (2, "AXIS"), (3, "CHANNL (channels)"), (4, "FRAME"), (5, "STATIC"), (6, "SCRIPT"), (7, "UPDATE"), (8, "UDI"), (9, "LNAME"), (10, "SPEC"), (11, "DICT")];
const DLIS_IFLR: EnumTable = &[(0, "FDATA (frame data)"), (1, "NOFORM"), (127, "EOD")];

async fn dlis(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let sul = cx.read(file.sub(0, 80)).await?;
    let field = |r: std::ops::Range<usize>| String::from_utf8_lossy(sul.get(r).unwrap_or_default()).trim().to_owned();
    cx.emit(Node::new("Storage unit label").span(file.sub(0, 80)).lazy(dlis_sul, file.sub(0, 80)));
    let set_id = field(20..80);
    let mut cur = Cursor::new(&cx, file, BE);
    cur.seek(80);
    let mut visible = 0u64;
    let mut kinds: Vec<(String, u64)> = Vec::new();
    while cur.remaining() >= 4 {
        let start = cur.pos();
        let len = u64::from(cur.u16().await?);
        let marker = cur.u16().await?;
        if len < 4 || marker != 0xff01 {
            cx.diag(Diagnostic::malformed(format!("visible record header {len:#x} {marker:#06x}")).at(file.sub(start, 4)));
            break;
        }
        let vr = file.sub(start, len);
        let mut segs = Vec::new();
        let mut at = 4u64;
        while at.saturating_add(4) <= len {
            let h = cx.read(vr.sub(at, 4)).await?;
            let slen = u64::from(u16_be(&h, 0).unwrap_or(0));
            let attrs = h.get(2).copied().unwrap_or(0);
            let kind = h.get(3).copied().unwrap_or(0);
            if slen < 4 {
                break;
            }
            let name = if attrs & 0x80 != 0 { lookup(DLIS_EFLR, kind.into()) } else { lookup(DLIS_IFLR, kind.into()) }.map_or_else(|| format!("type {kind}"), str::to_owned);
            if attrs & 0x40 == 0 {
                tally(&mut kinds, &name, 64);
            }
            segs.push((vr.sub(at, slen), attrs, kind, name));
            at = at.saturating_add(slen);
        }
        let n = segs.len();
        cx.push(Node::new(format!("Visible record {visible}")).span(vr).summary(format!("{n} segment(s)")).lazy(dlis_segments, segs)).await;
        visible = visible.saturating_add(1);
        cur.seek(start.saturating_add(len));
    }
    let parts: Vec<String> = kinds.iter().map(|(k, n)| format!("{n} {}", k.split(' ').next().unwrap_or_default())).collect();
    cx.annotate(format!("DLIS {:?}, {visible} visible record(s); {}", set_id, parts.join(", ")));
    Ok(())
}

async fn dlis_sul(cx: Cx, span: Span) -> Result<()> {
    let b = cx.block(span).await?;
    let mut f = crate::fields::Fields::emitting(&cx, &b, BE);
    f.ascii("Sequence number", 4).emit()?;
    f.ascii("DLIS version", 5).emit()?;
    f.ascii("Storage unit structure", 6).emit()?;
    f.ascii("Maximum record length", 5).emit()?;
    f.ascii("Storage set identifier", 60).emit()?;
    Ok(())
}

async fn dlis_segments(cx: Cx, segs: Vec<(Span, u8, u8, String)>) -> Result<()> {
    for (span, attrs, _, name) in segs {
        let mut node = Node::new(name).span(span).value(crate::formats::lines::flags(DLIS_ATTRS, attrs.into(), 8));
        if attrs & 0x80 != 0 && attrs & 0x40 == 0 {
            // EFLR bodies start with a SET component: descriptor, type, name.
            let b = cx.read_avail(span.sub(4, 256)).await?;
            let desc = b.first().copied().unwrap_or(0);
            if desc >> 5 >= 5 {
                let n = usize::from(b.get(1).copied().unwrap_or(0));
                let set_type = String::from_utf8_lossy(b.get(2..2usize.saturating_add(n)).unwrap_or_default()).into_owned();
                node = node.summary(format!("set {set_type}"));
            }
        }
        cx.push(node).await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wkt() {
        let w = br#"GEOGCS["WGS 84",DATUM["WGS_1984",SPHEROID["WGS 84",6378137,298.257223563]],UNIT["degree",0.0174532925199433]]"#;
        let e = wkt_elements(w);
        assert_eq!(e.len(), 1);
        let (k, inner) = wkt_split(w);
        assert_eq!(k, "GEOGCS");
        assert_eq!(wkt_name(inner), "WGS 84");
        assert_eq!(wkt_find(inner, "DATUM", 0).as_deref(), Some("WGS_1984"));
        assert_eq!(leader(b"00201 LE1 0900073   6604").map(|l| l.0), Some(201));

    }
}
