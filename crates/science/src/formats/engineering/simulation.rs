//! Simulation input and results: NASTRAN bulk data and ANSYS CDB decks,
//! Tecplot binary data, EnSight Gold cases and geometry, and OpenVDB
//! volumes.

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::science::kv_spans;
use crate::formats::util::lines::{
    Lines, contains, head_lines, is_text, preview, summarize, tally, text, uint,
};
use crate::formats::{Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::EnumTable;

const LE: Endian = Endian::Little;

// ---------------------------------------------------------------------------
// NASTRAN bulk data (BDF) and ANSYS CDB

fn nastran_probe(h: &Head<'_>) -> bool {
    let head = h.data.get(..0x4000).unwrap_or(h.data);
    is_text(h)
        && contains(head, b"BEGIN BULK")
        && (contains(head, b"CEND") || head.starts_with(b"$") || head.starts_with(b"SOL "))
}

declare_format!(pub NASTRAN = "nastran-bdf", "NASTRAN bulk data deck", ["bdf", "nas", "dat", "fem"], "text/x-nastran",
    Probe::Custom(nastran_probe), nastran);

async fn nastran(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut section = 0u8; // 0 executive, 1 case control, 2 bulk
    let mut starts = [0u64; 3];
    let mut ends = [0u64; 3];
    let mut cards: Vec<(String, u64)> = Vec::new();
    let mut sol = String::new();
    while let Some(line) = lines.next().await? {
        let t = line.text();
        let upper = t.trim().to_ascii_uppercase();
        if upper.starts_with("CEND") {
            ends[0] = lines.pos();
            section = 1;
            starts[1] = lines.pos();
            continue;
        }
        if upper.starts_with("BEGIN BULK") || upper.starts_with("BEGIN  BULK") {
            ends[1] = line.pos;
            section = 2;
            starts[2] = lines.pos();
            continue;
        }
        if upper.starts_with("ENDDATA") {
            ends[2] = line.pos;
            cx.emit(Node::new("ENDDATA").span(line.content()));
            break;
        }
        if section == 0 && upper.starts_with("SOL") {
            sol = upper.trim_start_matches("SOL").trim().to_owned();
        }
        if section == 2
            && !upper.starts_with('$')
            && !upper.is_empty()
            && !upper.starts_with('+')
            && !upper.starts_with('*')
            && !upper.starts_with(',')
        {
            let name = upper
                .split([',', ' ', '\t'])
                .next()
                .unwrap_or_default()
                .trim_end_matches('*')
                .to_owned();
            if !name.is_empty() {
                tally(&mut cards, &name, 512);
            }
        }
    }
    if ends[2] == 0 {
        ends[2] = lines.pos();
    }
    let names = ["Executive control", "Case control", "Bulk data"];
    for (i, name) in names.iter().enumerate() {
        let (s, e) = (
            starts.get(i).copied().unwrap_or(0),
            ends.get(i).copied().unwrap_or(0),
        );
        if e > s {
            let span = file.sub(s, e.saturating_sub(s));
            cx.emit(Node::new(*name).span(span).lazy(deck_lines, span));
        }
    }
    cards.sort_by_key(|c| std::cmp::Reverse(c.1));
    let top: Vec<String> = cards
        .iter()
        .take(6)
        .map(|(k, n)| format!("{n} {k}"))
        .collect();
    cx.emit(
        Node::new("Card types")
            .value(uint(to_u64(cards.len())))
            .lazy(card_counts, cards),
    );
    cx.annotate(format!(
        "NASTRAN deck{}, {}",
        if sol.is_empty() {
            String::new()
        } else {
            format!(" (SOL {sol})")
        },
        top.join(", ")
    ));
    Ok(())
}

async fn deck_lines(cx: Cx, span: Span) -> Result<()> {
    let mut lines = Lines::new(&cx, span);
    while let Some(line) = lines.next().await? {
        cx.progress_in(span, span.offset.saturating_add(lines.pos()));
        let t = line.text();
        if t.trim().is_empty() || t.starts_with('$') {
            continue;
        }
        let name = t
            .split([',', ' ', '\t'])
            .next()
            .unwrap_or_default()
            .to_owned();
        cx.push(
            Node::new(if name.is_empty() {
                "(continuation)".to_owned()
            } else {
                name
            })
            .span(line.content())
            .value(text(preview(&t, 160))),
        )
        .await;
    }
    Ok(())
}

async fn card_counts(cx: Cx, cards: Vec<(String, u64)>) -> Result<()> {
    for (k, n) in cards {
        cx.push(Node::new(k).value(uint(n))).await;
    }
    Ok(())
}

declare_format!(pub ANSYS_CDB = "ansys-cdb", "ANSYS archive (CDB)", ["cdb"], "text/x-ansys-cdb",
    Probe::Custom(|h| h.starts_with(b"/COM,ANSYS") && is_text(h)), ansys_cdb);

async fn ansys_cdb(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut block: Option<(String, u64, u64)> = None;
    let mut commands: Vec<(String, u64)> = Vec::new();
    let (mut nodes, mut elements) = (0u64, 0u64);
    let mut release = String::new();
    while let Some(line) = lines.next().await? {
        cx.progress_in(file, file.offset.saturating_add(lines.pos()));
        let t = line.text();
        if let Some((name, start, n)) = block.as_mut() {
            let end_block = t.trim_start().starts_with("N,R5")
                || t.trim() == "-1"
                || t.trim_start().starts_with("-1");
            if end_block {
                let span = file.sub(*start, lines.pos().saturating_sub(*start));
                if name == "NBLOCK" {
                    nodes = nodes.saturating_add(*n);
                } else {
                    elements = elements.saturating_add(*n);
                }
                cx.push(Node::new(name.clone()).span(span).value(uint(*n)))
                    .await;
                block = None;
            } else if !t.starts_with('(') {
                *n = n.saturating_add(1);
            }
            continue;
        }
        if line.pos == 0 {
            release = t.trim_start_matches("/COM,").trim().to_owned();
        }
        let cmd = t
            .split(',')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_uppercase();
        if cmd == "NBLOCK" || cmd == "EBLOCK" {
            block = Some((cmd, line.pos, 0));
            continue;
        }
        if !cmd.is_empty() {
            tally(&mut commands, &cmd, 256);
            cx.push(
                Node::new(cmd)
                    .span(line.content())
                    .value(text(preview(t.split_once(',').map_or("", |(_, r)| r), 160))),
            )
            .await;
        }
    }
    cx.annotate(format!(
        "ANSYS CDB ({release}), {nodes} node(s), {elements} element(s), {} command type(s)",
        commands.len()
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Tecplot binary data (.plt)

declare_format!(pub TECPLOT = "tecplot-plt", "Tecplot binary data", ["plt"], "application/x-tecplot",
    Probe::Custom(|h| h.at(0, b"#!TDV") && h.data.get(5..8).is_some_and(|v| v.iter().all(u8::is_ascii_digit))), tecplot);

const TEC_ZONES: EnumTable = &[
    (0, "ORDERED"),
    (1, "FELINESEG"),
    (2, "FETRIANGLE"),
    (3, "FEQUADRILATERAL"),
    (4, "FETETRAHEDRON"),
    (5, "FEBRICK"),
    (6, "FEPOLYGON"),
    (7, "FEPOLYHEDRON"),
];

/// A Tecplot string: one int32 per character, NUL-terminated.
async fn tec_string(cur: &mut Cursor<'_>) -> Result<String> {
    let mut s = String::new();
    loop {
        let c = cur.u32().await?;
        if c == 0 || s.len() > 4096 {
            break;
        }
        s.push(char::from_u32(c).unwrap_or('?'));
    }
    Ok(s)
}

async fn tecplot(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let magic = cx.read(file.sub(0, 8)).await?;
    let version: u32 = String::from_utf8_lossy(magic.get(5..8).unwrap_or_default())
        .parse()
        .unwrap_or(0);
    cx.emit(
        Node::new("Magic")
            .span(file.sub(0, 8))
            .value(text(String::from_utf8_lossy(&magic).into_owned())),
    );
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(8);
    let s = cur.pos();
    cur.u32().await?;
    cx.emit(Node::new("Byte order").span(cur.since(s)).value(uint(1)));
    if version >= 112 {
        let s = cur.pos();
        let t = cur.u32().await?;
        cx.emit(
            Node::new("File type").span(cur.since(s)).value(text(
                ["full", "grid", "solution"]
                    .get(usize::try_from(t).unwrap_or(9))
                    .copied()
                    .unwrap_or("?"),
            )),
        );
    }
    let s = cur.pos();
    let title = tec_string(&mut cur).await?;
    cx.emit(
        Node::new("Title")
            .span(cur.since(s))
            .value(text(title.clone())),
    );
    let s = cur.pos();
    let nvars = cur.u32().await?;
    let mut vars = Vec::new();
    for _ in 0..nvars.min(10_000) {
        vars.push(tec_string(&mut cur).await?);
    }
    cx.emit(
        Node::new("Variables")
            .span(cur.since(s))
            .value(text(vars.join(", "))),
    );
    let mut zones = 0u32;
    loop {
        let s = cur.pos();
        let marker = cur.int::<f32>().await?;
        if (marker - 357.0).abs() < f32::EPSILON {
            cx.emit(Node::new("End of header").span(cur.since(s)));
            break;
        }
        if (marker - 299.0).abs() >= f32::EPSILON {
            cx.diag(Diagnostic::unsupported(format!("header marker {marker}")).at(cur.since(s)));
            break;
        }
        let name = tec_string(&mut cur).await?;
        cur.skip(8);
        let time = cur.int::<f64>().await?;
        cur.skip(4);
        let kind = cur.u32().await?;
        let located = cur.u32().await?;
        if located == 1 {
            cur.skip(u64::from(nvars).saturating_mul(4));
        }
        cur.skip(8);
        let dims = if kind == 0 {
            let (i, j, k) = (cur.u32().await?, cur.u32().await?, cur.u32().await?);
            format!("{i}×{j}×{k}")
        } else {
            let pts = cur.u32().await?;
            if kind >= 6 {
                cur.skip(4);
            }
            let elems = cur.u32().await?;
            cur.skip(12);
            if kind >= 6 {
                cur.skip(12);
            }
            format!("{pts} node(s), {elems} element(s)")
        };
        let aux = cur.u32().await?;
        if aux != 0 {
            cx.diag(Diagnostic::unsupported("zone auxiliary data").at(cur.since(s)));
            break;
        }
        cx.push(
            Node::new(format!("Zone {name:?}"))
                .span(cur.since(s))
                .value(crate::formats::util::lines::enumeration(
                    TEC_ZONES,
                    kind.into(),
                    32,
                ))
                .summary(format!("{dims}, t = {time}")),
        )
        .await;
        zones = zones.saturating_add(1);
        if zones > 10_000 {
            break;
        }
    }
    cx.emit(Node::new("Data section").span(file.tail(cur.pos())));
    cx.annotate(format!(
        "Tecplot binary v{version} {title:?}, {nvars} variable(s) ({}), {zones} zone(s)",
        preview(&vars.join(", "), 60)
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// EnSight Gold (case file and C binary geometry)

declare_format!(pub ENSIGHT_CASE = "ensight-case", "EnSight case file", ["case", "encas"], "text/x-ensight-case",
    Probe::Custom(|h| is_text(h) && head_lines(h, 4).iter().map(|l| l.trim_ascii()).find(|l| !l.is_empty() && !l.starts_with(b"#")).is_some_and(|l| l == b"FORMAT") && contains(h.data, b"ensight")), ensight_case);
declare_format!(pub ENSIGHT_GOLD = "ensight-gold", "EnSight Gold binary geometry/variable", ["geo", "geom"], "application/x-ensight-gold",
    Probe::Custom(|h| h.at(0, b"C Binary") && h.data.get(8..80).is_some_and(|r| r.iter().all(|&b| b == 0 || b == b' ' || b.is_ascii_graphic()))), ensight_gold);

async fn ensight_case(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    type Section = (String, u64, Vec<(String, String, Span)>);
    let mut section: Option<Section> = None;
    let mut files = Vec::new();
    loop {
        let next = lines.next().await?;
        let starts = next.as_ref().is_none_or(|l| {
            l.bytes.first().is_some_and(u8::is_ascii_uppercase) && !l.bytes.contains(&b':')
        });
        if starts && let Some((name, start, items)) = section.take() {
            let end = next.as_ref().map_or(lines.pos(), |l| l.pos);
            cx.push(
                Node::new(name)
                    .span(file.sub(start, end.saturating_sub(start)))
                    .value(uint(to_u64(items.len())))
                    .lazy(kv_spans, items),
            )
            .await;
        }
        let Some(line) = next else { break };
        let t = line.text();
        if starts {
            section = Some((t.trim().to_owned(), line.pos, Vec::new()));
        } else if let Some((name, _, items)) = section.as_mut()
            && let Some((k, v)) = t.split_once(':')
            && items.len() < 10_000
        {
            if name == "GEOMETRY" || name == "VARIABLE" {
                files.push(v.split_whitespace().last().unwrap_or_default().to_owned());
            }
            items.push((k.trim().to_owned(), v.trim().to_owned(), line.content()));
        }
    }
    cx.annotate(format!(
        "EnSight case file, files {}",
        preview(&files.join(", "), 80)
    ));
    Ok(())
}

async fn ensight_gold(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, LE);
    let line80 = |b: Vec<u8>| {
        String::from_utf8_lossy(&b)
            .trim_end_matches(['\0', ' '])
            .to_owned()
    };
    let mut lines = Vec::new();
    for name in [
        "Format",
        "Description 1",
        "Description 2",
        "Node IDs",
        "Element IDs",
    ] {
        let s = cur.pos();
        let v = line80(cur.bytes(80).await?);
        cx.emit(Node::new(name).span(cur.since(s)).value(text(v.clone())));
        lines.push(v);
    }
    let node_ids = lines.get(3).cloned().unwrap_or_default();
    let elem_ids = lines.get(4).cloned().unwrap_or_default();
    let peek = String::from_utf8_lossy(&cx.read_avail(file.sub(cur.pos(), 80)).await?)
        .trim_end_matches(['\0', ' '])
        .to_owned();
    if peek.starts_with("extents") {
        let s = cur.pos();
        cur.skip(80);
        let mut e = Vec::new();
        for _ in 0..6 {
            e.push(cur.int::<f32>().await?.to_string());
        }
        cx.emit(
            Node::new("Extents")
                .span(cur.since(s))
                .value(text(e.join(", "))),
        );
    }
    let given = |s: &str| s.contains("given") || s.contains("ignore");
    let mut parts = 0u32;
    while cur.remaining() >= 84 {
        cx.progress_in(file, file.offset.saturating_add(cur.pos()));
        let s = cur.pos();
        let word = line80(cur.bytes(80).await?);
        if !word.starts_with("part") {
            cx.diag(Diagnostic::unsupported(format!("unexpected block {word:?}")).at(cur.since(s)));
            break;
        }
        let number = cur.u32().await?;
        let desc = line80(cur.bytes(80).await?);
        let mut summary = Vec::new();
        loop {
            if cur.remaining() < 80 {
                break;
            }
            let peek = String::from_utf8_lossy(&cx.read_avail(file.sub(cur.pos(), 80)).await?)
                .trim_end_matches(['\0', ' '])
                .to_owned();
            if peek.starts_with("part") || peek.is_empty() {
                break;
            }
            cur.skip(80);
            if peek.starts_with("coordinates") {
                let n = u64::from(cur.u32().await?);
                if given(&node_ids) {
                    cur.skip(n.saturating_mul(4));
                }
                cur.skip(n.saturating_mul(12));
                summary.push(format!("{n} node(s)"));
            } else if peek.starts_with("block") {
                cx.diag(Diagnostic::unsupported("structured parts").at(cur.since(s)));
                break;
            } else {
                // An element block: count, optional IDs, connectivity.
                let n = u64::from(cur.u32().await?);
                let per: u64 = match peek.as_str() {
                    "point" => 1,
                    "bar2" => 2,
                    "bar3" | "tria3" => 3,
                    "quad4" | "tetra4" => 4,
                    "pyramid5" => 5,
                    "tria6" | "penta6" => 6,
                    "quad8" | "hexa8" => 8,
                    "tetra10" => 10,
                    "pyramid13" => 13,
                    "penta15" => 15,
                    "hexa20" => 20,
                    _ => {
                        cx.diag(
                            Diagnostic::unsupported(format!("element type {peek:?}"))
                                .at(cur.since(s)),
                        );
                        break;
                    }
                };
                if given(&elem_ids) {
                    cur.skip(n.saturating_mul(4));
                }
                cur.skip(n.saturating_mul(per).saturating_mul(4));
                summary.push(format!("{n} {peek}"));
            }
        }
        cx.push(
            Node::new(format!("Part {number}"))
                .span(cur.since(s))
                .value(text(desc))
                .summary(summary.join(", ")),
        )
        .await;
        parts = parts.saturating_add(1);
    }
    cx.annotate(format!(
        "EnSight Gold binary geometry, {parts} part(s); {}",
        preview(lines.get(1).map_or("", String::as_str), 60)
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// OpenVDB volumes

declare_format!(pub OPENVDB = "openvdb", "OpenVDB sparse volume", ["vdb"], "application/x-openvdb",
    Probe::Magic(&[(0, b"\x20\x42\x44\x56\x00\x00\x00\x00")]), openvdb);

async fn vdb_string(cur: &mut Cursor<'_>) -> Result<String> {
    let n = cur.u32().await?;
    if u64::from(n) > cur.remaining() || n > 0x10000 {
        return Err(Diagnostic::malformed(format!("string of {n} bytes")));
    }
    Ok(String::from_utf8_lossy(&cur.bytes(n.into()).await?).into_owned())
}

async fn openvdb(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 21)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.u64("Magic").hex().emit()?;
    let version = f.u32("File version").emit()?;
    let major = f.u32("Library major").emit()?;
    let minor = f.u32("Library minor").emit()?;
    let offsets = f.u8("Has grid offsets").emit()?;
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(21);
    let s = cur.pos();
    let uuid = String::from_utf8_lossy(&cur.bytes(36).await?).into_owned();
    cx.emit(Node::new("UUID").span(cur.since(s)).value(text(uuid)));
    let s = cur.pos();
    let n = cur.u32().await?;
    let mut meta = Vec::new();
    for _ in 0..n.min(10_000) {
        let m = cur.pos();
        let name = vdb_string(&mut cur).await?;
        let kind = vdb_string(&mut cur).await?;
        let size = cur.u32().await?;
        let value = cur.bytes(size.into()).await?;
        let shown = match kind.as_str() {
            "string" => String::from_utf8_lossy(&value).into_owned(),
            "int32" => crate::bytes::i32_le(&value, 0).unwrap_or(0).to_string(),
            "int64" => crate::bytes::u64_le(&value, 0)
                .unwrap_or(0)
                .cast_signed()
                .to_string(),
            "float" => {
                f32::from_le_bytes(crate::bytes::array(&value, 0).unwrap_or_default()).to_string()
            }
            "bool" => (value.first() == Some(&1)).to_string(),
            _ => format!("{size} bytes"),
        };
        meta.push((name, format!("{shown} ({kind})"), cur.since(m)));
    }
    cx.emit(
        Node::new("File metadata")
            .span(cur.since(s))
            .value(uint(n.into()))
            .lazy(kv_spans, meta),
    );
    let mut grids = Vec::new();
    if offsets != 0 {
        let count = cur.u32().await?;
        for _ in 0..count.min(10_000) {
            let g = cur.pos();
            let name = vdb_string(&mut cur).await?;
            let kind = vdb_string(&mut cur).await?;
            let parent = vdb_string(&mut cur).await?;
            let pos = cur.u64().await?;
            let block = cur.u64().await?;
            let end = cur.u64().await?;
            let node = Node::new(name.clone())
                .span(cur.since(g))
                .value(text(kind))
                .target(file.sub(pos, end.saturating_sub(pos)));
            cx.push(summarize(
                node,
                format!(
                    "blocks at {block:#x}{}",
                    if parent.is_empty() {
                        String::new()
                    } else {
                        format!(", instance of {parent}")
                    }
                ),
            ))
            .await;
            grids.push(name);
        }
    }
    cx.annotate(format!(
        "OpenVDB file v{version} (library {major}.{minor}), {} grid(s){}",
        grids.len(),
        if grids.is_empty() {
            String::new()
        } else {
            format!(": {}", grids.join(", "))
        }
    ));
    Ok(())
}
