//! More EDA text formats: LTspice schematics and symbols, legacy KiCad
//! (schematics, libraries, boards), gEDA schematics, PADS ASCII, and the
//! LEF/DEF physical design exchange formats.

use crate::cx::Cx;
use crate::declare_format;
use crate::error::Result;
use crate::formats::util::lines::{
    Line, Lines, contains, head_lines, is_text, preview, tally, text, uint,
};
use crate::formats::{Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;

/// Counts of the first word of every line, plus the lines themselves.
async fn command_lines(
    cx: &Cx,
    file: Span,
    skip: usize,
) -> Result<(Vec<(String, u64)>, Vec<Line>)> {
    let mut lines = Lines::new(cx, file);
    let mut counts = Vec::new();
    let mut all = Vec::new();
    let mut i = 0usize;
    while let Some(line) = lines.next().await? {
        i = i.saturating_add(1);
        if i <= skip || line.bytes.trim_ascii().is_empty() {
            continue;
        }
        let t = line.text();
        let word = t.split_whitespace().next().unwrap_or_default().to_owned();
        tally(&mut counts, &word, 256);
        if all.len() < 200_000 {
            all.push(line);
        }
    }
    Ok((counts, all))
}

fn count(counts: &[(String, u64)], key: &str) -> u64 {
    counts.iter().find(|(k, _)| k == key).map_or(0, |(_, n)| *n)
}

async fn line_list(cx: Cx, lines: Vec<Line>) -> Result<()> {
    for l in lines {
        let t = l.text();
        let (k, v) = t
            .trim()
            .split_once(char::is_whitespace)
            .unwrap_or((t.trim(), ""));
        cx.push(
            Node::new(k.to_owned())
                .span(l.content())
                .value(text(preview(v, 160))),
        )
        .await;
    }
    Ok(())
}

/// Emits `lines` grouped into blocks that start with a line matching `start`.
async fn emit_blocks(
    cx: &Cx,
    file: Span,
    lines: Vec<Line>,
    start: impl Fn(&str) -> Option<String>,
) -> u64 {
    let mut blocks = 0u64;
    let mut current: Option<(String, Vec<Line>)> = None;
    let mut loose: Vec<Line> = Vec::new();
    for l in lines {
        let t = l.text();
        if let Some(name) = start(t.trim()) {
            if let Some((n, body)) = current.take() {
                emit_block(cx, file, n, body).await;
                blocks = blocks.saturating_add(1);
            }
            current = Some((name, vec![l]));
        } else if let Some((_, body)) = current.as_mut() {
            body.push(l);
        } else {
            loose.push(l);
        }
    }
    if let Some((n, body)) = current.take() {
        emit_block(cx, file, n, body).await;
        blocks = blocks.saturating_add(1);
    }
    if !loose.is_empty() {
        let n = loose.len();
        cx.push(
            Node::new("Other lines")
                .value(uint(crate::bytes::to_u64(n)))
                .lazy(line_list, loose),
        )
        .await;
    }
    blocks
}

async fn emit_block(cx: &Cx, file: Span, name: String, body: Vec<Line>) {
    let start = body.first().map_or(0, |l| l.pos);
    let end = body
        .last()
        .map_or(start, |l| l.pos.saturating_add(l.span.len));
    let n = body.len();
    cx.push(
        Node::new(name)
            .span(file.sub(start, end.saturating_sub(start)))
            .summary(format!("{n} line(s)"))
            .lazy(line_list, body),
    )
    .await;
}

// ---------------------------------------------------------------------------
// LTspice

fn ltspice_probe(h: &Head<'_>, second: &[u8]) -> bool {
    let l = head_lines(h, 2);
    is_text(h)
        && l.first().is_some_and(|x| x.starts_with(b"Version 4"))
        && l.get(1).is_some_and(|x| x.starts_with(second))
}

declare_format!(pub LTSPICE_ASC = "ltspice-asc", "LTspice schematic", ["asc"], "text/x-ltspice-schematic",
    Probe::Custom(|h| ltspice_probe(h, b"SHEET ")), ltspice_asc);
declare_format!(pub LTSPICE_ASY = "ltspice-asy", "LTspice symbol", ["asy"], "text/x-ltspice-symbol",
    Probe::Custom(|h| ltspice_probe(h, b"SymbolType ")), ltspice_asy);

async fn ltspice_asc(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let (counts, lines) = command_lines(&cx, file, 0).await?;
    let directives: Vec<String> = lines
        .iter()
        .map(Line::text)
        .filter(|t| t.starts_with("TEXT") && t.contains('!'))
        .filter_map(|t| t.split_once('!').map(|(_, d)| d.to_owned()))
        .collect();
    let instances: Vec<String> = lines
        .iter()
        .map(Line::text)
        .filter_map(|t| t.strip_prefix("SYMATTR InstName ").map(str::to_owned))
        .collect();
    emit_blocks(&cx, file, lines, |t| {
        t.strip_prefix("SYMBOL ")
            .map(|s| format!("SYMBOL {}", s.split_whitespace().next().unwrap_or_default()))
    })
    .await;
    cx.annotate(format!(
        "LTspice schematic, {} symbol(s) ({}), {} wire(s), {} label(s){}",
        count(&counts, "SYMBOL"),
        preview(&instances.join(", "), 60),
        count(&counts, "WIRE"),
        count(&counts, "FLAG"),
        if directives.is_empty() {
            String::new()
        } else {
            format!(", directives {}", preview(&directives.join("; "), 60))
        }
    ));
    Ok(())
}

async fn ltspice_asy(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let (counts, lines) = command_lines(&cx, file, 0).await?;
    let kind = lines
        .iter()
        .map(Line::text)
        .find_map(|t| t.strip_prefix("SymbolType ").map(str::to_owned))
        .unwrap_or_default();
    let prefix = lines
        .iter()
        .map(Line::text)
        .find_map(|t| t.strip_prefix("SYMATTR Prefix ").map(str::to_owned))
        .unwrap_or_default();
    emit_blocks(&cx, file, lines, |t| {
        if t.starts_with("PIN ") {
            Some("PIN".to_owned())
        } else {
            None
        }
    })
    .await;
    cx.annotate(format!(
        "LTspice {kind} symbol, prefix {prefix}, {} pin(s)",
        count(&counts, "PIN")
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Legacy KiCad (pre-5) schematics, libraries and boards

declare_format!(pub KICAD_LEGACY_SCH = "kicad-legacy-sch", "KiCad legacy schematic (.sch)", ["sch"], "text/x-kicad-legacy-schematic",
    Probe::Custom(|h| h.starts_with(b"EESchema Schematic File Version")), kicad_legacy_sch);
declare_format!(pub KICAD_LEGACY_LIB = "kicad-legacy-lib", "KiCad legacy symbol library (.lib)", ["lib"], "text/x-kicad-legacy-library",
    Probe::Custom(|h| h.starts_with(b"EESchema-LIBRARY Version")), kicad_legacy_lib);
declare_format!(pub KICAD_LEGACY_PCB = "kicad-legacy-pcb", "KiCad legacy board (.brd)", ["brd"], "text/x-kicad-legacy-board",
    Probe::Custom(|h| h.starts_with(b"PCBNEW-BOARD Version")), kicad_legacy_pcb);

async fn kicad_legacy_sch(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let (counts, lines) = command_lines(&cx, file, 0).await?;
    let version = lines
        .first()
        .map(|l| {
            l.text()
                .trim_start_matches("EESchema Schematic File Version")
                .trim()
                .to_owned()
        })
        .unwrap_or_default();
    let refs: Vec<String> = lines
        .iter()
        .map(Line::text)
        .filter(|t| t.starts_with("L "))
        .filter_map(|t| t.split_whitespace().nth(2).map(str::to_owned))
        .collect();
    emit_blocks(&cx, file, lines, |t| {
        if t.starts_with("$Comp") {
            Some("Component".to_owned())
        } else if t.starts_with("$Descr") {
            Some("Sheet description".to_owned())
        } else if t.starts_with("$Sheet") {
            Some("Hierarchical sheet".to_owned())
        } else {
            None
        }
    })
    .await;
    cx.annotate(format!(
        "KiCad legacy schematic v{version}, {} component(s) ({}), {} wire(s)",
        count(&counts, "$Comp"),
        preview(&refs.join(", "), 60),
        count(&counts, "Wire")
    ));
    Ok(())
}

async fn kicad_legacy_lib(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let (_, lines) = command_lines(&cx, file, 0).await?;
    let mut names = Vec::new();
    for l in &lines {
        let t = l.text();
        if let Some(rest) = t.strip_prefix("DEF ") {
            names.push(
                rest.split_whitespace()
                    .next()
                    .unwrap_or_default()
                    .to_owned(),
            );
        }
    }
    emit_blocks(&cx, file, lines, |t| {
        t.strip_prefix("DEF ")
            .map(|r| format!("DEF {}", r.split_whitespace().next().unwrap_or_default()))
    })
    .await;
    cx.annotate(format!(
        "KiCad legacy symbol library, {} symbol(s): {}",
        names.len(),
        preview(&names.join(", "), 80)
    ));
    Ok(())
}

async fn kicad_legacy_pcb(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let (counts, lines) = command_lines(&cx, file, 0).await?;
    emit_blocks(&cx, file, lines, |t| {
        if t.starts_with("$MODULE") {
            Some(format!("Module {}", t.trim_start_matches("$MODULE").trim()))
        } else if t.starts_with("$EQUIPOT") {
            Some("Net".to_owned())
        } else if t.starts_with("$TRACK") {
            Some("Tracks".to_owned())
        } else if t.starts_with("$GENERAL")
            || t.starts_with("$SHEETDESCR")
            || t.starts_with("$SETUP")
        {
            Some(t.trim_start_matches('$').to_owned())
        } else {
            None
        }
    })
    .await;
    cx.annotate(format!(
        "KiCad legacy board, {} module(s), {} net(s), {} track segment(s)",
        count(&counts, "$MODULE"),
        count(&counts, "$EQUIPOT"),
        count(&counts, "Po")
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// gEDA schematics

fn geda_probe(h: &Head<'_>) -> bool {
    let first = head_lines(h, 1).first().copied().unwrap_or_default();
    is_text(h)
        && first.starts_with(b"v ")
        && first
            .get(2..10)
            .is_some_and(|d| d.iter().all(u8::is_ascii_digit))
        && first.get(10) == Some(&b' ')
}

declare_format!(pub GEDA_SCH = "geda-sch", "gEDA/Lepton schematic or symbol", ["sch", "sym"], "text/x-geda-schematic",
    Probe::Custom(geda_probe), geda_sch);

async fn geda_sch(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let (counts, lines) = command_lines(&cx, file, 1).await?;
    let comps: Vec<String> = lines
        .iter()
        .map(Line::text)
        .filter(|t| t.starts_with("C "))
        .filter_map(|t| t.split_whitespace().nth(6).map(str::to_owned))
        .collect();
    let refdes: Vec<String> = lines
        .iter()
        .map(Line::text)
        .filter_map(|t| t.strip_prefix("refdes=").map(str::to_owned))
        .collect();
    emit_blocks(&cx, file, lines, |t| match t.chars().next() {
        Some('C') if t.starts_with("C ") => Some(format!(
            "Component {}",
            t.split_whitespace().nth(6).unwrap_or_default()
        )),
        Some('N') if t.starts_with("N ") => Some("Net".to_owned()),
        Some('T') if t.starts_with("T ") => Some("Text".to_owned()),
        Some('P') if t.starts_with("P ") => Some("Pin".to_owned()),
        Some('U') if t.starts_with("U ") => Some("Bus".to_owned()),
        Some('L' | 'B' | 'V' | 'A' | 'H') if t.get(1..2) == Some(" ") => Some("Graphic".to_owned()),
        _ => None,
    })
    .await;
    cx.annotate(format!(
        "gEDA schematic, {} component(s) ({}), {} net segment(s){}",
        comps.len(),
        preview(&comps.join(", "), 60),
        count(&counts, "N"),
        if refdes.is_empty() {
            String::new()
        } else {
            format!(", refdes {}", preview(&refdes.join(", "), 40))
        }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// PADS ASCII

declare_format!(pub PADS_ASCII = "pads-ascii", "PADS ASCII design", ["asc", "pads"], "text/x-pads-ascii",
    Probe::Custom(|h| h.starts_with(b"!PADS-")), pads_ascii);

async fn pads_ascii(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let (_, lines) = command_lines(&cx, file, 0).await?;
    let header = lines.first().map(Line::text).unwrap_or_default();
    let mut sections = Vec::new();
    for l in &lines {
        let t = l.text();
        let word = t.split_whitespace().next().unwrap_or_default();
        if word.len() > 2 && word.starts_with('*') && word.ends_with('*') && word != "*REMARK*" {
            sections.push(word.trim_matches('*').to_owned());
        }
    }
    emit_blocks(&cx, file, lines, |t| {
        let t = t.trim();
        let word = t.split_whitespace().next().unwrap_or_default();
        (word.len() > 2 && word.starts_with('*') && word.ends_with('*') && word != "*REMARK*")
            .then(|| t.to_owned())
    })
    .await;
    cx.annotate(format!(
        "PADS ASCII {}, section(s) {}",
        header.trim().trim_matches('!'),
        preview(&sections.join(", "), 80)
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// LEF / DEF

fn first_statement<'h>(h: &'h Head<'_>) -> Option<&'h [u8]> {
    head_lines(h, 32)
        .into_iter()
        .map(<[u8]>::trim_ascii)
        .find(|l| !l.is_empty() && !l.starts_with(b"#"))
}

declare_format!(pub DEF = "def", "Design Exchange Format (DEF)", ["def"], "text/x-def",
    Probe::Custom(|h| is_text(h) && first_statement(h).is_some_and(|l| l.starts_with(b"VERSION ")) && contains(h.data, b"DESIGN ") && (contains(h.data, b"DIEAREA") || contains(h.data, b"COMPONENTS") || contains(h.data, b"UNITS DISTANCE"))), def);
declare_format!(pub LEF = "lef", "Library Exchange Format (LEF)", ["lef", "tlef"], "text/x-lef",
    Probe::Custom(|h| is_text(h) && first_statement(h).is_some_and(|l| l.starts_with(b"VERSION ")) && !contains(h.data, b"DESIGN ") && (contains(h.data, b"\nMACRO ") || contains(h.data, b"\nLAYER ") || contains(h.data, b"\nSITE "))), lef);

async fn def(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let (_, lines) = command_lines(&cx, file, 0).await?;
    let mut design = String::new();
    let mut sizes: Vec<(String, String)> = Vec::new();
    for l in &lines {
        let t = l.text();
        let w: Vec<&str> = t.split_whitespace().collect();
        if w.first() == Some(&"DESIGN") {
            design = w.get(1).copied().unwrap_or_default().to_owned();
        }
        if matches!(
            w.first().copied(),
            Some("COMPONENTS" | "NETS" | "PINS" | "SPECIALNETS" | "VIAS" | "BLOCKAGES")
        ) && w.len() >= 2
        {
            sizes.push((
                w.first().copied().unwrap_or_default().to_owned(),
                w.get(1).copied().unwrap_or_default().to_owned(),
            ));
        }
    }
    emit_blocks(&cx, file, lines, |t| {
        let w = t.split_whitespace().next().unwrap_or_default();
        matches!(
            w,
            "COMPONENTS"
                | "NETS"
                | "PINS"
                | "SPECIALNETS"
                | "VIAS"
                | "BLOCKAGES"
                | "ROW"
                | "TRACKS"
                | "GCELLGRID"
                | "DIEAREA"
                | "DESIGN"
                | "VERSION"
                | "UNITS"
        )
        .then(|| t.trim_end_matches(';').trim().to_owned())
    })
    .await;
    let parts: Vec<String> = sizes
        .iter()
        .map(|(k, n)| format!("{n} {}", k.to_lowercase()))
        .collect();
    cx.annotate(format!("DEF design {design}, {}", parts.join(", ")));
    Ok(())
}

async fn lef(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let (_, lines) = command_lines(&cx, file, 0).await?;
    let mut macros = Vec::new();
    let mut layers = 0u32;
    for l in &lines {
        let t = l.text();
        let t = t.trim();
        if let Some(m) = t.strip_prefix("MACRO ") {
            macros.push(m.trim().to_owned());
        }
        if t.starts_with("LAYER ") && t.split_whitespace().count() == 2 {
            layers = layers.saturating_add(1);
        }
    }
    emit_blocks(&cx, file, lines, |t| {
        let w: Vec<&str> = t.split_whitespace().collect();
        match (w.first().copied(), w.len()) {
            (Some("MACRO" | "SITE" | "VIA" | "VIARULE"), 2) => Some(t.to_owned()),
            (Some("LAYER"), 2) if !t.ends_with(';') => Some(t.to_owned()),
            _ => None,
        }
    })
    .await;
    cx.annotate(format!(
        "LEF library, {} macro(s) ({}), {layers} layer(s)",
        macros.len(),
        preview(&macros.join(", "), 60)
    ));
    Ok(())
}
