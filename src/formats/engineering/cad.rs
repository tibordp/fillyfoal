//! Mechanical CAD and simulation input: STEP (ISO 10303-21), IGES,
//! Parasolid transmit files, Siemens JT, Gmsh meshes, OpenFOAM dictionaries,
//! and Abaqus / LS-DYNA keyword decks.

use crate::bytes::{to_u64, to_usize, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::lines::{
    Line, Lines, contains, head_lines, is_text, number, preview, summarize, tally, text, uint,
};
use crate::formats::{Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, lookup};

const LE: Endian = Endian::Little;

// ---------------------------------------------------------------------------
// STEP / ISO 10303-21 exchange structure

declare_format!(pub STEP = "step", "STEP product data (ISO 10303-21)", ["step", "stp", "p21", "ifc", "stpz"], "model/step",
    Probe::Custom(|h| h.data.trim_ascii_start().starts_with(b"ISO-10303-21;")), step);

/// Streams `;`-terminated statements, honouring '...' strings and /* */ comments.
struct Statements<'a> {
    cx: &'a Cx,
    region: Span,
    pos: u64,
    buf: Vec<u8>,
    buf_at: u64,
}

impl<'a> Statements<'a> {
    fn new(cx: &'a Cx, region: Span) -> Self {
        Statements {
            cx,
            region,
            pos: 0,
            buf: Vec::new(),
            buf_at: 0,
        }
    }

    /// The next statement (trimmed text, span without leading whitespace).
    async fn next(&mut self) -> Result<Option<(String, Span)>> {
        const CHUNK: u64 = 0x4000;
        const MAX: usize = 0x10_0000;
        self.cx.checkpoint().await;
        loop {
            let off = to_usize(self.pos.saturating_sub(self.buf_at));
            let avail = self.buf.get(off..).unwrap_or_default();
            // Scan for a terminating ';' outside strings and comments.
            let mut i = 0usize;
            let mut in_str = false;
            let mut in_comment = false;
            let mut end = None;
            while let Some(&c) = avail.get(i) {
                if in_comment {
                    if c == b'*' && avail.get(i.saturating_add(1)) == Some(&b'/') {
                        in_comment = false;
                        i = i.saturating_add(1);
                    }
                } else if in_str {
                    if c == b'\'' {
                        in_str = false;
                    }
                } else if c == b'\'' {
                    in_str = true;
                } else if c == b'/' && avail.get(i.saturating_add(1)) == Some(&b'*') {
                    in_comment = true;
                } else if c == b';' {
                    end = Some(i);
                    break;
                }
                i = i.saturating_add(1);
            }
            let buf_end = self.buf_at.saturating_add(to_u64(self.buf.len()));
            let found = match end {
                Some(e) => Some(e.saturating_add(1)),
                None if buf_end >= self.region.len || avail.len() >= MAX => {
                    (!avail.is_empty()).then_some(avail.len())
                }
                None => {
                    if off > 0 {
                        self.buf.drain(..off.min(self.buf.len()));
                        self.buf_at = self.pos;
                    }
                    let data = self.cx.read_avail(self.region.sub(buf_end, CHUNK)).await?;
                    if data.is_empty() {
                        self.region.len = buf_end;
                    }
                    self.buf.extend_from_slice(&data);
                    continue;
                }
            };
            let Some(len) = found else { return Ok(None) };
            let raw = avail.get(..len).unwrap_or_default();
            let lead = raw.iter().take_while(|b| b.is_ascii_whitespace()).count();
            let text = strip_step_comments(&String::from_utf8_lossy(raw))
                .trim()
                .to_owned();
            let span = self.region.sub(
                self.pos.saturating_add(to_u64(lead)),
                to_u64(len.saturating_sub(lead)),
            );
            self.pos = self.pos.saturating_add(to_u64(len).max(1));
            if text.is_empty() && self.pos >= self.region.len {
                return Ok(None);
            }
            return Ok(Some((text, span)));
        }
    }
}

/// Removes /* */ comments outside strings.
fn strip_step_comments(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    let mut in_str = false;
    while let Some(c) = chars.next() {
        if !in_str && c == '/' && chars.peek() == Some(&'*') {
            chars.next();
            let mut prev = ' ';
            for d in chars.by_ref() {
                if prev == '*' && d == '/' {
                    break;
                }
                prev = d;
            }
            continue;
        }
        if c == '\'' {
            in_str = !in_str;
        }
        out.push(c);
    }
    out
}

/// Decodes STEP strings: '' is a quote; \X2\…\X0\ is UTF-16 hex.
fn step_string(s: &str) -> String {
    let s = s.replace("''", "'");
    let mut out = String::new();
    let mut rest = s.as_str();
    while let Some(p) = rest.find("\\X2\\") {
        out.push_str(rest.get(..p).unwrap_or_default());
        let after = rest.get(p.saturating_add(4)..).unwrap_or_default();
        let (hexs, tail) = after.split_once("\\X0\\").unwrap_or((after, ""));
        let units: Vec<u16> = hexs
            .as_bytes()
            .chunks(4)
            .filter_map(|c| {
                std::str::from_utf8(c)
                    .ok()
                    .and_then(|h| u16::from_str_radix(h, 16).ok())
            })
            .collect();
        out.push_str(&String::from_utf16_lossy(&units));
        rest = tail;
    }
    out.push_str(rest);
    out
}

/// The quoted strings in a parameter list.
fn step_strings(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = s;
    while let Some(p) = rest.find('\'') {
        let after = rest.get(p.saturating_add(1)..).unwrap_or_default();
        let mut end = None;
        let b = after.as_bytes();
        let mut i = 0usize;
        while let Some(&c) = b.get(i) {
            if c == b'\'' {
                if b.get(i.saturating_add(1)) == Some(&b'\'') {
                    i = i.saturating_add(2);
                    continue;
                }
                end = Some(i);
                break;
            }
            i = i.saturating_add(1);
        }
        let Some(e) = end else { break };
        out.push(step_string(after.get(..e).unwrap_or_default()));
        rest = after.get(e.saturating_add(1)..).unwrap_or_default();
        if out.len() > 64 {
            break;
        }
    }
    out
}

async fn step(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut st = Statements::new(&cx, file);
    let mut section = String::new();
    let (mut schema, mut system, mut name) = (String::new(), String::new(), String::new());
    let mut data_start = None;
    let mut entities = 0u64;
    let mut kinds: Vec<(String, u64)> = Vec::new();
    let mut products: Vec<String> = Vec::new();
    while let Some((t, span)) = st.next().await? {
        let upper = t.to_ascii_uppercase();
        match upper.as_str() {
            "ISO-10303-21;" | "END-ISO-10303-21;" => {
                cx.push(Node::new(t.trim_end_matches(';').to_owned()).span(span))
                    .await;
                continue;
            }
            "HEADER;" | "ENDSEC;" => {
                section = if upper == "HEADER;" {
                    "HEADER".to_owned()
                } else {
                    String::new()
                };
                cx.push(Node::new(t.trim_end_matches(';').to_owned()).span(span))
                    .await;
                continue;
            }
            _ => {}
        }
        if upper.starts_with("DATA")
            && t.trim_end_matches(';')
                .trim_start_matches(|c: char| c.is_ascii_alphabetic())
                .trim()
                .starts_with(['(', ';'])
            || upper == "DATA;"
        {
            section = "DATA".to_owned();
            data_start.get_or_insert(span.offset.saturating_sub(file.offset));
            continue;
        }
        if section == "HEADER" {
            let (kind, params) = t.split_once('(').unwrap_or((t.as_str(), ""));
            let kind = kind.trim().to_owned();
            let strings = step_strings(params);
            match kind.as_str() {
                "FILE_SCHEMA" => schema = strings.join(", "),
                "FILE_NAME" => {
                    name = strings.first().cloned().unwrap_or_default();
                    system = strings
                        .get(strings.len().saturating_sub(2))
                        .cloned()
                        .unwrap_or_default();
                }
                _ => {}
            }
            cx.push(
                Node::new(kind)
                    .span(span)
                    .value(text(preview(&strings.join(" | "), 200)))
                    .lazy(step_params, t.clone()),
            )
            .await;
        } else if section == "DATA" {
            entities = entities.saturating_add(1);
            let kind = t
                .split_once('=')
                .map(|(_, r)| {
                    r.trim()
                        .split(['(', ' '])
                        .next()
                        .unwrap_or_default()
                        .to_owned()
                })
                .unwrap_or_default();
            tally(
                &mut kinds,
                if kind.is_empty() { "(complex)" } else { &kind },
                512,
            );
            if kind == "PRODUCT" && products.len() < 8 {
                products.extend(step_strings(&t).into_iter().nth(1));
            }
        }
    }
    if let Some(start) = data_start {
        let data = file.tail(start);
        cx.emit(
            Node::new("DATA")
                .span(data)
                .value(uint(entities))
                .lazy(step_entities, data),
        );
    }
    kinds.sort_by_key(|k| std::cmp::Reverse(k.1));
    let top: Vec<String> = kinds
        .iter()
        .take(5)
        .map(|(k, n)| format!("{n} {k}"))
        .collect();
    cx.emit(
        Node::new("Entity types")
            .value(uint(to_u64(kinds.len())))
            .lazy(step_kinds, kinds),
    );
    cx.annotate(format!(
        "STEP {schema}, {entities} entities{}{}{}; {}",
        if name.is_empty() {
            String::new()
        } else {
            format!(", {name:?}")
        },
        if system.is_empty() {
            String::new()
        } else {
            format!(", from {system}")
        },
        if products.is_empty() {
            String::new()
        } else {
            format!(", product(s) {}", products.join(", "))
        },
        top.join(", ")
    ));
    Ok(())
}

async fn step_params(cx: Cx, t: String) -> Result<()> {
    for (i, s) in step_strings(&t).into_iter().enumerate() {
        cx.emit(Node::new(format!("String {i}")).value(text(s)));
    }
    Ok(())
}

async fn step_kinds(cx: Cx, kinds: Vec<(String, u64)>) -> Result<()> {
    for (k, n) in kinds {
        cx.push(Node::new(k).value(uint(n))).await;
    }
    Ok(())
}

async fn step_entities(cx: Cx, span: Span) -> Result<()> {
    let mut st = Statements::new(&cx, span);
    while let Some((t, s)) = st.next().await? {
        if t.eq_ignore_ascii_case("ENDSEC;") {
            break;
        }
        if t.to_ascii_uppercase().starts_with("DATA") {
            continue;
        }
        let (id, rest) = t.split_once('=').unwrap_or(("?", t.as_str()));
        let rest = rest.trim().trim_end_matches(';');
        let (kind, params) = rest.split_once('(').unwrap_or((rest, ""));
        let kind = if kind.trim().is_empty() {
            "(complex)"
        } else {
            kind.trim()
        };
        cx.push(
            Node::new(id.trim().to_owned())
                .span(s)
                .value(text(kind))
                .summary(preview(&format!("({params}"), 120)),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// IGES

fn iges_probe(h: &Head<'_>) -> bool {
    let lines = head_lines(h, 3);
    lines.first().is_some_and(|l| {
        l.len() == 80
            && l.get(72) == Some(&b'S')
            && l.get(73..80).is_some_and(|n| n.trim_ascii() == b"1")
    }) && lines.iter().all(|l| l.len() == 80)
}

declare_format!(pub IGES = "iges", "IGES (Initial Graphics Exchange Specification)", ["igs", "iges"], "model/iges",
    Probe::Custom(iges_probe), iges);

const IGES_ENTITIES: EnumTable = &[
    (0, "Null"),
    (100, "Circular arc"),
    (102, "Composite curve"),
    (104, "Conic arc"),
    (106, "Copious data"),
    (108, "Plane"),
    (110, "Line"),
    (112, "Parametric spline curve"),
    (114, "Parametric spline surface"),
    (116, "Point"),
    (118, "Ruled surface"),
    (120, "Surface of revolution"),
    (122, "Tabulated cylinder"),
    (124, "Transformation matrix"),
    (125, "Flash"),
    (126, "Rational B-spline curve"),
    (128, "Rational B-spline surface"),
    (130, "Offset curve"),
    (140, "Offset surface"),
    (141, "Boundary"),
    (142, "Curve on a parametric surface"),
    (143, "Bounded surface"),
    (144, "Trimmed surface"),
    (150, "Block"),
    (152, "Right angular wedge"),
    (154, "Right circular cylinder"),
    (158, "Sphere"),
    (180, "Boolean tree"),
    (186, "Manifold solid B-rep object"),
    (190, "Plane surface"),
    (192, "Right circular cylindrical surface"),
    (196, "Spherical surface"),
    (202, "Angular dimension"),
    (206, "Diameter dimension"),
    (210, "General label"),
    (212, "General note"),
    (214, "Leader (arrow)"),
    (216, "Linear dimension"),
    (222, "Radius dimension"),
    (228, "General symbol"),
    (230, "Sectioned area"),
    (304, "Line font definition"),
    (308, "Subfigure definition"),
    (314, "Color definition"),
    (402, "Associativity instance"),
    (404, "Drawing"),
    (406, "Property"),
    (408, "Singular subfigure instance"),
    (410, "View"),
    (502, "Vertex"),
    (504, "Edge"),
    (508, "Loop"),
    (510, "Face"),
    (514, "Shell"),
];

const IGES_GLOBALS: [&str; 26] = [
    "Parameter delimiter",
    "Record delimiter",
    "Product ID (sender)",
    "File name",
    "Native system ID",
    "Preprocessor version",
    "Integer bits",
    "Single-precision magnitude",
    "Single-precision significance",
    "Double-precision magnitude",
    "Double-precision significance",
    "Product ID (receiver)",
    "Model space scale",
    "Units flag",
    "Units name",
    "Line weight gradations",
    "Maximum line weight",
    "Date and time of exchange",
    "Minimum resolution",
    "Maximum coordinate",
    "Author",
    "Organization",
    "IGES version",
    "Drafting standard",
    "Model creation date",
    "Application protocol",
];

/// Splits IGES global parameters, decoding Hollerith strings (`5HHELLO`).
fn iges_params(s: &str, delim: char, record: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = s;
    while !rest.is_empty() && out.len() < 64 {
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        if !digits.is_empty() && rest.get(digits.len()..).is_some_and(|r| r.starts_with('H')) {
            let n: usize = digits.parse().unwrap_or(0);
            let start = digits.len().saturating_add(1);
            let value: String = rest
                .get(start..)
                .unwrap_or_default()
                .chars()
                .take(n)
                .collect();
            out.push(value.clone());
            rest = rest
                .get(start.saturating_add(value.len())..)
                .unwrap_or_default();
            rest = rest
                .strip_prefix(delim)
                .or_else(|| rest.strip_prefix(record))
                .unwrap_or(rest);
            continue;
        }
        let end = rest.find([delim, record]).unwrap_or(rest.len());
        out.push(rest.get(..end).unwrap_or_default().trim().to_owned());
        if rest.get(end..).is_some_and(|r| r.starts_with(record)) {
            break;
        }
        rest = rest.get(end.saturating_add(1)..).unwrap_or_default();
    }
    out
}

async fn iges(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    // Section letter in column 73: S, G, D, P, T.
    let mut sections: Vec<(char, u64, u64, Vec<Line>)> = Vec::new();
    let mut global = String::new();
    let mut start_text = String::new();
    while let Some(line) = lines.next().await? {
        let letter = line.bytes.get(72).map_or('?', |&b| char::from(b));
        match sections.last_mut() {
            Some((l, _, end, list)) if *l == letter => {
                *end = lines.pos();
                if letter == 'D' && list.len() < 200_000 {
                    list.push(line.clone());
                }
            }
            _ => sections.push((
                letter,
                line.pos,
                lines.pos(),
                if letter == 'D' {
                    vec![line.clone()]
                } else {
                    Vec::new()
                },
            )),
        }
        let body = line.column(0, 72);
        match letter {
            'G' if global.len() < 0x10000 => {
                global.push_str(line.text().get(..72).unwrap_or_default())
            }
            'S' if start_text.len() < 400 => {
                start_text.push_str(&body);
                start_text.push(' ');
            }
            _ => {}
        }
    }
    let delim = if global.starts_with("1H") {
        global.chars().nth(2).unwrap_or(',')
    } else {
        ','
    };
    let record = {
        let after = global.get(4..).unwrap_or_default();
        if after.starts_with("1H") {
            after.chars().nth(2).unwrap_or(';')
        } else {
            ';'
        }
    };
    let params = iges_params(&global, delim, record);
    let mut directory = Vec::new();
    for (letter, start, end, list) in sections {
        let span = file.sub(start, end.saturating_sub(start));
        let name = match letter {
            'S' => "Start section",
            'G' => "Global section",
            'D' => "Directory entry section",
            'P' => "Parameter data section",
            'T' => "Terminate section",
            _ => "Unknown section",
        };
        let node = Node::new(name).span(span);
        match letter {
            'S' => cx.emit(node.value(text(start_text.trim()))),
            'G' => cx.emit(node.lazy(iges_globals, params.clone())),
            'D' => {
                directory = list.clone();
                cx.emit(
                    node.value(uint(to_u64(list.len() / 2)))
                        .lazy(iges_directory, list),
                );
            }
            _ => cx.emit(
                node.value(text(preview(
                    &cx.read_avail(span.sub(0, 72))
                        .await
                        .map(|b| String::from_utf8_lossy(&b).into_owned())
                        .unwrap_or_default(),
                    72,
                ))),
            ),
        }
    }
    let mut kinds: Vec<(String, u64)> = Vec::new();
    for pair in directory.chunks(2) {
        let t: u64 = pair
            .first()
            .map(|l| l.column(0, 8))
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        tally(&mut kinds, lookup(IGES_ENTITIES, t).unwrap_or("other"), 128);
    }
    kinds.sort_by_key(|k| std::cmp::Reverse(k.1));
    let top: Vec<String> = kinds
        .iter()
        .take(5)
        .map(|(k, n)| format!("{n} {}", k.to_lowercase()))
        .collect();
    let g = |i: usize| params.get(i).cloned().unwrap_or_default();
    cx.annotate(format!(
        "IGES, {} entit(ies) from {:?} ({}), units {}; {}",
        directory.len() / 2,
        g(3),
        g(4),
        g(14),
        top.join(", ")
    ));
    Ok(())
}

async fn iges_globals(cx: Cx, params: Vec<String>) -> Result<()> {
    for (i, v) in params.into_iter().enumerate() {
        let name = IGES_GLOBALS.get(i).copied().unwrap_or("Parameter");
        // Hollerith (string) parameters stay text even when they look numeric.
        let string = matches!(i, 0..=5 | 11 | 14 | 17 | 20 | 21 | 24 | 25);
        cx.emit(Node::new(name).value(if string { text(v) } else { number(&v) }));
    }
    Ok(())
}

async fn iges_directory(cx: Cx, list: Vec<Line>) -> Result<()> {
    for pair in list.chunks(2) {
        let (Some(a), b) = (pair.first(), pair.get(1)) else {
            continue;
        };
        let t: u64 = a.column(0, 8).parse().unwrap_or(0);
        let pointer = a.column(8, 16);
        let form = b.map(|l| l.column(32, 40)).unwrap_or_default();
        let label = b.map(|l| l.column(56, 64)).unwrap_or_default();
        let seq = a.column(73, 80);
        let span = b.map_or(a.span, |l| {
            a.span.sub(0, l.span.end().saturating_sub(a.span.offset))
        });
        let node = Node::new(format!("D{seq}")).span(span).value(
            crate::formats::util::lines::enumeration(IGES_ENTITIES, t, 16),
        );
        cx.push(summarize(
            node,
            format!(
                "form {form}, parameters at P{pointer}{}",
                if label.is_empty() {
                    String::new()
                } else {
                    format!(", label {label}")
                }
            ),
        ))
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Parasolid transmit (text) files

declare_format!(pub PARASOLID = "parasolid", "Parasolid transmit file (text)", ["x_t", "xmt_txt"], "model/x-parasolid",
    Probe::Magic(&[(0, b"**ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz**")]), parasolid);

async fn parasolid(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut header = String::new();
    let mut header_end = 0u64;
    while let Some(line) = lines.next().await? {
        let t = line.text();
        if t.starts_with("**END_OF_HEADER") {
            header_end = lines.pos();
            break;
        }
        if line.pos > 0
            && !t.starts_with("**ABC")
            && !t.starts_with("**PARASOLID")
            && header.len() < 0x10000
        {
            header.push_str(&t);
        }
    }
    let pairs: Vec<(String, String)> = header
        .split(';')
        .filter_map(|kv| {
            kv.trim()
                .trim_start_matches('*')
                .split_once('=')
                .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        })
        .collect();
    cx.emit(
        Node::new("Header")
            .span(file.sub(0, header_end))
            .value(uint(to_u64(pairs.len())))
            .lazy(key_values, pairs.clone()),
    );
    cx.emit(Node::new("Body").span(file.tail(header_end)));
    let get = |k: &str| {
        pairs
            .iter()
            .find(|(a, _)| a.eq_ignore_ascii_case(k))
            .map_or(String::new(), |(_, v)| v.clone())
    };
    cx.annotate(format!(
        "Parasolid transmit file{}{}",
        if get("APPL").is_empty() {
            String::new()
        } else {
            format!(" from {}", get("APPL"))
        },
        if get("SCH").is_empty() {
            String::new()
        } else {
            format!(", schema {}", get("SCH"))
        }
    ));
    Ok(())
}

async fn key_values(cx: Cx, pairs: Vec<(String, String)>) -> Result<()> {
    for (k, v) in pairs {
        cx.push(Node::new(k).value(number(&v))).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Siemens JT

fn jt_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"Version ") && h.data.get(..80).is_some_and(|v| contains(v, b" JT"))
}

declare_format!(pub JT = "jt", "Siemens JT 3D visualization", ["jt"], "model/jt",
    Probe::Custom(jt_probe), jt);

const JT_SEGMENTS: EnumTable = &[
    (1, "Logical Scene Graph"),
    (2, "JT B-Rep"),
    (3, "PMI Data"),
    (4, "Meta Data"),
    (6, "Shape"),
    (7, "Shape LOD0"),
    (8, "Shape LOD1"),
    (9, "Shape LOD2"),
    (10, "Shape LOD3"),
    (11, "Shape LOD4"),
    (12, "Shape LOD5"),
    (13, "Shape LOD6"),
    (14, "Shape LOD7"),
    (15, "Shape LOD8"),
    (16, "Shape LOD9"),
    (17, "XT B-Rep"),
    (18, "Wireframe"),
    (20, "ULP"),
    (24, "LWPA"),
];

async fn jt(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 120)).await?;
    let version_text = String::from_utf8_lossy(head.data.get(..80).unwrap_or_default())
        .trim_end_matches([' ', '\0', '\n'])
        .to_owned();
    let major: u32 = version_text
        .trim_start_matches("Version ")
        .split('.')
        .next()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(9);
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Version", 80).emit()?;
    let order = f.u8("Byte order").emit()?;
    f.u32("Empty field").emit()?;
    let toc = if major >= 10 {
        f.u64("TOC offset").hex().emit()?
    } else {
        u64::from(f.u32("TOC offset").hex().emit()?)
    };
    f.guid("LSG segment ID").emit()?;
    if order != 0 {
        cx.diag(Diagnostic::unsupported("big-endian JT"));
    }
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(toc);
    let count = cur.u32().await?;
    let entry = if major >= 10 { 32u64 } else { 28 };
    let entries = file.sub(
        toc.saturating_add(4),
        u64::from(count).saturating_mul(entry),
    );
    cx.emit(
        Node::new("TOC")
            .span(file.sub(toc, entries.len.saturating_add(4)))
            .value(uint(count.into()))
            .lazy(jt_toc, (file, entries, major >= 10)),
    );
    let mut kinds: Vec<(String, u64)> = Vec::new();
    let b = cx.read_avail(entries.sub(0, 0x100000)).await?;
    for c in b.chunks(to_usize(entry)) {
        let attr = u32_le(c, to_usize(entry).saturating_sub(4)).unwrap_or(0);
        tally(
            &mut kinds,
            lookup(JT_SEGMENTS, (attr >> 24).into()).unwrap_or("other"),
            32,
        );
    }
    let parts: Vec<String> = kinds.iter().map(|(k, n)| format!("{n} {k}")).collect();
    cx.annotate(format!(
        "JT {}, {count} segment(s): {}",
        version_text.trim_start_matches("Version ").trim(),
        parts.join(", ")
    ));
    Ok(())
}

async fn jt_toc(cx: Cx, (file, entries, wide): (Span, Span, bool)) -> Result<()> {
    let entry = if wide { 32u64 } else { 28 };
    let mut at = 0u64;
    while at.saturating_add(entry) <= entries.len {
        let s = entries.sub(at, entry);
        let b = cx.block(s).await?;
        let mut f = Fields::new(&b, LE);
        let id = f.guid("Segment ID").get()?;
        let offset = if wide {
            f.u64("Offset").get()?
        } else {
            u64::from(f.u32("Offset").get()?)
        };
        let len = f.u32("Length").get()?;
        let attr = f.u32("Attributes").get()?;
        let kind = lookup(JT_SEGMENTS, (attr >> 24).into()).unwrap_or("unknown");
        cx.push(
            Node::new(kind)
                .span(s)
                .value(text(id.to_string()))
                .summary(format!("{len} bytes"))
                .target(file.sub(offset, len.into())),
        )
        .await;
        at = at.saturating_add(entry);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Gmsh meshes

declare_format!(pub GMSH = "gmsh", "Gmsh mesh", ["msh"], "model/x-gmsh",
    Probe::Custom(|h| h.data.trim_ascii_start().starts_with(b"$MeshFormat")), gmsh);

async fn gmsh(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut current: Option<(String, u64, Vec<String>, u64)> = None;
    let (mut version, mut binary, mut nodes, mut elements) =
        (String::new(), false, String::new(), String::new());
    let mut names = Vec::new();
    while let Some(line) = lines.next().await? {
        let t = line.text();
        let t = t.trim();
        if let Some(end) = t.strip_prefix("$End") {
            if let Some((name, start, first, n)) = current.take() {
                let span = file.sub(start, lines.pos().saturating_sub(start));
                match name.as_str() {
                    "MeshFormat" => {
                        let w: Vec<&str> = first
                            .first()
                            .map(|s| s.split_whitespace().collect())
                            .unwrap_or_default();
                        version = w.first().copied().unwrap_or_default().to_owned();
                        binary = w.get(1) == Some(&"1");
                    }
                    "Nodes" => nodes = first.first().cloned().unwrap_or_default(),
                    "Elements" => elements = first.first().cloned().unwrap_or_default(),
                    "PhysicalNames" => names.extend(first.iter().skip(1).cloned()),
                    _ => {}
                }
                let _ = end;
                let node = Node::new(format!("${name}"))
                    .span(span)
                    .value(text(preview(first.first().map_or("", String::as_str), 100)));
                cx.push(node.summary(format!("{n} line(s)")).lazy(gmsh_lines, span))
                    .await;
            }
            continue;
        }
        if let Some(name) = t.strip_prefix('$')
            && current.is_none()
        {
            current = Some((name.to_owned(), line.pos, Vec::new(), 0));
            continue;
        }
        if let Some((_, _, first, n)) = current.as_mut() {
            *n = n.saturating_add(1);
            if first.len() < 32 {
                first.push(if binary {
                    preview(
                        &t.chars().filter(|c| !c.is_control()).collect::<String>(),
                        60,
                    )
                } else {
                    t.to_owned()
                });
            }
        }
    }
    let count = |s: &str, major: &str| -> String {
        let w: Vec<&str> = s.split_whitespace().collect();
        // Version 4 headers: numEntityBlocks numNodes minTag maxTag; version 2: count.
        if major.starts_with('4') {
            w.get(1).copied().unwrap_or("?").to_owned()
        } else {
            w.first().copied().unwrap_or("?").to_owned()
        }
    };
    cx.annotate(format!(
        "Gmsh {version} mesh ({}), {} node(s), {} element(s){}",
        if binary { "binary" } else { "ASCII" },
        count(&nodes, &version),
        count(&elements, &version),
        if names.is_empty() {
            String::new()
        } else {
            format!(", physical groups {}", preview(&names.join(", "), 80))
        }
    ));
    Ok(())
}

async fn gmsh_lines(cx: Cx, span: Span) -> Result<()> {
    let mut lines = Lines::new(&cx, span);
    let mut i = 0u32;
    while let Some(line) = lines.next().await? {
        if i > 0 && !line.bytes.starts_with(b"$End") {
            let t = line.text();
            cx.push(
                Node::new("Line").span(line.content()).value(text(preview(
                    &t.chars()
                        .map(|c| if c.is_control() { '.' } else { c })
                        .collect::<String>(),
                    120,
                ))),
            )
            .await;
        }
        i = i.saturating_add(1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// OpenFOAM dictionaries

fn openfoam_probe(h: &Head<'_>) -> bool {
    let head = h.data.get(..2048).unwrap_or(h.data);
    is_text(h)
        && (head.starts_with(b"/*") || head.starts_with(b"FoamFile") || head.starts_with(b"//"))
        && contains(head, b"FoamFile")
        && contains(head, b"{")
}

declare_format!(pub OPENFOAM = "openfoam", "OpenFOAM dictionary/field file", ["foam"], "text/x-openfoam",
    Probe::Custom(openfoam_probe), openfoam);

/// Removes // and /* */ comments, keeping offsets (comments become spaces).
fn strip_comments(data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    let mut i = 0usize;
    let mut in_str = false;
    while i < out.len() {
        let c = out.get(i).copied().unwrap_or(0);
        let n = out.get(i.saturating_add(1)).copied().unwrap_or(0);
        if c == b'"' {
            in_str = !in_str;
        } else if !in_str && c == b'/' && n == b'/' {
            while out.get(i).is_some_and(|&b| b != b'\n') {
                if let Some(b) = out.get_mut(i) {
                    *b = b' ';
                }
                i = i.saturating_add(1);
            }
            continue;
        } else if !in_str && c == b'/' && n == b'*' {
            while i < out.len()
                && !(out.get(i) == Some(&b'*') && out.get(i.saturating_add(1)) == Some(&b'/'))
            {
                if let Some(b) = out.get_mut(i)
                    && *b != b'\n'
                {
                    *b = b' ';
                }
                i = i.saturating_add(1);
            }
            for _ in 0..2 {
                if let Some(b) = out.get_mut(i) {
                    *b = b' ';
                }
                i = i.saturating_add(1);
            }
            continue;
        }
        i = i.saturating_add(1);
    }
    out
}

/// Top-level entries of a dictionary body: (keyword, value or None for a sub-dictionary, start, end).
fn foam_entries(data: &[u8]) -> Vec<(String, Option<String>, usize, usize)> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < data.len() && out.len() < 100_000 {
        while data.get(i).is_some_and(u8::is_ascii_whitespace) {
            i = i.saturating_add(1);
        }
        if i >= data.len() {
            break;
        }
        let start = i;
        while data
            .get(i)
            .is_some_and(|b| !b.is_ascii_whitespace() && *b != b'{' && *b != b';')
        {
            i = i.saturating_add(1);
        }
        let key = String::from_utf8_lossy(data.get(start..i).unwrap_or_default()).into_owned();
        while data.get(i).is_some_and(u8::is_ascii_whitespace) {
            i = i.saturating_add(1);
        }
        if data.get(i) == Some(&b'{') {
            let mut depth = 0u32;
            while let Some(&c) = data.get(i) {
                if c == b'{' {
                    depth = depth.saturating_add(1);
                } else if c == b'}' {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        break;
                    }
                }
                i = i.saturating_add(1);
            }
            i = i.saturating_add(1).min(data.len());
            out.push((key, None, start, i));
        } else {
            // A value runs to ';' outside parentheses (lists may be long).
            let vstart = i;
            let mut depth = 0u32;
            while let Some(&c) = data.get(i) {
                match c {
                    b'(' => depth = depth.saturating_add(1),
                    b')' => depth = depth.saturating_sub(1),
                    b';' if depth == 0 => break,
                    _ => {}
                }
                i = i.saturating_add(1);
            }
            let value = String::from_utf8_lossy(data.get(vstart..i).unwrap_or_default())
                .trim()
                .to_owned();
            i = i.saturating_add(1).min(data.len());
            if key.is_empty() {
                break;
            }
            out.push((key, Some(value), start, i));
        }
    }
    out
}

async fn openfoam(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let raw = cx.read_avail(file.sub(0, cx.limits().max_read)).await?;
    let data = strip_comments(&raw);
    let entries = foam_entries(&data);
    let mut class = String::new();
    let mut object = String::new();
    let mut format = String::new();
    for (key, value, start, end) in &entries {
        let span = file.sub(to_u64(*start), to_u64(end.saturating_sub(*start)));
        if key == "FoamFile" {
            let inner = data.get(start.saturating_add(8)..*end).unwrap_or_default();
            let body = inner.iter().position(|&b| b == b'{').map_or(inner, |p| {
                inner
                    .get(p.saturating_add(1)..inner.len().saturating_sub(1))
                    .unwrap_or_default()
            });
            for (k, v, _, _) in foam_entries(body) {
                match k.as_str() {
                    "class" => class = v.clone().unwrap_or_default(),
                    "object" => object = v.clone().unwrap_or_default(),
                    "format" => format = v.clone().unwrap_or_default(),
                    _ => {}
                }
            }
        }
        let node = Node::new(key.clone()).span(span);
        cx.push(match value {
            Some(v) => node.value(text(preview(v, 200))),
            None => node.lazy(foam_dict, (span, 0u32)),
        })
        .await;
    }
    cx.annotate(format!(
        "OpenFOAM {class} {object:?} ({format}), {} top-level entr(ies)",
        entries.len()
    ));
    Ok(())
}

async fn foam_dict(cx: Cx, (span, depth): (Span, u32)) -> Result<()> {
    if depth > 64 {
        return Err(Diagnostic::limit("dictionaries nested too deeply"));
    }
    let raw = cx.read_avail(span.sub(0, cx.limits().max_read)).await?;
    let data = strip_comments(&raw);
    let open = data
        .iter()
        .position(|&b| b == b'{')
        .unwrap_or(0)
        .saturating_add(1);
    let body = data
        .get(open..data.len().saturating_sub(1))
        .unwrap_or_default();
    for (key, value, start, end) in foam_entries(body) {
        let s = span.sub(
            to_u64(open.saturating_add(start)),
            to_u64(end.saturating_sub(start)),
        );
        let node = Node::new(key).span(s);
        cx.push(match value {
            Some(v) => node.value(number(&v)),
            None => node.lazy(
                crate::expander!(self::foam_dict: (Span, u32)),
                (s, depth.saturating_add(1)),
            ),
        })
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Keyword decks: Abaqus input, LS-DYNA keyword files

declare_format!(pub ABAQUS = "abaqus-inp", "Abaqus input deck", ["inp"], "text/x-abaqus",
    Probe::Custom(|h| is_text(h) && h.data.get(..8).is_some_and(|k| k.eq_ignore_ascii_case(b"*HEADING"))), keyword_deck);
declare_format!(pub LSDYNA = "lsdyna-key", "LS-DYNA keyword deck", ["k", "key", "dyn"], "text/x-lsdyna",
    Probe::Custom(|h| is_text(h) && head_lines(h, 16).iter().find(|l| !l.starts_with(b"$")).is_some_and(|l| l.trim_ascii().eq_ignore_ascii_case(b"*KEYWORD") || l.starts_with(b"*KEYWORD "))), keyword_deck);

async fn keyword_deck(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut current: Option<(String, u64, u64)> = None;
    let mut counts: Vec<(String, u64)> = Vec::new();
    let mut title = String::new();
    let mut lsdyna = false;
    loop {
        let next = lines.next().await?;
        let starts = next
            .as_ref()
            .is_none_or(|l| l.bytes.starts_with(b"*") && !l.bytes.starts_with(b"**"));
        if starts && let Some((kw, start, n)) = current.take() {
            let end = next.as_ref().map_or(lines.pos(), |l| l.pos);
            let span = file.sub(start, end.saturating_sub(start));
            let (name, params) = kw.split_once(',').unwrap_or((kw.as_str(), ""));
            let node = Node::new(name.trim().to_owned()).span(span);
            let node = summarize(
                node,
                if n > 0 {
                    format!("{n} data line(s)")
                } else {
                    String::new()
                },
            );
            cx.push(if params.trim().is_empty() {
                node
            } else {
                node.value(text(params.trim()))
            })
            .await;
            tally(&mut counts, &name.trim().to_ascii_uppercase(), 512);
        }
        let Some(line) = next else { break };
        let t = line.text();
        if starts {
            if t.trim().eq_ignore_ascii_case("*KEYWORD") {
                lsdyna = true;
            }
            current = Some((t.trim().to_owned(), line.pos, 0));
        } else if let Some((kw, _, n)) = current.as_mut()
            && !t.starts_with("**")
            && !t.starts_with('$')
            && !t.trim().is_empty()
        {
            *n = n.saturating_add(1);
            if (kw.eq_ignore_ascii_case("*HEADING") || kw.eq_ignore_ascii_case("*TITLE"))
                && title.is_empty()
            {
                title = t.trim().to_owned();
            }
        }
    }
    counts.sort_by_key(|c| std::cmp::Reverse(c.1));
    let top: Vec<String> = counts
        .iter()
        .take(6)
        .map(|(k, n)| format!("{n} {k}"))
        .collect();
    cx.annotate(format!(
        "{}{}, {}",
        if lsdyna {
            "LS-DYNA keyword deck"
        } else {
            "Abaqus input deck"
        },
        if title.is_empty() {
            String::new()
        } else {
            format!(" {title:?}")
        },
        top.join(", ")
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn step_strings_decode() {
        assert_eq!(
            step_strings("('a''b','',\\X2\\00E9\\X0\\)"),
            vec!["a'b".to_owned(), String::new()]
        );
        assert_eq!(step_string("caf\\X2\\00E9\\X0\\"), "café");
    }

    #[test]
    fn iges_hollerith() {
        let p = iges_params("1H,,1H;,4HTEST,8Htest.igs;", ',', ';');
        assert_eq!(p, vec![",", ";", "TEST", "test.igs"]);
    }

    #[test]
    fn foam_entries_split() {
        let e = foam_entries(b"a 1; b { c 2; } d (1 2 3);");
        assert_eq!(
            e.iter().map(|x| x.0.as_str()).collect::<Vec<_>>(),
            vec!["a", "b", "d"]
        );
        assert!(e.get(1).is_some_and(|x| x.1.is_none()));
        assert_eq!(
            strip_comments(b"a // x\nb /* y */ c"),
            b"a     \nb         c".to_vec()
        );
    }
}
