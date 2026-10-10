//! Wavefront OBJ geometry and its MTL material libraries.
//!
//! OBJ statements are grouped by object/group (`o`, `g`); each group lists
//! its statements (vertices with coordinates, faces with their vertex
//! references) as a paged collection. MTL files list materials.

use crate::cx::Cx;
use crate::error::Result;
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::Value;

use super::encoding::prepare;
use super::scan::Lines;
use super::{count, plural, probe, text_node};

pub static OBJ: Format = Format {
    name: "wavefront-obj",
    title: "Wavefront OBJ geometry",
    extensions: &["obj"],
    mime: "model/obj",
    probe: Probe::Custom(|h| probe_keywords(h, OBJ_KEYWORDS, b"v")),
    dissect: crate::expander!(dissect_obj: Input),
};

pub static MTL: Format = Format {
    name: "wavefront-mtl",
    title: "Wavefront MTL materials",
    extensions: &["mtl"],
    mime: "model/mtl",
    probe: Probe::Custom(|h| probe_keywords(h, MTL_KEYWORDS, b"newmtl")),
    dissect: crate::expander!(dissect_mtl: Input),
};

const OBJ_KEYWORDS: &[&[u8]] = &[
    b"v", b"vt", b"vn", b"vp", b"f", b"l", b"p", b"o", b"g", b"s", b"usemtl", b"mtllib", b"cstype",
    b"deg", b"curv", b"curv2", b"surf", b"parm", b"end", b"mg",
];

const MTL_KEYWORDS: &[&[u8]] = &[
    b"newmtl",
    b"Ka",
    b"Kd",
    b"Ks",
    b"Ke",
    b"Ns",
    b"Ni",
    b"d",
    b"Tr",
    b"Tf",
    b"illum",
    b"map_Ka",
    b"map_Kd",
    b"map_Ks",
    b"map_Ns",
    b"map_d",
    b"map_bump",
    b"bump",
    b"disp",
    b"decal",
    b"refl",
    b"sharpness",
    b"Pr",
    b"Pm",
    b"Ps",
    b"Pc",
    b"Pcr",
    b"aniso",
    b"map_Pr",
    b"map_Pm",
    b"norm",
];

/// Every significant line starts with a known keyword, and `required`
/// occurs among them.
fn probe_keywords(h: &Head<'_>, keywords: &[&[u8]], required: &[u8]) -> bool {
    let head = probe::head(h);
    let mut seen = false;
    let mut n = 0usize;
    for line in probe::significant(&head, &[b"#"]).take(60) {
        let t = probe::trim(line);
        let word = t
            .split(|b| b.is_ascii_whitespace())
            .next()
            .unwrap_or_default();
        if !keywords.contains(&word) {
            return false;
        }
        seen |= word == required;
        n = n.saturating_add(1);
    }
    seen && n >= 2 && probe::is_text(h)
}

/// Statement counts, used for vertex numbering and summaries.
#[derive(Clone, Copy, Debug, Default)]
struct Counts {
    v: u64,
    vt: u64,
    vn: u64,
    f: u64,
}

impl Counts {
    fn note(&mut self, word: &[u8]) {
        match word {
            b"v" => self.v = self.v.saturating_add(1),
            b"vt" => self.vt = self.vt.saturating_add(1),
            b"vn" => self.vn = self.vn.saturating_add(1),
            b"f" => self.f = self.f.saturating_add(1),
            _ => {}
        }
    }
}

#[derive(Clone, Debug)]
struct Group {
    span: Span,
    /// Counts before this group (for absolute vertex numbers).
    before: Counts,
}

async fn push_group(cx: &Cx, name: &str, span: Span, before: Counts, total: Counts) {
    if span.is_empty() {
        return;
    }
    let mine = Counts {
        v: total.v.saturating_sub(before.v),
        vt: total.vt.saturating_sub(before.vt),
        vn: total.vn.saturating_sub(before.vn),
        f: total.f.saturating_sub(before.f),
    };
    cx.push(
        Node::new(name.to_owned())
            .span(span)
            .summary(format!(
                "{}, {}",
                plural(mine.v, "vertex", "vertices"),
                plural(mine.f, "face", "faces")
            ))
            .lazy(group, Group { span, before }),
    )
    .await;
}

pub async fn dissect_obj(cx: Cx, input: Input) -> Result<()> {
    let prepared = prepare(&cx, input).await?;
    let span = prepared.span;
    let mut lines = Lines::new(&cx, span);
    let mut counts = Counts::default();
    let mut current = ("(default)".to_owned(), 0u64, Counts::default());
    let mut groups = 0u64;
    let mut library = None;
    loop {
        let before = lines.pos();
        let Some(line) = lines.next().await? else {
            let (name, start, at) = &current;
            push_group(
                &cx,
                name,
                span.sub(*start, before.saturating_sub(*start)),
                *at,
                counts,
            )
            .await;
            break;
        };
        // Groups are pushed as they end: a file without any is one long
        // scan before the first child.
        lines.progress();
        let t = line.piece().trim();
        let (word, rest) = t.split_word();
        if matches!(word.bytes(), b"o" | b"g") {
            let (name, start, at) = &current;
            push_group(
                &cx,
                name,
                span.sub(*start, before.saturating_sub(*start)),
                *at,
                counts,
            )
            .await;
            let kind = if word.bytes() == b"o" {
                "Object"
            } else {
                "Group"
            };
            current = (format!("{kind} {}", rest.text()), before, counts);
            groups = groups.saturating_add(1);
            continue;
        }
        if word.bytes() == b"mtllib" {
            library = Some(rest.text());
        }
        counts.note(word.bytes());
    }
    let mut summary = format!(
        "Wavefront OBJ: {}, {}",
        plural(counts.v, "vertex", "vertices"),
        plural(counts.f, "face", "faces")
    );
    if groups > 0 {
        summary = format!("{summary}, {} objects/groups", count(groups));
    }
    if let Some(l) = library {
        summary = format!("{summary}, materials from {l}");
    }
    cx.annotate(summary);
    Ok(())
}

/// Floats of a statement's arguments.
fn floats(rest: &super::piece::Piece<'_>) -> Vec<f64> {
    rest.words().filter_map(|w| w.text().parse().ok()).collect()
}

async fn group(cx: Cx, g: Group) -> Result<()> {
    let mut lines = Lines::new(&cx, g.span);
    let mut counts = g.before;
    while let Some(line) = lines.next().await? {
        let t = line.piece().trim();
        if t.is_empty() || t.first() == Some(b'#') {
            continue;
        }
        let (word, rest) = t.split_word();
        counts.note(word.bytes());
        let node =
            match word.bytes() {
                b"v" | b"vt" | b"vn" => {
                    let (name, n) = match word.bytes() {
                        b"v" => ("Vertex", counts.v),
                        b"vt" => ("Texture coordinate", counts.vt),
                        _ => ("Normal", counts.vn),
                    };
                    let values = floats(&rest);
                    let text: Vec<String> = values.iter().map(f64::to_string).collect();
                    Node::new(format!("{name} {n}"))
                        .span(line.span)
                        .value(Value::Text(text.join(", ")))
                }
                b"f" => {
                    let refs = rest.words().count();
                    text_node(format!("Face {}", counts.f), line.span, &rest.text())
                        .summary(plural(crate::bytes::to_u64(refs), "corner", "corners"))
                }
                _ => text_node(word.text(), rest.span(), &rest.text()),
            };
        lines.progress();
        cx.push(node).await;
    }
    Ok(())
}

pub async fn dissect_mtl(cx: Cx, input: Input) -> Result<()> {
    let prepared = prepare(&cx, input).await?;
    let span = prepared.span;
    let mut lines = Lines::new(&cx, span);
    let mut current: Option<(String, u64)> = None;
    let mut materials = 0u64;
    loop {
        let before = lines.pos();
        let line = lines.next().await?;
        let new = line.as_ref().and_then(|l| {
            let t = l.piece().trim();
            let (word, rest) = t.split_word();
            (word.bytes() == b"newmtl").then(|| rest.text())
        });
        if line.is_some() && new.is_none() {
            continue;
        }
        if let Some((name, start)) = current.take() {
            let s = span.sub(start, before.saturating_sub(start));
            cx.push(Node::new(name).span(s).lazy(material, s)).await;
            materials = materials.saturating_add(1);
        }
        match new {
            Some(name) => current = Some((name, before)),
            None => break,
        }
    }
    cx.annotate(format!(
        "Wavefront MTL: {}",
        plural(materials, "material", "materials")
    ));
    Ok(())
}

async fn material(cx: Cx, span: Span) -> Result<()> {
    let mut lines = Lines::new(&cx, span);
    while let Some(line) = lines.next().await? {
        let t = line.piece().trim();
        if t.is_empty() || t.first() == Some(b'#') {
            continue;
        }
        let (word, rest) = t.split_word();
        let desc = match word.bytes() {
            b"newmtl" => "Material name",
            b"Ka" => "Ambient color",
            b"Kd" => "Diffuse color",
            b"Ks" => "Specular color",
            b"Ke" => "Emissive color",
            b"Ns" => "Specular exponent",
            b"Ni" => "Optical density",
            b"d" => "Opacity",
            b"Tr" => "Transparency",
            b"illum" => "Illumination model",
            b"map_Kd" => "Diffuse texture",
            _ => "",
        };
        let mut node = match super::number(&rest.text()) {
            Some(v) => Node::new(word.text()).span(rest.span()).value(v),
            None => text_node(word.text(), rest.span(), &rest.text()),
        };
        if !desc.is_empty() {
            node = node.desc(desc);
        }
        cx.push(node).await;
    }
    Ok(())
}
