//! Text records from bioinformatics: HMMER3 profile HMMs, EMBL/UniProt flat
//! files, GTF annotations, BLAT PSL alignments, mzTab results and AMBER
//! parameter/topology files.

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::declare_format;
use crate::error::Result;
use crate::formats::util::lines::{
    Line, Lines, head_lines, is_text, number, preview, summarize, tally, text, uint,
};
use crate::formats::{Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;

// ---------------------------------------------------------------------------
// HMMER3 profile HMMs

declare_format!(pub HMMER3 = "hmmer3", "HMMER3 profile HMM", ["hmm"], "text/x-hmmer3",
    Probe::Custom(|h| h.starts_with(b"HMMER3/") && is_text(h)), hmmer3);

async fn hmmer3(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut start = 0u64;
    let mut fields: Vec<(String, String, Span)> = Vec::new();
    let mut models = 0u64;
    let mut first = String::new();
    let mut version = String::new();
    while let Some(line) = lines.next().await? {
        cx.progress_in(file, file.offset.saturating_add(lines.pos()));
        let t = line.text();
        if t.starts_with("HMMER3/") {
            start = line.pos;
            fields.clear();
            if version.is_empty() {
                version = t.split_whitespace().next().unwrap_or_default().to_owned();
            }
        } else if t.starts_with("//") {
            let span = file.sub(start, lines.pos().saturating_sub(start));
            let get = |k: &str| {
                fields
                    .iter()
                    .find(|(a, _, _)| a == k)
                    .map_or(String::new(), |(_, v, _)| v.clone())
            };
            let name = get("NAME");
            if first.is_empty() {
                first.clone_from(&name);
            }
            let node = Node::new(if name.is_empty() {
                format!("Model {models}")
            } else {
                name
            })
            .span(span)
            .value(text(get("DESC")));
            cx.push(
                summarize(
                    node,
                    format!("{} {}, length {}", get("ACC"), get("ALPH"), get("LENG")),
                )
                .lazy(kv_items, std::mem::take(&mut fields)),
            )
            .await;
            models = models.saturating_add(1);
        } else if !t.starts_with(' ') && !t.starts_with("HMM ") && fields.len() < 256 {
            let (k, v) = t
                .split_once(char::is_whitespace)
                .unwrap_or((t.as_str(), ""));
            if k.chars().all(|c| c.is_ascii_uppercase()) && !k.is_empty() {
                fields.push((k.to_owned(), v.trim().to_owned(), line.content()));
            }
        }
    }
    cx.annotate(format!(
        "{version} profile library, {models} model(s){}",
        if first.is_empty() {
            String::new()
        } else {
            format!(", first {first}")
        }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// EMBL / UniProt flat files

fn embl_probe(h: &Head<'_>) -> bool {
    let lines = head_lines(h, 2);
    is_text(h)
        && lines.first().is_some_and(|l| l.starts_with(b"ID   "))
        && lines.get(1).is_some_and(|l| {
            l.len() >= 2
                && l.get(..2)
                    .is_some_and(|c| c.iter().all(u8::is_ascii_uppercase))
                && l.get(2..5).is_none_or(|s| s.iter().all(|&b| b == b' '))
        })
}

declare_format!(pub EMBL = "embl", "EMBL/UniProt flat file", ["embl", "dat", "txt"], "text/x-embl",
    Probe::Custom(embl_probe), embl);

const EMBL_CODES: &[(&str, &str)] = &[
    ("ID", "Identification"),
    ("AC", "Accession"),
    ("PR", "Project"),
    ("DT", "Date"),
    ("DE", "Description"),
    ("KW", "Keywords"),
    ("OS", "Organism species"),
    ("OC", "Organism classification"),
    ("OG", "Organelle"),
    ("OX", "Taxonomy cross-reference"),
    ("GN", "Gene name"),
    ("RN", "Reference number"),
    ("RC", "Reference comment"),
    ("RP", "Reference positions"),
    ("RX", "Reference cross-reference"),
    ("RG", "Reference group"),
    ("RA", "Reference authors"),
    ("RT", "Reference title"),
    ("RL", "Reference location"),
    ("DR", "Database cross-reference"),
    ("CC", "Comments"),
    ("FH", "Feature header"),
    ("FT", "Feature table"),
    ("SQ", "Sequence header"),
    ("PE", "Protein existence"),
];

async fn embl(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut start = None;
    let mut records = 0u64;
    let mut first = String::new();
    while let Some(line) = lines.next().await? {
        cx.progress_in(file, file.offset.saturating_add(lines.pos()));
        let t = line.text();
        if t.starts_with("ID ") {
            start = Some((line.pos, t.get(5..).unwrap_or_default().trim().to_owned()));
        } else if t.starts_with("//")
            && let Some((s, id)) = start.take()
        {
            let span = file.sub(s, lines.pos().saturating_sub(s));
            let name = id.split([' ', ';']).next().unwrap_or_default().to_owned();
            if first.is_empty() {
                first.clone_from(&id);
            }
            cx.push(
                Node::new(name)
                    .span(span)
                    .value(text(id))
                    .lazy(embl_record, span),
            )
            .await;
            records = records.saturating_add(1);
        }
    }
    cx.annotate(format!(
        "EMBL/UniProt flat file, {records} entr(ies){}",
        if first.is_empty() {
            String::new()
        } else {
            format!("; {}", preview(&first, 60))
        }
    ));
    Ok(())
}

/// Lines grouped by their two-letter code.
async fn embl_record(cx: Cx, span: Span) -> Result<()> {
    let mut lines = Lines::new(&cx, span);
    let mut current: Option<(String, u64, String, u64)> = None;
    let mut features: Vec<Line> = Vec::new();
    loop {
        let next = lines.next().await?;
        let code = next
            .as_ref()
            .map(|l| l.text().get(..2).unwrap_or_default().to_owned());
        let changes = match (&current, &code) {
            (Some((c, ..)), Some(n)) => c != n && !(n == "  " && c == "SQ"),
            (Some(_), None) => true,
            _ => false,
        };
        if changes && let Some((c, start, value, n)) = current.take() {
            let end = next.as_ref().map_or(lines.pos(), |l| l.pos);
            let s = span.sub(start, end.saturating_sub(start));
            let desc = EMBL_CODES
                .iter()
                .find(|(k, _)| *k == c)
                .map_or("", |(_, d)| *d);
            let node = Node::new(c.clone()).span(s).desc(desc);
            let node = if c == "FT" {
                node.summary(format!(
                    "{} feature(s)",
                    features
                        .iter()
                        .filter(|l| l.bytes.get(5).is_some_and(|b| *b != b' '))
                        .count()
                ))
                .lazy(embl_features, std::mem::take(&mut features))
            } else if c == "SQ" {
                node.value(text(value)).summary(format!("{n} line(s)"))
            } else {
                node.value(text(preview(&value, 300)))
            };
            cx.push(node).await;
        }
        let (Some(line), Some(code)) = (next, code) else {
            break;
        };
        let body = line.text().get(5..).unwrap_or_default().trim().to_owned();
        if code == "XX" || code == "//" {
            continue;
        }
        match current.as_mut() {
            Some((c, _, value, n)) if *c == code || (code == "  " && c == "SQ") => {
                *n = n.saturating_add(1);
                if code != "  " && value.len() < 2000 {
                    value.push(' ');
                    value.push_str(&body);
                }
            }
            _ => current = Some((code.clone(), line.pos, body, 1)),
        }
        if code == "FT" && features.len() < 100_000 {
            features.push(line);
        }
    }
    Ok(())
}

async fn embl_features(cx: Cx, lines: Vec<Line>) -> Result<()> {
    // (key, location, qualifiers, span) of each feature.
    type Feature = (String, String, Vec<String>, Span);
    let mut features: Vec<Feature> = Vec::new();
    for line in lines {
        let t = line.text();
        let key = t.get(5..21).unwrap_or_default().trim().to_owned();
        if !key.is_empty() {
            features.push((
                key,
                t.get(21..).unwrap_or_default().trim().to_owned(),
                Vec::new(),
                line.content(),
            ));
        } else if let Some((_, _, quals, span)) = features.last_mut() {
            let body = t.get(21..).unwrap_or_default().trim().to_owned();
            if body.starts_with('/') || quals.is_empty() {
                if quals.len() < 64 {
                    quals.push(body);
                }
            } else if let Some(last) = quals.last_mut()
                && last.len() < 1000
            {
                last.push(' ');
                last.push_str(&body);
            }
            *span = Span::new(
                span.source,
                span.offset,
                line.content().end().saturating_sub(span.offset),
            );
        }
    }
    for (key, loc, quals, span) in features {
        let label = quals
            .iter()
            .find_map(|q| {
                q.strip_prefix("/gene=")
                    .or_else(|| q.strip_prefix("/product="))
                    .or_else(|| q.strip_prefix("/note="))
            })
            .map(|s| s.trim_matches('"').to_owned())
            .unwrap_or_default();
        cx.push(summarize(Node::new(key).span(span).value(text(loc)), label).desc(quals.join(" ")))
            .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// GTF (GFF 2.2) annotations

fn gtf_probe(h: &Head<'_>) -> bool {
    is_text(h)
        && head_lines(h, 8)
            .iter()
            .find(|l| !l.starts_with(b"#") && !l.is_empty())
            .is_some_and(|l| {
                let f: Vec<&[u8]> = l.split(|&b| b == b'\t').collect();
                f.len() == 9
                    && f.get(3)
                        .is_some_and(|x| !x.is_empty() && x.iter().all(u8::is_ascii_digit))
                    && f.get(4)
                        .is_some_and(|x| !x.is_empty() && x.iter().all(u8::is_ascii_digit))
                    && f.get(8).is_some_and(|a| {
                        crate::formats::util::lines::contains(a, b"gene_id \"")
                            || crate::formats::util::lines::contains(a, b"transcript_id \"")
                    })
            })
}

declare_format!(pub GTF = "gtf", "Gene Transfer Format (GTF)", ["gtf", "gff2"], "text/x-gtf",
    Probe::Custom(gtf_probe), gtf);

async fn gtf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut kinds: Vec<(String, u64)> = Vec::new();
    let mut genes: Vec<(String, u64)> = Vec::new();
    let mut features = 0u64;
    while let Some(line) = lines.next().await? {
        cx.progress_in(file, file.offset.saturating_add(lines.pos()));
        let t = line.text();
        if t.is_empty() {
            continue;
        }
        if t.starts_with('#') {
            cx.push(
                Node::new("Comment")
                    .span(line.content())
                    .value(text(t.trim_start_matches('#').trim())),
            )
            .await;
            continue;
        }
        let f = line.split(b'\t');
        let get = |i: usize| f.get(i).map_or("", |(s, _)| s.as_str());
        let attr = |k: &str| {
            get(8)
                .split(';')
                .find_map(|a| {
                    a.trim()
                        .strip_prefix(k)
                        .map(|v| v.trim().trim_matches('"').to_owned())
                })
                .unwrap_or_default()
        };
        let gene = attr("gene_name ");
        let gene = if gene.is_empty() {
            attr("gene_id ")
        } else {
            gene
        };
        tally(&mut kinds, get(2), 64);
        tally(&mut genes, &gene, 100_000);
        let node = Node::new(format!("{} {}:{}-{}", get(2), get(0), get(3), get(4)))
            .span(line.content())
            .value(text(gene))
            .summary(attr("transcript_id "));
        cx.push(node.lazy(gtf_columns, line.clone())).await;
        features = features.saturating_add(1);
    }
    let top: Vec<String> = kinds
        .iter()
        .take(5)
        .map(|(k, n)| format!("{n} {k}"))
        .collect();
    cx.annotate(format!(
        "GTF, {features} feature(s) in {} gene(s) ({})",
        genes.len(),
        top.join(", ")
    ));
    Ok(())
}

async fn gtf_columns(cx: Cx, line: Line) -> Result<()> {
    const COLUMNS: [&str; 9] = [
        "seqname",
        "source",
        "feature",
        "start",
        "end",
        "score",
        "strand",
        "frame",
        "attributes",
    ];
    for (i, (value, span)) in line.split(b'\t').into_iter().enumerate() {
        let name = COLUMNS.get(i).copied().unwrap_or("extra");
        if i == 8 {
            let mut at = 0u64;
            for a in value.split(';') {
                let len = to_u64(a.len());
                let t = a.trim();
                if let Some((k, v)) = t.split_once(' ') {
                    cx.emit(
                        Node::new(k.to_owned())
                            .span(span.sub(at, len))
                            .value(text(v.trim().trim_matches('"'))),
                    );
                }
                at = at.saturating_add(len).saturating_add(1);
            }
        } else {
            cx.emit(
                Node::new(name)
                    .span(span)
                    .value(if matches!(i, 3 | 4 | 5 | 7) {
                        number(&value)
                    } else {
                        text(value)
                    }),
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// BLAT PSL alignments

declare_format!(pub PSL = "psl", "BLAT PSL alignments", ["psl"], "text/x-psl",
    Probe::Custom(|h| h.starts_with(b"psLayout version") && is_text(h)), psl);

const PSL_COLUMNS: [&str; 21] = [
    "matches",
    "misMatches",
    "repMatches",
    "nCount",
    "qNumInsert",
    "qBaseInsert",
    "tNumInsert",
    "tBaseInsert",
    "strand",
    "qName",
    "qSize",
    "qStart",
    "qEnd",
    "tName",
    "tSize",
    "tStart",
    "tEnd",
    "blockCount",
    "blockSizes",
    "qStarts",
    "tStarts",
];

async fn psl(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut header_end = 0u64;
    let mut rows = 0u64;
    let mut version = String::new();
    while let Some(line) = lines.next().await? {
        cx.progress_in(file, file.offset.saturating_add(lines.pos()));
        let t = line.text();
        if line.pos == 0 {
            version = t.trim().to_owned();
        }
        if t.starts_with("------") {
            header_end = lines.pos();
            cx.emit(
                Node::new("Header")
                    .span(file.sub(0, header_end))
                    .value(text(version.clone())),
            );
            continue;
        }
        if header_end == 0 && line.pos > 0 && !t.chars().next().is_some_and(|c| c.is_ascii_digit())
        {
            continue;
        }
        let f = line.split(b'\t');
        if f.len() < 21 {
            continue;
        }
        let g = |i: usize| f.get(i).map_or("", |(s, _)| s.as_str());
        cx.push(
            Node::new(format!("{} → {}:{}-{}", g(9), g(13), g(15), g(16)))
                .span(line.content())
                .value(number(g(0)))
                .summary(format!("{} block(s), strand {}", g(17), g(8)))
                .lazy(psl_row, line.clone()),
        )
        .await;
        rows = rows.saturating_add(1);
    }
    cx.annotate(format!("PSL ({version}), {rows} alignment(s)"));
    Ok(())
}

async fn psl_row(cx: Cx, line: Line) -> Result<()> {
    for (i, (v, span)) in line.split(b'\t').into_iter().enumerate() {
        cx.emit(
            Node::new(PSL_COLUMNS.get(i).copied().unwrap_or("extra"))
                .span(span)
                .value(number(&v)),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// mzTab proteomics/metabolomics results

declare_format!(pub MZTAB = "mztab", "mzTab results", ["mztab"], "text/x-mztab",
    Probe::Custom(|h| h.starts_with(b"MTD\tmzTab-version") || h.starts_with(b"MTD  mzTab-version") || (h.starts_with(b"COM\t") && crate::formats::util::lines::contains(h.data.get(..4096).unwrap_or(h.data), b"\nMTD\tmzTab-version"))), mztab);

const MZTAB_SECTIONS: &[(&str, &str)] = &[
    ("MTD", "Metadata"),
    ("PRH", "Protein header"),
    ("PRT", "Protein"),
    ("PEH", "Peptide header"),
    ("PEP", "Peptide"),
    ("PSH", "PSM header"),
    ("PSM", "PSM"),
    ("SMH", "Small molecule header"),
    ("SML", "Small molecule"),
    ("SFH", "Small molecule feature header"),
    ("SMF", "Small molecule feature"),
    ("SEH", "Small molecule evidence header"),
    ("SME", "Small molecule evidence"),
    ("COM", "Comment"),
];

async fn mztab(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut section: Option<(String, u64, u64, Vec<Line>)> = None;
    let mut counts: Vec<(String, u64)> = Vec::new();
    let mut version = String::new();
    loop {
        cx.progress_in(file, file.offset.saturating_add(lines.pos()));
        let next = lines.next().await?;
        let prefix = next
            .as_ref()
            .map(|l| l.text().get(..3).unwrap_or_default().to_owned());
        if section
            .as_ref()
            .is_some_and(|(p, ..)| prefix.as_ref() != Some(p))
            && let Some((p, start, n, keep)) = section.take()
        {
            let end = next.as_ref().map_or(lines.pos(), |l| l.pos);
            let name = MZTAB_SECTIONS
                .iter()
                .find(|(k, _)| *k == p)
                .map_or(p.as_str(), |(_, d)| *d)
                .to_owned();
            let node = Node::new(name.clone())
                .span(file.sub(start, end.saturating_sub(start)))
                .value(uint(n));
            cx.push(if keep.is_empty() {
                node
            } else {
                node.lazy(mztab_lines, keep)
            })
            .await;
            tally(&mut counts, &name, 64);
            if let Some((_, c)) = counts.iter_mut().find(|(k, _)| *k == name) {
                *c = n;
            }
        }
        let (Some(line), Some(prefix)) = (next, prefix) else {
            break;
        };
        let t = line.text();
        if prefix == "MTD" && t.contains("mzTab-version") {
            version = t.split('\t').nth(2).unwrap_or_default().trim().to_owned();
        }
        match section.as_mut() {
            Some((_, _, n, keep)) => {
                *n = n.saturating_add(1);
                if keep.len() < 10_000 {
                    keep.push(line);
                }
            }
            None => section = Some((prefix, line.pos, 1, vec![line])),
        }
    }
    let parts: Vec<String> = counts
        .iter()
        .filter(|(k, _)| !k.ends_with("header") && k != "Comment" && k != "Metadata")
        .map(|(k, n)| format!("{n} {}", k.to_lowercase()))
        .collect();
    cx.annotate(format!(
        "mzTab {version}{}",
        if parts.is_empty() {
            String::new()
        } else {
            format!(", {}", parts.join(", "))
        }
    ));
    Ok(())
}

async fn mztab_lines(cx: Cx, lines: Vec<Line>) -> Result<()> {
    for l in lines {
        let fields = l.split(b'\t');
        let name = fields.get(1).map_or(String::new(), |(s, _)| s.clone());
        let rest: Vec<&str> = fields.iter().skip(2).map(|(s, _)| s.as_str()).collect();
        cx.push(
            Node::new(name)
                .span(l.content())
                .value(text(preview(&rest.join(" | "), 200))),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// AMBER parameter/topology (prmtop)

declare_format!(pub AMBER_PRMTOP = "amber-prmtop", "AMBER parameter/topology file", ["prmtop", "parm7", "top"], "chemical/x-amber-prmtop",
    Probe::Magic(&[(0, b"%VERSION ")]), amber_prmtop);

const PRMTOP_POINTERS: [&str; 12] = [
    "NATOM", "NTYPES", "NBONH", "MBONA", "NTHETH", "MTHETA", "NPHIH", "MPHIA", "NHPARM", "NPARM",
    "NNB", "NRES",
];

async fn amber_prmtop(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut section: Option<(String, u64, String, Vec<String>)> = None;
    let (mut title, mut pointers) = (String::new(), Vec::<u64>::new());
    let mut sections = 0u32;
    loop {
        cx.progress_in(file, file.offset.saturating_add(lines.pos()));
        let next = lines.next().await?;
        let starts = next.as_ref().is_none_or(|l| l.bytes.starts_with(b"%FLAG"));
        if starts && let Some((name, start, format, data)) = section.take() {
            let end = next.as_ref().map_or(lines.pos(), |l| l.pos);
            if name == "TITLE" {
                title = data.join(" ").trim().to_owned();
            }
            if name == "POINTERS" {
                pointers = data
                    .iter()
                    .flat_map(|l| l.split_whitespace().map(str::to_owned).collect::<Vec<_>>())
                    .filter_map(|v| v.parse().ok())
                    .collect();
            }
            let lines_n = data.len();
            let node = Node::new(name.clone())
                .span(file.sub(start, end.saturating_sub(start)))
                .value(text(format));
            let node = summarize(node, format!("{lines_n} line(s)"));
            cx.push(if name == "POINTERS" {
                node.lazy(prmtop_pointers, pointers.clone())
            } else {
                node
            })
            .await;
            sections = sections.saturating_add(1);
        }
        let Some(line) = next else { break };
        let t = line.text();
        if line.pos == 0 {
            cx.emit(
                Node::new("Version")
                    .span(line.content())
                    .value(text(t.trim_start_matches("%VERSION").trim())),
            );
            continue;
        }
        if let Some(name) = t.strip_prefix("%FLAG") {
            section = Some((name.trim().to_owned(), line.pos, String::new(), Vec::new()));
        } else if let Some(fmt) = t.strip_prefix("%FORMAT") {
            if let Some((_, _, format, _)) = section.as_mut() {
                *format = fmt.trim().to_owned();
            }
        } else if !t.starts_with('%')
            && let Some((name, _, _, data)) = section.as_mut()
            && (name == "TITLE" || name == "POINTERS" || data.len() < 8)
            && data.len() < 64
        {
            data.push(t);
        }
    }
    let p = |i: usize| pointers.get(i).copied().unwrap_or(0);
    cx.annotate(format!(
        "AMBER prmtop {title:?}, {} atom(s), {} residue(s), {} bond(s), {sections} section(s)",
        p(0),
        p(11),
        p(2).saturating_add(p(3))
    ));
    Ok(())
}

async fn prmtop_pointers(cx: Cx, values: Vec<u64>) -> Result<()> {
    for (i, v) in values.into_iter().enumerate().take(32) {
        cx.emit(Node::new(PRMTOP_POINTERS.get(i).copied().unwrap_or("pointer")).value(uint(v)));
    }
    Ok(())
}

async fn kv_items(cx: Cx, items: Vec<(String, String, Span)>) -> Result<()> {
    for (k, v, span) in items {
        cx.push(Node::new(k).span(span).value(number(&v))).await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probes() {
        let h = Head {
            data: b"ID   X; SV 1\nXX\n",
            tail: b"",
            len: 16,
            len_known: true,
        };
        assert!(embl_probe(&h));
        let g = Head {
            data: b"chr1\tsrc\texon\t1\t10\t.\t+\t.\tgene_id \"g\"; transcript_id \"t\";\n",
            tail: b"",
            len: 60,
            len_known: true,
        };
        assert!(gtf_probe(&g));
    }
}
