//! Text formats from bioinformatics and chemistry: sequences (FASTA, FASTQ,
//! GenBank), alignments (SAM, Stockholm, Clustal, MAF, NEXUS), variants and
//! annotations (VCF, GFF3, BED, WIG, GFA), structures (PDB, CIF, MDL
//! molfile/SDF) and spectra (JCAMP-DX).
//!
//! All probes require an exact leading keyword: these formats are probed
//! before generic text.

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::declare_format;
use crate::error::{Diagnostic, Result};
use crate::formats::science::bio::binary::SAM_FLAGS;
use crate::formats::util::lines::{
    Line, Lines, flags, head_lines, is_text, number, preview, summarize, tally, text, uint,
};
use crate::formats::{Head, Input, Probe, embedded_as};
use crate::node::{Count, Node};
use crate::span::Span;

/// Whether every byte is a sequence letter (IUPAC codes, gaps, stops).
fn is_sequence(line: &[u8]) -> bool {
    line.iter()
        .all(|b| b.is_ascii_alphabetic() || matches!(b, b'*' | b'-' | b'.'))
}

/// Mean Phred quality of a FASTQ quality string (offset 33).
fn mean_quality(q: &[u8]) -> Option<u64> {
    if q.is_empty() {
        return None;
    }
    q.iter()
        .map(|&b| u64::from(b.saturating_sub(33)))
        .sum::<u64>()
        .checked_div(to_u64(q.len()))
}

/// A node for one line, with its text as the value.
fn line_node(name: impl Into<String>, line: &Line) -> Node {
    Node::new(name.into())
        .span(line.content())
        .value(text(line.text()))
}

// ---------------------------------------------------------------------------
// FASTA

fn fasta_probe(h: &Head<'_>) -> bool {
    let lines = head_lines(h, 3);
    is_text(h)
        && lines
            .first()
            .is_some_and(|l| l.starts_with(b">") && l.len() > 1)
        && lines
            .get(1)
            .is_some_and(|l| !l.is_empty() && is_sequence(l))
}

declare_format!(pub FASTA = "fasta", "FASTA sequences", ["fasta", "fa", "fna", "faa", "ffn", "frn", "fas", "mpfa"], "text/x-fasta",
    Probe::Custom(fasta_probe), fasta);

async fn fasta(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut current: Option<(Line, u64, Vec<u8>)> = None;
    let (mut records, mut residues) = (0u64, 0u64);
    let mut nucleotide = true;
    loop {
        let next = lines.next().await?;
        let is_header = next.as_ref().is_none_or(|l| l.bytes.starts_with(b">"));
        if is_header && let Some((header, len, sample)) = current.take() {
            let end = next.as_ref().map_or(lines.pos(), |l| l.pos);
            let span = file.sub(header.pos, end.saturating_sub(header.pos));
            let t = header.text();
            let t = t.trim_start_matches('>');
            let (id, desc) = t.split_once([' ', '\t']).unwrap_or((t, ""));
            if records == 0 {
                nucleotide = sample.iter().all(|b| b"ACGTUNacgtun-".contains(b));
            }
            let mut node = Node::new(id.to_owned()).span(span);
            if !desc.trim().is_empty() {
                node = node.value(text(desc.trim()));
            }
            cx.push(node.summary(format!("{len} residues")).lazy(
                fasta_record,
                (
                    header.content(),
                    span.tail(header.span.len),
                    String::from_utf8_lossy(&sample).into_owned(),
                ),
            ))
            .await;
            records = records.saturating_add(1);
            residues = residues.saturating_add(len);
        }
        let Some(line) = next else { break };
        if line.bytes.starts_with(b">") {
            current = Some((line, 0, Vec::new()));
        } else if let Some((_, len, sample)) = current.as_mut() {
            let seq: Vec<u8> = line
                .bytes
                .iter()
                .copied()
                .filter(|b| !b.is_ascii_whitespace())
                .collect();
            *len = len.saturating_add(to_u64(seq.len()));
            if sample.len() < 200 {
                sample.extend(seq.iter().take(200usize.saturating_sub(sample.len())));
            }
        } else if !line.bytes.is_empty() && !line.bytes.starts_with(b";") {
            cx.diag(
                Diagnostic::malformed("sequence data before the first header").at(line.content()),
            );
        }
    }
    cx.set_count(Count::Exact(records));
    cx.annotate(format!(
        "FASTA, {records} {} sequence(s), {residues} residues",
        if nucleotide { "nucleotide" } else { "protein" }
    ));
    Ok(())
}

async fn fasta_record(cx: Cx, (header, body, sample): (Span, Span, String)) -> Result<()> {
    cx.emit(Node::new("Header").span(header));
    cx.emit(
        Node::new("Sequence")
            .span(body)
            .value(text(if sample.len() >= 200 {
                format!("{sample}…")
            } else {
                sample
            })),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// FASTQ

fn fastq_probe(h: &Head<'_>) -> bool {
    let l = head_lines(h, 4);
    is_text(h)
        && l.len() == 4
        && l.first()
            .is_some_and(|x| x.starts_with(b"@") && x.len() > 1)
        && l.get(1).is_some_and(|x| is_sequence(x))
        && l.get(2).is_some_and(|x| x.starts_with(b"+"))
        && l.get(1).map(|x| x.len()) == l.get(3).map(|x| x.len())
}

declare_format!(pub FASTQ = "fastq", "FASTQ reads", ["fastq", "fq"], "text/x-fastq",
    Probe::Custom(fastq_probe), fastq);

async fn fastq(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let (mut reads, mut bases) = (0u64, 0u64);
    let mut lengths = (u64::MAX, 0u64);
    while let Some(header) = lines.next().await? {
        if header.bytes.is_empty() {
            continue;
        }
        if !header.bytes.starts_with(b"@") {
            cx.diag(Diagnostic::malformed("expected a read header ('@')").at(header.content()));
            break;
        }
        let (Some(seq), Some(plus), Some(qual)) = (
            lines.next().await?,
            lines.next().await?,
            lines.next().await?,
        ) else {
            cx.diag(Diagnostic::malformed("incomplete record").at(file.tail(header.pos)));
            break;
        };
        let span = file.sub(header.pos, lines.pos().saturating_sub(header.pos));
        let t = header.text();
        let id = t
            .trim_start_matches('@')
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_owned();
        let len = to_u64(seq.bytes.len());
        let mut node = Node::new(id)
            .span(span)
            .summary(format!(
                "{len} bp{}",
                mean_quality(&qual.bytes)
                    .map(|q| format!(", mean Q{q}"))
                    .unwrap_or_default()
            ))
            .lazy(
                fastq_record,
                (header.clone(), seq.clone(), plus.clone(), qual.clone()),
            );
        if seq.bytes.len() != qual.bytes.len() {
            node = node.diag(Diagnostic::malformed("sequence and quality lengths differ"));
        }
        cx.push(node).await;
        reads = reads.saturating_add(1);
        bases = bases.saturating_add(len);
        lengths = (lengths.0.min(len), lengths.1.max(len));
    }
    cx.set_count(Count::Exact(reads));
    let range = if reads == 0 {
        String::new()
    } else if lengths.0 == lengths.1 {
        format!(", {} bp each", lengths.0)
    } else {
        format!(", {}–{} bp", lengths.0, lengths.1)
    };
    cx.annotate(format!("FASTQ, {reads} read(s), {bases} bases{range}"));
    Ok(())
}

async fn fastq_record(cx: Cx, (header, seq, plus, qual): (Line, Line, Line, Line)) -> Result<()> {
    let h = header.text();
    let (id, desc) = h
        .trim_start_matches('@')
        .split_once(' ')
        .unwrap_or((h.trim_start_matches('@'), ""));
    cx.emit(summarize(
        Node::new("Header").span(header.content()).value(text(id)),
        desc,
    ));
    cx.emit(line_node("Sequence", &seq).summary(format!("{} bp", seq.bytes.len())));
    cx.emit(line_node("Separator", &plus));
    cx.emit(
        line_node("Quality", &qual).summary(
            mean_quality(&qual.bytes)
                .map(|q| format!("mean Phred {q}"))
                .unwrap_or_default(),
        ),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// SAM

fn sam_probe(h: &Head<'_>) -> bool {
    is_text(h)
        && [
            &b"@HD\tVN:"[..],
            b"@SQ\tSN:",
            b"@PG\tID:",
            b"@RG\tID:",
            b"@CO\t",
        ]
        .iter()
        .any(|m| h.starts_with(m))
}

declare_format!(pub SAM = "sam", "Sequence Alignment/Map (SAM)", ["sam"], "text/x-sam",
    Probe::Custom(sam_probe), sam);

const SAM_COLUMNS: [&str; 11] = [
    "QNAME", "FLAG", "RNAME", "POS", "MAPQ", "CIGAR", "RNEXT", "PNEXT", "TLEN", "SEQ", "QUAL",
];

async fn sam(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut header_end = 0u64;
    let (mut refs, mut sort) = (0u32, String::new());
    let mut first = None;
    while let Some(line) = lines.next().await? {
        if !line.bytes.starts_with(b"@") {
            first = Some(line);
            break;
        }
        let t = line.text();
        if t.starts_with("@SQ") {
            refs = refs.saturating_add(1);
        } else if t.starts_with("@HD") {
            sort = t
                .split('\t')
                .find_map(|f| f.strip_prefix("SO:"))
                .unwrap_or_default()
                .to_owned();
        }
        header_end = lines.pos();
    }
    let header = file.sub(0, header_end);
    cx.emit(Node::new("Header").span(header).lazy(sam_header, header));
    cx.annotate(format!(
        "SAM, {refs} reference(s){}",
        if sort.is_empty() {
            String::new()
        } else {
            format!(", sorted by {sort}")
        }
    ));
    let mut count = 0u64;
    let mut next = first;
    while let Some(line) = next {
        if !line.bytes.is_empty() {
            let fields = line.split(b'\t');
            let get = |i: usize| fields.get(i).map_or("", |(s, _)| s.as_str());
            let mut node = Node::new(get(0).to_owned())
                .span(line.content())
                .summary(format!("{}:{} mapq {} {}", get(2), get(3), get(4), get(5)))
                .lazy(sam_record, line.clone());
            if fields.len() < 11 {
                node = node.diag(Diagnostic::malformed(format!(
                    "{} of 11 mandatory fields",
                    fields.len()
                )));
            }
            cx.push(node).await;
            count = count.saturating_add(1);
        }
        next = lines.next().await?;
    }
    cx.annotate(format!(
        "SAM, {refs} reference(s){}, {count} alignment(s)",
        if sort.is_empty() {
            String::new()
        } else {
            format!(", sorted by {sort}")
        }
    ));
    Ok(())
}

async fn sam_header(cx: Cx, span: Span) -> Result<()> {
    let mut lines = Lines::new(&cx, span);
    while let Some(line) = lines.next().await? {
        let fields = line.split(b'\t');
        let tag = fields.first().map_or(String::new(), |(s, _)| s.clone());
        let rest: Vec<&str> = fields.iter().skip(1).map(|(s, _)| s.as_str()).collect();
        let mut node = Node::new(tag)
            .span(line.content())
            .value(text(rest.join(" ")));
        if fields.len() > 2 {
            node = node.lazy(sam_tag_list, (line.clone(), 1usize, b':'));
        }
        cx.push(node).await;
    }
    Ok(())
}

/// `KEY:value` (header) or `TAG:TYPE:value` (alignment) fields of a line.
async fn sam_tag_list(cx: Cx, (line, skip, sep): (Line, usize, u8)) -> Result<()> {
    for (field, span) in line.split(b'\t').into_iter().skip(skip) {
        let mut parts = field.splitn(3, char::from(sep));
        let key = parts.next().unwrap_or_default().to_owned();
        let second = parts.next().unwrap_or_default();
        let node = match parts.next() {
            Some(value) => {
                let v = match second {
                    "i" => number(value),
                    "f" => number(value),
                    _ => text(value),
                };
                Node::new(key).value(v).desc(format!("type {second}"))
            }
            None => Node::new(key).value(text(second)),
        };
        cx.emit(node.span(span));
    }
    Ok(())
}

async fn sam_record(cx: Cx, line: Line) -> Result<()> {
    let fields = line.split(b'\t');
    for (i, (value, span)) in fields.iter().enumerate().take(11) {
        let name = SAM_COLUMNS.get(i).copied().unwrap_or("?");
        let v = match i {
            1 => value
                .parse::<u16>()
                .map_or_else(|_| text(value.as_str()), |f| flags(SAM_FLAGS, f.into(), 16)),
            3 | 4 | 7 | 8 => number(value),
            9 | 10 => text(preview(value, 200)),
            _ => text(value.as_str()),
        };
        let mut node = Node::new(name).span(*span).value(v);
        if i == 9 {
            node = node.summary(format!("{} bp", value.len()));
        }
        cx.emit(node);
    }
    if fields.len() > 11 {
        let start = fields.get(11).map_or(line.content(), |(_, s)| *s);
        cx.emit(
            Node::new("Tags")
                .span(
                    line.content()
                        .tail(start.offset.saturating_sub(line.span.offset)),
                )
                .lazy(sam_tag_list, (line.clone(), 11usize, b':')),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// VCF

declare_format!(pub VCF = "vcf", "Variant Call Format", ["vcf"], "text/x-vcf",
    Probe::Magic(&[(0, b"##fileformat=VCFv")]), vcf);

const VCF_COLUMNS: [&str; 9] = [
    "CHROM", "POS", "ID", "REF", "ALT", "QUAL", "FILTER", "INFO", "FORMAT",
];

async fn vcf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut meta_end = 0u64;
    let mut version = String::new();
    let mut contigs = 0u32;
    let mut samples: Vec<String> = Vec::new();
    let mut header_line = None;
    while let Some(line) = lines.next().await? {
        let t = line.text();
        if let Some(v) = t.strip_prefix("##fileformat=") {
            version = v.to_owned();
        }
        if t.starts_with("##contig=") {
            contigs = contigs.saturating_add(1);
        }
        if t.starts_with("#CHROM") {
            samples = t.split('\t').skip(9).map(str::to_owned).collect();
            header_line = Some(line);
            break;
        }
        if !t.starts_with("##") {
            break;
        }
        meta_end = lines.pos();
    }
    let meta = file.sub(0, meta_end);
    cx.emit(
        Node::new("Meta-information")
            .span(meta)
            .lazy(vcf_meta, meta),
    );
    if let Some(h) = &header_line {
        cx.emit(line_node("Header line", h).summary(format!("{} sample(s)", samples.len())));
    }
    let summary = format!(
        "{version}, {contigs} contig(s), {} sample(s)",
        samples.len()
    );
    cx.annotate(summary.clone());
    let mut count = 0u64;
    while let Some(line) = lines.next().await? {
        if line.bytes.is_empty() || line.bytes.starts_with(b"#") {
            continue;
        }
        let f = line.split(b'\t');
        let get = |i: usize| f.get(i).map_or("", |(s, _)| s.as_str());
        let id = get(2);
        cx.push(
            Node::new(format!("{}:{}", get(0), get(1)))
                .span(line.content())
                .value(text(if id == "." { "" } else { id }))
                .summary(format!(
                    "{}>{} qual {} {}",
                    preview(get(3), 20),
                    preview(get(4), 30),
                    get(5),
                    get(6)
                ))
                .lazy(vcf_record, (line.clone(), samples.clone())),
        )
        .await;
        count = count.saturating_add(1);
    }
    cx.annotate(format!("{summary}, {count} record(s)"));
    Ok(())
}

async fn vcf_meta(cx: Cx, span: Span) -> Result<()> {
    let mut lines = Lines::new(&cx, span);
    while let Some(line) = lines.next().await? {
        let t = line.text();
        let body = t.trim_start_matches('#');
        let (key, value) = body.split_once('=').unwrap_or((body, ""));
        let mut node = Node::new(key.to_owned()).span(line.content());
        if let Some(inner) = value.strip_prefix('<').and_then(|v| v.strip_suffix('>')) {
            let id = inner
                .split(',')
                .find_map(|kv| kv.strip_prefix("ID="))
                .unwrap_or_default();
            let desc = inner
                .split_once("Description=\"")
                .map(|(_, d)| d.split('"').next().unwrap_or_default())
                .unwrap_or_default();
            node = node.value(text(id)).desc(inner.to_owned());
            if !desc.is_empty() {
                node = node.summary(desc.to_owned());
            }
        } else {
            node = node.value(text(value));
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn vcf_record(cx: Cx, (line, samples): (Line, Vec<String>)) -> Result<()> {
    let fields = line.split(b'\t');
    for (i, (value, span)) in fields.iter().enumerate() {
        if let Some(&name) = VCF_COLUMNS.get(i) {
            let mut node = Node::new(name).span(*span);
            node = match i {
                1 | 5 => node.value(number(value)),
                7 => node
                    .value(text(preview(value, 120)))
                    .lazy(vcf_info, (value.clone(), *span)),
                _ => node.value(text(value.as_str())),
            };
            cx.emit(node);
        } else {
            let sample = samples
                .get(i.saturating_sub(9))
                .cloned()
                .unwrap_or_else(|| format!("Sample {}", i.saturating_sub(8)));
            let format = fields.get(8).map_or("", |(s, _)| s.as_str());
            let pairs: Vec<String> = format
                .split(':')
                .zip(value.split(':'))
                .map(|(k, v)| format!("{k}={v}"))
                .collect();
            cx.emit(
                Node::new(sample)
                    .span(*span)
                    .value(text(value.as_str()))
                    .summary(pairs.join(" ")),
            );
        }
    }
    Ok(())
}

async fn vcf_info(cx: Cx, (info, span): (String, Span)) -> Result<()> {
    let mut at = 0u64;
    for kv in info.split(';') {
        let len = to_u64(kv.len());
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        let node = Node::new(k.to_owned()).span(span.sub(at, len));
        cx.emit(if v.is_empty() {
            node.value(crate::value::Value::Bool(true))
        } else {
            node.value(number(v))
        });
        at = at.saturating_add(len).saturating_add(1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// GFF3

declare_format!(pub GFF3 = "gff3", "General Feature Format (GFF3)", ["gff3", "gff"], "text/x-gff3",
    Probe::Magic(&[(0, b"##gff-version 3"), (0, b"##gff-version\t3")]), gff3);

const GFF_COLUMNS: [&str; 9] = [
    "seqid",
    "source",
    "type",
    "start",
    "end",
    "score",
    "strand",
    "phase",
    "attributes",
];

fn unescape(s: &str) -> String {
    let mut out = Vec::new();
    let b = s.as_bytes();
    let mut i = 0usize;
    while let Some(&c) = b.get(i) {
        if c == b'%'
            && let Some(v) = b
                .get(i.saturating_add(1)..i.saturating_add(3))
                .and_then(|h| std::str::from_utf8(h).ok())
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(v);
            i = i.saturating_add(3);
            continue;
        }
        out.push(c);
        i = i.saturating_add(1);
    }
    String::from_utf8_lossy(&out).into_owned()
}

async fn gff3(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let (mut features, mut directives) = (0u64, 0u64);
    let mut types: Vec<(String, u64)> = Vec::new();
    while let Some(line) = lines.next().await? {
        let t = line.text();
        if t == "##FASTA" {
            let rest = file.tail(lines.pos());
            cx.emit(embedded_as("FASTA", input.nested(rest), &FASTA));
            break;
        }
        if t == "###" {
            cx.push(
                Node::new("###")
                    .span(line.content())
                    .summary("forward references resolved"),
            )
            .await;
            continue;
        }
        if t.starts_with("##") {
            let (k, v) = t
                .trim_start_matches('#')
                .split_once([' ', '\t'])
                .unwrap_or((t.trim_start_matches('#'), ""));
            cx.push(
                Node::new(format!("##{k}"))
                    .span(line.content())
                    .value(text(v.trim())),
            )
            .await;
            directives = directives.saturating_add(1);
            continue;
        }
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let f = line.split(b'\t');
        let get = |i: usize| f.get(i).map_or("", |(s, _)| s.as_str());
        let attrs = get(8);
        let label = attrs
            .split(';')
            .find_map(|a| a.strip_prefix("Name="))
            .or_else(|| attrs.split(';').find_map(|a| a.strip_prefix("ID=")))
            .map(unescape)
            .unwrap_or_default();
        let kind = get(2).to_owned();
        tally(&mut types, &kind, 64);
        let mut node = Node::new(format!("{kind} {}:{}-{}", get(0), get(3), get(4)))
            .span(line.content())
            .value(text(label))
            .lazy(gff_record, line.clone());
        if f.len() != 9 {
            node = node.diag(Diagnostic::malformed(format!("{} of 9 columns", f.len())));
        }
        cx.push(node).await;
        features = features.saturating_add(1);
    }
    let top: Vec<String> = types
        .iter()
        .take(5)
        .map(|(k, n)| format!("{n} {k}"))
        .collect();
    cx.annotate(format!(
        "GFF3, {features} feature(s){}, {directives} directive(s)",
        if top.is_empty() {
            String::new()
        } else {
            format!(" ({})", top.join(", "))
        }
    ));
    Ok(())
}

async fn gff_record(cx: Cx, line: Line) -> Result<()> {
    for (i, (value, span)) in line.split(b'\t').into_iter().enumerate() {
        let name = GFF_COLUMNS.get(i).copied().unwrap_or("extra");
        let node = Node::new(name).span(span);
        cx.emit(match i {
            3 | 4 | 5 | 7 => node.value(number(&value)),
            8 => node
                .value(text(preview(&value, 120)))
                .lazy(gff_attributes, (value, span)),
            _ => node.value(text(value)),
        });
    }
    Ok(())
}

async fn gff_attributes(cx: Cx, (attrs, span): (String, Span)) -> Result<()> {
    let mut at = 0u64;
    for kv in attrs.split(';') {
        let len = to_u64(kv.len());
        let (k, v) = kv.split_once(['=', ' ']).unwrap_or((kv, ""));
        if !k.trim().is_empty() {
            cx.emit(
                Node::new(unescape(k.trim()))
                    .span(span.sub(at, len))
                    .value(text(unescape(v.trim().trim_matches('"')))),
            );
        }
        at = at.saturating_add(len).saturating_add(1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// BED and WIG

/// Lines that may precede the data of a UCSC track file.
fn is_track_line(l: &[u8]) -> bool {
    l.starts_with(b"track ") || l.starts_with(b"browser ") || l.starts_with(b"#")
}

fn bed_data_line(l: &[u8]) -> bool {
    let f: Vec<&[u8]> = l.split(|&b| b == b'\t').collect();
    f.len() >= 3
        && f.get(1)
            .is_some_and(|x| !x.is_empty() && x.iter().all(u8::is_ascii_digit))
        && f.get(2)
            .is_some_and(|x| !x.is_empty() && x.iter().all(u8::is_ascii_digit))
}

fn wig_probe(h: &Head<'_>) -> bool {
    let lines = head_lines(h, 16);
    is_text(h)
        && lines
            .iter()
            .find(|l| !l.starts_with(b"browser ") && !l.starts_with(b"#"))
            .is_some_and(|l| {
                l.starts_with(b"variableStep ")
                    || l.starts_with(b"fixedStep ")
                    || (l.starts_with(b"track ")
                        && crate::formats::util::lines::contains(l, b"type=wiggle_0"))
            })
}

fn bed_probe(h: &Head<'_>) -> bool {
    let lines = head_lines(h, 16);
    is_text(h)
        && lines
            .first()
            .is_some_and(|l| l.starts_with(b"track ") || l.starts_with(b"browser "))
        && lines
            .iter()
            .find(|l| !is_track_line(l))
            .is_some_and(|l| bed_data_line(l))
}

declare_format!(pub WIG = "wig", "UCSC wiggle track", ["wig"], "text/x-wiggle",
    Probe::Custom(wig_probe), wig);
declare_format!(pub BED = "bed", "Browser Extensible Data (BED) track", ["bed"], "text/x-bed",
    Probe::Custom(bed_probe), bed);

const BED_COLUMNS: [&str; 12] = [
    "chrom",
    "chromStart",
    "chromEnd",
    "name",
    "score",
    "strand",
    "thickStart",
    "thickEnd",
    "itemRgb",
    "blockCount",
    "blockSizes",
    "blockStarts",
];

async fn bed(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let (mut features, mut tracks) = (0u64, 0u64);
    let mut columns = 0usize;
    while let Some(line) = lines.next().await? {
        if line.bytes.is_empty() {
            continue;
        }
        if is_track_line(&line.bytes) {
            let t = line.text();
            let (k, v) = t.split_once(' ').unwrap_or((t.as_str(), ""));
            if k == "track" {
                tracks = tracks.saturating_add(1);
            }
            let node = Node::new(k.to_owned()).span(line.content()).value(text(v));
            let settings_span = line.content().tail(to_u64(k.len()).saturating_add(1));
            cx.push(if k == "track" {
                node.lazy(track_settings, (v.to_owned(), settings_span))
            } else {
                node
            })
            .await;
            continue;
        }
        let f = line.split(b'\t');
        let get = |i: usize| f.get(i).map_or("", |(s, _)| s.as_str());
        columns = columns.max(f.len());
        cx.push(
            Node::new(format!("{}:{}-{}", get(0), get(1), get(2)))
                .span(line.content())
                .value(text(get(3)))
                .lazy(bed_record, line.clone()),
        )
        .await;
        features = features.saturating_add(1);
    }
    cx.annotate(format!(
        "BED{columns}, {features} feature(s), {tracks} track(s)"
    ));
    Ok(())
}

/// `key=value` settings of a track or step line (values may be quoted).
/// Returns `(key, value, start, end)` with byte offsets into `s`.
fn settings(s: &str) -> Vec<(String, String, usize, usize)> {
    let mut out = Vec::new();
    let mut rest = s.trim_start();
    while let Some((k, v)) = rest.split_once('=') {
        let start = s.len().saturating_sub(rest.len());
        let v = v.trim_start();
        let (value, tail) = if let Some(q) = v.strip_prefix('"') {
            q.split_once('"').unwrap_or((q, ""))
        } else {
            v.split_once(' ').unwrap_or((v, ""))
        };
        let end = s.len().saturating_sub(tail.len());
        out.push((k.trim().to_owned(), value.to_owned(), start, end));
        rest = tail.trim_start();
        if out.len() > 256 {
            break;
        }
    }
    out
}

async fn track_settings(cx: Cx, (s, span): (String, Span)) -> Result<()> {
    for (k, v, start, end) in settings(&s) {
        let len = end.saturating_sub(start);
        let len = if s.as_bytes().get(end.saturating_sub(1)) == Some(&b' ') {
            len.saturating_sub(1)
        } else {
            len
        };
        cx.emit(
            Node::new(k)
                .span(span.sub(to_u64(start), to_u64(len)))
                .value(text(v)),
        );
    }
    Ok(())
}

async fn bed_record(cx: Cx, line: Line) -> Result<()> {
    for (i, (value, span)) in line.split(b'\t').into_iter().enumerate() {
        let name = BED_COLUMNS.get(i).copied().unwrap_or("extra");
        cx.emit(
            Node::new(name)
                .span(span)
                .value(if matches!(i, 1 | 2 | 4 | 6 | 7 | 9) {
                    number(&value)
                } else {
                    text(value)
                }),
        );
    }
    Ok(())
}

async fn wig(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut sections = 0u64;
    let mut current: Option<(Line, u64)> = None;
    let mut total = 0u64;
    loop {
        let next = lines.next().await?;
        let starts_section = next.as_ref().is_none_or(|l| {
            l.bytes.starts_with(b"variableStep")
                || l.bytes.starts_with(b"fixedStep")
                || l.bytes.starts_with(b"track")
                || l.bytes.starts_with(b"browser")
        });
        if starts_section && let Some((decl, values)) = current.take() {
            let end = next.as_ref().map_or(lines.pos(), |l| l.pos);
            let t = decl.text();
            let (k, v) = t.split_once(' ').unwrap_or((t.as_str(), ""));
            let node = Node::new(k.to_owned())
                .span(file.sub(decl.pos, end.saturating_sub(decl.pos)))
                .value(text(v));
            let node = if k == "browser" {
                node
            } else {
                node.lazy(
                    track_settings,
                    (
                        v.to_owned(),
                        decl.content().tail(to_u64(k.len()).saturating_add(1)),
                    ),
                )
            };
            cx.push(if k == "track" || k == "browser" {
                node
            } else {
                node.summary(format!("{values} value(s)"))
            })
            .await;
            sections = sections.saturating_add(1);
        }
        let Some(line) = next else { break };
        if starts_section {
            current = Some((line, 0));
        } else if let Some((_, n)) = current.as_mut()
            && !line.bytes.is_empty()
        {
            *n = n.saturating_add(1);
            total = total.saturating_add(1);
        }
    }
    cx.annotate(format!(
        "Wiggle track, {sections} section(s), {total} value(s)"
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// GenBank flat file

declare_format!(pub GENBANK = "genbank", "GenBank flat file", ["gb", "gbk", "genbank", "gbff"], "text/x-genbank",
    Probe::Magic(&[(0, b"LOCUS       ")]), genbank);

async fn genbank(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut start = None;
    let mut locus = String::new();
    let mut count = 0u64;
    let mut first = String::new();
    while let Some(line) = lines.next().await? {
        let t = line.text();
        if t.starts_with("LOCUS") {
            start = Some(line.pos);
            locus = t.get(12..).unwrap_or_default().trim().to_owned();
        } else if t.starts_with("//")
            && let Some(s) = start.take()
        {
            let span = file.sub(s, lines.pos().saturating_sub(s));
            let words: Vec<&str> = locus.split_whitespace().collect();
            let name = words.first().copied().unwrap_or("record").to_owned();
            if first.is_empty() {
                first = format!(
                    "{name}, {}",
                    words.get(1..).map(|w| w.join(" ")).unwrap_or_default()
                );
            }
            cx.push(
                summarize(
                    Node::new(name).span(span),
                    words.get(1..).map(|w| w.join(" ")).unwrap_or_default(),
                )
                .lazy(genbank_record, span),
            )
            .await;
            count = count.saturating_add(1);
        }
    }
    if let Some(s) = start {
        cx.diag(Diagnostic::truncated(
            file.tail(s),
            file.len.saturating_sub(s),
        ));
    }
    cx.annotate(format!(
        "GenBank, {count} record(s){}",
        if first.is_empty() {
            String::new()
        } else {
            format!("; {first}")
        }
    ));
    Ok(())
}

/// Top-level keywords of one record, each with its continuation lines.
async fn genbank_record(cx: Cx, span: Span) -> Result<()> {
    let mut lines = Lines::new(&cx, span);
    let mut current: Option<(String, u64, String)> = None;
    loop {
        let next = lines.next().await?;
        let new_key = next.as_ref().is_none_or(|l| {
            l.bytes
                .first()
                .is_some_and(|b| b.is_ascii_uppercase() || *b == b'/')
        });
        if new_key && let Some((key, start, value)) = current.take() {
            let end = next.as_ref().map_or(lines.pos(), |l| l.pos);
            let s = span.sub(start, end.saturating_sub(start));
            let mut node = Node::new(key.clone()).span(s);
            node = match key.as_str() {
                "FEATURES" => node.lazy(genbank_features, s),
                "ORIGIN" => node.summary("sequence"),
                _ => node.value(text(preview(&value, 200))),
            };
            cx.push(node).await;
        }
        let Some(line) = next else { break };
        let t = line.text();
        if new_key {
            if t.starts_with("//") {
                break;
            }
            let key = t.get(..12).unwrap_or(&t).trim().to_owned();
            current = Some((
                key,
                line.pos,
                t.get(12..).unwrap_or_default().trim().to_owned(),
            ));
        } else if let Some((_, _, value)) = current.as_mut()
            && value.len() < 400
        {
            value.push(' ');
            value.push_str(t.trim());
        }
    }
    Ok(())
}

async fn genbank_features(cx: Cx, span: Span) -> Result<()> {
    let mut lines = Lines::new(&cx, span);
    let mut current: Option<(String, u64, String, Vec<String>)> = None;
    loop {
        let next = lines.next().await?;
        let new_feature = next.as_ref().is_none_or(|l| {
            l.bytes.get(5).is_some_and(|b| *b != b' ') && l.bytes.starts_with(b"     ")
        });
        if new_feature && let Some((key, start, location, quals)) = current.take() {
            let end = next.as_ref().map_or(lines.pos(), |l| l.pos);
            let label = quals
                .iter()
                .find_map(|q| {
                    q.strip_prefix("/gene=")
                        .or_else(|| q.strip_prefix("/product="))
                        .or_else(|| q.strip_prefix("/locus_tag="))
                })
                .map(|s| s.trim_matches('"').to_owned())
                .unwrap_or_default();
            let node = Node::new(key)
                .span(span.sub(start, end.saturating_sub(start)))
                .value(text(location));
            cx.push(summarize(node, label).lazy(genbank_qualifiers, quals))
                .await;
        }
        let Some(line) = next else { break };
        let t = line.text();
        if new_feature {
            current = Some((
                t.get(5..21).unwrap_or_default().trim().to_owned(),
                line.pos,
                t.get(21..).unwrap_or_default().trim().to_owned(),
                Vec::new(),
            ));
        } else if let Some((_, _, _, quals)) = current.as_mut() {
            let body = t.trim();
            if body.starts_with('/') || quals.is_empty() {
                if quals.len() < 256 {
                    quals.push(body.to_owned());
                }
            } else if let Some(last) = quals.last_mut()
                && last.len() < 1000
            {
                last.push(' ');
                last.push_str(body);
            }
        }
    }
    Ok(())
}

async fn genbank_qualifiers(cx: Cx, quals: Vec<String>) -> Result<()> {
    for q in quals {
        let (k, v) = q.trim_start_matches('/').split_once('=').map_or(
            (q.trim_start_matches('/').to_owned(), String::new()),
            |(k, v)| (k.to_owned(), v.trim_matches('"').to_owned()),
        );
        cx.emit(Node::new(k).value(text(preview(&v, 200))));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Multiple sequence alignments: Stockholm, Clustal, MAF

declare_format!(pub STOCKHOLM = "stockholm", "Stockholm multiple alignment", ["sto", "stk", "stockholm"], "text/x-stockholm",
    Probe::Magic(&[(0, b"# STOCKHOLM 1.")]), stockholm);

/// Sequences of an interleaved alignment: name, first span, aligned length.
struct Alignment {
    rows: Vec<(String, Span, u64)>,
}

impl Alignment {
    fn add(&mut self, name: &str, seq: &str, span: Span) {
        let len = to_u64(seq.len());
        if let Some(row) = self.rows.iter_mut().find(|(n, _, _)| n == name) {
            row.2 = row.2.saturating_add(len);
        } else if self.rows.len() < 100_000 {
            self.rows.push((name.to_owned(), span, len));
        }
    }

    async fn emit(&self, cx: &Cx) {
        for (name, span, len) in &self.rows {
            cx.push(
                Node::new(name.clone())
                    .span(*span)
                    .value(uint(*len))
                    .summary(format!("{len} columns")),
            )
            .await;
        }
    }
}

async fn alignment_rows(cx: Cx, rows: Vec<(String, Span, u64)>) -> Result<()> {
    Alignment { rows }.emit(&cx).await;
    Ok(())
}

async fn stockholm(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut aln = Alignment { rows: Vec::new() };
    let mut id = String::new();
    let mut alignments = 0u32;
    while let Some(line) = lines.next().await? {
        let t = line.text();
        if t.starts_with("# STOCKHOLM") {
            cx.emit(line_node("Header", &line));
        } else if let Some(rest) = t.strip_prefix("#=GF ") {
            let (k, v) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
            if k == "ID" && id.is_empty() {
                id = v.trim().to_owned();
            }
            cx.emit(
                Node::new(format!("GF {k}"))
                    .span(line.content())
                    .value(text(v.trim())),
            );
        } else if t.starts_with("#=") || t.trim().is_empty() || t.starts_with('#') {
            continue;
        } else if t.starts_with("//") {
            alignments = alignments.saturating_add(1);
        } else {
            let words = line.words();
            if let (Some((name, span)), Some((seq, _))) = (words.first(), words.get(1)) {
                aln.add(name, seq, *span);
            }
        }
    }
    let n = aln.rows.len();
    let width = aln.rows.first().map_or(0, |r| r.2);
    cx.emit(
        Node::new("Sequences")
            .value(uint(to_u64(n)))
            .lazy(alignment_rows, aln.rows),
    );
    cx.annotate(format!(
        "Stockholm alignment{}, {n} sequence(s) × {width} columns, {alignments} block(s)",
        if id.is_empty() {
            String::new()
        } else {
            format!(" {id}")
        }
    ));
    Ok(())
}

declare_format!(pub CLUSTAL = "clustal", "Clustal multiple alignment", ["aln", "clustal"], "text/x-clustal",
    Probe::Custom(|h| is_text(h) && (h.starts_with(b"CLUSTAL") || h.starts_with(b"MUSCLE (") || h.starts_with(b"PROBCONS"))), clustal);

async fn clustal(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut aln = Alignment { rows: Vec::new() };
    let mut header = String::new();
    let mut blocks = 0u32;
    let mut in_block = false;
    while let Some(line) = lines.next().await? {
        if line.pos == 0 {
            header = line.text();
            cx.emit(line_node("Header", &line));
            continue;
        }
        if line.bytes.first().is_none_or(|b| b.is_ascii_whitespace()) {
            // Blank lines separate blocks; indented lines are conservation marks.
            if line.bytes.iter().all(u8::is_ascii_whitespace) {
                in_block = false;
            }
            continue;
        }
        if !in_block {
            blocks = blocks.saturating_add(1);
            in_block = true;
        }
        let words = line.words();
        if let (Some((name, span)), Some((seq, _))) = (words.first(), words.get(1)) {
            aln.add(name, seq, *span);
        }
    }
    let n = aln.rows.len();
    let width = aln.rows.first().map_or(0, |r| r.2);
    cx.emit(
        Node::new("Sequences")
            .value(uint(to_u64(n)))
            .lazy(alignment_rows, aln.rows),
    );
    cx.annotate(format!(
        "{}, {n} sequence(s) × {width} columns in {blocks} block(s)",
        preview(&header, 40)
    ));
    Ok(())
}

declare_format!(pub MAF = "maf", "Multiple Alignment Format (MAF)", ["maf"], "text/x-maf",
    Probe::Magic(&[(0, b"##maf version=")]), maf);

async fn maf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut current: Option<(Line, Vec<Line>)> = None;
    let mut blocks = 0u64;
    loop {
        let next = lines.next().await?;
        let ends = next
            .as_ref()
            .is_none_or(|l| l.bytes.is_empty() || l.bytes.starts_with(b"a"));
        if ends && let Some((a, rows)) = current.take() {
            let end = rows.last().map_or(a.span.end(), |r| r.span.end());
            let span = file.sub(a.pos, end.saturating_sub(a.span.offset));
            let species: Vec<String> = rows
                .iter()
                .filter(|r| r.bytes.starts_with(b"s "))
                .filter_map(|r| r.words().get(1).map(|(s, _)| s.clone()))
                .collect();
            let node = Node::new(format!("Block {blocks}"))
                .span(span)
                .value(text(a.text().trim_start_matches('a').trim()));
            cx.push(summarize(node, preview(&species.join(", "), 100)).lazy(maf_block, rows))
                .await;
            blocks = blocks.saturating_add(1);
        }
        let Some(line) = next else { break };
        if line.bytes.starts_with(b"##") {
            cx.push(line_node("Header", &line)).await;
        } else if line.bytes.starts_with(b"a") {
            current = Some((line, Vec::new()));
        } else if let Some((_, rows)) = current.as_mut()
            && !line.bytes.is_empty()
            && rows.len() < 10_000
        {
            rows.push(line);
        }
    }
    cx.annotate(format!("MAF, {blocks} alignment block(s)"));
    Ok(())
}

const MAF_S: [&str; 7] = ["", "src", "start", "size", "strand", "srcSize", "text"];

async fn maf_block(cx: Cx, rows: Vec<Line>) -> Result<()> {
    for row in rows {
        let words = row.words();
        let kind = words.first().map_or(String::new(), |(w, _)| w.clone());
        let src = words.get(1).map_or(String::new(), |(w, _)| w.clone());
        let node = Node::new(format!("{kind} {src}")).span(row.content());
        if kind == "s" {
            cx.emit(
                node.summary(format!(
                    "{}+{} ({})",
                    words.get(2).map_or("", |w| w.0.as_str()),
                    words.get(3).map_or("", |w| w.0.as_str()),
                    words.get(4).map_or("", |w| w.0.as_str())
                ))
                .lazy(maf_row, row),
            );
        } else {
            cx.emit(node.value(text(row.text())));
        }
    }
    Ok(())
}

async fn maf_row(cx: Cx, row: Line) -> Result<()> {
    for (i, (w, span)) in row.words().into_iter().enumerate().skip(1) {
        let name = MAF_S.get(i).copied().unwrap_or("extra");
        cx.emit(Node::new(name).span(span).value(if matches!(i, 2 | 3 | 5) {
            number(&w)
        } else {
            text(preview(&w, 200))
        }));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// NEXUS

declare_format!(pub NEXUS = "nexus", "NEXUS phylogenetic data", ["nex", "nexus", "nxs"], "text/x-nexus",
    Probe::Custom(|h| h.data.get(..6).is_some_and(|m| m.eq_ignore_ascii_case(b"#NEXUS"))), nexus);

async fn nexus(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    // The open block: name, start, and its commands.
    type Block = (String, u64, Vec<(String, Span)>);
    let mut current: Option<Block> = None;
    let mut names = Vec::new();
    while let Some(line) = lines.next().await? {
        let t = line.text();
        let upper = t.trim().to_ascii_uppercase();
        if let Some(rest) = upper.strip_prefix("BEGIN ") {
            let name = rest.trim_end_matches(';').trim().to_owned();
            current = Some((name, line.pos, Vec::new()));
        } else if (upper.starts_with("END;") || upper.starts_with("ENDBLOCK;"))
            && let Some((name, start, commands)) = current.take()
        {
            let span = file.sub(start, lines.pos().saturating_sub(start));
            names.push(name.clone());
            cx.push(
                Node::new(format!("BEGIN {name}"))
                    .span(span)
                    .summary(format!("{} command(s)", commands.len()))
                    .lazy(nexus_commands, commands),
            )
            .await;
        } else if let Some((_, _, commands)) = current.as_mut() {
            let word = t.split_whitespace().next().unwrap_or_default();
            if !word.is_empty()
                && word.chars().all(|c| c.is_ascii_alphabetic())
                && commands.len() < 10_000
            {
                commands.push((t.trim().to_owned(), line.content()));
            }
        } else if line.pos == 0 {
            cx.emit(line_node("Header", &line));
        }
    }
    cx.annotate(format!("NEXUS, block(s): {}", names.join(", ")));
    Ok(())
}

async fn nexus_commands(cx: Cx, commands: Vec<(String, Span)>) -> Result<()> {
    for (c, span) in commands {
        let (k, v) = c
            .split_once(char::is_whitespace)
            .unwrap_or((c.as_str(), ""));
        cx.push(
            Node::new(k.to_ascii_uppercase())
                .span(span)
                .value(text(preview(v.trim_end_matches(';'), 200))),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// GFA (assembly graphs)

declare_format!(pub GFA = "gfa", "Graphical Fragment Assembly (GFA)", ["gfa"], "text/x-gfa",
    Probe::Magic(&[(0, b"H\tVN:Z:1."), (0, b"H\tVN:Z:2.")]), gfa);

const GFA_KINDS: &[(&str, &str)] = &[
    ("H", "Header"),
    ("S", "Segment"),
    ("L", "Link"),
    ("C", "Containment"),
    ("P", "Path"),
    ("W", "Walk"),
    ("J", "Jump"),
    ("E", "Edge"),
    ("F", "Fragment"),
    ("G", "Gap"),
    ("O", "Ordered group"),
    ("U", "Unordered group"),
    ("#", "Comment"),
];

async fn gfa(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut counts: Vec<(String, u64)> = Vec::new();
    while let Some(line) = lines.next().await? {
        if line.bytes.is_empty() {
            continue;
        }
        let f = line.split(b'\t');
        let kind = f.first().map_or("", |(s, _)| s.as_str());
        let name = GFA_KINDS
            .iter()
            .find(|(k, _)| *k == kind)
            .map_or("Record", |(_, n)| n);
        tally(&mut counts, name, 64);
        let get = |i: usize| f.get(i).map_or("", |(s, _)| s.as_str());
        let label = match kind {
            "S" => format!("{} ({} bp)", get(1), get(2).len()),
            "L" => format!("{}{} → {}{}", get(1), get(2), get(3), get(4)),
            "P" | "W" => get(1).to_owned(),
            _ => preview(&line.text(), 60),
        };
        cx.push(
            Node::new(name)
                .span(line.content())
                .value(text(label))
                .lazy(gfa_record, line.clone()),
        )
        .await;
    }
    let parts: Vec<String> = counts
        .iter()
        .map(|(k, n)| format!("{n} {}", k.to_lowercase()))
        .collect();
    cx.annotate(format!("GFA, {}", parts.join(", ")));
    Ok(())
}

/// Names of the positional fields of GFA 1 records.
const GFA_FIELDS: &[(&str, &[&str])] = &[
    ("S", &["Name", "Sequence"]),
    (
        "L",
        &[
            "From",
            "From orientation",
            "To",
            "To orientation",
            "Overlap",
        ],
    ),
    (
        "C",
        &[
            "Container",
            "Container orientation",
            "Contained",
            "Contained orientation",
            "Position",
            "Overlap",
        ],
    ),
    ("P", &["Path name", "Segments", "Overlaps"]),
    (
        "W",
        &["Sample", "Haplotype", "Sequence", "Start", "End", "Walk"],
    ),
];

async fn gfa_record(cx: Cx, line: Line) -> Result<()> {
    let fields = line.split(b'\t');
    let kind = fields.first().map_or("", |(k, _)| k.as_str());
    let names = GFA_FIELDS
        .iter()
        .find(|(k, _)| *k == kind)
        .map_or(&[][..], |(_, n)| n);
    for (i, (value, span)) in fields.iter().cloned().enumerate().skip(1) {
        if let Some(name) = names.get(i.saturating_sub(1)) {
            cx.emit(
                Node::new(*name)
                    .span(span)
                    .value(text(preview(&value, 200))),
            );
            continue;
        }
        let mut parts = value.splitn(3, ':');
        let (a, b, c) = (parts.next(), parts.next(), parts.next());
        let node = match (a, b, c) {
            (Some(tag), Some(kind), Some(v)) if tag.len() == 2 && kind.len() == 1 => {
                Node::new(tag.to_owned()).value(if kind == "i" || kind == "f" {
                    number(v)
                } else {
                    text(v)
                })
            }
            _ => Node::new(format!("Field {i}")).value(text(preview(&value, 200))),
        };
        cx.emit(node.span(span));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Protein Data Bank (PDB) coordinate files

const PDB_RECORDS: &[&str] = &[
    "HEADER", "OBSLTE", "TITLE ", "SPLIT ", "CAVEAT", "COMPND", "SOURCE", "KEYWDS", "EXPDTA",
    "NUMMDL", "MDLTYP", "AUTHOR", "REVDAT", "SPRSDE", "JRNL  ", "REMARK", "DBREF ", "SEQRES",
    "CRYST1", "ORIGX1", "SCALE1", "MODEL ", "ATOM  ", "HETATM",
];

fn pdb_probe(h: &Head<'_>) -> bool {
    let lines = head_lines(h, 3);
    is_text(h)
        && lines
            .first()
            .is_some_and(|l| l.starts_with(b"HEADER    ") || l.starts_with(b"CRYST1 "))
        && lines.iter().all(|l| l.len() <= 80)
        && lines
            .get(1)
            .is_some_and(|l| PDB_RECORDS.iter().any(|r| l.starts_with(r.as_bytes())))
}

declare_format!(pub PDB_STRUCTURE = "pdb-structure", "Protein Data Bank structure", ["pdb", "ent"], "chemical/x-pdb",
    Probe::Custom(pdb_probe), pdb_structure);

async fn pdb_structure(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let (mut id, mut classification, mut title) = (String::new(), String::new(), String::new());
    let (mut atoms, mut hetatms, mut models) = (0u64, 0u64, 0u64);
    let mut chains: Vec<char> = Vec::new();
    // Sections: title (before coordinates), coordinates, connectivity/bookkeeping.
    let (mut coords_start, mut coords_end) = (None, 0u64);
    while let Some(line) = lines.next().await? {
        let record = line.column(0, 6);
        match record.as_str() {
            "HEADER" => {
                classification = line.column(10, 50);
                id = line.column(62, 66);
            }
            "TITLE" if title.len() < 200 => {
                title.push(' ');
                title.push_str(&line.column(10, 80));
            }
            "ATOM" | "HETATM" => {
                if record == "ATOM" {
                    atoms = atoms.saturating_add(1);
                } else {
                    hetatms = hetatms.saturating_add(1);
                }
                let chain = line.bytes.get(21).map_or(' ', |&c| char::from(c));
                if !chains.contains(&chain) && chains.len() < 1000 {
                    chains.push(chain);
                }
            }
            "MODEL" => models = models.saturating_add(1),
            _ => {}
        }
        if matches!(
            record.as_str(),
            "MODEL" | "ATOM" | "HETATM" | "TER" | "ENDMDL" | "ANISOU"
        ) {
            coords_start.get_or_insert(line.pos);
            coords_end = lines.pos();
        }
    }
    let start = coords_start.unwrap_or(lines.pos());
    let sections = [
        ("Title and annotation", 0u64, start),
        ("Coordinates", start, coords_end.max(start)),
        (
            "Connectivity and bookkeeping",
            coords_end.max(start),
            lines.pos(),
        ),
    ];
    for (name, from, to) in sections {
        if to > from {
            let span = file.sub(from, to.saturating_sub(from));
            cx.emit(Node::new(name).span(span).lazy(pdb_section, span));
        }
    }
    let chain_list: String = chains.iter().filter(|c| **c != ' ').collect();
    cx.annotate(format!(
        "PDB {}{}: {atoms} atom(s), {hetatms} hetero atom(s){}{}",
        if id.is_empty() {
            "entry".to_owned()
        } else {
            id
        },
        if classification.is_empty() {
            String::new()
        } else {
            format!(" ({})", classification.to_lowercase())
        },
        if chain_list.is_empty() {
            String::new()
        } else {
            format!(", chains {chain_list}")
        },
        if models > 1 {
            format!(", {models} models")
        } else {
            String::new()
        }
    ));
    if !title.is_empty() {
        cx.emit(Node::new("Title").value(text(title.trim())));
    }
    Ok(())
}

async fn pdb_section(cx: Cx, span: Span) -> Result<()> {
    let mut lines = Lines::new(&cx, span);
    while let Some(line) = lines.next().await? {
        let record = line.column(0, 6);
        if record.is_empty() {
            continue;
        }
        let node = Node::new(record.clone()).span(line.content());
        let node = match record.as_str() {
            "ATOM" | "HETATM" => node
                .value(text(format!(
                    "{} {} {}{}",
                    line.column(12, 16),
                    line.column(17, 20),
                    line.column(21, 22),
                    line.column(22, 26)
                )))
                .summary(format!(
                    "({}, {}, {})",
                    line.column(30, 38),
                    line.column(38, 46),
                    line.column(46, 54)
                ))
                .lazy(pdb_atom, line.clone()),
            "HEADER" => node
                .value(text(line.column(10, 50)))
                .lazy(pdb_header, line.clone()),
            "CRYST1" => node
                .value(text(line.column(6, 70)))
                .lazy(pdb_cryst1, line.clone()),
            _ => node.value(text(line.column(6, 80))),
        };
        cx.push(node).await;
    }
    Ok(())
}

/// Emits fixed columns of a line: `(name, from, to, numeric)`.
fn pdb_columns(cx: &Cx, line: &Line, columns: &[(&'static str, usize, usize, bool)]) {
    for &(name, from, to, numeric) in columns {
        let v = line.column(from, to);
        let span = line.sub(
            from,
            to.saturating_sub(from)
                .min(line.bytes.len().saturating_sub(from)),
        );
        cx.emit(
            Node::new(name)
                .span(span)
                .value(if numeric && !v.is_empty() {
                    number(&v)
                } else {
                    text(v)
                }),
        );
    }
}

async fn pdb_atom(cx: Cx, line: Line) -> Result<()> {
    pdb_columns(
        &cx,
        &line,
        &[
            ("serial", 6, 11, true),
            ("name", 12, 16, false),
            ("altLoc", 16, 17, false),
            ("resName", 17, 20, false),
            ("chainID", 21, 22, false),
            ("resSeq", 22, 26, true),
            ("iCode", 26, 27, false),
            ("x", 30, 38, true),
            ("y", 38, 46, true),
            ("z", 46, 54, true),
            ("occupancy", 54, 60, true),
            ("tempFactor", 60, 66, true),
            ("element", 76, 78, false),
            ("charge", 78, 80, false),
        ],
    );
    Ok(())
}

async fn pdb_header(cx: Cx, line: Line) -> Result<()> {
    pdb_columns(
        &cx,
        &line,
        &[
            ("classification", 10, 50, false),
            ("depDate", 50, 59, false),
            ("idCode", 62, 66, false),
        ],
    );
    Ok(())
}

async fn pdb_cryst1(cx: Cx, line: Line) -> Result<()> {
    pdb_columns(
        &cx,
        &line,
        &[
            ("a", 6, 15, true),
            ("b", 15, 24, true),
            ("c", 24, 33, true),
            ("alpha", 33, 40, true),
            ("beta", 40, 47, true),
            ("gamma", 47, 54, true),
            ("sGroup", 55, 66, false),
            ("z", 66, 70, true),
        ],
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// CIF / mmCIF

fn cif_probe(h: &Head<'_>) -> bool {
    if !is_text(h) {
        return false;
    }
    let first = head_lines(h, 64)
        .into_iter()
        .find(|l| !l.is_empty() && !(l.starts_with(b"#") && !l.starts_with(b"#\\#CIF")));
    (h.starts_with(b"#\\#CIF_") || first.is_some_and(|l| l.starts_with(b"data_")))
        && h.data.windows(2).any(|w| w == b"\n_")
}

declare_format!(pub CIF = "cif", "Crystallographic Information File (CIF/mmCIF)", ["cif", "mmcif", "mcif"], "chemical/x-cif",
    Probe::Custom(cif_probe), cif);

/// Splits CIF values: whitespace-separated, with quoted strings.
fn cif_tokens(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = s.trim_start();
    while !rest.is_empty() {
        let (tok, tail) = match rest.chars().next() {
            Some(q @ ('\'' | '"')) => {
                let body = rest.get(1..).unwrap_or_default();
                // A closing quote must be followed by whitespace or the end.
                let mut end = None;
                for (i, c) in body.char_indices() {
                    if c == q
                        && body
                            .get(i.saturating_add(1)..)
                            .is_none_or(|t| t.is_empty() || t.starts_with(char::is_whitespace))
                    {
                        end = Some(i);
                        break;
                    }
                }
                match end {
                    Some(i) => (
                        body.get(..i).unwrap_or_default(),
                        body.get(i.saturating_add(1)..).unwrap_or_default(),
                    ),
                    None => (body, ""),
                }
            }
            _ => rest.split_once(char::is_whitespace).unwrap_or((rest, "")),
        };
        out.push(tok.to_owned());
        rest = tail.trim_start();
    }
    out
}

/// One data item or loop of a CIF data block.
#[derive(Clone, Debug)]
enum CifEntry {
    Item {
        name: String,
        value: String,
        span: Span,
    },
    Loop {
        columns: Vec<String>,
        rows: u64,
        span: Span,
    },
}

async fn cif(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut block: Option<(String, u64, Vec<CifEntry>)> = None;
    let mut blocks = Vec::new();
    // Loop state: columns, values seen, start.
    let mut lp: Option<(Vec<String>, u64, u64, bool)> = None;
    let mut pending: Option<(String, Span)> = None;
    let mut in_text: Option<(String, Span, String)> = None;
    let mut first_block = String::new();
    let flush_loop = |lp: &mut Option<(Vec<String>, u64, u64, bool)>,
                      block: &mut Option<(String, u64, Vec<CifEntry>)>,
                      end: u64| {
        if let (Some((columns, values, start, _)), Some((_, _, entries))) =
            (lp.take(), block.as_mut())
        {
            let rows = values.checked_div(to_u64(columns.len())).unwrap_or(0);
            entries.push(CifEntry::Loop {
                columns,
                rows,
                span: file.sub(start, end.saturating_sub(start)),
            });
        }
    };
    loop {
        let next = lines.next().await?;
        let Some(line) = next else {
            flush_loop(&mut lp, &mut block, lines.pos());
            if let Some(b) = block.take() {
                blocks.push(b);
            }
            break;
        };
        let t = line.text();
        // Semicolon-delimited text fields.
        if let Some((name, span, value)) = in_text.as_mut() {
            if t.starts_with(';') {
                let full = file.sub(
                    span.offset.saturating_sub(file.offset),
                    lines
                        .pos()
                        .saturating_sub(span.offset.saturating_sub(file.offset)),
                );
                if let Some((_, _, entries)) = block.as_mut() {
                    if name.is_empty() {
                        if let Some((_, values, _, _)) = lp.as_mut() {
                            *values = values.saturating_add(1);
                        }
                    } else {
                        entries.push(CifEntry::Item {
                            name: name.clone(),
                            value: value.trim().to_owned(),
                            span: full,
                        });
                    }
                }
                in_text = None;
            } else if value.len() < 200 {
                value.push(' ');
                value.push_str(t.trim());
            }
            continue;
        }
        if let Some(rest) = t.strip_prefix(';') {
            let name = pending.take().map(|(n, _)| n).unwrap_or_default();
            in_text = Some((name, line.content(), rest.to_owned()));
            continue;
        }
        let trimmed = t.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(name) = trimmed.strip_prefix("data_") {
            flush_loop(&mut lp, &mut block, line.pos);
            if let Some(b) = block.take() {
                blocks.push(b);
            }
            if first_block.is_empty() {
                first_block = name.to_owned();
            }
            block = Some((name.to_owned(), line.pos, Vec::new()));
            continue;
        }
        if trimmed.eq_ignore_ascii_case("loop_") {
            flush_loop(&mut lp, &mut block, line.pos);
            lp = Some((Vec::new(), 0, line.pos, true));
            continue;
        }
        if let Some((columns, values, _, header)) = lp.as_mut() {
            if trimmed.starts_with('_') && *header {
                if columns.len() < 4096 {
                    columns.push(
                        trimmed
                            .split_whitespace()
                            .next()
                            .unwrap_or_default()
                            .to_owned(),
                    );
                }
                continue;
            }
            if !trimmed.starts_with('_') {
                *header = false;
                *values = values.saturating_add(to_u64(cif_tokens(trimmed).len()));
                continue;
            }
            flush_loop(&mut lp, &mut block, line.pos);
        }
        if trimmed.starts_with('_') {
            let tokens = cif_tokens(trimmed);
            let name = tokens.first().cloned().unwrap_or_default();
            if let Some(value) = tokens.get(1) {
                if let Some((_, _, entries)) = block.as_mut() {
                    entries.push(CifEntry::Item {
                        name,
                        value: value.clone(),
                        span: line.content(),
                    });
                }
            } else {
                pending = Some((name, line.content()));
            }
        } else if let Some((name, span)) = pending.take()
            && let Some((_, _, entries)) = block.as_mut()
        {
            let value = cif_tokens(trimmed).into_iter().next().unwrap_or_default();
            entries.push(CifEntry::Item {
                name,
                value,
                span: span.sub(0, line.span.end().saturating_sub(span.offset)),
            });
        }
        if blocks.len() > 10_000 {
            break;
        }
    }
    let count = blocks.len();
    for (name, start, entries) in blocks {
        let end = entries
            .iter()
            .map(|e| match e {
                CifEntry::Item { span, .. } | CifEntry::Loop { span, .. } => span.end(),
            })
            .max()
            .unwrap_or(file.offset);
        let span = file.sub(start, end.saturating_sub(file.offset).saturating_sub(start));
        let n = entries.len();
        cx.push(
            Node::new(format!("data_{name}"))
                .span(span)
                .summary(format!("{n} item(s)/loop(s)"))
                .lazy(cif_block, entries),
        )
        .await;
    }
    cx.annotate(format!(
        "CIF, {count} data block(s){}",
        if first_block.is_empty() {
            String::new()
        } else {
            format!(", first {first_block}")
        }
    ));
    Ok(())
}

async fn cif_block(cx: Cx, entries: Vec<CifEntry>) -> Result<()> {
    for e in entries {
        match e {
            CifEntry::Item { name, value, span } => {
                cx.push(Node::new(name).span(span).value(number(&value)))
                    .await
            }
            CifEntry::Loop {
                columns,
                rows,
                span,
            } => {
                let category = columns
                    .first()
                    .and_then(|c| c.split('.').next())
                    .unwrap_or("loop")
                    .to_owned();
                cx.push(
                    Node::new(format!("loop_ {category}"))
                        .span(span)
                        .value(uint(rows))
                        .summary(format!("{rows} row(s) × {} column(s)", columns.len()))
                        .lazy(cif_columns, columns),
                )
                .await;
            }
        }
    }
    Ok(())
}

async fn cif_columns(cx: Cx, columns: Vec<String>) -> Result<()> {
    for (i, c) in columns.into_iter().enumerate() {
        cx.push(Node::new(format!("Column {i}")).value(text(c)))
            .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// MDL molfile and SDF

fn molfile_counts(h: &Head<'_>) -> bool {
    head_lines(h, 4).get(3).is_some_and(|l| {
        let t = String::from_utf8_lossy(l);
        let t = t.trim_end();
        (t.ends_with("V2000") || t.ends_with("V3000"))
            && t.len() >= 39
            && t.get(..6)
                .is_some_and(|c| c.chars().all(|ch| ch.is_ascii_digit() || ch == ' '))
    })
}

fn is_sdf(h: &Head<'_>) -> bool {
    h.data.windows(5).any(|w| w == b"\n$$$$")
}

declare_format!(pub SDF = "mdl-sdf", "MDL structure-data file (SDF)", ["sdf", "sd"], "chemical/x-mdl-sdfile",
    Probe::Custom(|h| is_text(h) && molfile_counts(h) && is_sdf(h)), sdf);
declare_format!(pub MOLFILE = "mdl-mol", "MDL molfile", ["mol"], "chemical/x-mdl-molfile",
    Probe::Custom(|h| is_text(h) && molfile_counts(h) && !is_sdf(h)), molfile);

const BOND_TYPES: &[&str] = &[
    "",
    "single",
    "double",
    "triple",
    "aromatic",
    "single or double",
    "single or aromatic",
    "double or aromatic",
    "any",
];

/// What the counts line and blocks of one molfile say.
struct Molecule {
    name: String,
    atoms: u64,
    bonds: u64,
    formula: String,
}

/// Emits the parts of a molfile in `span`; returns a summary.
async fn molfile_body(cx: &Cx, span: Span, emit: bool) -> Result<Molecule> {
    let mut lines = Lines::new(cx, span);
    let mut mol = Molecule {
        name: String::new(),
        atoms: 0,
        bonds: 0,
        formula: String::new(),
    };
    let mut elements: Vec<(String, u64)> = Vec::new();
    let mut index = 0u64;
    let (mut atoms_left, mut bonds_left) = (0u64, 0u64);
    let mut v3000_section = String::new();
    let mut v3000 = false;
    while let Some(line) = lines.next().await? {
        let t = line.text();
        let push = |node: Node| async move {
            if emit {
                cx.push(node).await;
            }
        };
        match index {
            0 => {
                mol.name = t.trim().to_owned();
                push(line_node("Molecule name", &line)).await;
            }
            1 => push(line_node("Program/timestamp", &line).summary(line.column(2, 10))).await,
            2 => push(line_node("Comment", &line)).await,
            3 => {
                v3000 = t.trim_end().ends_with("V3000");
                mol.atoms = line.column(0, 3).parse().unwrap_or(0);
                mol.bonds = line.column(3, 6).parse().unwrap_or(0);
                atoms_left = if v3000 { 0 } else { mol.atoms };
                bonds_left = if v3000 { 0 } else { mol.bonds };
                push(line_node("Counts line", &line).summary(format!(
                    "{} atoms, {} bonds, {}",
                    mol.atoms,
                    mol.bonds,
                    if v3000 { "V3000" } else { "V2000" }
                )))
                .await;
            }
            _ if t.starts_with("M  END") => {
                push(line_node("End", &line)).await;
                break;
            }
            _ if atoms_left > 0 => {
                atoms_left = atoms_left.saturating_sub(1);
                let symbol = line.column(31, 34);
                tally(&mut elements, &symbol, 200);
                push(
                    Node::new(format!("Atom {}", mol.atoms.saturating_sub(atoms_left)))
                        .span(line.content())
                        .value(text(symbol))
                        .summary(format!(
                            "({}, {}, {})",
                            line.column(0, 10),
                            line.column(10, 20),
                            line.column(20, 30)
                        )),
                )
                .await;
            }
            _ if bonds_left > 0 => {
                bonds_left = bonds_left.saturating_sub(1);
                let kind: usize = line.column(6, 9).parse().unwrap_or(0);
                push(
                    Node::new(format!("Bond {}", mol.bonds.saturating_sub(bonds_left)))
                        .span(line.content())
                        .value(text(format!("{}–{}", line.column(0, 3), line.column(3, 6))))
                        .summary(BOND_TYPES.get(kind).copied().unwrap_or("?").to_owned()),
                )
                .await;
            }
            _ if v3000 && t.starts_with("M  V30 ") => {
                let body = t.get(7..).unwrap_or_default().trim();
                if let Some(s) = body.strip_prefix("BEGIN ") {
                    v3000_section = s.to_owned();
                } else if body.starts_with("END ") {
                    v3000_section.clear();
                } else if let Some(c) = body.strip_prefix("COUNTS ") {
                    let n: Vec<u64> = c
                        .split_whitespace()
                        .filter_map(|x| x.parse().ok())
                        .collect();
                    mol.atoms = n.first().copied().unwrap_or(0);
                    mol.bonds = n.get(1).copied().unwrap_or(0);
                } else if v3000_section == "ATOM" {
                    let symbol = body
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or_default()
                        .to_owned();
                    tally(&mut elements, &symbol, 200);
                }
                push(
                    Node::new(if v3000_section.is_empty() {
                        "V30"
                    } else {
                        "V30 entry"
                    })
                    .span(line.content())
                    .value(text(body)),
                )
                .await;
            }
            _ => {
                let key = line.column(0, 6);
                push(
                    Node::new(if key.is_empty() {
                        "Line".to_owned()
                    } else {
                        key
                    })
                    .span(line.content())
                    .value(text(line.column(6, 200))),
                )
                .await;
            }
        }
        index = index.saturating_add(1);
    }
    // Hill order: C, H, then alphabetical.
    elements.sort_by(|a, b| {
        let rank = |e: &str| match e {
            "C" => 0,
            "H" => 1,
            _ => 2,
        };
        rank(&a.0).cmp(&rank(&b.0)).then(a.0.cmp(&b.0))
    });
    mol.formula = elements
        .iter()
        .map(|(e, n)| {
            if *n == 1 {
                e.clone()
            } else {
                format!("{e}{n}")
            }
        })
        .collect();
    Ok(mol)
}

async fn molfile(cx: Cx, input: Input) -> Result<()> {
    let mol = molfile_body(&cx, input.span, true).await?;
    cx.annotate(format!(
        "MDL molfile {:?}, {}, {} atom(s), {} bond(s)",
        mol.name, mol.formula, mol.atoms, mol.bonds
    ));
    Ok(())
}

async fn sdf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut start = 0u64;
    let mut count = 0u64;
    let mut mol_end = None;
    while let Some(line) = lines.next().await? {
        if line.bytes.starts_with(b"M  END") {
            mol_end = Some(lines.pos());
        }
        if line.bytes.starts_with(b"$$$$") {
            let span = file.sub(start, lines.pos().saturating_sub(start));
            let mol = file.sub(start, mol_end.unwrap_or(line.pos).saturating_sub(start));
            let data = file.sub(
                mol.end().saturating_sub(file.offset),
                line.pos
                    .saturating_sub(mol.end().saturating_sub(file.offset)),
            );
            let summary = molfile_body(&cx, mol, false).await?;
            cx.push(
                Node::new(if summary.name.is_empty() {
                    format!("Record {count}")
                } else {
                    summary.name.clone()
                })
                .span(span)
                .value(text(summary.formula.clone()))
                .summary(format!(
                    "{} atom(s), {} bond(s)",
                    summary.atoms, summary.bonds
                ))
                .lazy(sdf_record, (mol, data)),
            )
            .await;
            count = count.saturating_add(1);
            start = lines.pos();
            mol_end = None;
        }
    }
    if start < lines.pos() {
        cx.diag(Diagnostic::malformed("trailing record without $$$$").at(file.tail(start)));
    }
    cx.set_count(Count::Exact(count));
    cx.annotate(format!("SDF, {count} molecule(s)"));
    Ok(())
}

async fn sdf_record(cx: Cx, (mol, data): (Span, Span)) -> Result<()> {
    cx.emit(Node::new("Molfile").span(mol).lazy(sdf_molfile, mol));
    let mut lines = Lines::new(&cx, data);
    let mut current: Option<(String, u64, Vec<String>)> = None;
    loop {
        let next = lines.next().await?;
        let starts = next.as_ref().is_none_or(|l| l.bytes.starts_with(b">"));
        if starts && let Some((name, s, values)) = current.take() {
            let end = next.as_ref().map_or(lines.pos(), |l| l.pos);
            cx.push(
                Node::new(name)
                    .span(data.sub(s, end.saturating_sub(s)))
                    .value(number(&values.join("\n"))),
            )
            .await;
        }
        let Some(line) = next else { break };
        let t = line.text();
        if starts {
            let name = t
                .split_once('<')
                .and_then(|(_, r)| r.split_once('>'))
                .map_or_else(|| t.clone(), |(n, _)| n.to_owned());
            current = Some((name, line.pos, Vec::new()));
        } else if let Some((_, _, values)) = current.as_mut()
            && !t.is_empty()
            && values.len() < 64
        {
            values.push(t);
        }
    }
    Ok(())
}

async fn sdf_molfile(cx: Cx, mol: Span) -> Result<()> {
    molfile_body(&cx, mol, true).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// JCAMP-DX spectra

fn jcamp_probe(h: &Head<'_>) -> bool {
    let head = h.data.get(..2048).unwrap_or(h.data);
    is_text(h)
        && h.starts_with(b"##TITLE=")
        && (crate::formats::util::lines::contains(head, b"##JCAMP-DX=")
            || crate::formats::util::lines::contains(head, b"##JCAMPDX="))
}

declare_format!(pub JCAMP = "jcamp-dx", "JCAMP-DX spectrum", ["jdx", "dx", "jcm"], "chemical/x-jcamp-dx",
    Probe::Custom(jcamp_probe), jcamp);

async fn jcamp(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut current: Option<(String, u64, String, u64)> = None;
    let (mut title, mut kind, mut version, mut npoints) =
        (String::new(), String::new(), String::new(), String::new());
    let mut blocks = 0u32;
    let mut depth = 0u32;
    loop {
        let next = lines.next().await?;
        let starts = next.as_ref().is_none_or(|l| l.bytes.starts_with(b"##"));
        if starts && let Some((label, s, value, extra)) = current.take() {
            let end = next.as_ref().map_or(lines.pos(), |l| l.pos);
            let span = file.sub(s, end.saturating_sub(s));
            let mut node = Node::new(format!("##{label}"))
                .span(span)
                .value(number(&value));
            if extra > 0 {
                node = node.summary(format!("{extra} data line(s)"));
            }
            cx.push(node).await;
        }
        let Some(line) = next else { break };
        if starts {
            let t = line.text();
            let body = t.trim_start_matches('#');
            let (label, value) = body.split_once('=').unwrap_or((body, ""));
            // Labels compare without spaces, dashes, slashes and underscores.
            let norm: String = label
                .chars()
                .filter(|c| c.is_ascii_alphanumeric())
                .collect::<String>()
                .to_ascii_uppercase();
            let value = value
                .split("$$")
                .next()
                .unwrap_or_default()
                .trim()
                .to_owned();
            match norm.as_str() {
                "TITLE" => {
                    depth = depth.saturating_add(1);
                    blocks = blocks.saturating_add(1);
                    if title.is_empty() {
                        title.clone_from(&value);
                    }
                }
                "END" => depth = depth.saturating_sub(1),
                "JCAMPDX" if version.is_empty() => version.clone_from(&value),
                "DATATYPE" if kind.is_empty() => kind.clone_from(&value),
                "NPOINTS" if npoints.is_empty() => npoints.clone_from(&value),
                _ => {}
            }
            current = Some((label.to_owned(), line.pos, value, 0));
        } else if let Some((_, _, _, extra)) = current.as_mut() {
            *extra = extra.saturating_add(1);
        }
    }
    if depth > 0 {
        cx.diag(Diagnostic::malformed("missing ##END="));
    }
    cx.annotate(format!(
        "JCAMP-DX {version}, {}{}{}",
        if kind.is_empty() {
            "spectrum".to_owned()
        } else {
            kind.to_lowercase()
        },
        if npoints.is_empty() {
            String::new()
        } else {
            format!(", {npoints} points")
        },
        if blocks > 1 {
            format!(", {blocks} blocks")
        } else {
            format!(": {}", preview(&title, 60))
        }
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cif_tokens_handle_quotes() {
        assert_eq!(
            cif_tokens("_a 'it''s x' \"b c\" d"),
            vec!["_a", "it''s x", "b c", "d"]
        );
        assert_eq!(cif_tokens("'a'b' c"), vec!["a'b", "c"]);
    }

    #[test]
    fn settings_split() {
        assert_eq!(
            settings("name=\"my track\" visibility=2"),
            vec![
                ("name".to_owned(), "my track".to_owned(), 0, 15),
                ("visibility".to_owned(), "2".to_owned(), 16, 28)
            ]
        );
    }

    #[test]
    fn unescape_percent() {
        assert_eq!(unescape("a%3Bb%2C"), "a;b,");
        assert_eq!(
            crate::formats::util::lines::int(1),
            crate::value::Value::Int { value: 1, bits: 64 }
        );
    }
}
