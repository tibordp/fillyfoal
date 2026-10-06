//! More bioinformatics formats: 454 SFF and ZTR traces, nanopore
//! SLOW5/BLOW5, Juicer .hic contact maps, HMMER3 profiles, EMBL flat files,
//! GTF annotations, BLAT PSL alignments, mzTab results and AMBER topologies.

use crate::bytes::{to_u64, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, read_record};
use crate::error::Result;
use crate::fields::{Endian, Fields};
use crate::formats::lines::{
    Line, Lines, head_lines, is_text, number, preview, summarize, tally, text, uint,
};
use crate::formats::{Codec, Head, Input, Probe, content};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// 454 Standard Flowgram Format (SFF)

declare_format!(pub SFF = "sff", "Standard Flowgram Format (454/Ion Torrent)", ["sff"], "application/x-sff",
    Probe::Magic(&[(0, b".sff\0\0\0\x01")]), sff);

record! {
    pub struct SffHeader {
        magic: ascii[4] "Magic",
        version: bytes[4] "Version",
        index_offset: u64 "Index offset" .hex(),
        index_length: u32 "Index length",
        reads: u32 "Reads",
        header_length: u16 "Header length",
        key_length: u16 "Key length",
        flows: u16 "Flows per read",
        flowgram_format: u8 "Flowgram format",
    }
}

async fn sff(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let hs = file.sub(0, SffHeader::SIZE);
    let h: SffHeader = read_record(&cx, hs, BE).await?;
    cx.emit(SffHeader::node("Common header", hs, BE));
    let flows = file.sub(SffHeader::SIZE, h.flows.into());
    let chars = String::from_utf8_lossy(&cx.read_avail(flows.sub(0, 4096)).await?).into_owned();
    cx.emit(
        Node::new("Flow characters")
            .span(flows)
            .value(text(preview(&chars, 80))),
    );
    let key = file.sub(flows.end().saturating_sub(file.offset), h.key_length.into());
    let key_text = String::from_utf8_lossy(&cx.read_avail(key).await?).into_owned();
    cx.emit(
        Node::new("Key sequence")
            .span(key)
            .value(text(key_text.clone())),
    );
    if h.index_length > 0 {
        cx.emit(Node::new("Index").span(file.sub(h.index_offset, h.index_length.into())));
    }
    let reads = file.tail(h.header_length.into());
    cx.emit(
        Node::new("Reads")
            .span(reads)
            .value(uint(h.reads.into()))
            .lazy(sff_reads, (reads, h.reads, h.flows)),
    );
    cx.annotate(format!(
        "SFF, {} read(s), {} flows ({}), key {key_text}",
        h.reads,
        h.flows,
        preview(&chars, 8)
    ));
    Ok(())
}

async fn sff_reads(cx: Cx, (span, count, flows): (Span, u32, u16)) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, BE);
    cx.set_count(Count::Exact(count.into()));
    for _ in 0..count {
        if cur.remaining() < 16 {
            break;
        }
        let start = cur.pos();
        let hlen = cur.u16().await?;
        let nlen = cur.u16().await?;
        let bases = u64::from(cur.u32().await?);
        let clip = cur.bytes(8).await?;
        let name = String::from_utf8_lossy(&cur.bytes(nlen.into()).await?).into_owned();
        cur.seek(start.saturating_add(hlen.into()));
        let data = u64::from(flows)
            .saturating_mul(2)
            .saturating_add(bases.saturating_mul(3));
        let seq_span = span.sub(
            cur.pos()
                .saturating_add(u64::from(flows).saturating_mul(2))
                .saturating_add(bases),
            bases,
        );
        let seq = String::from_utf8_lossy(&cx.read_avail(seq_span.sub(0, 200)).await?).into_owned();
        cur.skip(data.next_multiple_of(8));
        let ql = u16::from_be_bytes([
            clip.first().copied().unwrap_or(0),
            clip.get(1).copied().unwrap_or(0),
        ]);
        let qr = u16::from_be_bytes([
            clip.get(2).copied().unwrap_or(0),
            clip.get(3).copied().unwrap_or(0),
        ]);
        cx.push(
            Node::new(name)
                .span(cur.since(start))
                .value(text(preview(&seq, 120)))
                .summary(format!("{bases} bases, quality clip {ql}–{qr}")),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ZTR traces

declare_format!(pub ZTR = "ztr", "ZTR sequence trace", ["ztr"], "application/x-ztr",
    Probe::Magic(&[(0, b"\xaeZTR\r\n\x1a\n")]), ztr);

const ZTR_CHUNKS: &[(&str, &str)] = &[
    ("SAMP", "Trace samples (one channel)"),
    ("SMP4", "Trace samples (four channels)"),
    ("BASE", "Base calls"),
    ("BPOS", "Base positions"),
    ("CNF4", "Confidence (four values per base)"),
    ("CNF1", "Confidence (one value per base)"),
    ("CSID", "Call sequence identifiers"),
    ("TEXT", "Text identifiers"),
    ("CLIP", "Clip points"),
    ("COMM", "Comments"),
    ("CR32", "CRC-32"),
    ("REGN", "Regions"),
];

async fn ztr(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 10)).await?;
    cx.emit(Node::new("Magic").span(file.sub(0, 8)));
    cx.emit(
        Node::new("Version")
            .span(file.sub(8, 2))
            .value(text(format!(
                "{}.{}",
                head.get(8).unwrap_or(&0),
                head.get(9).unwrap_or(&0)
            ))),
    );
    let mut cur = Cursor::new(&cx, file, BE);
    cur.seek(10);
    let mut bases = None;
    let mut chunks = 0u32;
    while cur.remaining() >= 12 {
        let start = cur.pos();
        let kind = String::from_utf8_lossy(&cur.bytes(4).await?).into_owned();
        let mlen = cur.u32().await?;
        let meta = cur.span(mlen.into());
        cur.skip(mlen.into());
        let dlen = cur.u32().await?;
        let data = cur.span(dlen.into());
        cur.skip(dlen.into());
        let format = cx
            .read_avail(data.sub(0, 1))
            .await?
            .first()
            .copied()
            .unwrap_or(0);
        if kind == "BASE" {
            bases = Some(dlen.saturating_sub(1));
        }
        let desc = ZTR_CHUNKS
            .iter()
            .find(|(k, _)| *k == kind)
            .map_or("chunk", |(_, d)| *d);
        let fmt = match format {
            0 => "raw",
            1 => "run-length",
            2 => "zlib",
            64..=79 => "delta/shuffle",
            _ => "encoded",
        };
        let mut node = Node::new(kind.clone())
            .span(cur.since(start))
            .desc(desc)
            .summary(format!("{dlen} bytes, {fmt}"));
        if format == 2 {
            node = node.lazy(ztr_zlib, (input, data));
        } else if format == 0 && (kind == "TEXT" || kind == "BASE" || kind == "COMM") {
            node = node.lazy(ztr_raw_text, (data, kind.clone()));
        }
        let _ = meta;
        cx.push(node).await;
        chunks = chunks.saturating_add(1);
    }
    cx.annotate(format!(
        "ZTR trace, {chunks} chunk(s){}",
        bases.map(|b| format!(", {b} bases")).unwrap_or_default()
    ));
    Ok(())
}

async fn ztr_zlib(cx: Cx, (input, data): (Input, Span)) -> Result<()> {
    let b = cx.read(data.sub(0, 5)).await?;
    let raw = u32_le(&b, 1).unwrap_or(0);
    cx.emit(Node::new("Format").span(data.sub(0, 1)).value(text("zlib")));
    cx.emit(
        Node::new("Uncompressed length")
            .span(data.sub(1, 4))
            .value(uint(raw.into())),
    );
    cx.emit(content(
        "Data",
        input,
        data.tail(5),
        Codec::Zlib,
        Some(raw.into()),
    ));
    Ok(())
}

async fn ztr_raw_text(cx: Cx, (data, kind): (Span, String)) -> Result<()> {
    let b = cx.read_avail(data.sub(1, 0x10000)).await?;
    if kind == "TEXT" {
        let parts: Vec<String> = b
            .split(|&c| c == 0)
            .map(|p| String::from_utf8_lossy(p).into_owned())
            .collect();
        for kv in parts.chunks(2) {
            if let (Some(k), Some(v)) = (kv.first(), kv.get(1))
                && !k.is_empty()
            {
                cx.emit(Node::new(k.clone()).value(text(v.clone())));
            }
        }
    } else {
        cx.emit(
            Node::new("Text")
                .span(data.tail(1))
                .value(text(preview(&String::from_utf8_lossy(&b), 200))),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Nanopore SLOW5 (text) and BLOW5 (binary)

declare_format!(pub SLOW5 = "slow5", "Nanopore raw signal (SLOW5)", ["slow5"], "text/x-slow5",
    Probe::Magic(&[(0, b"#slow5_version\t")]), slow5);
declare_format!(pub BLOW5 = "blow5", "Nanopore raw signal (BLOW5)", ["blow5"], "application/x-blow5",
    Probe::Magic(&[(0, b"BLOW5\x01")]), blow5);

/// Header lines of a SLOW5 header: (key, value, span); stops at the column line.
async fn slow5_header(cx: &Cx, span: Span) -> Result<(Vec<(String, String, Span)>, u64, String)> {
    let mut lines = Lines::new(cx, span);
    let mut items = Vec::new();
    let mut columns = String::new();
    let mut end = 0u64;
    while let Some(line) = lines.next().await? {
        let t = line.text();
        if t.starts_with("#read_id") {
            columns = t.trim_start_matches('#').replace('\t', ", ");
            end = lines.pos();
            break;
        }
        if t.starts_with('#') || t.starts_with('@') {
            let (k, v) = t.split_once('\t').unwrap_or((t.as_str(), ""));
            if items.len() < 4096 {
                items.push((k.to_owned(), v.to_owned(), line.content()));
            }
            end = lines.pos();
        } else {
            break;
        }
    }
    Ok((items, end, columns))
}

async fn slow5(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let (items, end, columns) = slow5_header(&cx, file).await?;
    let get = |k: &str| {
        items
            .iter()
            .find(|(a, _, _)| a == k)
            .map_or(String::new(), |(_, v, _)| v.clone())
    };
    let n = items.len();
    cx.emit(
        Node::new("Header")
            .span(file.sub(0, end))
            .value(uint(to_u64(n)))
            .summary(columns)
            .lazy(kv_items, items.clone()),
    );
    let mut lines = Lines::at(&cx, file, end);
    let mut reads = 0u64;
    while let Some(line) = lines.next().await? {
        if line.bytes.is_empty() {
            continue;
        }
        let fields = line.split(b'\t');
        let g = |i: usize| fields.get(i).map_or("", |(s, _)| s.as_str());
        cx.push(
            Node::new(g(0).to_owned())
                .span(line.content())
                .summary(format!("{} sample(s) at {} Hz", g(6), g(5))),
        )
        .await;
        reads = reads.saturating_add(1);
    }
    cx.annotate(format!(
        "SLOW5 {}, {reads} read(s), {} read group(s)",
        get("#slow5_version"),
        get("#num_read_groups")
    ));
    Ok(())
}

async fn kv_items(cx: Cx, items: Vec<(String, String, Span)>) -> Result<()> {
    for (k, v, span) in items {
        cx.push(Node::new(k).span(span).value(number(&v))).await;
    }
    Ok(())
}

const BLOW5_COMPRESSION: &[&str] = &["none", "zlib", "zstd"];

async fn blow5(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 68)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Magic", 5).emit()?;
    f.u8("Magic version").emit()?;
    let major = f.u8("Version major").emit()?;
    let minor = f.u8("Version minor").emit()?;
    let patch = f.u8("Version patch").emit()?;
    let rc = f.u8("Record compression").emit()?;
    let groups = f.u32("Read groups").emit()?;
    let sc = f.u8("Signal compression").emit()?;
    f.seek(64);
    let hlen = f.u32("Header length").emit()?;
    let header = file.sub(68, hlen.into());
    let (items, _, columns) = slow5_header(&cx, header).await?;
    cx.emit(
        Node::new("Header text")
            .span(header)
            .value(uint(to_u64(items.len())))
            .summary(columns)
            .lazy(kv_items, items),
    );
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(68u64.saturating_add(hlen.into()));
    let mut records = 0u64;
    while cur.remaining() >= 8 {
        let start = cur.pos();
        if cx.read_avail(file.sub(start, 5)).await? == b"5WOLB" {
            cx.emit(Node::new("End of file marker").span(file.sub(start, 5)));
            break;
        }
        let size = cur.u64().await?;
        let data = cur.span(size);
        cur.skip(size);
        let node = Node::new(format!("Record {records}"))
            .span(cur.since(start))
            .summary(format!("{size} bytes"));
        cx.push(if rc == 0 {
            node.lazy(blow5_record, data)
        } else {
            node
        })
        .await;
        records = records.saturating_add(1);
    }
    let comp = |c: u8| {
        BLOW5_COMPRESSION
            .get(usize::from(c))
            .copied()
            .unwrap_or("svb-zd/other")
    };
    cx.annotate(format!("BLOW5 v{major}.{minor}.{patch}, {records} record(s), {groups} read group(s), record compression {}, signal compression {}", comp(rc), comp(sc)));
    Ok(())
}

/// The fixed primary fields of an uncompressed BLOW5 record.
async fn blow5_record(cx: Cx, data: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, data, LE);
    let start = cur.pos();
    let n = cur.u16().await?;
    let id = String::from_utf8_lossy(&cur.bytes(n.into()).await?).into_owned();
    cx.emit(Node::new("read_id").span(cur.since(start)).value(text(id)));
    let b = cx.block(data.sub(cur.pos(), 44)).await?;
    let mut f = Fields::emitting(&cx, &b, LE);
    f.u32("read_group").emit()?;
    f.f64("digitisation").emit()?;
    f.f64("offset").emit()?;
    f.f64("range").emit()?;
    f.f64("sampling_rate").emit()?;
    let samples = f.u64("len_raw_signal").emit()?;
    let signal = data.sub(cur.pos().saturating_add(44), samples.saturating_mul(2));
    cx.emit(
        Node::new("raw_signal")
            .span(signal)
            .summary(format!("{samples} int16 sample(s)")),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Juicer .hic contact maps

declare_format!(pub HIC = "hic", "Juicer Hi-C contact map (.hic)", ["hic"], "application/x-hic",
    Probe::Custom(|h| h.at(0, b"HIC\0") && u32_le(h.data, 4).is_some_and(|v| (1..=20).contains(&v))), hic);

async fn hic(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, LE);
    let start = cur.pos();
    cur.skip(4);
    cx.emit(Node::new("Magic").span(cur.since(start)).value(text("HIC")));
    let s = cur.pos();
    let version = cur.u32().await?;
    cx.emit(
        Node::new("Version")
            .span(cur.since(s))
            .value(uint(version.into())),
    );
    let s = cur.pos();
    let footer = cur.u64().await?;
    cx.emit(
        Node::new("Footer position")
            .span(cur.since(s))
            .value(crate::formats::lines::hex(footer, 64)),
    );
    let s = cur.pos();
    let (genome, _) = cur.cstr(0x1000).await?;
    cx.emit(
        Node::new("Genome")
            .span(cur.since(s))
            .value(text(genome.clone())),
    );
    if version >= 9 {
        let s = cur.pos();
        let at = cur.u64().await?;
        let len = cur.u64().await?;
        cx.emit(
            Node::new("Normalization vector index")
                .span(cur.since(s))
                .value(crate::formats::lines::hex(at, 64))
                .summary(format!("{len} bytes")),
        );
    }
    let s = cur.pos();
    let nattr = cur.u32().await?;
    let mut attrs = Vec::new();
    for _ in 0..nattr.min(1000) {
        let a = cur.pos();
        let (k, _) = cur.cstr(0x1000).await?;
        let (v, _) = cur.cstr(0x10_0000).await?;
        attrs.push((k, preview(&v, 200), cur.since(a)));
    }
    cx.emit(
        Node::new("Attributes")
            .span(cur.since(s))
            .value(uint(nattr.into()))
            .lazy(kv_items, attrs),
    );
    let s = cur.pos();
    let nchr = cur.u32().await?;
    let mut chroms = Vec::new();
    for _ in 0..nchr.min(100_000) {
        let a = cur.pos();
        let (name, _) = cur.cstr(0x1000).await?;
        let len = if version >= 9 {
            cur.u64().await?
        } else {
            u64::from(cur.u32().await?)
        };
        chroms.push((name, len.to_string(), cur.since(a)));
    }
    let names: Vec<String> = chroms.iter().take(4).map(|c| c.0.clone()).collect();
    cx.emit(
        Node::new("Chromosomes")
            .span(cur.since(s))
            .value(uint(nchr.into()))
            .lazy(kv_items, chroms),
    );
    let s = cur.pos();
    let nres = cur.u32().await?;
    let mut res = Vec::new();
    for _ in 0..nres.min(1000) {
        res.push(cur.u32().await?.to_string());
    }
    cx.emit(
        Node::new("Base-pair resolutions")
            .span(cur.since(s))
            .value(text(res.join(", "))),
    );
    let s = cur.pos();
    let nfrag = cur.u32().await?;
    for _ in 0..nfrag.min(1000) {
        cur.u32().await?;
    }
    cx.emit(
        Node::new("Fragment resolutions")
            .span(cur.since(s))
            .value(uint(nfrag.into())),
    );
    cx.emit(
        Node::new("Footer (master index)")
            .span(file.tail(footer))
            .lazy(hic_footer, (file, footer, version)),
    );
    cx.annotate(format!(
        "Juicer .hic v{version}, genome {genome}, {nchr} chromosome(s) ({}…), resolutions {} bp",
        names.join(", "),
        res.join("/")
    ));
    Ok(())
}

async fn hic_footer(cx: Cx, (file, at, version): (Span, u64, u32)) -> Result<()> {
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(at);
    let s = cur.pos();
    let bytes = if version >= 9 {
        cur.u64().await?
    } else {
        u64::from(cur.u32().await?)
    };
    cx.emit(Node::new("Size").span(cur.since(s)).value(uint(bytes)));
    let s = cur.pos();
    let n = cur.u32().await?;
    cx.emit(
        Node::new("Entries")
            .span(cur.since(s))
            .value(uint(n.into())),
    );
    for _ in 0..n.min(1_000_000) {
        let s = cur.pos();
        let (key, _) = cur.cstr(0x1000).await?;
        let pos = cur.u64().await?;
        let size = cur.u32().await?;
        cx.push(
            Node::new(key)
                .span(cur.since(s))
                .value(crate::formats::lines::hex(pos, 64))
                .summary(format!("{size} bytes"))
                .target(file.sub(pos, size.into())),
        )
        .await;
    }
    Ok(())
}

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
                        crate::formats::lines::contains(a, b"gene_id \"")
                            || crate::formats::lines::contains(a, b"transcript_id \"")
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
    Probe::Custom(|h| h.starts_with(b"MTD\tmzTab-version") || h.starts_with(b"MTD  mzTab-version") || (h.starts_with(b"COM\t") && crate::formats::lines::contains(h.data.get(..4096).unwrap_or(h.data), b"\nMTD\tmzTab-version"))), mztab);

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probes() {
        let h = Head {
            data: b"ID   X; SV 1\nXX\n",
            tail: b"",
            len: 16,
        };
        assert!(embl_probe(&h));
        let g = Head {
            data: b"chr1\tsrc\texon\t1\t10\t.\t+\t.\tgene_id \"g\"; transcript_id \"t\";\n",
            tail: b"",
            len: 60,
        };
        assert!(gtf_probe(&g));
    }
}
