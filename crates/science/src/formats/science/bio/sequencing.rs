//! Sequencing reads, traces and signal: 454 SFF flowgrams, ZTR traces,
//! nanopore SLOW5/BLOW5, and Juicer `.hic` contact maps.

use crate::bytes::{to_u64, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, read_record};
use crate::error::Result;
use crate::fields::{Endian, Fields};
use crate::formats::util::lines::{Lines, number, preview, text, uint};
use crate::formats::{Codec, Input, Probe, content};
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
        cx.progress_in(file, file.offset.saturating_add(cur.pos()));
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
        cx.progress_in(file, file.offset.saturating_add(cur.pos()));
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
            .value(crate::formats::util::lines::hex(footer, 64)),
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
                .value(crate::formats::util::lines::hex(at, 64))
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
                .value(crate::formats::util::lines::hex(pos, 64))
                .summary(format!("{size} bytes"))
                .target(file.sub(pos, size.into())),
        )
        .await;
    }
    Ok(())
}
