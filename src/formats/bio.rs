//! Binary bioinformatics formats: the BGZF family (BAM, BCF, bgzipped VCF,
//! tabix and CSI indexes), BAI, CRAM, 2bit, BigWig/BigBed, and Sanger trace
//! files (ABIF, SCF).

use crate::bytes::{to_u64, to_usize, u16_le, u32_be, u32_le};
use crate::codec::inflate::{Inflate, Step};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::lines::{enumeration, float32, hex, int, preview, summarize, text, uint};
use crate::formats::{Codec, Head, Input, Probe, content, embedded, embedded_as};
use crate::node::{Count, Node};
use crate::record;
use crate::span::{Origin, Span};
use crate::value::{EnumTable, FlagTable, flag, lookup};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// BGZF: concatenated gzip members, each carrying its size in a "BC" subfield.

record! {
    pub struct BgzfHeader {
        magic: bytes[2] "ID",
        method: u8 "CM",
        flags: u8 "FLG" .hex(),
        mtime: u32 "MTIME" .timestamp(),
        xfl: u8 "XFL",
        os: u8 "OS",
        xlen: u16 "XLEN" .desc("Length of the extra field"),
    }
}

record! {
    pub struct BgzfTrailer {
        crc: u32 "CRC32" .hex(),
        isize: u32 "ISIZE" .desc("Uncompressed size of this block"),
    }
}

/// The BSIZE of the "BC" subfield in a gzip extra field.
fn bc_subfield(extra: &[u8]) -> Option<u16> {
    let mut at = 0usize;
    while at.saturating_add(4) <= extra.len() {
        let len = usize::from(u16_le(extra, at.saturating_add(2))?);
        if extra.get(at..at.saturating_add(2)) == Some(b"BC") && len == 2 {
            return u16_le(extra, at.saturating_add(4));
        }
        at = at.saturating_add(4).saturating_add(len);
    }
    None
}

/// The first decompressed bytes of a BGZF stream seen by a probe.
fn bgzf_peek(h: &Head<'_>) -> Option<Vec<u8>> {
    if !h.at(0, b"\x1f\x8b\x08\x04") {
        return None;
    }
    let xlen = usize::from(u16_le(h.data, 10)?);
    let extra = h.data.get(12..12usize.saturating_add(xlen))?;
    let bsize = usize::from(bc_subfield(extra)?);
    let start = 12usize.saturating_add(xlen);
    let end = bsize.saturating_add(1).saturating_sub(8).min(h.data.len());
    let cdata = h.data.get(start..end)?;
    let mut out = Vec::new();
    let mut inflater = Inflate::new();
    while out.len() < 64 {
        match inflater.step(cdata, &mut out, 64, 0x10000) {
            Ok(Step::More) => {}
            Ok(Step::Done) | Err(_) => break,
        }
    }
    Some(out)
}

fn is_bgzf(h: &Head<'_>) -> bool {
    bgzf_peek(h).is_some()
}

declare_format!(pub BAM = "bam", "Binary Alignment/Map (BAM)", ["bam"], "application/x-bam",
    Probe::Custom(|h| bgzf_peek(h).is_some_and(|d| d.starts_with(b"BAM\x01"))), bam);
declare_format!(pub BCF = "bcf", "Binary variant call format (BCF)", ["bcf"], "application/x-bcf",
    Probe::Custom(|h| bgzf_peek(h).is_some_and(|d| d.starts_with(b"BCF\x02"))), bcf);
declare_format!(pub VCF_BGZF = "vcf-bgzf", "Variant call format, BGZF-compressed", ["vcf.gz", "vcf.bgz"], "application/x-vcf+bgzf",
    Probe::Custom(|h| bgzf_peek(h).is_some_and(|d| d.starts_with(b"##fileformat=VCF"))), vcf_bgzf);
declare_format!(pub TABIX = "tabix", "Tabix index", ["tbi"], "application/x-tabix",
    Probe::Custom(|h| bgzf_peek(h).is_some_and(|d| d.starts_with(b"TBI\x01"))), tabix);
declare_format!(pub CSI = "csi", "Coordinate-sorted index (CSI)", ["csi"], "application/x-csi",
    Probe::Custom(|h| bgzf_peek(h).is_some_and(|d| d.starts_with(b"CSI\x01"))), csi);
declare_format!(pub BGZF = "bgzf", "Blocked gzip (BGZF)", ["gz", "bgz"], "application/x-bgzf",
    Probe::Custom(is_bgzf), bgzf);

/// One BGZF block: where it is, its compressed payload and uncompressed size.
#[derive(Clone, Copy, Debug)]
struct BgzfBlock {
    span: Span,
    xlen: u16,
    cdata: Span,
    isize: u32,
}

/// Reads the block at `pos`, or `None` at the end or on garbage.
async fn bgzf_block(cx: &Cx, file: Span, pos: u64) -> Result<Option<BgzfBlock>> {
    if pos >= file.len {
        return Ok(None);
    }
    let head = cx.read_avail(file.sub(pos, 12)).await?;
    if !head.starts_with(b"\x1f\x8b\x08") || head.len() < 12 {
        return Ok(None);
    }
    let xlen = u16_le(&head, 10).unwrap_or(0);
    let extra = cx
        .read_avail(file.sub(pos.saturating_add(12), xlen.into()))
        .await?;
    let Some(bsize) = bc_subfield(&extra) else {
        return Ok(None);
    };
    let total = u64::from(bsize).saturating_add(1);
    let span = file.sub(pos, total);
    let header_len = 12u64.saturating_add(xlen.into());
    let cdata = span.sub(
        header_len,
        total.saturating_sub(header_len).saturating_sub(8),
    );
    let trailer = cx.read_avail(span.sub(total.saturating_sub(4), 4)).await?;
    let isize = u32_le(&trailer, 0).unwrap_or(0);
    Ok(Some(BgzfBlock {
        span,
        xlen,
        cdata,
        isize,
    }))
}

/// Lists the blocks of a BGZF file.
async fn bgzf_blocks(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut pos = 0u64;
    let mut index = 0u64;
    while let Some(block) = bgzf_block(&cx, file, pos).await? {
        let eof = block.isize == 0 && block.span.len == 28;
        let summary = if eof {
            "end-of-file marker".to_owned()
        } else {
            format!("{} → {} bytes", block.cdata.len, block.isize)
        };
        cx.push(
            Node::new(format!("Block {index}"))
                .span(block.span)
                .value(hex(pos, 64))
                .summary(summary)
                .lazy(
                    bgzf_block_node,
                    (input, block.span, block.xlen, block.cdata, block.isize),
                ),
        )
        .await;
        index = index.saturating_add(1);
        pos = pos.saturating_add(block.span.len.max(1));
    }
    if pos < file.len {
        cx.diag(
            Diagnostic::malformed("data after the last BGZF block is not a BGZF block")
                .at(file.tail(pos)),
        );
    }
    Ok(())
}

async fn bgzf_block_node(
    cx: Cx,
    (input, span, xlen, cdata, isize): (Input, Span, u16, Span, u32),
) -> Result<()> {
    cx.emit(BgzfHeader::node(
        "Header",
        span.sub(0, BgzfHeader::SIZE),
        LE,
    ));
    let extra = span.sub(12, xlen.into());
    let data = cx.block(extra).await?;
    let mut f = Fields::emitting(&cx, &data, LE);
    f.ascii("Subfield ID", 2).emit()?;
    f.u16("Subfield length").emit()?;
    f.u16("BSIZE").desc("Total block size minus 1").emit()?;
    cx.emit(
        content("Data", input, cdata, Codec::Deflate, Some(isize.into()))
            .summary(format!("{} compressed bytes", cdata.len)),
    );
    cx.emit(BgzfTrailer::node(
        "Trailer",
        span.sub(span.len.saturating_sub(8), 8),
        LE,
    ));
    Ok(())
}

/// Most blocks decompressed into one stream, and whether that was all of it.
const STREAM_BLOCKS: u32 = 64;

/// Decompresses the first blocks of a BGZF file into one contiguous source
/// (the blocks' decoded sources joined as pieces). `head_only` stops after a
/// few blocks, which is enough for headers.
async fn bgzf_stream(cx: &Cx, file: Span, head_only: bool) -> Result<(Span, bool)> {
    let max = if head_only { 4 } else { STREAM_BLOCKS };
    let mut pieces = Vec::new();
    let mut pos = 0u64;
    let mut complete = true;
    let mut count = 0u32;
    while let Some(block) = bgzf_block(cx, file, pos).await? {
        if count >= max {
            complete = false;
            break;
        }
        if block.isize > 0 {
            let decoded =
                crate::codec::inflate_span(cx, block.cdata, false, Some(block.isize.into()))
                    .await?;
            pieces.push(decoded.span);
            if decoded.error.is_some() {
                complete = false;
                break;
            }
        }
        count = count.saturating_add(1);
        pos = pos.saturating_add(block.span.len.max(1));
    }
    let origin = Origin {
        parent: file,
        transform: if head_only {
            "bgzf (first blocks)"
        } else {
            "bgzf"
        },
    };
    Ok((cx.add_pieces(origin, pieces)?, complete))
}

fn blocks_node(input: Input) -> Node {
    Node::new("BGZF blocks")
        .span(input.span)
        .lazy(bgzf_blocks, input)
}

fn stream_note(complete: bool) -> Option<Diagnostic> {
    (!complete).then(|| {
        Diagnostic::limit(format!(
            "only the first {STREAM_BLOCKS} BGZF blocks are decompressed"
        ))
    })
}

async fn bgzf(cx: Cx, input: Input) -> Result<()> {
    let (stream, complete) = bgzf_stream(&cx, input.span, false).await?;
    cx.emit(blocks_node(input));
    let mut node = embedded("Decompressed data", input.nested(stream));
    if let Some(d) = stream_note(complete) {
        node = node.diag(d);
    }
    cx.emit(node);
    cx.annotate("BGZF (blocked gzip)");
    Ok(())
}

async fn vcf_bgzf(cx: Cx, input: Input) -> Result<()> {
    let (stream, complete) = bgzf_stream(&cx, input.span, false).await?;
    cx.emit(blocks_node(input));
    let mut node = embedded_as(
        "Decompressed VCF",
        input.nested(stream),
        &crate::formats::biotext::VCF,
    );
    if let Some(d) = stream_note(complete) {
        node = node.diag(d);
    }
    cx.emit(node);
    let head = cx.read_avail(stream.sub(0, 64)).await?;
    let version = String::from_utf8_lossy(&head)
        .lines()
        .next()
        .unwrap_or_default()
        .trim_start_matches("##fileformat=")
        .to_owned();
    cx.annotate(format!("{version}, BGZF-compressed"));
    Ok(())
}

// ---------------------------------------------------------------------------
// BAM

/// A length-prefixed reference list: names and lengths.
#[derive(Clone, Debug, Default)]
struct References(Vec<(String, u32)>);

async fn bam(cx: Cx, input: Input) -> Result<()> {
    let (head, _) = bgzf_stream(&cx, input.span, true).await?;
    cx.emit(blocks_node(input));
    let mut cur = Cursor::new(&cx, head, LE);
    let magic_span = cur.span(4);
    cur.skip(4);
    let l_text = cur.u32().await?;
    let text_span = cur.span(l_text.into());
    cur.skip(l_text.into());
    let n_ref = cur.u32().await?;
    let header_text = cx.read_avail(text_span.sub(0, 0x10000)).await?;
    let header_text = String::from_utf8_lossy(&header_text).into_owned();
    let refs_start = cur.pos();
    let mut refs = Vec::new();
    for _ in 0..n_ref.min(100_000) {
        if cur.at_end() {
            break;
        }
        let l_name = cur.u32().await?;
        let name = cur.bytes(l_name.into()).await?;
        let len = cur.u32().await?;
        refs.push((crate::text::until_nul(&name), len));
    }
    let header = head.sub(0, cur.pos());
    cx.emit(Node::new("Header").span(header).lazy(
        bam_header,
        (
            magic_span,
            text_span,
            head.sub(refs_start.saturating_sub(4), 4),
            head.sub(refs_start, cur.pos().saturating_sub(refs_start)),
        ),
    ));
    let refs = References(refs);
    cx.emit(Node::new("Alignments").lazy(bam_alignments, (input, header.len, refs.clone())));
    let sort = header_text
        .lines()
        .find(|l| l.starts_with("@HD"))
        .and_then(|l| l.split('\t').find_map(|f| f.strip_prefix("SO:")))
        .map(|s| format!(", sorted by {s}"))
        .unwrap_or_default();
    let names: Vec<&str> = refs.0.iter().take(3).map(|(n, _)| n.as_str()).collect();
    cx.annotate(format!(
        "BAM, {} reference(s){}{}",
        refs.0.len(),
        if names.is_empty() {
            String::new()
        } else {
            format!(
                " ({}{})",
                names.join(", "),
                if refs.0.len() > 3 { ", …" } else { "" }
            )
        },
        sort
    ));
    Ok(())
}

async fn bam_header(
    cx: Cx,
    (magic, text_span, n_ref, refs): (Span, Span, Span, Span),
) -> Result<()> {
    cx.emit(Node::new("Magic").span(magic).value(text("BAM\\1")));
    cx.emit(
        Node::new("l_text")
            .span(Span::new(
                text_span.source,
                text_span.offset.saturating_sub(4),
                4,
            ))
            .value(uint(text_span.len)),
    );
    cx.emit(
        Node::new("Header text")
            .span(text_span)
            .summary(format!("{} bytes", text_span.len))
            .lazy(sam_header_lines, text_span),
    );
    let count = cx.read_avail(n_ref).await?;
    cx.emit(
        Node::new("n_ref")
            .span(n_ref)
            .value(uint(u32_le(&count, 0).unwrap_or(0).into())),
    );
    cx.emit(Node::new("References").span(refs).lazy(bam_refs, refs));
    Ok(())
}

/// The lines of an embedded SAM header.
async fn sam_header_lines(cx: Cx, span: Span) -> Result<()> {
    let mut lines = crate::formats::util::lines::Lines::new(&cx, span);
    while let Some(line) = lines.next().await? {
        let t = line.text();
        let t = t.trim_end_matches('\0');
        if t.is_empty() {
            continue;
        }
        let tag = t.get(..3).unwrap_or(t).to_owned();
        cx.push(
            Node::new(tag)
                .span(line.span)
                .value(text(t.get(3..).unwrap_or_default().trim())),
        )
        .await;
    }
    Ok(())
}

async fn bam_refs(cx: Cx, span: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, LE);
    while !cur.at_end() {
        let start = cur.pos();
        let l_name = cur.u32().await?;
        let name = cur.bytes(l_name.into()).await?;
        let len = cur.u32().await?;
        cx.push(
            Node::new(crate::text::until_nul(&name))
                .span(cur.since(start))
                .value(uint(len.into()))
                .summary(format!("{len} bp")),
        )
        .await;
    }
    Ok(())
}

record! {
    pub struct BamRecord {
        block_size: u32 "block_size",
        ref_id: i32 "refID",
        pos: i32 "pos" .desc("0-based leftmost coordinate"),
        l_read_name: u8 "l_read_name",
        mapq: u8 "mapq",
        bin: u16 "bin",
        n_cigar_op: u16 "n_cigar_op",
        flag: u16 "flag" .flags(SAM_FLAGS),
        l_seq: u32 "l_seq",
        next_ref_id: i32 "next_refID",
        next_pos: i32 "next_pos",
        tlen: i32 "tlen",
    }
}

pub const SAM_FLAGS: FlagTable = &[
    flag(0x1, "PAIRED"),
    flag(0x2, "PROPER_PAIR"),
    flag(0x4, "UNMAP"),
    flag(0x8, "MUNMAP"),
    flag(0x10, "REVERSE"),
    flag(0x20, "MREVERSE"),
    flag(0x40, "READ1"),
    flag(0x80, "READ2"),
    flag(0x100, "SECONDARY"),
    flag(0x200, "QCFAIL"),
    flag(0x400, "DUP"),
    flag(0x800, "SUPPLEMENTARY"),
];

const CIGAR_OPS: &[u8; 9] = b"MIDNSHP=X";
const SEQ_CODES: &[u8; 16] = b"=ACMGRSVTWYHKDBN";

fn ref_name(refs: &References, id: i32) -> String {
    usize::try_from(id)
        .ok()
        .and_then(|i| refs.0.get(i))
        .map_or_else(|| "*".to_owned(), |(n, _)| n.clone())
}

async fn bam_alignments(cx: Cx, (input, start, refs): (Input, u64, References)) -> Result<()> {
    let (stream, complete) = bgzf_stream(&cx, input.span, false).await?;
    let mut cur = Cursor::new(&cx, stream, LE);
    cur.seek(start);
    let mut count = 0u64;
    while cur.remaining() >= 4 {
        let at = cur.pos();
        let size = cur.u32().await?;
        let span = stream.sub(at, u64::from(size).saturating_add(4));
        if span.len < u64::from(size).saturating_add(4) {
            if complete {
                cx.diag(Diagnostic::truncated(span, span.len));
            }
            break;
        }
        let rec: BamRecord = read_record(&cx, span.sub(0, BamRecord::SIZE), LE).await?;
        let name = cx
            .cstr(span.sub(BamRecord::SIZE, rec.l_read_name.into()))
            .await
            .map(|(n, _)| n)
            .unwrap_or_default();
        let summary = format!(
            "{}:{} mapq {} flag {:#x}",
            ref_name(&refs, rec.ref_id),
            i64::from(rec.pos).saturating_add(1),
            rec.mapq,
            rec.flag
        );
        cx.push(
            Node::new(name)
                .span(span)
                .summary(summary)
                .lazy(bam_record, (span, refs.clone())),
        )
        .await;
        count = count.saturating_add(1);
        cur.seek(at.saturating_add(span.len));
    }
    if let Some(d) = stream_note(complete) {
        cx.diag(d);
    }
    cx.set_count(Count::Exact(count));
    Ok(())
}

async fn bam_record(cx: Cx, (span, refs): (Span, References)) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    let rec = BamRecord::read(&mut f)?;
    let name = f.cstr("read_name").emit()?;
    let _ = name;
    let cigar_span = f.peek_span(u64::from(rec.n_cigar_op).saturating_mul(4));
    let cigar = cx.read_avail(cigar_span).await?;
    let ops: String = cigar
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| {
            let v = u32_le(c, 0).unwrap_or(0);
            let op = CIGAR_OPS
                .get(to_usize((v & 0xf).into()))
                .copied()
                .unwrap_or(b'?');
            format!("{}{}", v >> 4, char::from(op))
        })
        .collect();
    f.skip(cigar_span.len);
    cx.emit(
        Node::new("cigar")
            .span(cigar_span)
            .value(text(if ops.is_empty() { "*".to_owned() } else { ops })),
    );
    let seq_len = u64::from(rec.l_seq).div_ceil(2);
    let seq_span = f.peek_span(seq_len);
    let packed = cx.read_avail(seq_span.sub(0, 4096)).await?;
    let mut seq = String::new();
    for b in &packed {
        for nibble in [b >> 4, b & 0xf] {
            if to_u64(seq.len()) < u64::from(rec.l_seq) {
                seq.push(char::from(
                    SEQ_CODES.get(usize::from(nibble)).copied().unwrap_or(b'N'),
                ));
            }
        }
    }
    f.skip(seq_len);
    cx.emit(
        Node::new("seq")
            .span(seq_span)
            .value(text(preview(&seq, 200))),
    );
    let qual_span = f.peek_span(rec.l_seq.into());
    let qual = cx.read_avail(qual_span.sub(0, 4096)).await?;
    let mean = if qual.is_empty() || qual.first() == Some(&0xff) {
        None
    } else {
        qual.iter()
            .map(|&q| u64::from(q))
            .sum::<u64>()
            .checked_div(to_u64(qual.len()))
    };
    f.skip(rec.l_seq.into());
    cx.emit(
        Node::new("qual")
            .span(qual_span)
            .summary(mean.map_or_else(|| "absent".to_owned(), |m| format!("mean Phred {m}"))),
    );
    let tags = span.tail(f.pos());
    cx.emit(Node::new("Tags").span(tags).lazy(bam_tags, tags));
    cx.emit(Node::new("Reference").value(text(ref_name(&refs, rec.ref_id))));
    Ok(())
}

/// Size of one value of a BAM tag type.
fn tag_size(kind: u8) -> Option<u64> {
    Some(match kind {
        b'A' | b'c' | b'C' => 1,
        b's' | b'S' => 2,
        b'i' | b'I' | b'f' => 4,
        _ => return None,
    })
}

fn tag_value(kind: u8, b: &[u8]) -> crate::value::Value {
    match kind {
        b'A' => text(String::from_utf8_lossy(b.get(..1).unwrap_or_default())),
        b'c' => int(b.first().map_or(0, |&v| i64::from(v.cast_signed()))),
        b'C' => uint(b.first().map_or(0, |&v| u64::from(v))),
        b's' => int(crate::bytes::i16_le(b, 0).map_or(0, i64::from)),
        b'S' => uint(u16_le(b, 0).map_or(0, u64::from)),
        b'i' => int(crate::bytes::i32_le(b, 0).map_or(0, i64::from)),
        b'I' => uint(u32_le(b, 0).map_or(0, u64::from)),
        b'f' => float32(f32::from_bits(u32_le(b, 0).unwrap_or(0))),
        _ => text("?"),
    }
}

async fn bam_tags(cx: Cx, span: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, LE);
    while cur.remaining() >= 3 {
        let start = cur.pos();
        let head = cur.bytes(3).await?;
        let tag = String::from_utf8_lossy(head.get(..2).unwrap_or_default()).into_owned();
        let kind = head.get(2).copied().unwrap_or(0);
        let node = if let Some(size) = tag_size(kind) {
            let b = cur.bytes(size).await?;
            Node::new(tag).value(tag_value(kind, &b))
        } else if kind == b'Z' || kind == b'H' {
            let (s, _) = cur.cstr(0x10000).await?;
            Node::new(tag).value(text(s))
        } else if kind == b'B' {
            let sub = cur.u8().await?;
            let n = cur.u32().await?;
            let size = tag_size(sub).ok_or_else(|| {
                Diagnostic::malformed(format!("bad array type {sub:#x}")).at(cur.since(start))
            })?;
            cur.skip(size.saturating_mul(n.into()));
            Node::new(tag).summary(format!("array of {n} '{}'", char::from(sub)))
        } else {
            return Err(
                Diagnostic::malformed(format!("unknown tag type {kind:#x}")).at(cur.since(start))
            );
        };
        cx.push(
            node.span(cur.since(start))
                .desc(format!("type {}", char::from(kind))),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// BCF

async fn bcf(cx: Cx, input: Input) -> Result<()> {
    let (head, _) = bgzf_stream(&cx, input.span, true).await?;
    cx.emit(blocks_node(input));
    let mut cur = Cursor::new(&cx, head, LE);
    let magic = cur.bytes(5).await?;
    let l_text = cur.u32().await?;
    let text_span = cur.span(l_text.into());
    cx.emit(Node::new("Magic").span(head.sub(0, 5)).value(text(format!(
        "BCF {}.{}",
        magic.get(3).unwrap_or(&0),
        magic.get(4).unwrap_or(&0)
    ))));
    cx.emit(
        Node::new("l_text")
            .span(head.sub(5, 4))
            .value(uint(l_text.into())),
    );
    let vcf_text = if l_text > 0
        && cx
            .read_avail(text_span.sub(text_span.len.saturating_sub(1), 1))
            .await?
            == [0]
    {
        text_span.sub(0, text_span.len.saturating_sub(1))
    } else {
        text_span
    };
    cx.emit(embedded_as(
        "Header (VCF)",
        input.nested(vcf_text),
        &crate::formats::biotext::VCF,
    ));
    let header = cx.read_avail(text_span.sub(0, 0x100000)).await?;
    let header = String::from_utf8_lossy(&header).into_owned();
    // Dictionary indexes: contigs in order; strings (FILTER/INFO/FORMAT) by IDX or order with PASS first.
    let contigs: Vec<String> = header
        .lines()
        .filter_map(|l| l.strip_prefix("##contig=<"))
        .filter_map(|l| {
            l.split(',')
                .find_map(|f| f.strip_prefix("ID="))
                .map(|s| s.trim_end_matches('>').to_owned())
        })
        .collect();
    let samples = header
        .lines()
        .find(|l| l.starts_with("#CHROM"))
        .map_or(0, |l| l.split('\t').count().saturating_sub(9));
    cx.emit(Node::new("Records").lazy(
        bcf_records,
        (
            input,
            9u64.saturating_add(l_text.into()),
            References(contigs.iter().map(|c| (c.clone(), 0)).collect()),
        ),
    ));
    cx.annotate(format!(
        "BCF {}.{}, {} contig(s), {samples} sample(s)",
        magic.get(3).unwrap_or(&0),
        magic.get(4).unwrap_or(&0),
        contigs.len()
    ));
    Ok(())
}

record! {
    pub struct BcfShared {
        l_shared: u32 "l_shared",
        l_indiv: u32 "l_indiv",
        chrom: i32 "CHROM" .desc("Contig index in the header dictionary"),
        pos: i32 "POS" .desc("0-based position"),
        rlen: i32 "rlen",
        qual: f32 "QUAL",
        n_info_allele: u32 "n_allele << 16 | n_info" .hex(),
        n_fmt_sample: u32 "n_fmt << 24 | n_sample" .hex(),
    }
}

/// Reads one BCF typed value; returns its rendering.
async fn bcf_typed(cur: &mut Cursor<'_>) -> Result<String> {
    let descriptor = cur.u8().await?;
    let mut count = u64::from(descriptor >> 4);
    let kind = descriptor & 0xf;
    if count == 15 {
        let inner = cur.u8().await?;
        count = match inner & 0xf {
            1 => cur.u8().await?.into(),
            2 => cur.u16().await?.into(),
            3 => cur.u32().await?.into(),
            _ => return Err(Diagnostic::malformed("bad typed count")),
        };
    }
    let size: u64 = match kind {
        0 => 0,
        1 | 7 => 1,
        2 => 2,
        3 | 5 => 4,
        _ => return Err(Diagnostic::malformed(format!("bad BCF type {kind}"))),
    };
    let data = cur.bytes(size.saturating_mul(count).min(0x10000)).await?;
    Ok(match kind {
        7 => String::from_utf8_lossy(&data)
            .trim_end_matches('\0')
            .to_owned(),
        1 => data
            .iter()
            .map(|b| b.cast_signed().to_string())
            .collect::<Vec<_>>()
            .join(","),
        2 => data
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| crate::bytes::i16_le(c, 0).unwrap_or(0).to_string())
            .collect::<Vec<_>>()
            .join(","),
        3 => data
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| crate::bytes::i32_le(c, 0).unwrap_or(0).to_string())
            .collect::<Vec<_>>()
            .join(","),
        5 => data
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| f32::from_bits(u32_le(c, 0).unwrap_or(0)).to_string())
            .collect::<Vec<_>>()
            .join(","),
        _ => String::new(),
    })
}

async fn bcf_records(cx: Cx, (input, start, contigs): (Input, u64, References)) -> Result<()> {
    let (stream, complete) = bgzf_stream(&cx, input.span, false).await?;
    let mut cur = Cursor::new(&cx, stream, LE);
    cur.seek(start);
    while cur.remaining() >= 8 {
        let at = cur.pos();
        let l_shared = cur.u32().await?;
        let l_indiv = cur.u32().await?;
        let span = stream.sub(
            at,
            8u64.saturating_add(l_shared.into())
                .saturating_add(l_indiv.into()),
        );
        let shared: BcfShared = read_record(&cx, span.sub(0, BcfShared::SIZE), LE).await?;
        let mut body = Cursor::new(&cx, span, LE);
        body.seek(BcfShared::SIZE);
        let id = bcf_typed(&mut body).await.unwrap_or_default();
        let mut alleles = Vec::new();
        for _ in 0..(shared.n_info_allele >> 16).min(64) {
            alleles.push(bcf_typed(&mut body).await.unwrap_or_default());
        }
        let summary = format!(
            "{}:{} {} {}",
            ref_name(&contigs, shared.chrom),
            i64::from(shared.pos).saturating_add(1),
            alleles.first().map_or("", String::as_str),
            alleles.get(1..).map(|a| a.join(",")).unwrap_or_default()
        );
        cx.push(
            Node::new(if id.is_empty() || id == "." {
                format!("Record @{at:#x}")
            } else {
                id
            })
            .span(span)
            .summary(summary)
            .lazy(bcf_record, span),
        )
        .await;
        cur.seek(at.saturating_add(span.len.max(8)));
    }
    if let Some(d) = stream_note(complete) {
        cx.diag(d);
    }
    Ok(())
}

async fn bcf_record(cx: Cx, span: Span) -> Result<()> {
    let shared: BcfShared = read_record(&cx, span.sub(0, BcfShared::SIZE), LE).await?;
    cx.emit(BcfShared::node(
        "Fixed fields",
        span.sub(0, BcfShared::SIZE),
        LE,
    ));
    let mut cur = Cursor::new(&cx, span, LE);
    cur.seek(BcfShared::SIZE);
    let start = cur.pos();
    let id = bcf_typed(&mut cur).await?;
    cx.emit(Node::new("ID").span(cur.since(start)).value(text(id)));
    for i in 0..(shared.n_info_allele >> 16).min(1024) {
        let start = cur.pos();
        let allele = bcf_typed(&mut cur).await?;
        cx.emit(
            Node::new(if i == 0 { "REF" } else { "ALT" })
                .span(cur.since(start))
                .value(text(allele)),
        );
    }
    let start = cur.pos();
    let filters = bcf_typed(&mut cur).await?;
    cx.emit(
        Node::new("FILTER")
            .span(cur.since(start))
            .value(text(filters))
            .desc("Indexes into the header's string dictionary"),
    );
    let info = span.sub(
        cur.pos(),
        8u64.saturating_add(shared.l_shared.into())
            .saturating_sub(cur.pos()),
    );
    cx.emit(Node::new("INFO").span(info).summary(format!(
        "{} key/value pair(s)",
        shared.n_info_allele & 0xffff
    )));
    cx.emit(
        Node::new("Genotype data")
            .span(span.tail(8u64.saturating_add(shared.l_shared.into())))
            .summary(format!(
                "{} FORMAT field(s) × {} sample(s)",
                shared.n_fmt_sample >> 24,
                shared.n_fmt_sample & 0xff_ffff
            )),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Tabix, CSI and BAI indexes

/// One binning index (shared by BAI, tabix and CSI): bins with chunks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IndexKind {
    Bai,
    Tabix,
    Csi,
}

/// A virtual file offset: compressed block offset and offset within it.
fn voffset(v: u64) -> String {
    format!("{:#x}:{}", v >> 16, v & 0xffff)
}

/// Walks one reference's index; returns its length in bytes.
async fn index_ref_len(cur: &mut Cursor<'_>, kind: IndexKind) -> Result<()> {
    let n_bin = cur.u32().await?;
    for _ in 0..n_bin {
        cur.skip(4);
        if kind == IndexKind::Csi {
            cur.skip(8);
        }
        let n_chunk = cur.u32().await?;
        cur.skip(u64::from(n_chunk).saturating_mul(16));
        if cur.at_end() {
            break;
        }
    }
    if kind != IndexKind::Csi {
        let n_intv = cur.u32().await?;
        cur.skip(u64::from(n_intv).saturating_mul(8));
    }
    Ok(())
}

async fn index_refs(cx: Cx, (span, kind, names): (Span, IndexKind, Vec<String>)) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, LE);
    let mut i = 0usize;
    while cur.remaining() >= 4 {
        let start = cur.pos();
        let n_bin = cur
            .peek(4)
            .await
            .ok()
            .and_then(|b| u32_le(&b, 0))
            .unwrap_or(0);
        index_ref_len(&mut cur, kind).await?;
        let s = cur.since(start);
        let name = names
            .get(i)
            .cloned()
            .unwrap_or_else(|| format!("Reference {i}"));
        cx.push(
            Node::new(name)
                .span(s)
                .summary(format!("{n_bin} bin(s)"))
                .lazy(index_ref, (s, kind)),
        )
        .await;
        i = i.saturating_add(1);
        if names.len() == i {
            break;
        }
    }
    let rest = span.tail(cur.pos());
    if rest.len >= 8 {
        let b = cx.read_avail(rest.sub(0, 8)).await?;
        cx.emit(
            Node::new("n_no_coor")
                .span(rest.sub(0, 8))
                .value(uint(crate::bytes::u64_le(&b, 0).unwrap_or(0)))
                .desc("Unplaced unmapped reads"),
        );
    }
    Ok(())
}

async fn index_ref(cx: Cx, (span, kind): (Span, IndexKind)) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, LE);
    let n_bin = cur.u32().await?;
    cx.emit(
        Node::new("n_bin")
            .span(span.sub(0, 4))
            .value(uint(n_bin.into())),
    );
    for _ in 0..n_bin {
        if cur.at_end() {
            break;
        }
        let start = cur.pos();
        let bin = cur.u32().await?;
        let loffset = if kind == IndexKind::Csi {
            Some(cur.u64().await?)
        } else {
            None
        };
        let n_chunk = cur.u32().await?;
        let chunks = cur.span(u64::from(n_chunk).saturating_mul(16));
        let data = cx.read_avail(chunks.sub(0, 16 * 16)).await?;
        cur.skip(chunks.len);
        let shown: Vec<String> = data
            .as_chunks::<16>()
            .0
            .iter()
            .map(|c| {
                format!(
                    "{}–{}",
                    voffset(crate::bytes::u64_le(c, 0).unwrap_or(0)),
                    voffset(crate::bytes::u64_le(c, 8).unwrap_or(0))
                )
            })
            .collect();
        let pseudo = bin == 37450 || (kind == IndexKind::Csi && bin > 37449 && n_chunk == 2);
        let mut node = Node::new(format!("Bin {bin}"))
            .span(cur.since(start))
            .summary(format!(
                "{n_chunk} chunk(s): {}{}",
                shown.join(", "),
                if n_chunk > 16 { ", …" } else { "" }
            ));
        if pseudo {
            node = node.desc("Pseudo-bin with mapped/unmapped counts");
        }
        if let Some(l) = loffset {
            node = node.desc(format!("loffset {}", voffset(l)));
        }
        cx.push(node).await;
    }
    if kind != IndexKind::Csi && cur.remaining() >= 4 {
        let start = cur.pos();
        let n_intv = cur.u32().await?;
        let s = cur.span(u64::from(n_intv).saturating_mul(8));
        cur.skip(s.len);
        cx.push(
            Node::new("Linear index")
                .span(cur.since(start))
                .summary(format!("{n_intv} 16 kbp interval(s)")),
        )
        .await;
    }
    Ok(())
}

const TABIX_PRESETS: EnumTable = &[
    (0, "generic"),
    (1, "SAM"),
    (2, "VCF"),
    (0x10000, "generic, UCSC 0-based"),
];

async fn tabix_header(cx: &Cx, stream: Span) -> Result<(u32, Vec<String>, u64)> {
    let block = cx.block(stream.sub(0, 36)).await?;
    let mut f = Fields::emitting(cx, &block, LE);
    f.ascii("Magic", 4).emit()?;
    f.u32("n_ref").emit()?;
    let format = f.u32("format").enumeration(TABIX_PRESETS).emit()?;
    f.u32("col_seq")
        .desc("Column of the sequence name (1-based)")
        .emit()?;
    f.u32("col_beg").emit()?;
    f.u32("col_end").emit()?;
    f.u32("meta")
        .desc("Comment line prefix character")
        .with(|&v, n| {
            n.summary(
                char::from_u32(v)
                    .map(|c| format!("{c:?}"))
                    .unwrap_or_default(),
            )
        })
        .emit()?;
    f.u32("skip").desc("Header lines to skip").emit()?;
    let l_nm = f.u32("l_nm").emit()?;
    let names_span = stream.sub(36, l_nm.into());
    let names = cx.read_avail(names_span.sub(0, 0x100000)).await?;
    let names: Vec<String> = names
        .split(|&b| b == 0)
        .filter(|n| !n.is_empty())
        .map(|n| String::from_utf8_lossy(n).into_owned())
        .collect();
    cx.emit(
        Node::new("Sequence names")
            .span(names_span)
            .summary(preview(&names.join(", "), 120)),
    );
    Ok((format, names, 36u64.saturating_add(l_nm.into())))
}

async fn tabix(cx: Cx, input: Input) -> Result<()> {
    let (stream, complete) = bgzf_stream(&cx, input.span, false).await?;
    cx.emit(blocks_node(input));
    let (format, names, start) = tabix_header(&cx, stream).await?;
    let mut node = Node::new("Index").span(stream.tail(start)).lazy(
        index_refs,
        (stream.tail(start), IndexKind::Tabix, names.clone()),
    );
    if let Some(d) = stream_note(complete) {
        node = node.diag(d);
    }
    cx.emit(node);
    cx.annotate(format!(
        "Tabix index ({}), {} sequence(s)",
        lookup(TABIX_PRESETS, format.into()).unwrap_or("custom"),
        names.len()
    ));
    Ok(())
}

async fn csi(cx: Cx, input: Input) -> Result<()> {
    let (stream, complete) = bgzf_stream(&cx, input.span, false).await?;
    cx.emit(blocks_node(input));
    let block = cx.block(stream.sub(0, 16)).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.ascii("Magic", 4).emit()?;
    let min_shift = f.u32("min_shift").emit()?;
    let depth = f.u32("depth").emit()?;
    let l_aux = f.u32("l_aux").emit()?;
    let aux = stream.sub(16, l_aux.into());
    let mut names = Vec::new();
    if l_aux >= 28 {
        // Tabix-style auxiliary data: the same header fields and names.
        let a = cx.read_avail(aux.sub(0, 0x100000)).await?;
        let nm = a.get(28..).unwrap_or_default();
        names = nm
            .split(|&b| b == 0)
            .filter(|n| !n.is_empty())
            .map(|n| String::from_utf8_lossy(n).into_owned())
            .collect();
    }
    cx.emit(
        Node::new("Auxiliary data")
            .span(aux)
            .summary(if names.is_empty() {
                format!("{l_aux} bytes")
            } else {
                preview(&names.join(", "), 120)
            }),
    );
    let n_ref_at = 16u64.saturating_add(l_aux.into());
    let n = cx.read_avail(stream.sub(n_ref_at, 4)).await?;
    let n_ref = u32_le(&n, 0).unwrap_or(0);
    cx.emit(
        Node::new("n_ref")
            .span(stream.sub(n_ref_at, 4))
            .value(uint(n_ref.into())),
    );
    let refs = stream.tail(n_ref_at.saturating_add(4));
    let names = if names.len() == to_usize(n_ref.into()) {
        names
    } else {
        (0..n_ref.min(100_000))
            .map(|i| format!("Reference {i}"))
            .collect()
    };
    let mut node = Node::new("Index")
        .span(refs)
        .lazy(index_refs, (refs, IndexKind::Csi, names));
    if let Some(d) = stream_note(complete) {
        node = node.diag(d);
    }
    cx.emit(node);
    cx.annotate(format!(
        "CSI index, min_shift {min_shift}, depth {depth}, {n_ref} reference(s)"
    ));
    Ok(())
}

declare_format!(pub BAI = "bai", "BAM index", ["bai"], "application/x-bai",
    Probe::Magic(&[(0, b"BAI\x01")]), bai);

async fn bai(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 8)).await?;
    cx.emit(
        Node::new("Magic")
            .span(file.sub(0, 4))
            .value(text("BAI\\1")),
    );
    let n_ref = u32_le(&head, 4).unwrap_or(0);
    cx.emit(
        Node::new("n_ref")
            .span(file.sub(4, 4))
            .value(uint(n_ref.into())),
    );
    let names = (0..n_ref.min(100_000))
        .map(|i| format!("Reference {i}"))
        .collect();
    cx.emit(
        Node::new("Index")
            .span(file.tail(8))
            .lazy(index_refs, (file.tail(8), IndexKind::Bai, names)),
    );
    cx.annotate(format!("BAM index, {n_ref} reference(s)"));
    Ok(())
}

// ---------------------------------------------------------------------------
// CRAM

declare_format!(pub CRAM = "cram", "Compressed Reference-oriented Alignment Map (CRAM)", ["cram"], "application/x-cram",
    Probe::Custom(|h| h.at(0, b"CRAM") && h.data.get(4).is_some_and(|&m| (1..=4).contains(&m))), cram);

/// Reads an ITF8 integer.
async fn itf8(cur: &mut Cursor<'_>) -> Result<i64> {
    let b0 = cur.u8().await?;
    let extra: u32 = match b0 {
        0..=0x7f => 0,
        0x80..=0xbf => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        _ => 4,
    };
    let rest = cur.bytes(extra.into()).await?;
    let v = if extra < 4 {
        rest.iter().fold(
            u32::from(b0) & (0xffu32 >> extra.saturating_add(1)),
            |a, &b| (a << 8) | u32::from(b),
        )
    } else {
        let r = |i: usize| u32::from(rest.get(i).copied().unwrap_or(0));
        (u32::from(b0 & 0xf) << 28) | (r(0) << 20) | (r(1) << 12) | (r(2) << 4) | (r(3) & 0xf)
    };
    Ok(i64::from(v.cast_signed()))
}

/// Reads an LTF8 integer.
async fn ltf8(cur: &mut Cursor<'_>) -> Result<i64> {
    let b0 = cur.u8().await?;
    let extra = u64::from(b0.leading_ones());
    let rest = cur.bytes(extra).await?;
    let mut v = if extra >= 7 {
        0
    } else {
        u64::from(b0) & (0xffu64 >> extra.saturating_add(1))
    };
    for &b in &rest {
        v = (v << 8) | u64::from(b);
    }
    Ok(v.cast_signed())
}

const CRAM_METHODS: EnumTable = &[
    (0, "raw"),
    (1, "gzip"),
    (2, "bzip2"),
    (3, "lzma"),
    (4, "rANS 4x8"),
    (5, "rANS Nx16"),
    (6, "adaptive arithmetic"),
    (7, "fqzcomp"),
    (8, "name tokeniser"),
];

const CRAM_CONTENT: EnumTable = &[
    (0, "FILE_HEADER"),
    (1, "COMPRESSION_HEADER"),
    (2, "MAPPED_SLICE"),
    (3, "reserved"),
    (4, "EXTERNAL_DATA"),
    (5, "CORE_DATA"),
];

#[derive(Clone, Copy, Debug)]
struct CramContainer {
    span: Span,
    header: Span,
    blocks: Span,
    ref_id: i64,
    start: i64,
    records: i64,
    n_blocks: i64,
}

async fn cram_container(cx: &Cx, file: Span, pos: u64, major: u8) -> Result<CramContainer> {
    let mut cur = Cursor::new(cx, file, LE);
    cur.seek(pos);
    let length = cur.u32().await?;
    let ref_id = itf8(&mut cur).await?;
    let start = itf8(&mut cur).await?;
    let _span = itf8(&mut cur).await?;
    let records = itf8(&mut cur).await?;
    if major >= 2 {
        ltf8(&mut cur).await?; // record counter
        ltf8(&mut cur).await?; // bases
    }
    let n_blocks = itf8(&mut cur).await?;
    let n_landmarks = itf8(&mut cur).await?;
    for _ in 0..n_landmarks.clamp(0, 100_000) {
        itf8(&mut cur).await?;
    }
    if major >= 3 {
        cur.skip(4);
    }
    let header = file.sub(pos, cur.pos().saturating_sub(pos));
    let blocks = file.sub(cur.pos(), length.into());
    Ok(CramContainer {
        span: file.sub(pos, header.len.saturating_add(length.into())),
        header,
        blocks,
        ref_id,
        start,
        records,
        n_blocks,
    })
}

async fn cram(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 26)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Magic", 4).emit()?;
    let major = f.u8("Major version").emit()?;
    let minor = f.u8("Minor version").emit()?;
    let id = f.bytes("File ID", 20).emit()?;
    cx.emit(
        Node::new("Containers")
            .span(file.tail(26))
            .lazy(cram_containers, (input, major)),
    );
    let first = cram_container(&cx, file, 26, major).await;
    let mut summary = format!("CRAM {major}.{minor}, {}", crate::text::until_nul(&id));
    if let Ok(c) = first {
        let text = cram_header_text(&cx, c.blocks, major)
            .await
            .unwrap_or_default();
        let refs = text.lines().filter(|l| l.starts_with("@SQ")).count();
        summary = format!("{summary}, {refs} reference(s) in header");
    }
    cx.annotate(summary);
    Ok(())
}

/// The SAM header text in the first (raw) block of the header container.
async fn cram_header_text(cx: &Cx, blocks: Span, major: u8) -> Result<String> {
    let block = cram_block(cx, blocks, 0, major).await?;
    if block.method != 0 {
        return Ok(String::new());
    }
    let data = cx.read_avail(block.data.sub(0, 0x10000)).await?;
    let len = u32_le(&data, 0).unwrap_or(0);
    Ok(String::from_utf8_lossy(
        data.get(4..to_usize(u64::from(len).saturating_add(4)).min(data.len()))
            .unwrap_or_default(),
    )
    .into_owned())
}

#[derive(Clone, Copy, Debug)]
struct CramBlock {
    span: Span,
    method: u8,
    content_type: u8,
    content_id: i64,
    raw_size: i64,
    data: Span,
}

async fn cram_block(cx: &Cx, region: Span, pos: u64, major: u8) -> Result<CramBlock> {
    let mut cur = Cursor::new(cx, region, LE);
    cur.seek(pos);
    let method = cur.u8().await?;
    let content_type = cur.u8().await?;
    let content_id = itf8(&mut cur).await?;
    let size = itf8(&mut cur).await?;
    let raw_size = itf8(&mut cur).await?;
    let data = region.sub(cur.pos(), size.max(0).unsigned_abs());
    cur.skip(data.len);
    if major >= 3 {
        cur.skip(4);
    }
    Ok(CramBlock {
        span: region.sub(pos, cur.pos().saturating_sub(pos)),
        method,
        content_type,
        content_id,
        raw_size,
        data,
    })
}

async fn cram_containers(cx: Cx, (input, major): (Input, u8)) -> Result<()> {
    let file = input.span;
    let mut pos = 26u64;
    let mut index = 0u32;
    while pos < file.len {
        let c = cram_container(&cx, file, pos, major).await?;
        let eof = c.ref_id == -1 && c.start == 4_542_278;
        let name = if index == 0 {
            "Header container".to_owned()
        } else if eof {
            "EOF container".to_owned()
        } else {
            format!("Container {index}")
        };
        let summary = if index == 0 || eof {
            format!("{} block(s)", c.n_blocks)
        } else {
            format!(
                "ref {} @{}, {} record(s), {} block(s)",
                c.ref_id, c.start, c.records, c.n_blocks
            )
        };
        cx.push(
            Node::new(name)
                .span(c.span)
                .summary(summary)
                .lazy(cram_container_node, (input, c.header, c.blocks, major)),
        )
        .await;
        index = index.saturating_add(1);
        pos = c
            .span
            .end()
            .saturating_sub(file.offset)
            .max(pos.saturating_add(1));
    }
    Ok(())
}

async fn cram_container_node(
    cx: Cx,
    (input, header, blocks, major): (Input, Span, Span, u8),
) -> Result<()> {
    let mut cur = Cursor::new(&cx, header, LE);
    let length = cur.u32().await?;
    cx.emit(
        Node::new("Length")
            .span(header.sub(0, 4))
            .value(uint(length.into())),
    );
    let fields: &[(&str, bool)] = if major >= 2 {
        &[
            ("Reference sequence ID", false),
            ("Start position", false),
            ("Alignment span", false),
            ("Number of records", false),
            ("Record counter", true),
            ("Bases", true),
            ("Number of blocks", false),
        ]
    } else {
        &[
            ("Reference sequence ID", false),
            ("Start position", false),
            ("Alignment span", false),
            ("Number of records", false),
            ("Number of blocks", false),
        ]
    };
    for &(name, long) in fields {
        let start = cur.pos();
        let v = if long {
            ltf8(&mut cur).await?
        } else {
            itf8(&mut cur).await?
        };
        cx.emit(Node::new(name).span(cur.since(start)).value(int(v)));
    }
    let start = cur.pos();
    let n = itf8(&mut cur).await?;
    let mut landmarks = Vec::new();
    for _ in 0..n.clamp(0, 100_000) {
        landmarks.push(itf8(&mut cur).await?.to_string());
    }
    cx.emit(
        Node::new("Landmarks")
            .span(cur.since(start))
            .value(text(landmarks.join(", "))),
    );
    if major >= 3 {
        let crc = cur.u32().await?;
        cx.emit(
            Node::new("CRC32")
                .span(header.sub(cur.pos().saturating_sub(4), 4))
                .value(hex(crc.into(), 32)),
        );
    }
    let mut pos = 0u64;
    let mut i = 0u32;
    while pos < blocks.len {
        let b = cram_block(&cx, blocks, pos, major).await?;
        let kind = lookup(CRAM_CONTENT, b.content_type.into()).unwrap_or("?");
        let method = lookup(CRAM_METHODS, b.method.into()).unwrap_or("?");
        cx.push(
            Node::new(format!("Block {i}"))
                .span(b.span)
                .summary(format!(
                    "{kind} (content {}), {method}, {} → {} bytes",
                    b.content_id, b.data.len, b.raw_size
                ))
                .lazy(cram_block_node, (input, b.span, b.data, b.method, major)),
        )
        .await;
        i = i.saturating_add(1);
        pos = pos.saturating_add(b.span.len.max(1));
    }
    Ok(())
}

async fn cram_block_node(
    cx: Cx,
    (input, span, data, method, major): (Input, Span, Span, u8, u8),
) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, LE);
    let start = cur.pos();
    let m = cur.u8().await?;
    cx.emit(
        Node::new("Method")
            .span(cur.since(start))
            .value(enumeration(CRAM_METHODS, m.into(), 8)),
    );
    let start = cur.pos();
    let t = cur.u8().await?;
    cx.emit(
        Node::new("Content type")
            .span(cur.since(start))
            .value(enumeration(CRAM_CONTENT, t.into(), 8)),
    );
    for name in ["Content ID", "Compressed size", "Raw size"] {
        let start = cur.pos();
        let v = itf8(&mut cur).await?;
        cx.emit(Node::new(name).span(cur.since(start)).value(int(v)));
    }
    if method == 0 && t == 0 {
        let head = cx.read_avail(data.sub(0, 4)).await?;
        let len = u32_le(&head, 0).unwrap_or(0);
        cx.emit(
            Node::new("Header length")
                .span(data.sub(0, 4))
                .value(uint(len.into())),
        );
        cx.emit(
            Node::new("SAM header")
                .span(data.sub(4, len.into()))
                .lazy(sam_header_lines, data.sub(4, len.into())),
        );
    } else if method == 1 {
        cx.emit(embedded("Data (gzip)", input.nested(data)));
    } else if method == 2 {
        cx.emit(embedded("Data (bzip2)", input.nested(data)));
    } else if method == 3 {
        // htslib's "lzma" blocks are .xz streams.
        cx.emit(embedded("Data (xz)", input.nested(data)));
    } else if method == 0 {
        cx.emit(Node::new("Data").span(data));
    } else {
        cx.emit(
            Node::new("Data")
                .span(data)
                .diag(Diagnostic::unsupported(format!(
                    "{} compression",
                    lookup(CRAM_METHODS, method.into()).unwrap_or("unknown")
                ))),
        );
    }
    if major >= 3 {
        let crc = cx
            .read_avail(span.sub(span.len.saturating_sub(4), 4))
            .await?;
        cx.emit(
            Node::new("CRC32")
                .span(span.sub(span.len.saturating_sub(4), 4))
                .value(hex(u32_le(&crc, 0).unwrap_or(0).into(), 32)),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// UCSC 2bit

declare_format!(pub TWOBIT = "2bit", "UCSC 2bit sequence", ["2bit"], "application/x-2bit",
    Probe::Magic(&[(0, b"\x43\x27\x41\x1a\0\0\0\0"), (0, b"\x1a\x41\x27\x43\0\0\0\0"), (0, b"\x43\x27\x41\x1a\x01\0\0\0")]), twobit);

async fn twobit(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let sig = cx.read(file.sub(0, 4)).await?;
    let endian = if sig == b"\x43\x27\x41\x1a" { LE } else { BE };
    let block = cx.block(file.sub(0, 16)).await?;
    let mut f = Fields::emitting(&cx, &block, endian);
    f.u32("Signature").hex().emit()?;
    let version = f.u32("Version").emit()?;
    let count = f.u32("Sequence count").emit()?;
    f.u32("Reserved").emit()?;
    cx.emit(
        Node::new("Sequences")
            .span(file.tail(16))
            .lazy(twobit_index, (input, endian, version, count)),
    );
    cx.annotate(format!("2bit v{version}, {count} sequence(s)"));
    Ok(())
}

async fn twobit_index(
    cx: Cx,
    (input, endian, version, count): (Input, Endian, u32, u32),
) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, endian);
    cur.seek(16);
    cx.set_count(Count::Exact(count.into()));
    for _ in 0..count {
        let start = cur.pos();
        let n = cur.u8().await?;
        let name = String::from_utf8_lossy(&cur.bytes(n.into()).await?).into_owned();
        let offset = if version == 1 {
            cur.u64().await?
        } else {
            cur.u32().await?.into()
        };
        let entry = cur.since(start);
        let mut rec = Cursor::new(&cx, file, endian);
        rec.seek(offset);
        let dna = rec.u32().await.unwrap_or(0);
        cx.push(
            Node::new(name)
                .span(entry)
                .summary(format!("{dna} bp"))
                .target(file.sub(offset, 4))
                .lazy(twobit_record, (input, endian, offset)),
        )
        .await;
    }
    Ok(())
}

async fn twobit_record(cx: Cx, (input, endian, offset): (Input, Endian, u64)) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, endian);
    cur.seek(offset);
    let start = cur.pos();
    let dna = cur.u32().await?;
    cx.emit(
        Node::new("DNA size")
            .span(cur.since(start))
            .value(uint(dna.into())),
    );
    let mut n_blocks = Vec::new();
    for name in ["N blocks", "Mask blocks"] {
        let start = cur.pos();
        let count = cur.u32().await?;
        let starts = cur.span(u64::from(count).saturating_mul(4));
        cur.skip(starts.len);
        let sizes = cur.span(u64::from(count).saturating_mul(4));
        cur.skip(sizes.len);
        let s = cx.read_avail(starts.sub(0, 64)).await?;
        let z = cx.read_avail(sizes.sub(0, 64)).await?;
        let read = |b: &[u8], i: usize| match endian {
            Endian::Little => u32_le(b, i.saturating_mul(4)).unwrap_or(0),
            Endian::Big => u32_be(b, i.saturating_mul(4)).unwrap_or(0),
        };
        let shown: Vec<(u32, u32)> = (0..to_usize(count.min(16).into()))
            .map(|i| (read(&s, i), read(&z, i)))
            .collect();
        if name == "N blocks" {
            n_blocks.clone_from(&shown);
        }
        let list: Vec<String> = shown.iter().map(|(a, b)| format!("{a}+{b}")).collect();
        cx.emit(summarize(
            Node::new(name)
                .span(cur.since(start))
                .value(uint(count.into())),
            format!("{}{}", list.join(", "), if count > 16 { ", …" } else { "" }),
        ));
    }
    let start = cur.pos();
    cur.skip(4);
    cx.emit(Node::new("Reserved").span(cur.since(start)));
    let packed = cur.span(u64::from(dna).div_ceil(4));
    let head = cx.read_avail(packed.sub(0, 32)).await?;
    let mut seq = String::new();
    for (i, b) in head.iter().enumerate() {
        for k in 0..4u32 {
            let pos = to_u64(i).saturating_mul(4).saturating_add(k.into());
            if pos >= u64::from(dna) {
                break;
            }
            let base = (b >> (6u32.saturating_sub(k.saturating_mul(2)))) & 3;
            let in_n = n_blocks
                .iter()
                .any(|&(s, l)| pos >= u64::from(s) && pos < u64::from(s).saturating_add(l.into()));
            seq.push(if in_n {
                'N'
            } else {
                char::from(b"TCAG".get(usize::from(base)).copied().unwrap_or(b'N'))
            });
        }
    }
    cx.emit(
        Node::new("Packed DNA")
            .span(packed)
            .value(text(if u64::from(dna) > 128 {
                format!("{seq}…")
            } else {
                seq
            }))
            .desc("2 bits per base: T, C, A, G"),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// BigWig / BigBed

fn bbi_probe(h: &Head<'_>, magic: u32) -> bool {
    u32_le(h.data, 0) == Some(magic) || u32_be(h.data, 0) == Some(magic)
}

declare_format!(pub BIGWIG = "bigwig", "UCSC BigWig", ["bw", "bigwig"], "application/x-bigwig",
    Probe::Custom(|h| bbi_probe(h, 0x888f_fc26)), bigwig);
declare_format!(pub BIGBED = "bigbed", "UCSC BigBed", ["bb", "bigbed"], "application/x-bigbed",
    Probe::Custom(|h| bbi_probe(h, 0x8789_f2eb)), bigbed);

record! {
    pub struct BbiHeader {
        magic: u32 "magic" .hex(),
        version: u16 "version",
        zoom_levels: u16 "zoomLevels",
        chrom_tree: u64 "chromosomeTreeOffset" .hex(),
        full_data: u64 "fullDataOffset" .hex(),
        full_index: u64 "fullIndexOffset" .hex(),
        field_count: u16 "fieldCount",
        defined_field_count: u16 "definedFieldCount",
        auto_sql: u64 "autoSqlOffset" .hex(),
        total_summary: u64 "totalSummaryOffset" .hex(),
        uncompress_buf: u32 "uncompressBufSize" .desc("0 if data is not compressed"),
        extension: u64 "extensionOffset" .hex(),
    }
}

record! {
    pub struct BbiZoom {
        reduction: u32 "reductionLevel",
        reserved: u32 "reserved",
        data: u64 "dataOffset" .hex(),
        index: u64 "indexOffset" .hex(),
    }
}

record! {
    pub struct BbiSummary {
        bases: u64 "basesCovered",
        min: f64 "minVal",
        max: f64 "maxVal",
        sum: f64 "sumData",
        sum_squares: f64 "sumSquares",
    }
}

record! {
    pub struct BptHeader {
        magic: u32 "magic" .hex(),
        block_size: u32 "blockSize",
        key_size: u32 "keySize",
        val_size: u32 "valSize",
        item_count: u64 "itemCount",
        reserved: u64 "reserved",
    }
}

record! {
    pub struct RTreeHeader {
        magic: u32 "magic" .hex(),
        block_size: u32 "blockSize",
        item_count: u64 "itemCount",
        start_chrom: u32 "startChromIx",
        start_base: u32 "startBase",
        end_chrom: u32 "endChromIx",
        end_base: u32 "endBase",
        end_file_offset: u64 "endFileOffset" .hex(),
        items_per_slot: u32 "itemsPerSlot",
        reserved: u32 "reserved",
    }
}

async fn bigwig(cx: Cx, input: Input) -> Result<()> {
    bbi(cx, input, false).await
}

async fn bigbed(cx: Cx, input: Input) -> Result<()> {
    bbi(cx, input, true).await
}

async fn bbi(cx: Cx, input: Input, bed: bool) -> Result<()> {
    let file = input.span;
    let sig = cx.read(file.sub(0, 4)).await?;
    let magic: u32 = if bed { 0x8789_f2eb } else { 0x888f_fc26 };
    let endian = if u32_le(&sig, 0) == Some(magic) {
        LE
    } else {
        BE
    };
    let hspan = file.sub(0, BbiHeader::SIZE);
    let h: BbiHeader = read_record(&cx, hspan, endian).await?;
    cx.emit(BbiHeader::node("Header", hspan, endian));
    let zooms = file.sub(
        BbiHeader::SIZE,
        u64::from(h.zoom_levels).saturating_mul(BbiZoom::SIZE),
    );
    cx.emit(
        Node::new("Zoom levels")
            .span(zooms)
            .value(uint(h.zoom_levels.into()))
            .lazy(bbi_zooms, (zooms, endian)),
    );
    let mut summary = None;
    if h.total_summary != 0 {
        let s = file.sub(h.total_summary, BbiSummary::SIZE);
        let sum: BbiSummary = read_record(&cx, s, endian).await?;
        cx.emit(
            BbiSummary::node("Total summary", s, endian)
                .summary(format!("{} bases, {}–{}", sum.bases, sum.min, sum.max)),
        );
        summary = Some(sum);
    }
    if h.auto_sql != 0 {
        let (sql, span) = cx.cstr(file.sub(h.auto_sql, 0x10000)).await?;
        let name = sql.split_whitespace().nth(1).unwrap_or_default().to_owned();
        cx.emit(
            Node::new("autoSql")
                .span(span)
                .value(text(sql))
                .summary(name),
        );
    }
    if h.extension != 0 {
        let e = file.sub(h.extension, 12);
        let b = cx.block(e).await?;
        let mut f = Fields::new(&b, endian);
        let size = f.u16("extensionSize").get()?;
        let extra = f.u16("extraIndexCount").get()?;
        cx.emit(
            Node::new("Extension header")
                .span(e)
                .summary(format!("{size} bytes, {extra} extra index(es)"))
                .lazy(bbi_extension, (e, endian)),
        );
    }
    let chroms = bbi_chroms(&cx, file, h.chrom_tree, endian)
        .await
        .unwrap_or_default();
    cx.emit(
        Node::new("Chromosome B+ tree")
            .span(file.sub(h.chrom_tree, BptHeader::SIZE))
            .summary(format!("{} chromosome(s)", chroms.0.len()))
            .lazy(bbi_tree, (file, h.chrom_tree, endian)),
    );
    let count_len = if bed { 8 } else { 4 };
    let dc = cx.read_avail(file.sub(h.full_data, count_len)).await?;
    let data_count = if bed {
        match endian {
            Endian::Little => crate::bytes::u64_le(&dc, 0),
            Endian::Big => crate::bytes::u64_be(&dc, 0),
        }
    } else {
        match endian {
            Endian::Little => u32_le(&dc, 0).map(u64::from),
            Endian::Big => u32_be(&dc, 0).map(u64::from),
        }
    }
    .unwrap_or(0);
    cx.emit(
        Node::new("Data")
            .span(file.sub(h.full_data, h.full_index.saturating_sub(h.full_data)))
            .summary(format!(
                "{data_count} {}",
                if bed { "item(s)" } else { "section(s)" }
            )),
    );
    cx.emit(
        Node::new("R-tree index")
            .span(file.sub(h.full_index, RTreeHeader::SIZE))
            .lazy(
                rtree,
                (
                    input,
                    h.full_index,
                    endian,
                    bed,
                    h.uncompress_buf > 0,
                    chroms.clone(),
                ),
            ),
    );
    let mut note = format!(
        "{} v{}, {} chromosome(s), {} zoom level(s){}",
        if bed { "BigBed" } else { "BigWig" },
        h.version,
        chroms.0.len(),
        h.zoom_levels,
        if h.uncompress_buf > 0 {
            ", zlib-compressed"
        } else {
            ""
        }
    );
    if let Some(s) = summary {
        note = format!("{note}, {} bases covered", s.bases);
    }
    cx.annotate(note);
    Ok(())
}

async fn bbi_zooms(cx: Cx, (span, endian): (Span, Endian)) -> Result<()> {
    let mut at = 0u64;
    while at < span.len {
        let s = span.sub(at, BbiZoom::SIZE);
        let z: BbiZoom = read_record(&cx, s, endian).await?;
        cx.push(
            BbiZoom::node(format!("Level {}", at / BbiZoom::SIZE), s, endian)
                .summary(format!("{} bp per item", z.reduction)),
        )
        .await;
        at = at.saturating_add(BbiZoom::SIZE);
    }
    Ok(())
}

async fn bbi_extension(cx: Cx, (span, endian): (Span, Endian)) -> Result<()> {
    let b = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &b, endian);
    f.u16("extensionSize").emit()?;
    f.u16("extraIndexCount").emit()?;
    f.u64("extraIndexListOffset").hex().emit()?;
    Ok(())
}

/// Chromosome names and sizes from the B+ tree, by chromosome ID.
async fn bbi_chroms(cx: &Cx, file: Span, at: u64, endian: Endian) -> Result<References> {
    let h: BptHeader = read_record(cx, file.sub(at, BptHeader::SIZE), endian).await?;
    let mut out = Vec::new();
    let mut stack = vec![(at.saturating_add(BptHeader::SIZE), 0u32)];
    let mut visited = 0u32;
    while let Some((node, depth)) = stack.pop() {
        visited = visited.saturating_add(1);
        if depth > 16 || visited > 10_000 || out.len() > 1_000_000 {
            break;
        }
        let mut cur = Cursor::new(cx, file, endian);
        cur.seek(node);
        let leaf = cur.u8().await? != 0;
        cur.skip(1);
        let count = cur.u16().await?;
        let mut children = Vec::new();
        for _ in 0..count {
            let key = cur.bytes(h.key_size.into()).await?;
            if leaf {
                let id = cur.u32().await?;
                let size = cur.u32().await?;
                cur.skip(u64::from(h.val_size).saturating_sub(8));
                out.push((id, crate::text::until_nul(&key), size));
            } else {
                children.push((cur.u64().await?, depth.saturating_add(1)));
            }
        }
        stack.extend(children.into_iter().rev());
    }
    out.sort_by_key(|(id, _, _)| *id);
    Ok(References(
        out.into_iter().map(|(_, n, s)| (n, s)).collect(),
    ))
}

async fn bbi_tree(cx: Cx, (file, at, endian): (Span, u64, Endian)) -> Result<()> {
    let hs = file.sub(at, BptHeader::SIZE);
    cx.emit(BptHeader::node("Header", hs, endian));
    let chroms = bbi_chroms(&cx, file, at, endian).await?;
    for (i, (name, size)) in chroms.0.iter().enumerate() {
        cx.push(
            Node::new(name.clone())
                .value(uint((*size).into()))
                .summary(format!("ID {i}, {size} bp")),
        )
        .await;
    }
    Ok(())
}

async fn rtree(
    cx: Cx,
    (input, at, endian, bed, compressed, chroms): (Input, u64, Endian, bool, bool, References),
) -> Result<()> {
    let file = input.span;
    let hs = file.sub(at, RTreeHeader::SIZE);
    cx.emit(RTreeHeader::node("Header", hs, endian));
    let mut stack = vec![(at.saturating_add(RTreeHeader::SIZE), 0u32)];
    let mut visited = 0u32;
    while let Some((node, depth)) = stack.pop() {
        visited = visited.saturating_add(1);
        if depth > 16 || visited > 100_000 {
            return Err(Diagnostic::limit("R-tree too deep or too large"));
        }
        let mut cur = Cursor::new(&cx, file, endian);
        cur.seek(node);
        let leaf = cur.u8().await? != 0;
        cur.skip(1);
        let count = cur.u16().await?;
        let mut children = Vec::new();
        for _ in 0..count {
            let start = cur.pos();
            let sc = cur.u32().await?;
            let sb = cur.u32().await?;
            let ec = cur.u32().await?;
            let eb = cur.u32().await?;
            let offset = cur.u64().await?;
            if leaf {
                let size = cur.u64().await?;
                let data = file.sub(offset, size);
                let (from, to) = (
                    ref_name(&chroms, sc.cast_signed()),
                    ref_name(&chroms, ec.cast_signed()),
                );
                let range = if sc == ec {
                    format!("{from}:{sb}-{eb}")
                } else {
                    format!("{from}:{sb}–{to}:{eb}")
                };
                cx.push(
                    Node::new(format!("Block {range}"))
                        .span(data)
                        .target(cur.since(start))
                        .summary(format!("{size} bytes"))
                        .lazy(
                            bbi_block,
                            (input, data, endian, bed, compressed, chroms.clone()),
                        ),
                )
                .await;
            } else {
                children.push((offset, depth.saturating_add(1)));
            }
        }
        stack.extend(children.into_iter().rev());
    }
    Ok(())
}

const BW_TYPES: EnumTable = &[(1, "bedGraph"), (2, "variableStep"), (3, "fixedStep")];

async fn bbi_block(
    cx: Cx,
    (input, data, endian, bed, compressed, chroms): (Input, Span, Endian, bool, bool, References),
) -> Result<()> {
    let body = if compressed {
        let d = crate::codec::inflate_span(&cx, data, true, None).await?;
        if let Some(e) = d.error {
            cx.diag(e);
        }
        d.span
    } else {
        data
    };
    let _ = input;
    let mut cur = Cursor::new(&cx, body, endian);
    if bed {
        while cur.remaining() >= 12 {
            let start = cur.pos();
            let chrom = cur.u32().await?;
            let s = cur.u32().await?;
            let e = cur.u32().await?;
            let (rest, _) = cur.cstr(0x10000).await?;
            cx.push(
                Node::new(format!(
                    "{}:{s}-{e}",
                    ref_name(&chroms, chrom.cast_signed())
                ))
                .span(cur.since(start))
                .value(text(rest.replace('\t', " "))),
            )
            .await;
        }
        return Ok(());
    }
    let hs = body.sub(0, 24);
    let b = cx.block(hs).await?;
    let mut f = Fields::emitting(&cx, &b, endian);
    let chrom = f.u32("chromId").emit()?;
    let start = f.u32("chromStart").emit()?;
    f.u32("chromEnd").emit()?;
    let step = f.u32("itemStep").emit()?;
    let span = f.u32("itemSpan").emit()?;
    let kind = f.u8("type").enumeration(BW_TYPES).emit()?;
    f.u8("reserved").emit()?;
    let count = f.u16("itemCount").emit()?;
    cur.seek(24);
    let chrom = ref_name(&chroms, chrom.cast_signed());
    for i in 0..count {
        let at = cur.pos();
        let (s, e, v) = match kind {
            1 => {
                let s = cur.u32().await?;
                let e = cur.u32().await?;
                (s, e, cur.int::<f32>().await?)
            }
            2 => {
                let s = cur.u32().await?;
                (s, s.saturating_add(span), cur.int::<f32>().await?)
            }
            _ => {
                let s = start.saturating_add(step.saturating_mul(i.into()));
                (s, s.saturating_add(span), cur.int::<f32>().await?)
            }
        };
        cx.push(
            Node::new(format!("{chrom}:{s}-{e}"))
                .span(cur.since(at))
                .value(float32(v)),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ABIF (Applied Biosystems sequencing traces)

declare_format!(pub ABIF = "abif", "Applied Biosystems trace (ABIF)", ["ab1", "abi", "fsa", "hid"], "application/x-abif",
    Probe::Magic(&[(0, b"ABIF")]), abif);

record! {
    pub struct AbifEntry {
        name: ascii[4] "Tag name",
        number: u32 "Tag number",
        element_type: u16 "Element type" .enumeration(ABIF_TYPES),
        element_size: u16 "Element size",
        count: u32 "Number of elements",
        data_size: u32 "Data size",
        data_offset: u32 "Data offset" .hex().desc("The data itself if it fits in 4 bytes"),
        handle: u32 "Data handle",
    }
}

const ABIF_TYPES: EnumTable = &[
    (1, "byte"),
    (2, "char"),
    (3, "word"),
    (4, "short"),
    (5, "long"),
    (7, "float"),
    (8, "double"),
    (10, "date"),
    (11, "time"),
    (12, "thumb"),
    (13, "bool"),
    (18, "pString"),
    (19, "cString"),
    (1023, "directory"),
];

const ABIF_TAGS: &[(&str, &str)] = &[
    ("PBAS", "Called bases"),
    ("PLOC", "Peak locations"),
    ("PCON", "Quality values"),
    ("DATA", "Channel data"),
    ("FWO_", "Base order"),
    ("SMPL", "Sample name"),
    ("RUND", "Run date"),
    ("RUNT", "Run time"),
    ("MCHN", "Instrument name"),
    ("MODL", "Instrument model"),
    ("LANE", "Lane/capillary"),
    ("TUBE", "Well ID"),
    ("CMNT", "Comment"),
    ("S/N%", "Signal strength per dye"),
    ("SPAC", "Average peak spacing"),
    ("DyeN", "Dye name"),
    ("DySN", "Dye set name"),
    ("HCFG", "Instrument class"),
    ("APrN", "Analysis protocol"),
    ("SVER", "Software version"),
    ("PDMF", "Mobility file"),
    ("CTID", "Container ID"),
    ("CTNM", "Container name"),
    ("RunN", "Run name"),
];

async fn abif(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 6)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Magic", 4).emit()?;
    let version = f.u16("Version").emit()?;
    let dir_span = file.sub(6, AbifEntry::SIZE);
    let dir: AbifEntry = read_record(&cx, dir_span, BE).await?;
    cx.emit(AbifEntry::node("Directory entry", dir_span, BE));
    let entries = file.sub(
        dir.data_offset.into(),
        u64::from(dir.count).saturating_mul(AbifEntry::SIZE),
    );
    cx.emit(
        Node::new("Directory")
            .span(entries)
            .value(uint(dir.count.into()))
            .lazy(abif_dir, (file, entries)),
    );
    // Summary: sample name, base count.
    let mut sample = String::new();
    let mut bases = None;
    let mut cur = 0u64;
    while cur < entries.len {
        let e: AbifEntry = read_record(&cx, entries.sub(cur, AbifEntry::SIZE), BE).await?;
        if e.name == "SMPL" && e.number == 1 {
            sample = abif_value(&cx, file, &e, entries.sub(cur, AbifEntry::SIZE))
                .await
                .unwrap_or_default();
        }
        if e.name == "PBAS" && e.number == 2 {
            bases = Some(e.count);
        }
        cur = cur.saturating_add(AbifEntry::SIZE);
    }
    cx.annotate(format!(
        "ABIF v{}.{:02}, {} tags{}{}",
        version / 100,
        version % 100,
        dir.count,
        if sample.is_empty() {
            String::new()
        } else {
            format!(", sample {sample}")
        },
        bases
            .map(|b| format!(", {b} bases called"))
            .unwrap_or_default()
    ));
    Ok(())
}

fn abif_data_span(file: Span, e: &AbifEntry, entry: Span) -> Span {
    if e.data_size <= 4 {
        entry.sub(20, e.data_size.into())
    } else {
        file.sub(e.data_offset.into(), e.data_size.into())
    }
}

/// Renders a small tag value.
async fn abif_value(cx: &Cx, file: Span, e: &AbifEntry, entry: Span) -> Result<String> {
    let span = abif_data_span(file, e, entry);
    let data = cx.read_avail(span.sub(0, 256)).await?;
    Ok(match e.element_type {
        2 if e.name == "PBAS" => String::from_utf8_lossy(&data).into_owned(),
        2 | 19 => crate::text::until_nul(&data),
        18 => String::from_utf8_lossy(data.get(1..).unwrap_or_default()).into_owned(),
        4 => data
            .as_chunks::<2>()
            .0
            .iter()
            .take(16)
            .map(|c| {
                crate::bytes::u16_be(c, 0)
                    .unwrap_or(0)
                    .cast_signed()
                    .to_string()
            })
            .collect::<Vec<_>>()
            .join(", "),
        3 => data
            .as_chunks::<2>()
            .0
            .iter()
            .take(16)
            .map(|c| crate::bytes::u16_be(c, 0).unwrap_or(0).to_string())
            .collect::<Vec<_>>()
            .join(", "),
        5 => data
            .as_chunks::<4>()
            .0
            .iter()
            .take(16)
            .map(|c| u32_be(c, 0).unwrap_or(0).cast_signed().to_string())
            .collect::<Vec<_>>()
            .join(", "),
        1 => data
            .iter()
            .take(32)
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(", "),
        7 => data
            .as_chunks::<4>()
            .0
            .iter()
            .take(16)
            .map(|c| f32::from_bits(u32_be(c, 0).unwrap_or(0)).to_string())
            .collect::<Vec<_>>()
            .join(", "),
        10 => format!(
            "{:04}-{:02}-{:02}",
            crate::bytes::u16_be(&data, 0).unwrap_or(0),
            data.get(2).unwrap_or(&0),
            data.get(3).unwrap_or(&0)
        ),
        11 => format!(
            "{:02}:{:02}:{:02}.{:02}",
            data.first().unwrap_or(&0),
            data.get(1).unwrap_or(&0),
            data.get(2).unwrap_or(&0),
            data.get(3).unwrap_or(&0)
        ),
        _ => format!("{} bytes", e.data_size),
    })
}

async fn abif_dir(cx: Cx, (file, entries): (Span, Span)) -> Result<()> {
    let mut at = 0u64;
    while at < entries.len {
        let s = entries.sub(at, AbifEntry::SIZE);
        let e: AbifEntry = read_record(&cx, s, BE).await?;
        let value = abif_value(&cx, file, &e, s).await.unwrap_or_default();
        let desc = ABIF_TAGS
            .iter()
            .find(|(t, _)| *t == e.name)
            .map(|(_, d)| *d);
        let mut node = AbifEntry::node(format!("{}{}", e.name, e.number), s, BE)
            .value(text(preview(&value, 120)))
            .target(abif_data_span(file, &e, s));
        if let Some(d) = desc {
            node = node.desc(d);
        }
        if e.count > 16 && matches!(e.element_type, 3 | 4 | 5 | 7) {
            node = node.summary(format!("{} values", e.count));
        }
        cx.push(node).await;
        at = at.saturating_add(AbifEntry::SIZE);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// SCF (Staden trace format)

declare_format!(pub SCF = "scf", "Standard Chromatogram Format (SCF)", ["scf"], "application/x-scf",
    Probe::Magic(&[(0, b".scf")]), scf);

record! {
    pub struct ScfHeader {
        magic: ascii[4] "Magic",
        samples: u32 "Samples",
        samples_offset: u32 "Samples offset" .hex(),
        bases: u32 "Bases",
        left_clip: u32 "Bases left clip",
        right_clip: u32 "Bases right clip",
        bases_offset: u32 "Bases offset" .hex(),
        comments_size: u32 "Comments size",
        comments_offset: u32 "Comments offset" .hex(),
        version: ascii[4] "Version",
        sample_size: u32 "Sample size" .desc("Bytes per trace sample"),
        code_set: u32 "Code set",
        private_size: u32 "Private data size",
        private_offset: u32 "Private data offset" .hex(),
        spare: bytes[72] "Spare",
    }
}

async fn scf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: ScfHeader = read_record(&cx, file.sub(0, ScfHeader::SIZE), BE).await?;
    cx.emit(ScfHeader::node("Header", file.sub(0, ScfHeader::SIZE), BE));
    let sample_bytes = u64::from(h.samples)
        .saturating_mul(4)
        .saturating_mul(h.sample_size.into());
    cx.emit(
        Node::new("Samples")
            .span(file.sub(h.samples_offset.into(), sample_bytes))
            .summary(format!("4 channels × {} samples", h.samples)),
    );
    let bases = file.sub(h.bases_offset.into(), u64::from(h.bases).saturating_mul(12));
    let v3 = h.version.starts_with('3');
    // Version 3 stores the base calls column-wise: peak indexes, 4 probability arrays, then bases.
    let calls = if v3 {
        bases.sub(u64::from(h.bases).saturating_mul(8), h.bases.into())
    } else {
        bases
    };
    let called = cx
        .read_avail(calls.sub(0, if v3 { 200 } else { 2400 }))
        .await?;
    let seq: String = if v3 {
        called.iter().map(|&b| char::from(b)).collect()
    } else {
        called
            .as_chunks::<12>()
            .0
            .iter()
            .map(|c| char::from(c.get(8).copied().unwrap_or(b'N')))
            .collect()
    };
    cx.emit(
        Node::new("Bases")
            .span(bases)
            .value(text(preview(&seq, 200)))
            .summary(format!("{} base(s)", h.bases)),
    );
    let comments = file.sub(h.comments_offset.into(), h.comments_size.into());
    cx.emit(
        Node::new("Comments")
            .span(comments)
            .lazy(scf_comments, comments),
    );
    if h.private_size > 0 {
        cx.emit(
            Node::new("Private data")
                .span(file.sub(h.private_offset.into(), h.private_size.into())),
        );
    }
    cx.annotate(format!(
        "SCF {}, {} bases, {} samples",
        h.version, h.bases, h.samples
    ));
    Ok(())
}

async fn scf_comments(cx: Cx, span: Span) -> Result<()> {
    let mut lines = crate::formats::util::lines::Lines::new(&cx, span);
    while let Some(line) = lines.next().await? {
        let t = line.text();
        let t = t.trim_end_matches('\0');
        if let Some((k, v)) = t.split_once('=') {
            cx.push(
                Node::new(k.trim().to_owned())
                    .span(line.content())
                    .value(text(v.trim())),
            )
            .await;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bc_subfield_is_found() {
        assert_eq!(bc_subfield(b"BC\x02\x00\x1b\x00"), Some(27));
        assert_eq!(bc_subfield(b"XY\x01\x00\x00BC\x02\x00\x10\x00"), Some(16));
        assert_eq!(bc_subfield(b"BC\x03\x00\x1b\x00\x00"), None);
    }

    #[test]
    fn flags_value_is_typed() {
        assert!(matches!(
            crate::formats::util::lines::flags(SAM_FLAGS, 0x41, 16),
            crate::value::Value::Flags { .. }
        ));
        assert_eq!(voffset(0x0001_0000_0005), "0x10000:5");
    }
}
