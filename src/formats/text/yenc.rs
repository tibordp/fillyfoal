//! yEnc (`=ybegin` ... `=yend`), the binary encoding of Usenet posts:
//! single files and multi-part posts (`=ypart`), each block decoded into a
//! derived source with its size and CRC-32 checked, and the parts of a file
//! joined when the post holds more than one.
//!
//! Reference: yEnc 1.3 (<http://www.yenc.org/yenc-draft.1.3.txt>).

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::Arc;

use crate::cx::Cx;
use crate::error::{DiagKind, Diagnostic, Result};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::{Origin, Span};
use crate::value::{Radix, Value};

use super::decode::{self, Decoded};
use super::scan::Lines;
use super::{plural, text_node};

pub static FORMAT: Format = Format {
    name: "yenc",
    title: "yEnc-encoded data",
    extensions: &["yenc", "ync", "yen"],
    mime: "text/x-yenc",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

/// A `=ybegin` line (with `size=` and `name=`) among the first lines.
fn probe(h: &Head<'_>) -> bool {
    h.data
        .split(|&b| b == b'\n')
        .take(64)
        .any(|l| parse(l, b"=ybegin ").is_some_and(|y| y.name.is_some() && y.get("size").is_some()))
}

/// One `key=value` of a `=y` line, with its position in the line.
#[derive(Clone, Debug)]
struct Param {
    key: String,
    value: String,
    at: u64,
    len: u64,
}

/// A parsed `=ybegin`, `=ypart` or `=yend` line.
#[derive(Clone, Debug, Default)]
struct YLine {
    params: Vec<Param>,
    /// `name=` takes the rest of the line (names may contain spaces).
    name: Option<Param>,
}

impl YLine {
    fn get(&self, key: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|p| p.key == key)
            .map(|p| p.value.as_str())
    }

    fn num(&self, key: &str) -> Option<u64> {
        self.get(key)?.parse().ok()
    }

    fn crc(&self, key: &str) -> Option<u32> {
        let v = self.get(key)?;
        let v = v.strip_prefix("0x").unwrap_or(v);
        u32::from_str_radix(v, 16).ok()
    }
}

/// Parses `line` if it starts with `keyword` (e.g. `=ybegin `).
fn parse(line: &[u8], keyword: &[u8]) -> Option<YLine> {
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let rest = line.strip_prefix(keyword)?;
    let base = keyword.len();
    let mut y = YLine::default();
    let mut pos = 0usize;
    while pos < rest.len() {
        let tail = rest.get(pos..)?;
        let skip = tail.iter().take_while(|&&b| b == b' ').count();
        pos = pos.saturating_add(skip);
        let tail = rest.get(pos..)?;
        if tail.is_empty() {
            break;
        }
        let at = crate::bytes::to_u64(base.saturating_add(pos));
        if let Some(name) = tail.strip_prefix(b"name=") {
            let value = super::encoding::decode_8bit(name).trim_end().to_owned();
            y.name = Some(Param {
                key: "name".to_owned(),
                len: crate::bytes::to_u64(tail.len()),
                value,
                at,
            });
            break;
        }
        let word_len = tail.iter().position(|&b| b == b' ').unwrap_or(tail.len());
        let word = tail.get(..word_len)?;
        if let Some(eq) = word.iter().position(|&b| b == b'=') {
            y.params.push(Param {
                key: String::from_utf8_lossy(word.get(..eq)?).to_ascii_lowercase(),
                value: String::from_utf8_lossy(word.get(eq.saturating_add(1)..)?).into_owned(),
                at,
                len: crate::bytes::to_u64(word_len),
            });
        }
        pos = pos.saturating_add(word_len.max(1));
    }
    Some(y)
}

/// Decodes yEnc-encoded lines: each byte is its value plus 42, and critical
/// bytes are escaped as `=` and the value plus 106. Line breaks are not
/// data.
pub fn ydecode(data: &[u8]) -> Vec<u8> {
    let mut y = YDecoder::new(Expect::default(), data.len());
    decode::Step::step(&mut y, data, usize::MAX);
    y.out
}

/// [`ydecode`] a bounded number of bytes at a time, with the decoded size
/// checked against the promise at the end.
struct YDecoder {
    expect: Expect,
    pos: usize,
    escape: bool,
    out: Vec<u8>,
}

impl YDecoder {
    fn new(expect: Expect, len: usize) -> Self {
        YDecoder {
            expect,
            pos: 0,
            escape: false,
            out: Vec::with_capacity(len),
        }
    }
}

impl decode::Step for YDecoder {
    fn step(&mut self, data: &[u8], limit: usize) -> bool {
        let end = self.pos.saturating_add(limit).min(data.len());
        for &b in data.get(self.pos..end).unwrap_or_default() {
            match b {
                b'\r' | b'\n' => continue,
                b'=' if !self.escape => {
                    self.escape = true;
                    continue;
                }
                _ => {}
            }
            let v = if self.escape { b.wrapping_sub(64) } else { b };
            self.escape = false;
            self.out.push(v.wrapping_sub(42));
        }
        self.pos = end;
        self.pos >= data.len()
    }

    fn finish(self) -> Decoded {
        let error = self.expect.check(&self.out);
        Decoded {
            bytes: self.out,
            error,
        }
    }
}

/// What a block's trailer and headers promise about its decoded bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Expect {
    size: Option<u64>,
    crc: Option<u32>,
}

impl Expect {
    /// A mismatch between the size of `data` and the promise (the CRC is
    /// checked separately, see [`crc_node`]).
    fn check(&self, data: &[u8]) -> Option<String> {
        let len = crate::bytes::to_u64(data.len());
        if let Some(size) = self.size
            && size != len
        {
            return Some(format!("{len} bytes decoded, {size} expected"));
        }
        None
    }
}

/// One `=ybegin` ... `=yend` block.
#[derive(Clone, Debug)]
struct Block {
    input: Input,
    span: Span,
    begin: (Span, YLine),
    part: Option<(Span, YLine)>,
    body: Span,
    end: Option<(Span, YLine)>,
}

impl Block {
    fn name(&self) -> String {
        self.begin
            .1
            .name
            .as_ref()
            .map_or_else(String::new, |n| n.value.clone())
    }

    fn part_number(&self) -> Option<u64> {
        self.begin.1.num("part")
    }

    /// Where this part starts in the file (1-based `begin=`).
    fn offset(&self) -> u64 {
        self.part
            .as_ref()
            .and_then(|(_, p)| p.num("begin"))
            .unwrap_or(1)
            .saturating_sub(1)
    }

    /// What the decoded block must be: a part checks against its own size
    /// and `pcrc32`, a single-part file against the whole size and `crc32`.
    fn expect(&self) -> Expect {
        let end = self.end.as_ref().map(|(_, y)| y);
        if self.part.is_some() {
            let size = end.and_then(|y| y.num("size")).or_else(|| {
                let p = &self.part.as_ref()?.1;
                Some(
                    p.num("end")?
                        .saturating_sub(p.num("begin")?)
                        .saturating_add(1),
                )
            });
            Expect {
                size,
                crc: end.and_then(|y| y.crc("pcrc32")),
            }
        } else {
            Expect {
                size: end
                    .and_then(|y| y.num("size"))
                    .or_else(|| self.begin.1.num("size")),
                crc: end.and_then(|y| y.crc("crc32")),
            }
        }
    }
}

/// The most blocks remembered for joining parts.
const MAX_BLOCKS: usize = 100_000;

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let span = input.span;
    let mut lines = Lines::new(&cx, span);
    let mut blocks: Vec<Block> = Vec::new();
    let mut count = 0u64;
    let mut first = true;
    let mut text_end = 0u64;
    while let Some(line) = lines.next().await? {
        let Some(begin) = parse(&line.bytes, b"=ybegin ") else {
            if first {
                text_end = line.next;
            }
            continue;
        };
        if first && text_end > 0 {
            cx.push(
                Node::new("Text")
                    .span(span.sub(0, text_end))
                    .summary("before the first =ybegin line"),
            )
            .await;
        }
        first = false;
        let start = line.start;
        let mut body_start = line.next;
        let mut part = None;
        if let Some(next) = lines.peek().await?
            && let Some(p) = parse(&next.bytes, b"=ypart ")
        {
            lines.next().await?;
            part = Some((next.span, p));
            body_start = next.next;
        }
        let mut body_end = body_start;
        let mut end = None;
        let mut stop = body_start;
        loop {
            let (pos, number) = (lines.pos(), lines.number());
            let Some(l) = lines.next().await? else {
                break;
            };
            if let Some(y) = parse(&l.bytes, b"=yend") {
                end = Some((l.span, y));
                stop = l.next;
                break;
            }
            if l.bytes.starts_with(b"=ybegin ") {
                lines.seek(pos, number);
                break;
            }
            body_end = l.next;
            stop = l.next;
        }
        let block = Block {
            input,
            span: span.sub(start, stop.saturating_sub(start)),
            begin: (line.span, begin),
            part,
            body: span.sub(body_start, body_end.saturating_sub(body_start)),
            end,
        };
        count = count.saturating_add(1);
        lines.progress();
        cx.push(block_node(&block)).await;
        if blocks.len() < MAX_BLOCKS {
            blocks.push(block);
        }
    }
    // Parts of the same file, joined (names in order of appearance; a map
    // keeps this linear in the number of blocks).
    let mut names: Vec<String> = Vec::new();
    let mut groups: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, b) in blocks.iter().enumerate() {
        if i.is_multiple_of(1024) {
            cx.checkpoint().await;
        }
        if b.part.is_none() {
            continue;
        }
        match groups.entry(b.name()) {
            Entry::Occupied(e) => e.into_mut().push(i),
            Entry::Vacant(e) => {
                names.push(e.key().clone());
                e.insert(vec![i]);
            }
        }
    }
    for name in names {
        let indexes = groups.remove(&name).unwrap_or_default();
        let mut parts: Vec<Block> = Vec::with_capacity(indexes.len());
        for (n, &i) in indexes.iter().enumerate() {
            if n.is_multiple_of(1024) {
                cx.checkpoint().await;
            }
            parts.extend(blocks.get(i).cloned());
        }
        // At most `MAX_BLOCKS` parts: a bounded sort.
        parts.sort_by_key(Block::offset);
        let parts = Arc::new(parts);
        let total = parts.first().and_then(|b| b.begin.1.num("total"));
        let size = parts.first().and_then(|b| b.begin.1.num("size"));
        let (Some(a), Some(z)) = (parts.first(), parts.last()) else {
            continue;
        };
        let whole = Span::new(
            span.source,
            a.span.offset,
            z.span.end().saturating_sub(a.span.offset),
        );
        let mut summary = format!(
            "{} of {}",
            plural(crate::bytes::to_u64(parts.len()), "part", "parts"),
            total.map_or_else(|| "?".to_owned(), |t| t.to_string())
        );
        if let Some(s) = size {
            summary = format!("{summary}, {s} bytes");
        }
        cx.push(
            Node::new(format!("Joined: {name}"))
                .span(whole)
                .summary(summary)
                .lazy(joined, (input, whole, parts)),
        )
        .await;
    }
    cx.annotate(format!("yEnc, {}", plural(count, "block", "blocks")));
    Ok(())
}

fn block_node(b: &Block) -> Node {
    let y = &b.begin.1;
    let mut summary = String::from("yEnc");
    if let Some(p) = b.part_number() {
        summary = match y.num("total") {
            Some(t) => format!("{summary}, part {p} of {t}"),
            None => format!("{summary}, part {p}"),
        };
    }
    if let Some(size) = b.expect().size {
        summary = format!("{summary}, {size} bytes");
    }
    let name = match b.part_number() {
        Some(p) => format!("{} (part {p})", b.name()),
        None => b.name(),
    };
    let mut node = Node::new(name)
        .span(b.span)
        .summary(summary)
        .lazy(block_fields, b.clone());
    if b.end.is_none() {
        node = node.diag(Diagnostic::new(DiagKind::Truncated, "=yend line missing"));
    }
    node
}

/// Nodes for the parameters of a `=y` line at `span`.
fn line_node(title: &'static str, span: Span, y: &YLine) -> Node {
    Node::new(title)
        .span(span)
        .lazy(line_fields, (span, y.clone()))
}

async fn line_fields(cx: Cx, (span, y): (Span, YLine)) -> Result<()> {
    for p in y.params.iter().chain(y.name.iter()) {
        let at = span.sub(p.at, p.len);
        let node = match p.key.as_str() {
            "crc32" | "pcrc32" => match u32::from_str_radix(&p.value, 16) {
                Ok(v) => Node::new(p.key.clone()).span(at).value(Value::UInt {
                    value: u64::from(v),
                    bits: 32,
                    radix: Radix::Hex,
                }),
                Err(_) => text_node(p.key.clone(), at, &p.value),
            },
            _ => match p.value.parse::<u64>() {
                Ok(v) if p.key != "name" => Node::new(p.key.clone()).span(at).value(Value::UInt {
                    value: v,
                    bits: 64,
                    radix: Radix::Dec,
                }),
                _ => text_node(p.key.clone(), at, &p.value),
            },
        };
        cx.emit(node);
    }
    Ok(())
}

async fn block_fields(cx: Cx, b: Block) -> Result<()> {
    cx.emit(line_node("Header", b.begin.0, &b.begin.1));
    if let Some((span, y)) = &b.part {
        cx.emit(line_node("Part", *span, y));
    }
    let (span, error) = decode_block(&cx, &b).await?;
    let mut content = Node::new("Content")
        .span(b.body)
        .summary(format!("{:#x} bytes decoded", span.len))
        .lazy(dissect_decoded, (b.input, span));
    if let Some(e) = error {
        content = content.diag(e);
    }
    cx.emit(content);
    cx.emit(crc_node(&cx, span, b.expect().crc).await?);
    if let Some((span, y)) = &b.end {
        cx.emit(line_node("Trailer", *span, y));
    }
    Ok(())
}

/// Decodes a block's body into a derived source (once), with its size
/// checked.
async fn decode_block(cx: &Cx, b: &Block) -> Result<(Span, Option<Diagnostic>)> {
    let expect = b.expect();
    decode::derive_stepped(cx, b.body, "ydecode", |len| YDecoder::new(expect, len)).await
}

/// The CRC-32 of the bytes of `span`, checked against the trailer.
async fn crc_node(cx: &Cx, span: Span, want: Option<u32>) -> Result<Node> {
    // In pieces: each read is a suspension point, so a large body is
    // checksummed over several steps.
    const PIECE: u64 = 256 * 1024;
    let mut crc = !0u32;
    let mut pos = 0u64;
    while pos < span.len {
        let data = cx.read(span.sub(pos, PIECE)).await?;
        if data.is_empty() {
            break;
        }
        crate::formats::util::datakit::feed_paced(cx, &data, |piece| {
            crc = crate::codec::crc::crc32_update(crc, piece);
        })
        .await;
        pos = pos.saturating_add(crate::bytes::to_u64(data.len()));
    }
    let got = !crc;
    let node = Node::new("CRC-32").value(Value::UInt {
        value: u64::from(got),
        bits: 32,
        radix: Radix::Hex,
    });
    Ok(match want {
        Some(w) if w == got => node.summary("matches the trailer"),
        Some(w) => node.diag(Diagnostic::malformed(format!(
            "CRC-32 {got:08x}, {w:08x} expected"
        ))),
        None => node.summary("no CRC-32 in the trailer"),
    })
}

async fn dissect_decoded(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    crate::formats::dissect_or_data(cx, input.nested(span)).await
}

/// The parts of one file, decoded and concatenated in `begin=` order.
async fn joined(cx: Cx, (input, whole, parts): (Input, Span, Arc<Vec<Block>>)) -> Result<()> {
    let mut pieces = Vec::with_capacity(parts.len());
    let mut next = 0u64;
    for b in parts.iter() {
        cx.checkpoint().await;
        let (span, error) = decode_block(&cx, b).await?;
        if let Some(e) = error {
            cx.diag(e);
        }
        let offset = b.offset();
        if offset > next {
            cx.diag(Diagnostic::malformed(format!(
                "bytes {next}..{offset} missing (part not in this file)"
            )));
        } else if offset < next {
            cx.diag(Diagnostic::malformed(format!(
                "part at byte {offset} overlaps the previous one"
            )));
        }
        next = offset.saturating_add(span.len);
        pieces.push(span);
    }
    let joined = cx
        .add_pieces_stepped(
            Origin {
                parent: whole,
                transform: "yenc-join",
            },
            &pieces,
        )
        .await?;

    let size = parts.first().and_then(|b| b.begin.1.num("size"));
    let mut content = Node::new("Content")
        .span(whole)
        .summary(format!("{:#x} bytes", joined.len))
        .lazy(dissect_decoded, (input, joined));
    if let Some(size) = size
        && size != joined.len
    {
        content = content.diag(Diagnostic::new(
            DiagKind::Truncated,
            format!("{:#x} of {size:#x} bytes present", joined.len),
        ));
    }
    cx.emit(content);
    let crc = parts
        .iter()
        .find_map(|b| b.end.as_ref().and_then(|(_, y)| y.crc("crc32")));
    if crc.is_some() {
        cx.emit(crc_node(&cx, joined, crc).await?);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lines_and_decodes() {
        let y = parse(
            b"=ybegin part=1 total=2 line=128 size=500 name=my file.bin\r",
            b"=ybegin ",
        )
        .unwrap_or_default();
        assert_eq!(y.num("part"), Some(1));
        assert_eq!(y.num("size"), Some(500));
        assert_eq!(y.name.map(|n| n.value).as_deref(), Some("my file.bin"));
        assert!(
            parse(b"=yend size=3 crc32=abcdef12", b"=yend")
                .is_some_and(|y| y.crc("crc32") == Some(0xabcd_ef12))
        );
        // 0x00 -> '*', 0xd6 -> NUL (escaped as "=@"), 0xe0 -> LF ("=J").
        assert_eq!(ydecode(b"*=@\r\n=J"), [0x00, 0xd6, 0xe0]);
    }
}
