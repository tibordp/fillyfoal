//! Bencode, the serialisation of BitTorrent metainfo (`.torrent`) files.
//!
//! Values are integers `i42e`, byte strings `4:spam`, lists `l...e` and
//! dictionaries `d...e`. Nothing records the size of a container, so walking
//! one means scanning it; each container is scanned only when expanded.

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::datakit::{clip, hex_string, size};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::Value;

/// Deepest nesting the scanner accepts.
const MAX_DEPTH: u32 = 512;
/// Longest string decoded into a value.
const MAX_TEXT: u64 = 0x1000;

pub static FORMAT: Format = Format {
    name: "torrent",
    title: "BitTorrent metainfo (bencode)",
    extensions: &["torrent"],
    mime: "application/x-bittorrent",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

/// A dictionary whose first key is a short ASCII string, and a torrent key
/// somewhere in the head.
fn probe(h: &Head<'_>) -> bool {
    let data = h.data;
    if data.first() != Some(&b'd') {
        return false;
    }
    let digits = data
        .iter()
        .skip(1)
        .take_while(|b| b.is_ascii_digit())
        .count();
    if !(1..=3).contains(&digits) || data.get(digits.saturating_add(1)) != Some(&b':') {
        return false;
    }
    let has = |needle: &[u8]| data.windows(needle.len()).any(|w| w == needle);
    has(b"4:infod") || has(b"8:announce")
}

/// Buffered byte-at-a-time access to a region.
struct Scan<'a> {
    cx: &'a Cx,
    region: Span,
    buf: Vec<u8>,
    buf_start: u64,
}

impl<'a> Scan<'a> {
    fn new(cx: &'a Cx, region: Span) -> Self {
        Scan {
            cx,
            region,
            buf: Vec::new(),
            buf_start: 0,
        }
    }

    async fn byte(&mut self, at: u64) -> Result<u8> {
        let rel = at.wrapping_sub(self.buf_start);
        if at < self.buf_start || rel >= to_u64(self.buf.len()) {
            self.buf = self.cx.read_avail(self.region.sub(at, 0x1000)).await?;
            self.buf_start = at;
        }
        let rel = to_usize(at.saturating_sub(self.buf_start));
        self.buf.get(rel).copied().ok_or_else(|| {
            Diagnostic::truncated(
                Span::new(self.region.source, self.region.offset.saturating_add(at), 1),
                0,
            )
        })
    }

    /// Reads ASCII digits (with an optional leading minus) up to `end`.
    async fn number(&mut self, mut at: u64, end: u8) -> Result<(i128, u64)> {
        let start = at;
        let mut negative = false;
        let mut value = 0i128;
        loop {
            let b = self.byte(at).await?;
            at = at.saturating_add(1);
            match b {
                b'-' if at == start.saturating_add(1) => negative = true,
                b'0'..=b'9' => {
                    value = value
                        .checked_mul(10)
                        .and_then(|v| v.checked_add(i128::from(b.wrapping_sub(b'0'))))
                        .ok_or_else(|| self.malformed(start, "number too large"))?;
                }
                _ if b == end && at > start.saturating_add(1) => break,
                _ => return Err(self.malformed(start, "malformed number")),
            }
            if at.saturating_sub(start) > 40 {
                return Err(self.malformed(start, "number too long"));
            }
        }
        Ok((
            if negative {
                value.saturating_neg()
            } else {
                value
            },
            at,
        ))
    }

    fn malformed(&self, at: u64, what: &str) -> Diagnostic {
        Diagnostic::malformed(what.to_owned()).at(self.region.sub(at, 1))
    }

    /// Decodes the item at `at`, scanning containers to find their end.
    async fn item(&mut self, at: u64) -> Result<Item> {
        let kind = match self.byte(at).await? {
            b'i' => {
                let (value, end) = self.number(at.saturating_add(1), b'e').await?;
                return Ok(Item {
                    kind: Kind::Int(value),
                    start: at,
                    end,
                    count: 0,
                });
            }
            b'0'..=b'9' => {
                let (len, data) = self.number(at, b':').await?;
                let len = u64::try_from(len).map_err(|_| self.malformed(at, "bad length"))?;
                let end = data.saturating_add(len);
                if end > self.region.len {
                    return Err(Diagnostic::truncated(
                        Span::new(
                            self.region.source,
                            self.region.offset.saturating_add(data),
                            len,
                        ),
                        self.region.len.saturating_sub(data),
                    ));
                }
                return Ok(Item {
                    kind: Kind::Str { data, len },
                    start: at,
                    end,
                    count: 0,
                });
            }
            b'l' => Kind::List,
            b'd' => Kind::Dict,
            _ => return Err(self.malformed(at, "expected a bencode value")),
        };
        // Scan to the matching `e`, counting direct members.
        let mut depth = 1u32;
        let mut count = 0u64;
        let mut pos = at.saturating_add(1);
        loop {
            self.cx.checkpoint().await;
            let b = self.byte(pos).await?;
            if b == b'e' {
                depth = depth.saturating_sub(1);
                pos = pos.saturating_add(1);
                if depth == 0 {
                    break;
                }
                continue;
            }
            if depth == 1 {
                count = count.saturating_add(1);
            }
            match b {
                b'l' | b'd' => {
                    depth = depth.saturating_add(1);
                    if depth > MAX_DEPTH {
                        return Err(Diagnostic::limit(format!(
                            "containers nested deeper than {MAX_DEPTH}"
                        ))
                        .at(self.region.sub(pos, 1)));
                    }
                    pos = pos.saturating_add(1);
                }
                b'i' => pos = self.number(pos.saturating_add(1), b'e').await?.1,
                b'0'..=b'9' => {
                    let (len, data) = self.number(pos, b':').await?;
                    let len = u64::try_from(len).map_err(|_| self.malformed(pos, "bad length"))?;
                    pos = data.saturating_add(len);
                }
                _ => return Err(self.malformed(pos, "expected a bencode value")),
            }
        }
        if kind == Kind::Dict {
            count /= 2;
        }
        Ok(Item {
            kind,
            start: at,
            end: pos,
            count,
        })
    }

    /// The string at `at`, decoded lossily (bounded).
    async fn string(&mut self, item: &Item) -> Result<Vec<u8>> {
        match item.kind {
            Kind::Str { data, len } => self.cx.read(self.region.sub(data, len.min(MAX_TEXT))).await,
            _ => Err(self.malformed(item.start, "expected a string")),
        }
    }

    /// Finds `key` in the dictionary `dict`; returns the value item.
    async fn lookup(&mut self, dict: &Item, key: &[u8]) -> Result<Option<Item>> {
        if dict.kind != Kind::Dict {
            return Ok(None);
        }
        let mut pos = dict.start.saturating_add(1);
        while pos < dict.end.saturating_sub(1) {
            let k = self.item(pos).await?;
            let v = self.item(k.end).await?;
            if self.string(&k).await? == key {
                return Ok(Some(v));
            }
            pos = v.end;
        }
        Ok(None)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Int(i128),
    Str { data: u64, len: u64 },
    List,
    Dict,
}

#[derive(Clone, Copy, Debug)]
struct Item {
    kind: Kind,
    start: u64,
    end: u64,
    count: u64,
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let mut scan = Scan::new(&cx, input.span);
    let root = scan.item(0).await?;
    if let Ok(summary) = torrent_summary(&mut scan, &root).await {
        cx.annotate(summary);
    }
    let node = item_node(&mut scan, input.span, "Root".into(), &root, None).await?;
    cx.emit(node);
    // The info hash identifies the torrent: SHA-1 of the bencoded info dict.
    if let Ok(Some(info)) = scan.lookup(&root, b"info").await {
        let span = input
            .span
            .sub(info.start, info.end.saturating_sub(info.start));
        if span.len <= cx.limits().max_read {
            let bytes = cx.read(span).await?;
            cx.emit(
                Node::new("Info hash")
                    .span(span)
                    .value(Value::Text(hex_string(
                        &crate::formats::util::datakit::sha1(&bytes),
                    )))
                    .desc("SHA-1 of the bencoded info dictionary (BitTorrent v1)"),
            );
        }
    }
    if root.end < input.span.len {
        cx.emit(
            Node::new("Trailing data")
                .span(input.span.tail(root.end))
                .diag(Diagnostic::warning("data after the top-level value")),
        );
    }
    Ok(())
}

async fn torrent_summary(scan: &mut Scan<'_>, root: &Item) -> Result<String> {
    let Some(info) = scan.lookup(root, b"info").await? else {
        return Ok(format!("bencode dictionary ({} keys)", root.count));
    };
    let mut parts = vec!["torrent".to_owned()];
    if let Some(name) = scan.lookup(&info, b"name").await? {
        let name = scan.string(&name).await?;
        parts.push(format!("{:?}", clip(&String::from_utf8_lossy(&name), 60)));
    }
    if let Some(files) = scan.lookup(&info, b"files").await? {
        let mut total = 0u64;
        let mut pos = files.start.saturating_add(1);
        while pos < files.end.saturating_sub(1) {
            let file = scan.item(pos).await?;
            if let Some(Item {
                kind: Kind::Int(n), ..
            }) = scan.lookup(&file, b"length").await?
            {
                total = total.saturating_add(u64::try_from(n).unwrap_or(0));
            }
            pos = file.end;
        }
        parts.push(format!("{} files, {}", files.count, size(total)));
    } else if let Some(Item {
        kind: Kind::Int(n), ..
    }) = scan.lookup(&info, b"length").await?
    {
        parts.push(size(u64::try_from(n).unwrap_or(0)));
    }
    if let Some(Item {
        kind: Kind::Int(n), ..
    }) = scan.lookup(&info, b"piece length").await?
    {
        parts.push(format!("{} pieces", size(u64::try_from(n).unwrap_or(0))));
    }
    Ok(parts.join(", "))
}

/// A node for `item`, with containers expandable. `key` is the dictionary
/// key it belongs to, which gives some strings a special meaning.
async fn item_node(
    scan: &mut Scan<'_>,
    region: Span,
    name: String,
    item: &Item,
    key: Option<&[u8]>,
) -> Result<Node> {
    let span = region.sub(item.start, item.end.saturating_sub(item.start));
    let node = Node::new(name).span(span);
    Ok(match item.kind {
        Kind::Int(v) => match i64::try_from(v) {
            Ok(v) if key == Some(b"creation date") => {
                node.value(Value::Timestamp { unix_seconds: v })
            }
            Ok(v) => node.value(Value::Int { value: v, bits: 64 }),
            Err(_) => node.value(Value::Text(v.to_string())),
        },
        Kind::Str { data, len } => {
            let body = region.sub(data, len);
            if key == Some(b"pieces") {
                return Ok(node
                    .summary(format!("{} SHA-1 piece hashes", len / 20))
                    .lazy(pieces, body));
            }
            let bytes = scan.string(item).await?;
            let utf8 = std::str::from_utf8(&bytes)
                .ok()
                .filter(|s| !s.chars().any(|c| c.is_control() && c != '\n' && c != '\t'));
            match utf8 {
                Some(text) if len <= MAX_TEXT => node.value(Value::Text(text.to_owned())),
                Some(text) => node
                    .value(Value::Text(text.to_owned()))
                    .summary(format!("{len} bytes, truncated")),
                None => node
                    .value(Value::Bytes(bytes.get(..32).unwrap_or(&bytes).to_vec()))
                    .summary(format!("{len} bytes")),
            }
        }
        Kind::List => node.summary(format!("list ({})", item.count)).lazy(
            crate::expander!(self::members: (Span, u64)),
            (region, item.start),
        ),
        Kind::Dict => node.summary(format!("dict ({})", item.count)).lazy(
            crate::expander!(self::members: (Span, u64)),
            (region, item.start),
        ),
    })
}

async fn members(cx: Cx, (region, start): (Span, u64)) -> Result<()> {
    let mut scan = Scan::new(&cx, region);
    let container = scan.item(start).await?;
    cx.set_count(Count::Exact(container.count));
    let mut pos = start.saturating_add(1);
    let mut index = 0u64;
    while pos < container.end.saturating_sub(1) {
        let node = if container.kind == Kind::Dict {
            let k = scan.item(pos).await?;
            let v = scan.item(k.end).await?;
            let key = scan.string(&k).await?;
            pos = v.end;
            let name = clip(&String::from_utf8_lossy(&key), 80);
            item_node(&mut scan, region, name, &v, Some(&key)).await?
        } else {
            let v = scan.item(pos).await?;
            pos = v.end;
            item_node(&mut scan, region, format!("[{index}]"), &v, None).await?
        };
        cx.push(node).await;
        index = index.saturating_add(1);
    }
    Ok(())
}

async fn pieces(cx: Cx, span: Span) -> Result<()> {
    let n = span.len / 20;
    cx.set_count(Count::Exact(n));
    for i in 0..n {
        let at = span.sub(i.saturating_mul(20), 20);
        let hash = cx.read(at).await?;
        cx.push(
            Node::new(format!("Piece {i}"))
                .span(at)
                .value(Value::Text(hex_string(&hash))),
        )
        .await;
    }
    if !span.len.is_multiple_of(20) {
        cx.diag(Diagnostic::malformed(
            "piece hashes are not a multiple of 20 bytes",
        ));
    }
    Ok(())
}
