//! PDF syntax: an incremental parser for objects ([`Reader`]), which reads
//! its input as it goes and works in bounded steps, and a small cursor over
//! bytes in memory ([`Parser`]). Every parsed item records where it starts
//! and ends, so nodes get exact spans.

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::Diagnostic;
use crate::span::Span;

/// Nesting of arrays and dictionaries accepted.
const MAX_DEPTH: usize = 64;

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    Malformed(String, usize),
    /// Reading failed, or the object is too large.
    Stop(Diagnostic),
}

pub type PResult<T> = std::result::Result<T, Error>;

/// A parsed object and the buffer range it occupies.
#[derive(Clone, Debug)]
pub struct Item {
    pub start: usize,
    pub end: usize,
    pub obj: Obj,
}

#[derive(Clone, Debug)]
pub struct Entry {
    pub key: String,
    pub key_start: usize,
    pub value: Item,
}

#[derive(Clone, Debug)]
pub enum Obj {
    Null,
    Bool(bool),
    Int(i64),
    Real(f64),
    Str { bytes: Vec<u8>, hex: bool },
    Name(String),
    Ref(u32, u16),
    Array(Arc<Vec<Item>>),
    Dict(Arc<Vec<Entry>>),
}

impl Item {
    pub fn get(&self, key: &str) -> Option<&Item> {
        match &self.obj {
            Obj::Dict(entries) => entries.iter().find(|e| e.key == key).map(|e| &e.value),
            _ => None,
        }
    }

    pub fn int(&self) -> Option<i64> {
        match self.obj {
            Obj::Int(v) => Some(v),
            _ => None,
        }
    }

    pub fn name(&self) -> Option<&str> {
        match &self.obj {
            Obj::Name(n) => Some(n),
            _ => None,
        }
    }

    pub fn reference(&self) -> Option<(u32, u16)> {
        match self.obj {
            Obj::Ref(n, g) => Some((n, g)),
            _ => None,
        }
    }

    pub fn array(&self) -> Option<&[Item]> {
        match &self.obj {
            Obj::Array(items) => Some(items),
            _ => None,
        }
    }

    pub fn is_dict(&self) -> bool {
        matches!(self.obj, Obj::Dict(_))
    }
}

pub fn is_white(b: u8) -> bool {
    matches!(b, 0 | b'\t' | b'\n' | 0x0c | b'\r' | b' ')
}

fn is_delim(b: u8) -> bool {
    matches!(
        b,
        b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
    )
}

fn is_regular(b: u8) -> bool {
    !is_white(b) && !is_delim(b)
}

/// A cursor over a small buffer held whole in memory (the tail of the
/// file, a few bytes after an object): words, keywords and integers only.
pub struct Parser<'a> {
    data: &'a [u8],
    pub pos: usize,
}

impl<'a> Parser<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Parser { data, pos: 0 }
    }

    pub fn at(data: &'a [u8], pos: usize) -> Self {
        Parser { data, pos }
    }

    fn peek(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    fn bump(&mut self) {
        self.pos = self.pos.saturating_add(1);
    }

    /// Skips whitespace and comments.
    pub fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            if is_white(b) {
                self.bump();
            } else if b == b'%' {
                while let Some(c) = self.peek() {
                    if c == b'\r' || c == b'\n' {
                        break;
                    }
                    self.bump();
                }
            } else {
                break;
            }
        }
    }

    /// The bare word (keyword or number) at the cursor.
    pub fn word(&mut self) -> &'a [u8] {
        let rest = self.data.get(self.pos..).unwrap_or_default();
        let end = rest
            .iter()
            .position(|&b| !is_regular(b))
            .unwrap_or(rest.len());
        self.pos = self.pos.saturating_add(end);
        rest.get(..end).unwrap_or_default()
    }

    /// Consumes `keyword` (after whitespace) if it is next.
    pub fn keyword(&mut self, keyword: &[u8]) -> bool {
        self.skip_ws();
        let save = self.pos;
        if self.word() == keyword {
            return true;
        }
        self.pos = save;
        false
    }

    /// An unsigned integer word.
    pub fn uint(&mut self) -> Option<u64> {
        self.skip_ws();
        std::str::from_utf8(self.word()).ok()?.parse().ok()
    }
}

/// How a [`Reader`] reads past what it holds.
#[derive(Clone, Copy, Debug)]
enum Growth {
    /// A window of 4 KiB at first, four times larger each time, up to
    /// `max` bytes (one object).
    Object { max: u64 },
    /// Pieces of [`PIECE`] bytes, with no limit (a content stream).
    Pieces,
}

/// First window of [`Growth::Object`].
const FIRST_WINDOW: u64 = 4096;
/// Read size of [`Growth::Pieces`].
const PIECE: u64 = 1 << 16;
/// Bytes a reader scans per unit of work, and at most between suspension
/// points.
const UNIT: usize = 1024;
/// Work charged per token, in bytes scanned.
const TOKEN_COST: usize = 64;
/// Longest bare word (name, number, keyword) accepted. Real ones are a few
/// dozen bytes; this bounds the work spent decoding one.
pub const MAX_WORD: usize = 1 << 16;

/// A parser that reads its input as it goes, in bounded steps: it reads
/// more only when it needs to look further, and suspends (charging the
/// work budget) every [`UNIT`] bytes scanned, so no object, however large,
/// is parsed in one step. Positions are offsets from where it starts.
pub struct Reader<'c> {
    cx: Option<&'c Cx>,
    region: Span,
    /// Where the reader starts, in `region`.
    offset: u64,
    growth: Growth,
    /// Bytes requested so far, from `offset`.
    window: u64,
    /// Bytes from position `base` on (earlier ones were released).
    buf: Vec<u8>,
    base: usize,
    pub pos: usize,
    /// Whether `buf` reaches the end of `region`.
    complete: bool,
    /// Bytes scanned since the last suspension point.
    work: usize,
    /// Without a `Cx` (tests): the bytes not handed out yet, and how many
    /// each read hands out.
    rest: Vec<u8>,
    trickle: usize,
}

impl<'c> Reader<'c> {
    /// A reader for one object at `offset` in `region`, of at most `max`
    /// bytes.
    pub fn for_object(cx: &'c Cx, region: Span, offset: u64, max: u64) -> Self {
        Reader::new(Some(cx), region, offset, Growth::Object { max })
    }

    /// A reader over all of `span`, which may be large: the caller releases
    /// what it no longer needs with [`Reader::release`].
    pub fn pieces(cx: &'c Cx, span: Span) -> Self {
        Reader::new(Some(cx), span, 0, Growth::Pieces)
    }

    /// A reader over bytes in memory (for tests).
    #[cfg(test)]
    pub fn memory(data: &[u8]) -> Self {
        Reader::trickle(data, usize::MAX)
    }

    /// A reader over bytes in memory that reads `piece` bytes at a time
    /// (for tests).
    #[cfg(test)]
    pub fn trickle(data: &[u8], piece: usize) -> Self {
        let mut r = Reader::new(None, Span::zeros(to_u64(data.len())), 0, Growth::Pieces);
        r.rest = data.to_vec();
        r.trickle = piece.max(1);
        r
    }

    fn new(cx: Option<&'c Cx>, region: Span, offset: u64, growth: Growth) -> Self {
        Reader {
            cx,
            region,
            offset,
            growth,
            window: 0,
            buf: Vec::new(),
            base: 0,
            pos: 0,
            complete: false,
            work: 0,
            rest: Vec::new(),
            trickle: 0,
        }
    }

    /// The bytes requested so far: positions are relative to its start.
    pub fn window(&self) -> Span {
        self.region.sub(self.offset, self.window)
    }

    /// The end of the bytes read so far.
    pub fn end(&self) -> usize {
        self.base.saturating_add(self.buf.len())
    }

    fn byte(&self, at: usize) -> Option<u8> {
        self.buf.get(at.checked_sub(self.base)?).copied()
    }

    /// Bytes `from..to` (those still held).
    pub fn slice(&self, from: usize, to: usize) -> &[u8] {
        let from = from.saturating_sub(self.base);
        let to = to.saturating_sub(self.base);
        self.buf.get(from..to).unwrap_or_default()
    }

    /// Drops the bytes before `at`, when that frees enough to be worth it.
    pub fn release(&mut self, at: usize) {
        let n = at.saturating_sub(self.base).min(self.buf.len());
        if n >= to_usize(PIECE) && n >= self.buf.len() / 2 {
            self.buf.drain(..n);
            self.base = self.base.saturating_add(n);
        }
    }

    fn malformed(&self, msg: impl Into<String>) -> Error {
        Error::Malformed(msg.into(), self.pos)
    }

    fn eof(&self) -> Error {
        Error::Malformed("unexpected end of data".to_owned(), self.pos)
    }

    /// Charges for `n` bytes scanned, suspending every [`UNIT`].
    async fn charge(&mut self, n: usize) {
        self.work = self.work.saturating_add(n);
        while self.work >= UNIT {
            self.work = self.work.saturating_sub(UNIT);
            if let Some(cx) = self.cx {
                cx.checkpoint().await;
            }
        }
    }

    /// Reads more; false at the end of the region.
    async fn fill(&mut self) -> PResult<bool> {
        if self.complete {
            return Ok(false);
        }
        let Some(cx) = self.cx else {
            let n = self.trickle.min(self.rest.len());
            self.buf.extend(self.rest.drain(..n));
            self.window = self.window.saturating_add(to_u64(n));
            self.complete = self.rest.is_empty();
            return Ok(n > 0);
        };
        let next = match self.growth {
            Growth::Object { max } => {
                if self.window >= max {
                    return Err(Error::Stop(
                        Diagnostic::limit(format!(
                            "object at {:#x} is larger than {max:#x} bytes",
                            self.offset
                        ))
                        .at(self.window()),
                    ));
                }
                if self.window == 0 {
                    FIRST_WINDOW
                } else {
                    self.window.saturating_mul(4)
                }
            }
            Growth::Pieces => self.window.saturating_add(PIECE),
        };
        let span = self.region.sub(
            self.offset.saturating_add(self.window),
            next.saturating_sub(self.window),
        );
        let data = cx.read_avail(span).await.map_err(Error::Stop)?;
        self.window = next;
        self.complete = to_u64(data.len()) < span.len || self.window().end() >= self.region.end();
        self.buf.extend_from_slice(&data);
        Ok(!data.is_empty() || !self.complete)
    }

    /// Reads until position `at` is held; false if the input ends first.
    pub async fn ensure(&mut self, at: usize) -> PResult<bool> {
        while at >= self.end() {
            if !self.fill().await? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// The byte at `at`, reading it if needed.
    async fn peek_at(&mut self, at: usize) -> PResult<Option<u8>> {
        self.ensure(at).await?;
        Ok(self.byte(at))
    }

    /// Up to [`UNIT`] bytes held from `at` on.
    fn chunk(&self, at: usize) -> &[u8] {
        let from = at.saturating_sub(self.base);
        self.buf
            .get(from..from.saturating_add(UNIT).min(self.buf.len()))
            .unwrap_or_default()
    }

    /// Skips whitespace and comments.
    pub async fn skip_ws(&mut self) -> PResult<()> {
        let mut comment = false;
        loop {
            if !self.ensure(self.pos).await? {
                return Ok(());
            }
            let mut used = 0usize;
            let mut done = false;
            for &b in self.chunk(self.pos) {
                if comment {
                    // A comment ends with its line.
                    comment = b != b'\r' && b != b'\n';
                } else if b == b'%' {
                    comment = true;
                } else if !is_white(b) {
                    done = true;
                    break;
                }
                used = used.saturating_add(1);
            }
            self.pos = self.pos.saturating_add(used);
            self.charge(used).await;
            if done {
                return Ok(());
            }
        }
    }

    /// The end of the bare word at `at` (at most [`MAX_WORD`] bytes).
    pub async fn word_end(&mut self, at: usize) -> PResult<usize> {
        let mut end = at;
        loop {
            if !self.ensure(end).await? {
                return Ok(end);
            }
            let avail = self.chunk(end);
            let run = avail
                .iter()
                .position(|&b| !is_regular(b))
                .unwrap_or(avail.len());
            let stopped = run < avail.len();
            end = end.saturating_add(run);
            self.charge(run).await;
            if end.saturating_sub(at) > MAX_WORD {
                return Err(Error::Malformed(
                    format!("word longer than {MAX_WORD} bytes"),
                    at,
                ));
            }
            if stopped {
                return Ok(end);
            }
        }
    }

    /// Consumes the bare word at the cursor; returns where it starts.
    pub async fn word(&mut self) -> PResult<usize> {
        let start = self.pos;
        self.pos = self.word_end(start).await?;
        Ok(start)
    }

    /// Consumes `keyword` (after whitespace) if it is next.
    pub async fn keyword(&mut self, keyword: &[u8]) -> PResult<bool> {
        self.skip_ws().await?;
        let start = self.pos;
        let end = self.word_end(start).await?;
        if self.slice(start, end) == keyword {
            self.pos = end;
            return Ok(true);
        }
        if start == end && self.byte(start).is_none() {
            return Err(self.eof());
        }
        Ok(false)
    }

    /// An unsigned integer word.
    pub async fn uint(&mut self) -> PResult<u64> {
        self.skip_ws().await?;
        let start = self.word().await?;
        let w = self.slice(start, self.pos);
        if w.is_empty() {
            return Err(if self.byte(start).is_none() {
                self.eof()
            } else {
                self.malformed("expected a number")
            });
        }
        std::str::from_utf8(w)
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| Error::Malformed("expected an integer".to_owned(), start))
    }

    /// `N G obj`: the header of an indirect object.
    pub async fn object_header(&mut self) -> PResult<(u32, u16)> {
        let num = self.uint().await?;
        let generation = self.uint().await?;
        if !self.keyword(b"obj").await? {
            return Err(self.malformed("expected 'obj'"));
        }
        let num = u32::try_from(num).map_err(|_| self.malformed("object number too large"))?;
        let generation =
            u16::try_from(generation).map_err(|_| self.malformed("generation too large"))?;
        Ok((num, generation))
    }

    /// One object. Containers are kept on an explicit stack, so arrays and
    /// dictionaries of any size are parsed a token at a time.
    pub async fn object(&mut self) -> PResult<Item> {
        enum Frame {
            Array(usize, Vec<Item>),
            /// The entries, and the key whose value comes next.
            Dict(usize, Vec<Entry>, Option<(String, usize)>),
        }
        let mut stack: Vec<Frame> = Vec::new();
        loop {
            self.charge(TOKEN_COST).await;
            self.skip_ws().await?;
            let start = self.pos;
            // The end of a container, or a dictionary key.
            let closed = match stack.last() {
                Some(Frame::Array(..)) => match self.peek_at(start).await? {
                    None => return Err(self.eof()),
                    Some(b']') => {
                        self.pos = start.saturating_add(1);
                        true
                    }
                    Some(_) => false,
                },
                Some(Frame::Dict(_, _, None)) => match self.peek_at(start).await? {
                    None => return Err(self.eof()),
                    Some(b'>') => match self.peek_at(start.saturating_add(1)).await? {
                        Some(b'>') => {
                            self.pos = start.saturating_add(2);
                            true
                        }
                        None => return Err(self.eof()),
                        Some(_) => return Err(self.malformed("expected '>>'")),
                    },
                    Some(b'/') => {
                        let key = self.name().await?;
                        if let Some(Frame::Dict(_, _, pending)) = stack.last_mut() {
                            *pending = Some((key, start));
                        }
                        continue;
                    }
                    Some(_) => return Err(self.malformed("expected a name as dictionary key")),
                },
                _ => false,
            };
            let item = if closed {
                let (from, obj) = match stack.pop() {
                    Some(Frame::Array(from, items)) => (from, Obj::Array(Arc::new(items))),
                    Some(Frame::Dict(from, entries, _)) => (from, Obj::Dict(Arc::new(entries))),
                    None => return Err(self.malformed("unbalanced container")),
                };
                Item {
                    start: from,
                    end: self.pos,
                    obj,
                }
            } else {
                let Some(b) = self.peek_at(start).await? else {
                    return Err(self.eof());
                };
                let obj = match b {
                    b'/' => Obj::Name(self.name().await?),
                    b'(' => Obj::Str {
                        bytes: self.literal().await?,
                        hex: false,
                    },
                    b'<' if self.peek_at(start.saturating_add(1)).await? == Some(b'<') => {
                        if stack.len() >= MAX_DEPTH {
                            return Err(self.malformed("dictionaries nested too deeply"));
                        }
                        self.pos = start.saturating_add(2);
                        stack.push(Frame::Dict(start, Vec::new(), None));
                        continue;
                    }
                    b'<' => Obj::Str {
                        bytes: self.hex().await?,
                        hex: true,
                    },
                    b'[' => {
                        if stack.len() >= MAX_DEPTH {
                            return Err(self.malformed("arrays nested too deeply"));
                        }
                        self.pos = start.saturating_add(1);
                        stack.push(Frame::Array(start, Vec::new()));
                        continue;
                    }
                    b'+' | b'-' | b'.' | b'0'..=b'9' => self.number().await?,
                    _ => {
                        self.word().await?;
                        match self.slice(start, self.pos) {
                            b"true" => Obj::Bool(true),
                            b"false" => Obj::Bool(false),
                            b"null" => Obj::Null,
                            b"" => {
                                return Err(Error::Malformed(
                                    format!("unexpected byte {b:#04x}"),
                                    start,
                                ));
                            }
                            w => {
                                return Err(Error::Malformed(
                                    format!("unexpected keyword {:?}", String::from_utf8_lossy(w)),
                                    start,
                                ));
                            }
                        }
                    }
                };
                Item {
                    start,
                    end: self.pos,
                    obj,
                }
            };
            // Hand the item to its container.
            match stack.last_mut() {
                None => return Ok(item),
                Some(Frame::Array(_, items)) => items.push(item),
                Some(Frame::Dict(_, entries, pending)) => {
                    let Some((key, key_start)) = pending.take() else {
                        return Err(self.malformed("expected a name as dictionary key"));
                    };
                    entries.push(Entry {
                        key,
                        key_start,
                        value: item,
                    });
                }
            }
        }
    }

    /// A number, or `N G R` (a reference) when one follows.
    async fn number(&mut self) -> PResult<Obj> {
        let start = self.word().await?;
        let text = std::str::from_utf8(self.slice(start, self.pos))
            .unwrap_or("")
            .to_owned();
        if let Ok(v) = text.parse::<i64>() {
            // Look ahead for "G R".
            let save = self.pos;
            if v >= 0
                && let Some(generation) = self.generation_and_r().await?
            {
                let num = u32::try_from(v)
                    .map_err(|_| Error::Malformed("object number too large".to_owned(), start))?;
                let generation = generation
                    .ok_or_else(|| Error::Malformed("generation too large".to_owned(), start))?;
                return Ok(Obj::Ref(num, generation));
            }
            self.pos = save;
            return Ok(Obj::Int(v));
        }
        text.parse::<f64>()
            .map(Obj::Real)
            .or_else(|_| {
                // Tolerate forms like "--5" or "5." that some writers produce.
                let cleaned: String = text
                    .trim_start_matches('-')
                    .chars()
                    .filter(|c| c.is_ascii_digit() || *c == '.')
                    .collect();
                cleaned.parse::<f64>().map(Obj::Real)
            })
            .map_err(|_| Error::Malformed(format!("invalid number {text:?}"), start))
    }

    /// After an integer: whether a word of digits and the keyword `R`
    /// follow (consumed if so), with the generation (`None` if too large).
    async fn generation_and_r(&mut self) -> PResult<Option<Option<u16>>> {
        self.skip_ws().await?;
        let gen_start = self.pos;
        let mut end = gen_start;
        loop {
            match self.peek_at(end).await? {
                Some(d) if d.is_ascii_digit() => {
                    end = end.saturating_add(1);
                    if end.saturating_sub(gen_start) > MAX_WORD {
                        return Ok(None);
                    }
                }
                Some(b) if is_regular(b) => return Ok(None),
                _ => break,
            }
        }
        if end == gen_start {
            return Ok(None);
        }
        self.charge(end.saturating_sub(gen_start)).await;
        let generation = std::str::from_utf8(self.slice(gen_start, end))
            .ok()
            .and_then(|s| s.parse::<u16>().ok());
        self.pos = end;
        self.skip_ws().await?;
        let r = self.pos;
        if self.peek_at(r).await? == Some(b'R')
            && self
                .peek_at(r.saturating_add(1))
                .await?
                .is_none_or(|b| !is_regular(b))
        {
            self.pos = r.saturating_add(1);
            return Ok(Some(generation));
        }
        Ok(None)
    }

    async fn name(&mut self) -> PResult<String> {
        self.pos = self.pos.saturating_add(1);
        let start = self.word().await?;
        let raw = self.slice(start, self.pos);
        let mut out = Vec::with_capacity(raw.len());
        let mut i = 0usize;
        while let Some(&b) = raw.get(i) {
            if b == b'#'
                && let Some(v) = raw
                    .get(i.saturating_add(1)..i.saturating_add(3))
                    .and_then(|h| std::str::from_utf8(h).ok())
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
            {
                out.push(v);
                i = i.saturating_add(3);
                continue;
            }
            out.push(b);
            i = i.saturating_add(1);
        }
        Ok(String::from_utf8_lossy(&out).into_owned())
    }

    /// A literal string, [`UNIT`] bytes per step.
    async fn literal(&mut self) -> PResult<Vec<u8>> {
        self.pos = self.pos.saturating_add(1);
        let mut out = Vec::new();
        let mut depth = 1u32;
        loop {
            // An escape looks at most 3 bytes past its backslash.
            self.ensure(self.pos.saturating_add(3)).await?;
            let first = self.pos.saturating_sub(self.base);
            let total = self.buf.len();
            if first >= total {
                return Err(self.eof());
            }
            let stop = if self.complete {
                total
            } else {
                total.saturating_sub(3)
            }
            .min(first.saturating_add(UNIT));
            let buf = &self.buf;
            let at = |i: usize| buf.get(i).copied();
            let mut i = first;
            // Some(true) at the end of the string, Some(false) at the end
            // of the input.
            let mut ended = None;
            while i < stop {
                let Some(b) = at(i) else { break };
                i = i.saturating_add(1);
                match b {
                    b'(' => {
                        depth = depth.saturating_add(1);
                        out.push(b);
                    }
                    b')' => {
                        depth = depth.saturating_sub(1);
                        if depth == 0 {
                            ended = Some(true);
                            break;
                        }
                        out.push(b);
                    }
                    b'\\' => {
                        let Some(e) = at(i) else {
                            ended = Some(false);
                            break;
                        };
                        i = i.saturating_add(1);
                        match e {
                            b'n' => out.push(b'\n'),
                            b'r' => out.push(b'\r'),
                            b't' => out.push(b'\t'),
                            b'b' => out.push(0x08),
                            b'f' => out.push(0x0c),
                            b'0'..=b'7' => {
                                let mut v = u32::from(e.saturating_sub(b'0'));
                                for _ in 0..2 {
                                    match at(i) {
                                        Some(d @ b'0'..=b'7') => {
                                            v = v
                                                .saturating_mul(8)
                                                .saturating_add(u32::from(d.saturating_sub(b'0')));
                                            i = i.saturating_add(1);
                                        }
                                        _ => break,
                                    }
                                }
                                out.push((v & 0xff) as u8);
                            }
                            b'\r' => {
                                if at(i) == Some(b'\n') {
                                    i = i.saturating_add(1);
                                }
                            }
                            b'\n' => {}
                            other => out.push(other),
                        }
                    }
                    _ => out.push(b),
                }
            }
            self.pos = self.base.saturating_add(i);
            self.charge(i.saturating_sub(first)).await;
            match ended {
                Some(true) => return Ok(out),
                Some(false) => return Err(self.eof()),
                None => {}
            }
        }
    }

    /// A hexadecimal string, [`UNIT`] bytes per step.
    async fn hex(&mut self) -> PResult<Vec<u8>> {
        self.pos = self.pos.saturating_add(1);
        let mut out = Vec::new();
        let mut high: Option<u8> = None;
        loop {
            if !self.ensure(self.pos).await? {
                return Err(self.eof());
            }
            let mut used = 0usize;
            // Some(true) at '>', Some(false) at an invalid character.
            let mut ended = None;
            for &b in self.chunk(self.pos) {
                used = used.saturating_add(1);
                let digit = match b {
                    b'>' => {
                        ended = Some(true);
                        break;
                    }
                    b'0'..=b'9' => b.saturating_sub(b'0'),
                    b'a'..=b'f' => b.saturating_sub(b'a').saturating_add(10),
                    b'A'..=b'F' => b.saturating_sub(b'A').saturating_add(10),
                    _ if is_white(b) => continue,
                    _ => {
                        ended = Some(false);
                        break;
                    }
                };
                match high.take() {
                    Some(h) => out.push(h << 4 | digit),
                    None => high = Some(digit),
                }
            }
            self.pos = self.pos.saturating_add(used);
            self.charge(used).await;
            match ended {
                Some(true) => break,
                Some(false) => return Err(self.malformed("invalid character in hex string")),
                None => {}
            }
        }
        if let Some(h) = high {
            out.push(h << 4);
        }
        Ok(out)
    }

    /// After a stream dictionary: consumes `stream` and its end-of-line and
    /// returns the offset where the data starts, if this is a stream.
    pub async fn stream_start(&mut self) -> PResult<Option<usize>> {
        if !self.keyword(b"stream").await? {
            return Ok(None);
        }
        match self.peek_at(self.pos).await? {
            Some(b'\r') => {
                self.pos = self.pos.saturating_add(1);
                if self.peek_at(self.pos).await? == Some(b'\n') {
                    self.pos = self.pos.saturating_add(1);
                }
            }
            Some(b'\n') => self.pos = self.pos.saturating_add(1),
            Some(_) => {}
            None => return Err(self.eof()),
        }
        Ok(Some(self.pos))
    }

    /// The first position from `from` on where `len` bytes satisfy
    /// `pred(before, bytes, after)` (the bytes around them, `None` outside
    /// the input), or the end of the input. Near the end, `bytes` may be
    /// shorter than `len`.
    pub async fn scan(
        &mut self,
        from: usize,
        len: usize,
        pred: impl Fn(Option<u8>, &[u8], Option<u8>) -> bool,
    ) -> PResult<usize> {
        let mut i = from;
        loop {
            self.ensure(i.saturating_add(len)).await?;
            let end = self.end();
            if i >= end {
                return Ok(end);
            }
            let stop = if self.complete {
                end
            } else {
                end.saturating_sub(len)
            }
            .min(i.saturating_add(UNIT));
            let first = i;
            while i < stop {
                let before = i.checked_sub(1).and_then(|j| self.byte(j));
                let after = self.byte(i.saturating_add(len));
                if pred(before, self.slice(i, i.saturating_add(len)), after) {
                    self.charge(i.saturating_sub(first)).await;
                    return Ok(i);
                }
                i = i.saturating_add(1);
            }
            self.charge(i.saturating_sub(first)).await;
        }
    }

    /// The first `needle` at or after `from`.
    pub async fn find(&mut self, needle: &[u8], from: usize) -> PResult<Option<usize>> {
        let at = self.scan(from, needle.len(), |_, w, _| w == needle).await?;
        Ok((self.slice(at, at.saturating_add(needle.len())) == needle).then_some(at))
    }
}

/// Finds `needle` in `data` starting at `from`.
pub fn find(data: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    let hay = data.get(from..)?;
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len())
        .position(|w| w == needle)
        .and_then(|i| i.checked_add(from))
}

/// Finds the last `needle` in `data`.
pub fn rfind(data: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || data.len() < needle.len() {
        return None;
    }
    data.windows(needle.len()).rposition(|w| w == needle)
}

/// Text of a PDF string: UTF-16BE with a byte order mark, UTF-8 with one,
/// or PDFDocEncoding (approximated by Latin-1).
pub fn text(bytes: &[u8]) -> String {
    if let Some(rest) = bytes.strip_prefix(&[0xfe, 0xff]) {
        crate::text::utf16(rest, crate::fields::Endian::Big)
    } else if let Some(rest) = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]) {
        String::from_utf8_lossy(rest).into_owned()
    } else {
        crate::text::latin1(bytes)
    }
}

/// Whether a string's bytes read as text.
pub fn is_text(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0xfe, 0xff])
        || bytes
            .iter()
            .all(|&b| b >= 0x20 || matches!(b, b'\n' | b'\r' | b'\t'))
}

pub fn len_u64(item: &Item) -> u64 {
    to_u64(item.end.saturating_sub(item.start))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;

    /// Runs a future that never suspends (a memory reader has no `Cx`).
    fn now<T>(f: impl std::future::Future<Output = T>) -> T {
        let mut f = std::pin::pin!(f);
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        match f.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(v) => v,
            std::task::Poll::Pending => panic!("suspended"),
        }
    }

    /// Parses `src` whole, and checks that reading it in small pieces
    /// gives the same result.
    fn object(src: &[u8]) -> PResult<Item> {
        let whole = now(Reader::memory(src).object());
        for piece in [1, 2, 3, 5, 1000] {
            let pieces = now(Reader::trickle(src, piece).object());
            assert_eq!(format!("{pieces:?}"), format!("{whole:?}"), "{piece}");
        }
        whole
    }

    #[test]
    fn parses_objects() {
        let src = b"12 0 obj << /Type /Page /Kids [1 0 R 2 0 R] /N 5 /S (a\\(b\\)\\101) /H <48 49> /F 1.5 /Na#20me true >> stream\r\nDATA";
        let mut p = Reader::memory(src);
        assert_eq!(now(p.object_header()).unwrap(), (12, 0));
        let item = now(p.object()).unwrap();
        assert_eq!((item.start, item.end), (9, 99));
        assert_eq!(item.get("Type").unwrap().name(), Some("Page"));
        let kids = item.get("Kids").unwrap().array().unwrap();
        assert_eq!(kids[1].reference(), Some((2, 0)));
        assert_eq!((kids[1].start, kids[1].end), (37, 42));
        assert_eq!(item.get("N").unwrap().int(), Some(5));
        assert!(matches!(&item.get("S").unwrap().obj, Obj::Str { bytes, .. } if bytes == b"a(b)A"));
        assert!(matches!(&item.get("H").unwrap().obj, Obj::Str { bytes, .. } if bytes == b"HI"));
        assert!(item.get("Na me").is_some());
        let start = now(p.stream_start()).unwrap().unwrap();
        assert_eq!(&src[start..], b"DATA");
        assert!(matches!(object(b"<< /A [1 2"), Err(Error::Malformed(..))));
        // Numbers that are not references.
        let item = object(b"[5 0 6 -1 0 R]");
        assert!(matches!(item, Err(Error::Malformed(m, 12)) if m.contains("\"R\"")));
        let item = object(b"[5 0 6 7 8 R 1.5 +3]").unwrap();
        let items = item.array().unwrap();
        assert_eq!(items.len(), 6);
        assert_eq!(items[3].reference(), Some((7, 8)));
        assert_eq!(object(b"5 0").unwrap().int(), Some(5));
        assert_eq!(object(b"5 0 R").unwrap().reference(), Some((5, 0)));
        assert!(object(b"5 0 Rx").unwrap().int().is_some());
    }

    #[test]
    fn reports_errors_where_they_are() {
        let err = |src: &[u8]| match object(src) {
            Err(Error::Malformed(m, at)) => (m, at),
            other => panic!("{other:?}"),
        };
        assert_eq!(err(b"<< /A 1 2 >>").1, 8);
        assert_eq!(err(b"<< /A >>").0, "unexpected byte 0x3e");
        assert_eq!(err(b"<< /A 1 >x").0, "expected '>>'");
        assert_eq!(err(b"(abc").1, 4);
        assert_eq!(err(b"(abc\\").1, 5);
        assert_eq!(err(b"<4x>").1, 3);
        let deep = [b"[".repeat(64), b"1".to_vec(), b"]".repeat(64)].concat();
        assert!(object(&deep).is_ok());
        let deeper = [b"[".repeat(65), b"1".to_vec(), b"]".repeat(65)].concat();
        assert_eq!(err(&deeper), ("arrays nested too deeply".to_owned(), 64));
    }

    #[test]
    fn strings_span_many_steps() {
        // Escapes split across the scanning units still decode.
        let mut src = b"(".to_vec();
        let mut want = Vec::new();
        for _ in 0..3000 {
            src.extend_from_slice(b"x\\101\\\r\n\\(\\)(y)\\7");
            want.extend_from_slice(b"xA()(y)\x07");
        }
        src.push(b')');
        let item = object(&src).unwrap();
        assert!(matches!(&item.obj, Obj::Str { bytes, .. } if *bytes == want));
        assert_eq!(item.end, src.len());
        let hex = [b"<".to_vec(), b"4 1".repeat(5000), b">".to_vec()].concat();
        let item = object(&hex).unwrap();
        assert!(matches!(&item.obj, Obj::Str { bytes, .. } if bytes.len() == 5000));
        // A long comment and long whitespace between tokens.
        let spaced = [
            b"[1 %".to_vec(),
            b"c".repeat(5000),
            b"\n".to_vec(),
            b" ".repeat(5000),
            b"0 R]".to_vec(),
        ]
        .concat();
        let item = object(&spaced).unwrap();
        assert_eq!(item.array().unwrap()[0].reference(), Some((1, 0)));
        // Overlong words are refused.
        let long = [b"/".to_vec(), b"a".repeat(MAX_WORD + 1)].concat();
        assert!(object(&long).is_err());
    }

    #[test]
    fn finds_and_scans() {
        let mut r = Reader::memory(b"abc ID xyz EI end");
        assert_eq!(now(r.find(b"ID", 0)).unwrap(), Some(4));
        assert_eq!(now(r.find(b"ID", 5)).unwrap(), None);
        let ei = |b: Option<u8>, w: &[u8], a: Option<u8>| {
            w == b"EI" && b.is_some_and(is_white) && a.is_none_or(is_white)
        };
        assert_eq!(now(r.scan(7, 2, ei)).unwrap(), 11);
        assert_eq!(now(r.scan(12, 2, ei)).unwrap(), 17);
    }
}
