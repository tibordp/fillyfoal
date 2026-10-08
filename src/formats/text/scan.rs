//! Windowed, sequential access to a text region.
//!
//! Text files can be arbitrarily large, so nothing here reads more than one
//! window ([`WINDOW`] bytes) at a time. A [`Scanner`] caches the current
//! window; [`Lines`] walks a region line by line on top of it.

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::Result;
use crate::span::Span;

use super::piece::Piece;

/// How many bytes a scanner reads at once.
pub const WINDOW: u64 = 64 * 1024;

/// The longest line content kept in memory; longer lines keep their full
/// span but only this prefix of their bytes.
pub const LINE_CAP: usize = 64 * 1024;

/// Byte access to a region, one window at a time. Positions are relative to
/// the region.
pub struct Scanner<'a> {
    cx: &'a Cx,
    region: Span,
    buf: Vec<u8>,
    start: u64,
    /// Where the bytes actually end (the source may be shorter than the
    /// region claims).
    end: u64,
    /// Calls to [`Scanner::tick`] since the last checkpoint.
    ticks: u32,
    /// Calls to [`Scanner::byte`], which byte-at-a-time loops (CSV records,
    /// tags, quoted strings) make over a cached window: reads alone would
    /// charge them too little.
    touched: u32,
}

impl<'a> Scanner<'a> {
    pub fn new(cx: &'a Cx, region: Span) -> Self {
        Scanner {
            cx,
            region,
            buf: Vec::new(),
            start: 0,
            end: region.len,
            ticks: 0,
            touched: 0,
        }
    }

    /// Charges work for one step of an input-dependent loop, suspending
    /// every so often (a checkpoint per step would make cheap steps, such
    /// as tokens in a cached window, dominate the work budget).
    pub async fn tick(&mut self) {
        self.ticks = self.ticks.wrapping_add(1);
        if self.ticks.is_multiple_of(64) {
            self.cx.checkpoint().await;
        }
    }

    pub fn cx(&self) -> &'a Cx {
        self.cx
    }

    pub fn region(&self) -> Span {
        self.region
    }

    /// Length of the region, as far as it is known to exist.
    pub fn len(&self) -> u64 {
        self.end
    }

    pub fn is_empty(&self) -> bool {
        self.end == 0
    }

    /// The span of `start..end` (relative positions).
    pub fn span(&self, start: u64, end: u64) -> Span {
        self.region.sub(start, end.saturating_sub(start))
    }

    fn cached(&self, pos: u64) -> Option<u8> {
        let i = pos.checked_sub(self.start)?;
        self.buf.get(to_usize(i)).copied()
    }

    /// Loads the window starting at `pos`. Returns false at the end.
    async fn load(&mut self, pos: u64) -> Result<bool> {
        if pos >= self.end {
            return Ok(false);
        }
        let want = self.region.sub(pos, WINDOW);
        let data = self.cx.read_avail(want).await?;
        if to_u64(data.len()) < want.len {
            self.end = pos.saturating_add(to_u64(data.len()));
        }
        if data.is_empty() {
            return Ok(false);
        }
        self.buf = data;
        self.start = pos;
        Ok(true)
    }

    /// The byte at `pos`, or `None` past the end.
    pub async fn byte(&mut self, pos: u64) -> Result<Option<u8>> {
        self.touched = self.touched.wrapping_add(1);
        if self.touched.is_multiple_of(256) {
            self.cx.checkpoint().await;
        }
        if let Some(b) = self.cached(pos) {
            return Ok(Some(b));
        }
        if !self.load(pos).await? {
            return Ok(None);
        }
        Ok(self.cached(pos))
    }

    /// The bytes of `start..end`, at most `cap` of them.
    pub async fn bytes(&mut self, start: u64, end: u64, cap: usize) -> Result<Vec<u8>> {
        let end = end.min(start.saturating_add(to_u64(cap))).min(self.end);
        if end <= start {
            return Ok(Vec::new());
        }
        let buf_end = self.start.saturating_add(to_u64(self.buf.len()));
        if start >= self.start && end <= buf_end {
            let a = to_usize(start.saturating_sub(self.start));
            let b = to_usize(end.saturating_sub(self.start));
            return Ok(self.buf.get(a..b).unwrap_or_default().to_vec());
        }
        self.cx.read_avail(self.span(start, end)).await
    }

    /// A piece of text: the bytes of `start..end` (at most `cap`) with spans.
    pub async fn owned(&mut self, start: u64, end: u64, cap: usize) -> Result<Owned> {
        let bytes = self.bytes(start, end, cap).await?;
        let span = self.region.sub(start, to_u64(bytes.len()));
        Ok(Owned { bytes, span })
    }

    /// The first position at or after `from` whose byte satisfies `pred`.
    pub async fn find(&mut self, from: u64, pred: impl Fn(u8) -> bool) -> Result<Option<u64>> {
        let mut pos = from;
        loop {
            if self.cached(pos).is_none() && !self.load(pos).await? {
                return Ok(None);
            }
            let rel = to_usize(pos.saturating_sub(self.start));
            let rest = self.buf.get(rel..).unwrap_or_default();
            if let Some(i) = rest.iter().position(|&b| pred(b)) {
                return Ok(Some(pos.saturating_add(to_u64(i))));
            }
            let next = self.start.saturating_add(to_u64(self.buf.len()));
            if next <= pos {
                return Ok(None);
            }
            pos = next;
        }
    }

    /// The first position at or after `from` where `needle` occurs.
    pub async fn find_seq(&mut self, from: u64, needle: &[u8]) -> Result<Option<u64>> {
        self.find_seq_by(from, needle, |a, b| a == b).await
    }

    /// Like [`Scanner::find_seq`], ignoring ASCII case.
    pub async fn find_seq_nocase(&mut self, from: u64, needle: &[u8]) -> Result<Option<u64>> {
        self.find_seq_by(from, needle, |a, b| a.eq_ignore_ascii_case(&b))
            .await
    }

    async fn find_seq_by(
        &mut self,
        from: u64,
        needle: &[u8],
        eq: impl Fn(u8, u8) -> bool,
    ) -> Result<Option<u64>> {
        let Some(&first) = needle.first() else {
            return Ok(Some(from));
        };
        let mut pos = from;
        loop {
            let Some(at) = self.find(pos, |b| eq(b, first)).await? else {
                return Ok(None);
            };
            if self.matches_by(at, needle, &eq).await? {
                return Ok(Some(at));
            }
            pos = at.saturating_add(1);
        }
    }

    /// Whether `needle` occurs at `pos`.
    pub async fn matches(&mut self, pos: u64, needle: &[u8]) -> Result<bool> {
        self.matches_by(pos, needle, &|a, b| a == b).await
    }

    /// Whether `needle` occurs at `pos`, ignoring ASCII case.
    pub async fn matches_nocase(&mut self, pos: u64, needle: &[u8]) -> Result<bool> {
        self.matches_by(pos, needle, &|a: u8, b: u8| a.eq_ignore_ascii_case(&b))
            .await
    }

    async fn matches_by(
        &mut self,
        pos: u64,
        needle: &[u8],
        eq: &impl Fn(u8, u8) -> bool,
    ) -> Result<bool> {
        let mut at = pos;
        for &n in needle {
            match self.byte(at).await? {
                Some(b) if eq(b, n) => at = at.saturating_add(1),
                _ => return Ok(false),
            }
        }
        Ok(true)
    }

    /// The line starting at `pos`, or `None` at the end.
    pub async fn line(&mut self, pos: u64) -> Result<Option<Line>> {
        if self.byte(pos).await?.is_none() {
            return Ok(None);
        }
        let Some(eol) = self.find(pos, |b| b == b'\n' || b == b'\r').await? else {
            let end = self.end.max(pos);
            return Ok(Some(Line {
                start: pos,
                end,
                next: end,
            }));
        };
        let next = match self.byte(eol).await? {
            Some(b'\r') if self.byte(eol.saturating_add(1)).await? == Some(b'\n') => {
                eol.saturating_add(2)
            }
            _ => eol.saturating_add(1),
        };
        Ok(Some(Line {
            start: pos,
            end: eol,
            next,
        }))
    }
}

/// Owned bytes together with the span they were read from.
#[derive(Clone, Debug)]
pub struct Owned {
    pub bytes: Vec<u8>,
    pub span: Span,
}

impl Owned {
    pub fn piece(&self) -> Piece<'_> {
        Piece::new(&self.bytes, self.span)
    }
}

/// A line: content `start..end` and the terminator `end..next` (relative
/// positions).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Line {
    pub start: u64,
    pub end: u64,
    pub next: u64,
}

/// A line read by [`Lines`].
#[derive(Clone, Debug)]
pub struct LineBuf {
    /// 1-based line number within the region.
    pub number: u64,
    /// The line content (without terminator), at most [`LINE_CAP`] bytes.
    pub bytes: Vec<u8>,
    /// The span of the whole content.
    pub span: Span,
    /// The span including the terminator.
    pub full: Span,
    /// Relative position of the next line.
    pub next: u64,
    /// Relative position of this line.
    pub start: u64,
}

impl LineBuf {
    /// The content as a piece (only the bytes kept in memory).
    pub fn piece(&self) -> Piece<'_> {
        Piece::new(&self.bytes, self.span)
    }

    pub fn truncated(&self) -> bool {
        to_u64(self.bytes.len()) < self.span.len
    }

    pub fn is_blank(&self) -> bool {
        self.bytes.iter().all(u8::is_ascii_whitespace)
    }

    pub fn text(&self) -> String {
        super::encoding::decode_8bit(&self.bytes)
    }
}

/// Walks a region line by line (`\n`, `\r\n` or `\r` terminated).
pub struct Lines<'a> {
    scan: Scanner<'a>,
    pos: u64,
    number: u64,
}

impl<'a> Lines<'a> {
    pub fn new(cx: &'a Cx, region: Span) -> Self {
        Lines {
            scan: Scanner::new(cx, region),
            pos: 0,
            number: 0,
        }
    }

    /// Relative position of the next line.
    pub fn pos(&self) -> u64 {
        self.pos
    }

    /// Number of lines returned so far.
    pub fn number(&self) -> u64 {
        self.number
    }

    /// Reports the walk's position in its region as progress (for walkers
    /// over records whose count is not known up front).
    pub fn progress(&self) {
        let region = self.scan.region;
        self.scan
            .cx
            .progress_in(region, region.offset.saturating_add(self.pos));
    }

    pub fn scanner(&mut self) -> &mut Scanner<'a> {
        &mut self.scan
    }

    /// Continues at relative position `pos`, numbering the next line
    /// `number + 1`.
    pub fn seek(&mut self, pos: u64, number: u64) {
        self.pos = pos;
        self.number = number;
    }

    /// The span from relative `start` up to the current position.
    pub fn since(&self, start: u64) -> Span {
        self.scan.span(start, self.pos)
    }

    /// The next line, without its content (cheap for long lines).
    pub async fn next_bounds(&mut self) -> Result<Option<Line>> {
        self.scan.tick().await;
        let Some(line) = self.scan.line(self.pos).await? else {
            return Ok(None);
        };
        self.pos = line.next.max(self.pos.saturating_add(1));
        self.number = self.number.saturating_add(1);
        Ok(Some(line))
    }

    /// The next line and (a prefix of) its content.
    pub async fn next(&mut self) -> Result<Option<LineBuf>> {
        let Some(line) = self.next_bounds().await? else {
            return Ok(None);
        };
        let bytes = self.scan.bytes(line.start, line.end, LINE_CAP).await?;
        Ok(Some(LineBuf {
            number: self.number,
            bytes,
            span: self.scan.span(line.start, line.end),
            full: self.scan.span(line.start, line.next),
            next: line.next,
            start: line.start,
        }))
    }

    /// The next line without consuming it.
    pub async fn peek(&mut self) -> Result<Option<LineBuf>> {
        let (pos, number) = (self.pos, self.number);
        let line = self.next().await?;
        self.seek(pos, number);
        Ok(line)
    }
}

/// The lines of the first `max` bytes of `region` as text, with the spans of
/// their content: the simple way to read a small text header (`KEY=value`
/// labels, `Name: value` preambles) inside binary or text formats.
pub async fn head_lines(cx: &Cx, region: Span, max: u64) -> Result<Vec<(String, Span)>> {
    let mut lines = Lines::new(cx, region.sub(0, max));
    let mut out = Vec::new();
    while let Some(line) = lines.next().await? {
        out.push((line.text(), line.span));
    }
    Ok(out)
}
