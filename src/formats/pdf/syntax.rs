//! PDF syntax: a tokenizer and a recursive-descent parser for objects over
//! bytes in memory. Every parsed item records where it starts and ends in
//! the buffer, so nodes get exact spans.
//!
//! Parsing distinguishes running out of bytes ([`Error::Incomplete`], the
//! caller reads more and retries) from malformed input.

use std::sync::Arc;

use crate::bytes::to_u64;

/// Nesting of arrays and dictionaries accepted.
const MAX_DEPTH: u32 = 64;

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    /// The buffer ended inside the object.
    Incomplete,
    Malformed(String, usize),
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

/// A cursor over a buffer.
pub struct Parser<'a> {
    data: &'a [u8],
    pub pos: usize,
    /// Whether the buffer ends where the input ends (so running out of
    /// bytes is malformed rather than incomplete).
    complete: bool,
}

impl<'a> Parser<'a> {
    pub fn new(data: &'a [u8], complete: bool) -> Self {
        Parser {
            data,
            pos: 0,
            complete,
        }
    }

    pub fn at(data: &'a [u8], pos: usize, complete: bool) -> Self {
        Parser {
            data,
            pos,
            complete,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    fn bump(&mut self) {
        self.pos = self.pos.saturating_add(1);
    }

    fn eof(&self) -> Error {
        if self.complete {
            Error::Malformed("unexpected end of data".to_owned(), self.pos)
        } else {
            Error::Incomplete
        }
    }

    fn malformed(&self, msg: impl Into<String>) -> Error {
        Error::Malformed(msg.into(), self.pos)
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

    /// The bare word (keyword or number) at the cursor, without consuming it.
    pub fn peek_word(&self) -> &'a [u8] {
        let rest = self.data.get(self.pos..).unwrap_or_default();
        let end = rest
            .iter()
            .position(|&b| !is_regular(b))
            .unwrap_or(rest.len());
        rest.get(..end).unwrap_or_default()
    }

    pub fn word(&mut self) -> &'a [u8] {
        let w = self.peek_word();
        self.pos = self.pos.saturating_add(w.len());
        w
    }

    /// Consumes `keyword` (after whitespace) if it is next.
    pub fn keyword(&mut self, keyword: &[u8]) -> PResult<bool> {
        self.skip_ws();
        let w = self.peek_word();
        if w == keyword && (self.pos.saturating_add(w.len()) < self.data.len() || self.complete) {
            self.pos = self.pos.saturating_add(w.len());
            return Ok(true);
        }
        if w.is_empty() && self.pos >= self.data.len() {
            return Err(self.eof());
        }
        Ok(false)
    }

    /// An unsigned integer word.
    pub fn uint(&mut self) -> PResult<u64> {
        self.skip_ws();
        let start = self.pos;
        let w = self.word();
        if w.is_empty() {
            return Err(if start >= self.data.len() {
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
    pub fn object_header(&mut self) -> PResult<(u32, u16)> {
        let num = self.uint()?;
        let generation = self.uint()?;
        if !self.keyword(b"obj")? {
            return Err(self.malformed("expected 'obj'"));
        }
        let num = u32::try_from(num).map_err(|_| self.malformed("object number too large"))?;
        let generation =
            u16::try_from(generation).map_err(|_| self.malformed("generation too large"))?;
        Ok((num, generation))
    }

    pub fn object(&mut self) -> PResult<Item> {
        self.object_at(0)
    }

    fn object_at(&mut self, depth: u32) -> PResult<Item> {
        self.skip_ws();
        let start = self.pos;
        let Some(b) = self.peek() else {
            return Err(self.eof());
        };
        let obj = match b {
            b'/' => Obj::Name(self.name()?),
            b'(' => Obj::Str {
                bytes: self.literal()?,
                hex: false,
            },
            b'<' if self.data.get(self.pos.saturating_add(1)) == Some(&b'<') => {
                if depth >= MAX_DEPTH {
                    return Err(self.malformed("dictionaries nested too deeply"));
                }
                Obj::Dict(Arc::new(self.dict(depth)?))
            }
            b'<' => Obj::Str {
                bytes: self.hex()?,
                hex: true,
            },
            b'[' => {
                if depth >= MAX_DEPTH {
                    return Err(self.malformed("arrays nested too deeply"));
                }
                self.bump();
                let mut items = Vec::new();
                loop {
                    self.skip_ws();
                    match self.peek() {
                        None => return Err(self.eof()),
                        Some(b']') => {
                            self.bump();
                            break;
                        }
                        Some(_) => items.push(self.object_at(depth.saturating_add(1))?),
                    }
                }
                Obj::Array(Arc::new(items))
            }
            b'+' | b'-' | b'.' | b'0'..=b'9' => self.number()?,
            _ => {
                let w = self.word();
                match w {
                    b"true" => Obj::Bool(true),
                    b"false" => Obj::Bool(false),
                    b"null" => Obj::Null,
                    b"" => {
                        self.bump();
                        return Err(Error::Malformed(format!("unexpected byte {b:#04x}"), start));
                    }
                    _ => {
                        return Err(Error::Malformed(
                            format!("unexpected keyword {:?}", String::from_utf8_lossy(w)),
                            start,
                        ));
                    }
                }
            }
        };
        Ok(Item {
            start,
            end: self.pos,
            obj,
        })
    }

    /// A number, or `N G R` (a reference) when one follows.
    fn number(&mut self) -> PResult<Obj> {
        let start = self.pos;
        let w = self.word();
        if self.pos >= self.data.len() && !self.complete {
            return Err(Error::Incomplete);
        }
        let text = std::str::from_utf8(w).unwrap_or("");
        if let Ok(v) = text.parse::<i64>() {
            // Look ahead for "G R".
            let save = self.pos;
            self.skip_ws();
            let g = self.peek_word();
            if !g.is_empty() && g.iter().all(u8::is_ascii_digit) && v >= 0 {
                self.pos = self.pos.saturating_add(g.len());
                self.skip_ws();
                let r = self.peek_word();
                if r == b"R" {
                    self.bump();
                    let num = u32::try_from(v).map_err(|_| {
                        Error::Malformed("object number too large".to_owned(), start)
                    })?;
                    let generation = std::str::from_utf8(g)
                        .ok()
                        .and_then(|s| s.parse::<u16>().ok())
                        .ok_or_else(|| {
                            Error::Malformed("generation too large".to_owned(), start)
                        })?;
                    return Ok(Obj::Ref(num, generation));
                }
                if r.is_empty() && self.pos >= self.data.len() && !self.complete {
                    return Err(Error::Incomplete);
                }
            } else if g.is_empty() && self.pos >= self.data.len() && !self.complete {
                return Err(Error::Incomplete);
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

    fn name(&mut self) -> PResult<String> {
        self.bump();
        let raw = self.word();
        if self.pos >= self.data.len() && !self.complete {
            return Err(Error::Incomplete);
        }
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

    fn literal(&mut self) -> PResult<Vec<u8>> {
        self.bump();
        let mut out = Vec::new();
        let mut depth = 1u32;
        loop {
            let Some(b) = self.peek() else {
                return Err(self.eof());
            };
            self.bump();
            match b {
                b'(' => {
                    depth = depth.saturating_add(1);
                    out.push(b);
                }
                b')' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        return Ok(out);
                    }
                    out.push(b);
                }
                b'\\' => {
                    let Some(e) = self.peek() else {
                        return Err(self.eof());
                    };
                    self.bump();
                    match e {
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0c),
                        b'0'..=b'7' => {
                            let mut v = u32::from(e.saturating_sub(b'0'));
                            for _ in 0..2 {
                                match self.peek() {
                                    Some(d @ b'0'..=b'7') => {
                                        v = v
                                            .saturating_mul(8)
                                            .saturating_add(u32::from(d.saturating_sub(b'0')));
                                        self.bump();
                                    }
                                    _ => break,
                                }
                            }
                            out.push((v & 0xff) as u8);
                        }
                        b'\r' => {
                            if self.peek() == Some(b'\n') {
                                self.bump();
                            }
                        }
                        b'\n' => {}
                        other => out.push(other),
                    }
                }
                _ => out.push(b),
            }
        }
    }

    fn hex(&mut self) -> PResult<Vec<u8>> {
        self.bump();
        let mut out = Vec::new();
        let mut high: Option<u8> = None;
        loop {
            let Some(b) = self.peek() else {
                return Err(self.eof());
            };
            self.bump();
            let digit = match b {
                b'>' => break,
                b'0'..=b'9' => b.saturating_sub(b'0'),
                b'a'..=b'f' => b.saturating_sub(b'a').saturating_add(10),
                b'A'..=b'F' => b.saturating_sub(b'A').saturating_add(10),
                _ if is_white(b) => continue,
                _ => return Err(self.malformed("invalid character in hex string")),
            };
            match high.take() {
                Some(h) => out.push(h << 4 | digit),
                None => high = Some(digit),
            }
        }
        if let Some(h) = high {
            out.push(h << 4);
        }
        Ok(out)
    }

    fn dict(&mut self, depth: u32) -> PResult<Vec<Entry>> {
        self.pos = self.pos.saturating_add(2);
        let mut entries = Vec::new();
        loop {
            self.skip_ws();
            match self.peek() {
                None => return Err(self.eof()),
                Some(b'>') => {
                    if self.data.get(self.pos.saturating_add(1)) == Some(&b'>') {
                        self.pos = self.pos.saturating_add(2);
                        return Ok(entries);
                    }
                    if self.pos.saturating_add(1) >= self.data.len() {
                        return Err(self.eof());
                    }
                    return Err(self.malformed("expected '>>'"));
                }
                Some(b'/') => {
                    let key_start = self.pos;
                    let key = self.name()?;
                    let value = self.object_at(depth.saturating_add(1))?;
                    entries.push(Entry {
                        key,
                        key_start,
                        value,
                    });
                }
                Some(_) => return Err(self.malformed("expected a name as dictionary key")),
            }
        }
    }

    /// After a stream dictionary: consumes `stream` and its end-of-line and
    /// returns the offset where the data starts, if this is a stream.
    pub fn stream_start(&mut self) -> PResult<Option<usize>> {
        if !self.keyword(b"stream")? {
            return Ok(None);
        }
        match self.peek() {
            Some(b'\r') => {
                self.bump();
                if self.peek() == Some(b'\n') {
                    self.bump();
                }
            }
            Some(b'\n') => self.bump(),
            Some(_) => {}
            None => return Err(self.eof()),
        }
        Ok(Some(self.pos))
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
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn parses_objects() {
        let src = b"12 0 obj << /Type /Page /Kids [1 0 R 2 0 R] /N 5 /S (a\\(b\\)\\101) /H <48 49> /F 1.5 /Na#20me true >> stream\r\nDATA";
        let mut p = Parser::new(src, true);
        assert_eq!(p.object_header().unwrap(), (12, 0));
        let item = p.object().unwrap();
        assert_eq!(item.get("Type").unwrap().name(), Some("Page"));
        let kids = item.get("Kids").unwrap().array().unwrap();
        assert_eq!(kids[1].reference(), Some((2, 0)));
        assert_eq!(item.get("N").unwrap().int(), Some(5));
        assert!(matches!(&item.get("S").unwrap().obj, Obj::Str { bytes, .. } if bytes == b"a(b)A"));
        assert!(matches!(&item.get("H").unwrap().obj, Obj::Str { bytes, .. } if bytes == b"HI"));
        assert!(item.get("Na me").is_some());
        let start = p.stream_start().unwrap().unwrap();
        assert_eq!(&src[start..], b"DATA");
        // Incomplete input asks for more.
        assert_eq!(
            Parser::new(b"<< /A [1 2", false).object().unwrap_err(),
            Error::Incomplete
        );
        assert!(matches!(
            Parser::new(b"<< /A [1 2", true).object(),
            Err(Error::Malformed(..))
        ));
        // A trailing number may still become a reference.
        assert_eq!(
            Parser::new(b"[5 0", false).object().unwrap_err(),
            Error::Incomplete
        );
    }
}
