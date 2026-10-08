//! A small JSON reader for headers embedded in binary formats (safetensors,
//! ...). It keeps object members in file order and is bounded in depth.
//! Parsing is charged by the byte and yields in bounded steps, so headers
//! of any size can be read.

use crate::cx::Cx;
use crate::formats::util::pace::{Pace, STEPS_PER_UNIT};
use std::fmt::Write;
use std::future::Future;
use std::pin::Pin;

#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    /// Numbers are kept as text; use [`Json::as_u64`] and friends.
    Num(String),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

const MAX_DEPTH: usize = 64;

impl Json {
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(members) => members.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Json::Num(n) => n.parse().ok(),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Arr(a) => Some(a),
            _ => None,
        }
    }

    /// A compact rendering, for values shown as text.
    pub fn render(&self) -> String {
        let mut out = String::new();
        self.render_into(&mut out);
        out
    }

    fn render_into(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Num(n) => out.push_str(n),
            Json::Str(s) => {
                let _ = write!(out, "{s:?}");
            }
            Json::Arr(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    item.render_into(out);
                }
                out.push(']');
            }
            Json::Obj(members) => {
                out.push('{');
                for (i, (k, v)) in members.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    let _ = write!(out, "{k:?}: ");
                    v.render_into(out);
                }
                out.push('}');
            }
        }
    }
}

struct Parser<'a> {
    data: &'a [u8],
    pos: usize,
    pace: Pace<'a>,
}

type ValueFuture<'s> = Pin<Box<dyn Future<Output = Result<Json, String>> + Send + 's>>;

/// Parses one JSON value (trailing whitespace is allowed, nothing else).
pub async fn parse(cx: &Cx, data: &[u8]) -> Result<Json, String> {
    let mut p = Parser {
        data,
        pos: 0,
        pace: Pace::new(cx, STEPS_PER_UNIT),
    };
    let value = p.value(0).await?;
    p.ws().await;
    if p.pos < data.len() {
        return Err(format!("unexpected data at offset {}", p.pos));
    }
    Ok(value)
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos = self.pos.saturating_add(1);
        Some(b)
    }

    async fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos = self.pos.saturating_add(1);
            self.pace.step().await;
        }
    }

    async fn expect(&mut self, b: u8) -> Result<(), String> {
        self.ws().await;
        match self.bump() {
            Some(c) if c == b => Ok(()),
            _ => Err(format!(
                "expected {:?} at offset {}",
                char::from(b),
                self.pos
            )),
        }
    }

    fn literal(&mut self, word: &[u8], value: Json) -> Result<Json, String> {
        let end = self.pos.saturating_add(word.len());
        if self.data.get(self.pos..end) == Some(word) {
            self.pos = end;
            Ok(value)
        } else {
            Err(format!("bad literal at offset {}", self.pos))
        }
    }

    fn value_boxed<'s>(&'s mut self, depth: usize) -> ValueFuture<'s>
    where
        'a: 's,
    {
        Box::pin(self.value(depth))
    }

    async fn value(&mut self, depth: usize) -> Result<Json, String> {
        if depth > MAX_DEPTH {
            return Err("nested too deeply".into());
        }
        self.pace.step().await;
        self.ws().await;
        match self.peek() {
            Some(b'{') => {
                self.pos = self.pos.saturating_add(1);
                let mut members = Vec::new();
                self.ws().await;
                if self.peek() == Some(b'}') {
                    self.pos = self.pos.saturating_add(1);
                    return Ok(Json::Obj(members));
                }
                loop {
                    self.ws().await;
                    let key = self.string().await?;
                    self.expect(b':').await?;
                    let value = self.value_boxed(depth.saturating_add(1)).await?;
                    members.push((key, value));
                    self.ws().await;
                    match self.bump() {
                        Some(b',') => {}
                        Some(b'}') => return Ok(Json::Obj(members)),
                        _ => return Err(format!("expected , or }} at offset {}", self.pos)),
                    }
                }
            }
            Some(b'[') => {
                self.pos = self.pos.saturating_add(1);
                let mut items = Vec::new();
                self.ws().await;
                if self.peek() == Some(b']') {
                    self.pos = self.pos.saturating_add(1);
                    return Ok(Json::Arr(items));
                }
                loop {
                    items.push(self.value_boxed(depth.saturating_add(1)).await?);
                    self.ws().await;
                    match self.bump() {
                        Some(b',') => {}
                        Some(b']') => return Ok(Json::Arr(items)),
                        _ => return Err(format!("expected , or ] at offset {}", self.pos)),
                    }
                }
            }
            Some(b'"') => Ok(Json::Str(self.string().await?)),
            Some(b't') => self.literal(b"true", Json::Bool(true)),
            Some(b'f') => self.literal(b"false", Json::Bool(false)),
            Some(b'n') => self.literal(b"null", Json::Null),
            Some(b'-' | b'0'..=b'9') => {
                let start = self.pos;
                while matches!(
                    self.peek(),
                    Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
                ) {
                    self.pos = self.pos.saturating_add(1);
                    self.pace.step().await;
                }
                let text = self.data.get(start..self.pos).unwrap_or_default();
                Ok(Json::Num(String::from_utf8_lossy(text).into_owned()))
            }
            _ => Err(format!("unexpected input at offset {}", self.pos)),
        }
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let end = self.pos.saturating_add(4);
        let digits = self
            .data
            .get(self.pos..end)
            .and_then(|d| std::str::from_utf8(d).ok())
            .and_then(|d| u32::from_str_radix(d, 16).ok())
            .ok_or_else(|| format!("bad \\u escape at offset {}", self.pos))?;
        self.pos = end;
        Ok(digits)
    }

    async fn string(&mut self) -> Result<String, String> {
        if self.bump() != Some(b'"') {
            return Err(format!("expected a string at offset {}", self.pos));
        }
        let mut out = Vec::new();
        loop {
            self.pace.step().await;
            match self.bump() {
                None => return Err("unterminated string".into()),
                Some(b'"') => break,
                Some(b'\\') => {
                    let c = match self.bump() {
                        Some(b'n') => '\n',
                        Some(b't') => '\t',
                        Some(b'r') => '\r',
                        Some(b'b') => '\u{8}',
                        Some(b'f') => '\u{c}',
                        Some(b'u') => {
                            let hi = self.hex4()?;
                            let code = if (0xd800..0xdc00).contains(&hi)
                                && self.data.get(self.pos..self.pos.saturating_add(2))
                                    == Some(b"\\u")
                            {
                                self.pos = self.pos.saturating_add(2);
                                let lo = self.hex4()?;
                                0x10000u32
                                    .saturating_add(hi.saturating_sub(0xd800) << 10)
                                    .saturating_add(lo.saturating_sub(0xdc00))
                            } else {
                                hi
                            };
                            char::from_u32(code).unwrap_or('\u{fffd}')
                        }
                        Some(c) => char::from(c),
                        None => return Err("unterminated escape".into()),
                    };
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                }
                Some(b) => out.push(b),
            }
        }
        Ok(String::from_utf8_lossy(&out).into_owned())
    }
}
