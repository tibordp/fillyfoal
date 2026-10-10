//! Span-preserving slices of text held in memory.
//!
//! A [`Piece`] is a byte slice together with the span it came from. Every
//! operation (trimming, splitting, finding) returns pieces whose spans follow
//! along, so tokens found in a line keep exact provenance for free.

use crate::bytes::{to_u64, to_usize};
use crate::span::Span;

#[derive(Clone, Copy, Debug)]
pub struct Piece<'a> {
    bytes: &'a [u8],
    offset: u64,
    source: crate::span::SourceId,
}

impl<'a> Piece<'a> {
    /// `bytes` starting at `span.offset` (the span's length is ignored: a
    /// piece covers exactly its bytes).
    pub fn new(bytes: &'a [u8], span: Span) -> Self {
        Piece {
            bytes,
            offset: span.offset,
            source: span.source,
        }
    }

    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    pub fn span(&self) -> Span {
        Span::new(self.source, self.offset, to_u64(self.bytes.len()))
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// The text: UTF-8, or Windows-1252 if it is not valid UTF-8.
    pub fn text(&self) -> String {
        super::encoding::decode_8bit(self.bytes)
    }

    pub fn first(&self) -> Option<u8> {
        self.bytes.first().copied()
    }

    pub fn last(&self) -> Option<u8> {
        self.bytes.last().copied()
    }

    pub fn at(&self, i: usize) -> Option<u8> {
        self.bytes.get(i).copied()
    }

    /// `start..end`, clamped.
    pub fn slice(&self, start: usize, end: usize) -> Piece<'a> {
        let end = end.min(self.bytes.len());
        let start = start.min(end);
        Piece {
            bytes: self.bytes.get(start..end).unwrap_or_default(),
            offset: self.offset.saturating_add(to_u64(start)),
            source: self.source,
        }
    }

    pub fn from(&self, start: usize) -> Piece<'a> {
        self.slice(start, self.bytes.len())
    }

    pub fn to(&self, end: usize) -> Piece<'a> {
        self.slice(0, end)
    }

    /// The part of `self` before `other` starts (`other` must lie within).
    pub fn before(&self, other: &Piece<'_>) -> Piece<'a> {
        self.to(to_usize(other.offset.saturating_sub(self.offset)))
    }

    /// The part of `self` after `other` ends.
    pub fn after(&self, other: &Piece<'_>) -> Piece<'a> {
        let end = other.offset.saturating_add(to_u64(other.bytes.len()));
        self.from(to_usize(end.saturating_sub(self.offset)))
    }

    /// The piece spanning from the start of `self` to the end of `other`.
    pub fn through(&self, other: &Piece<'_>) -> Piece<'a> {
        let end = other.offset.saturating_add(to_u64(other.bytes.len()));
        self.to(to_usize(end.saturating_sub(self.offset)))
    }

    pub fn trim(&self) -> Piece<'a> {
        self.trim_start().trim_end()
    }

    pub fn trim_start(&self) -> Piece<'a> {
        let n = self
            .bytes
            .iter()
            .take_while(|b| b.is_ascii_whitespace())
            .count();
        self.from(n)
    }

    pub fn trim_end(&self) -> Piece<'a> {
        let n = self
            .bytes
            .iter()
            .rev()
            .take_while(|b| b.is_ascii_whitespace())
            .count();
        self.to(self.bytes.len().saturating_sub(n))
    }

    /// Strips trailing bytes for which `pred` holds.
    pub fn trim_end_matches(&self, pred: impl Fn(u8) -> bool) -> Piece<'a> {
        let n = self.bytes.iter().rev().take_while(|&&b| pred(b)).count();
        self.to(self.bytes.len().saturating_sub(n))
    }

    pub fn find(&self, byte: u8) -> Option<usize> {
        self.bytes.iter().position(|&b| b == byte)
    }

    pub fn find_by(&self, pred: impl Fn(u8) -> bool) -> Option<usize> {
        self.bytes.iter().position(|&b| pred(b))
    }

    pub fn rfind(&self, byte: u8) -> Option<usize> {
        self.bytes.iter().rposition(|&b| b == byte)
    }

    pub fn find_seq(&self, needle: &[u8]) -> Option<usize> {
        if needle.is_empty() {
            return Some(0);
        }
        self.bytes.windows(needle.len()).position(|w| w == needle)
    }

    pub fn contains(&self, needle: &[u8]) -> bool {
        self.find_seq(needle).is_some()
    }

    /// Splits at the first `byte` (which belongs to neither part).
    pub fn split_once(&self, byte: u8) -> Option<(Piece<'a>, Piece<'a>)> {
        let i = self.find(byte)?;
        Some((self.to(i), self.from(i.saturating_add(1))))
    }

    /// Splits at the first byte satisfying `pred`.
    pub fn split_once_by(&self, pred: impl Fn(u8) -> bool) -> Option<(Piece<'a>, Piece<'a>)> {
        let i = self.find_by(pred)?;
        Some((self.to(i), self.from(i.saturating_add(1))))
    }

    /// Splits at the first run of ASCII whitespace.
    pub fn split_word(&self) -> (Piece<'a>, Piece<'a>) {
        match self.find_by(|b| b.is_ascii_whitespace()) {
            Some(i) => (self.to(i), self.from(i).trim_start()),
            None => (*self, self.from(self.bytes.len())),
        }
    }

    /// Whitespace-separated words.
    pub fn words(&self) -> impl Iterator<Item = Piece<'a>> + use<'a> {
        let mut rest = self.trim_start();
        std::iter::from_fn(move || {
            if rest.is_empty() {
                return None;
            }
            let (word, tail) = rest.split_word();
            rest = tail;
            Some(word)
        })
    }

    /// Splits at every `byte`.
    pub fn split(&self, byte: u8) -> impl Iterator<Item = Piece<'a>> + use<'a> {
        let mut rest = Some(*self);
        std::iter::from_fn(move || {
            let cur = rest?;
            match cur.split_once(byte) {
                Some((head, tail)) => {
                    rest = Some(tail);
                    Some(head)
                }
                None => {
                    rest = None;
                    Some(cur)
                }
            }
        })
    }

    pub fn starts_with(&self, prefix: &[u8]) -> bool {
        self.bytes.starts_with(prefix)
    }

    pub fn starts_with_nocase(&self, prefix: &[u8]) -> bool {
        self.bytes
            .get(..prefix.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(prefix))
    }

    pub fn ends_with(&self, suffix: &[u8]) -> bool {
        self.bytes.ends_with(suffix)
    }

    pub fn strip_prefix(&self, prefix: &[u8]) -> Option<Piece<'a>> {
        self.starts_with(prefix).then(|| self.from(prefix.len()))
    }

    pub fn strip_prefix_nocase(&self, prefix: &[u8]) -> Option<Piece<'a>> {
        self.starts_with_nocase(prefix)
            .then(|| self.from(prefix.len()))
    }

    pub fn strip_suffix(&self, suffix: &[u8]) -> Option<Piece<'a>> {
        self.ends_with(suffix)
            .then(|| self.to(self.bytes.len().saturating_sub(suffix.len())))
    }

    pub fn eq_nocase(&self, other: &[u8]) -> bool {
        self.bytes.eq_ignore_ascii_case(other)
    }

    /// Removes one pair of matching surrounding quotes (`"` or `'`).
    pub fn unquote(&self) -> Piece<'a> {
        match (self.first(), self.last()) {
            (Some(a), Some(b)) if self.len() >= 2 && a == b && (a == b'"' || a == b'\'') => {
                self.slice(1, self.len().saturating_sub(1))
            }
            _ => *self,
        }
    }
}
