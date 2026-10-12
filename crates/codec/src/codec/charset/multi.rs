//! Double-byte East Asian code pages: Windows code pages 932 (Shift_JIS),
//! 936 (GBK), 949 (Unified Hangul Code, a superset of EUC-KR) and 950
//! (Big5); Big5-HKSCS, which WHATWG's `big5` label names; and EUC-JP, whose
//! JIS X 0208 pairs are looked up in the code page 932 table (the WHATWG
//! decoder uses one JIS X 0208 index for both). EUC-JP's three-byte JIS X
//! 0212 sequences (`8F xx xx`) are not decoded (U+FFFD).
//!
//! Big5-HKSCS is CPython's `big5hkscs` (HKSCS-2004 over Big5) plus the
//! euro sign at A3E1. It differs from code page 950 in 4,911 pairs: 4,657
//! HKSCS pairs code page 950 leaves unmapped (1,693 of them outside the
//! BMP, and 4 that decode to a letter and a combining accent, e.g. 8862 =
//! U+00CA U+0304), and 254 that map differently (C6A1..C7FC, a few
//! punctuation marks in A1xx and A2xx, F9FE).
//!
//! The tables (`cp9xx.bin`, `big5hkscs.bin`) are generated from CPython's
//! codecs by `tests/data/charset/multibyte.py`, which documents their
//! layout and checks them; they are read in place (a binary search over a
//! few hundred segments per lookup), nothing is built at run time. Malformed input is
//! handled as in the WHATWG Encoding Standard: an invalid sequence becomes
//! U+FFFD, and an ASCII byte after a lead byte is not swallowed.

use crate::bytes::{u16_le, u32_le};

static CP932: &[u8] = include_bytes!("cp932.bin");
static CP936: &[u8] = include_bytes!("cp936.bin");
static CP949: &[u8] = include_bytes!("cp949.bin");
static CP950: &[u8] = include_bytes!("cp950.bin");
/// The one wide table: u32 entries (see the generator).
static BIG5_HKSCS: &[u8] = include_bytes!("big5hkscs.bin");

/// A decoded pair: one code point, or two.
type Chars = (char, Option<char>);

/// Offsets in a table file.
const SINGLE: usize = 4;
const SEGMENTS: usize = SINGLE + 256;
const LEAD: u16 = 0xffff;

/// A double-byte code page.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MultiByte {
    /// Shift_JIS as Windows has it (code page 932, "Windows-31J").
    Cp932,
    /// GBK (code page 936).
    Cp936,
    /// EUC-KR with Windows' Unified Hangul Code extension (code page 949).
    Cp949,
    /// Big5 (code page 950).
    Cp950,
    /// Big5-HKSCS (HKSCS-2004 over Big5, as CPython's `big5hkscs`): what
    /// the WHATWG `big5` label names.
    Big5Hkscs,
    /// EUC-JP: JIS X 0208 pairs (`A1..FE A1..FE`) and half-width katakana
    /// (`8E A1..DF`).
    EucJp,
}

impl MultiByte {
    pub const ALL: &'static [MultiByte] = &[
        MultiByte::Cp932,
        MultiByte::Cp936,
        MultiByte::Cp949,
        MultiByte::Cp950,
        MultiByte::Big5Hkscs,
        MultiByte::EucJp,
    ];

    /// The usual name, e.g. `"Shift_JIS"`.
    pub fn name(self) -> &'static str {
        match self {
            MultiByte::Cp932 => "Shift_JIS",
            MultiByte::Cp936 => "GBK",
            MultiByte::Cp949 => "EUC-KR",
            MultiByte::Cp950 => "Big5",
            MultiByte::Big5Hkscs => "Big5-HKSCS",
            MultiByte::EucJp => "EUC-JP",
        }
    }

    /// The transform name of sources transcoded from this code page into
    /// UTF-8 (see [`crate::span::Origin`]).
    pub fn transform(self) -> &'static str {
        match self {
            MultiByte::Cp932 => "from Shift_JIS",
            MultiByte::Cp936 => "from GBK",
            MultiByte::Cp949 => "from EUC-KR",
            MultiByte::Cp950 => "from Big5",
            MultiByte::Big5Hkscs => "from Big5-HKSCS",
            MultiByte::EucJp => "from EUC-JP",
        }
    }

    fn table(self) -> &'static [u8] {
        match self {
            MultiByte::Cp932 | MultiByte::EucJp => CP932,
            MultiByte::Cp936 => CP936,
            MultiByte::Cp949 => CP949,
            MultiByte::Cp950 => CP950,
            MultiByte::Big5Hkscs => BIG5_HKSCS,
        }
    }

    /// What a byte 0x80..=0xFF is on its own: a code point, [`LEAD`], or
    /// anything else for an invalid byte.
    fn single(self, b: u8) -> u16 {
        let i = usize::from(b & 0x7f).saturating_mul(2);
        u16_le(self.table(), SINGLE.saturating_add(i)).unwrap_or(0xfffe)
    }

    /// Whether `b` starts a multi-byte sequence.
    pub fn is_lead(self, b: u8) -> bool {
        if self == MultiByte::EucJp {
            return matches!(b, 0x8e | 0x8f | 0xa1..=0xfe);
        }
        b >= 0x80 && self.single(b) == LEAD
    }

    /// The character of the pair `lead`, `trail`, if mapped. A pair that
    /// decodes to two code points (four in Big5-HKSCS) gives the first.
    pub fn pair(self, lead: u8, trail: u8) -> Option<char> {
        self.pair_chars(lead, trail).map(|(c, _)| c)
    }

    /// The code point(s) of the pair `lead`, `trail`, if mapped.
    fn pair_chars(self, lead: u8, trail: u8) -> Option<Chars> {
        if self == MultiByte::EucJp {
            return euc_jp_pair(lead, trail).map(|c| (c, None));
        }
        let wide = self == MultiByte::Big5Hkscs;
        let t = self.table();
        let &[lead_min, lead_max, trail_min, trail_max, ..] = t else {
            return None;
        };
        if !(lead_min..=lead_max).contains(&lead) || !(trail_min..=trail_max).contains(&trail) {
            return None;
        }
        let width = u16::from(trail_max.saturating_sub(trail_min)).saturating_add(1);
        let p = u16::from(lead.saturating_sub(lead_min))
            .saturating_mul(width)
            .saturating_add(u16::from(trail.saturating_sub(trail_min)));
        let count = usize::from(u16_le(t, SEGMENTS)?);
        let seg = |i: usize| -> Option<(u16, u16, u16)> {
            let at = SEGMENTS
                .saturating_add(2)
                .saturating_add(i.saturating_mul(6));
            Some((
                u16_le(t, at)?,
                u16_le(t, at.saturating_add(2))?,
                u16_le(t, at.saturating_add(4))?,
            ))
        };
        // The last segment starting at or before the pointer.
        let (mut lo, mut hi) = (0usize, count);
        while lo < hi {
            let mid = lo.saturating_add(hi) / 2;
            if seg(mid)?.0 <= p {
                lo = mid.saturating_add(1);
            } else {
                hi = mid;
            }
        }
        let (start, kind_len, value) = seg(lo.checked_sub(1)?)?;
        let off = p.saturating_sub(start);
        if off >= kind_len & 0x3fff {
            return None;
        }
        let data = SEGMENTS
            .saturating_add(2)
            .saturating_add(count.saturating_mul(6));
        // A data entry: u16 in the narrow tables, u32 in the wide one.
        let entry = |i: usize| -> Option<u32> {
            if wide {
                u32_le(t, data.saturating_add(i.saturating_mul(4)))
            } else {
                u16_le(t, data.saturating_add(i.saturating_mul(2))).map(u32::from)
            }
        };
        let code = match kind_len >> 14 {
            // A run from `value` (narrow) or from data[value] (wide).
            1 if wide => entry(usize::from(value))?.checked_add(u32::from(off))?,
            1 => u32::from(value.checked_add(off)?),
            2 => entry(usize::from(value).saturating_add(usize::from(off)))?,
            _ => return None,
        };
        if code == if wide { u32::MAX } else { 0xffff } {
            return None;
        }
        if wide && code & 0x8000_0000 != 0 {
            // Two code points, stored after the entries.
            let i = usize::try_from(code & 0x7fff_ffff).ok()?;
            let first = char::from_u32(entry(i)?)?;
            let second = char::from_u32(entry(i.saturating_add(1))?)?;
            return Some((first, Some(second)));
        }
        char::from_u32(code).map(|c| (c, None))
    }

    /// The character at the start of `bytes` (`None` for an invalid
    /// sequence) and how many bytes it takes; `None` for empty input or a
    /// lead byte at the very end (the rest of the character may follow).
    /// Of a pair that decodes to two code points (four in Big5-HKSCS),
    /// only the first; [`MultiByte::decode_partial`] gives both.
    pub fn next(self, bytes: &[u8]) -> Option<(Option<char>, usize)> {
        self.next_chars(bytes)
            .map(|(c, n)| (c.map(|(first, _)| first), n))
    }

    /// [`MultiByte::next`] with the second code point of a pair that has
    /// two.
    fn next_chars(self, bytes: &[u8]) -> Option<(Option<Chars>, usize)> {
        let &b = bytes.first()?;
        if b < 0x80 {
            return Some((Some((char::from(b), None)), 1));
        }
        if self == MultiByte::EucJp && b == 0x8f {
            // JIS X 0212: three bytes, not decoded.
            let &second = bytes.get(1)?;
            if !(0xa1..=0xfe).contains(&second) {
                return Some((None, if second < 0x80 { 1 } else { 2 }));
            }
            let &third = bytes.get(2)?;
            return Some((None, if third < 0x80 { 2 } else { 3 }));
        }
        if self == MultiByte::EucJp {
            if !self.is_lead(b) {
                return Some((None, 1));
            }
            let &trail = bytes.get(1)?;
            return Some(match euc_jp_pair(b, trail) {
                Some(c) => (Some((c, None)), 2),
                None if trail < 0x80 => (None, 1),
                None => (None, 2),
            });
        }
        match self.single(b) {
            LEAD => {
                let &trail = bytes.get(1)?;
                Some(match self.pair_chars(b, trail) {
                    Some(c) => (Some(c), 2),
                    // An ASCII byte after a lead stands for itself.
                    None if trail < 0x80 => (None, 1),
                    None => (None, 2),
                })
            }
            u => Some((
                char::from_u32(u32::from(u))
                    .filter(|_| u < 0xfffe)
                    .map(|c| (c, None)),
                1,
            )),
        }
    }

    /// Decodes `bytes` into `out`, stopping before a lead byte at the end;
    /// returns the bytes consumed. Feeding the rest in front of the next
    /// chunk gives the same text as decoding everything at once.
    pub fn decode_partial(self, bytes: &[u8], out: &mut String) -> usize {
        let mut pos = 0usize;
        while let Some((c, n)) = self.next_chars(bytes.get(pos..).unwrap_or_default()) {
            let (first, second) = c.unwrap_or((char::REPLACEMENT_CHARACTER, None));
            out.push(first);
            out.extend(second);
            pos = pos.saturating_add(n);
        }
        pos
    }

    /// Decodes all of `bytes` (a lead byte at the end is U+FFFD).
    pub fn decode(self, bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len());
        let used = self.decode_partial(bytes, &mut out);
        if used < bytes.len() {
            out.push(char::REPLACEMENT_CHARACTER);
        }
        out
    }
}

/// An EUC-JP pair: half-width katakana after 0x8E, or a JIS X 0208
/// row and cell (0xA1 + 0..94 each), looked up at its Shift_JIS position
/// in the code page 932 table.
fn euc_jp_pair(lead: u8, trail: u8) -> Option<char> {
    if lead == 0x8e {
        return (0xa1..=0xdf)
            .contains(&trail)
            .then(|| {
                char::from_u32(0xff61_u32.saturating_add(u32::from(trail.saturating_sub(0xa1))))
            })
            .flatten();
    }
    if !(0xa1..=0xfe).contains(&lead) || !(0xa1..=0xfe).contains(&trail) {
        return None;
    }
    let row = lead.saturating_sub(0xa0); // 1..=94
    let cell = trail.saturating_sub(0xa0);
    let first = (row.saturating_add(1) / 2).saturating_add(if row <= 62 { 0x80 } else { 0xc0 });
    let second = if row % 2 == 1 {
        cell.saturating_add(if cell <= 63 { 0x3f } else { 0x40 })
    } else {
        cell.saturating_add(0x9e)
    };
    MultiByte::Cp932.pair(first, second)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(s.get(i..i + 2).unwrap(), 16).unwrap())
            .collect()
    }

    /// Strings encoded with CPython 3.13's codecs.
    #[test]
    fn decodes_like_python() {
        let cases = [
            (
                MultiByte::Cp932,
                "93fa967b8cea82cc8365834c835883678141b6c0b6c58740",
                "日本語のテキスト、ｶﾀｶﾅ①",
            ),
            (
                MultiByte::Cp936,
                "d6d0cec4cec4b1bea3acb2e2cad480",
                "中文文本，测试€",
            ),
            (
                MultiByte::Cp949,
                "c7d1b1b9beee20c5d8bdbac6ae208c63b9e6b0a2c7cf",
                "한국어 텍스트 똠방각하",
            ),
            (
                MultiByte::Cp950,
                "c163c5e9a4a4a4e5a141b4fab8d5",
                "繁體中文，測試",
            ),
        ];
        for (cs, bytes, text) in cases {
            assert_eq!(cs.decode(&hex(bytes)), text, "{cs:?}");
        }
    }

    /// EUC-JP as Node.js's `TextDecoder("euc-jp")` (the WHATWG decoder)
    /// decodes it, except JIS X 0212 (`8F B0 A1`, 丂 there), which is not
    /// decoded. Every pair `A1..FE A1..FE` and `8E A1..DF` was checked
    /// against it the same way.
    #[test]
    fn euc_jp_decodes_like_whatwg() {
        let euc = MultiByte::EucJp;
        assert_eq!(
            euc.decode(&hex(
                "c6fccbdcb8eca4cea5c6a5ada5b9a5c8a1a28eb68ec08eb68ec5ada1a4a28fb0a1"
            )),
            "日本語のテキスト、ｶﾀｶﾅ①あ\u{fffd}"
        );
        // A lead byte at the end waits; an ASCII byte after a lead is kept.
        let mut out = String::new();
        assert_eq!(euc.decode_partial(b"\xa4\xa2\xa4", &mut out), 2);
        assert_eq!(euc.decode(b"\xa4a\x8e\xe0"), "\u{fffd}a\u{fffd}");
        assert_eq!(euc.decode(b"\x8f\xb0"), "\u{fffd}");
    }

    /// Big5-HKSCS against CPython 3.13's `big5hkscs`: a BMP character, one
    /// outside it (8845 = U+2010C), a pair that decodes to two code points, a pair
    /// that differs from code page 950 (C6A1), and the euro sign it adds.
    #[test]
    fn big5_hkscs_decodes_like_python() {
        let hk = MultiByte::Big5Hkscs;
        assert_eq!(
            hk.decode(&hex("a4a488628845c6a1a3e1")),
            "中\u{ca}\u{304}\u{2010c}①€"
        );
        assert_eq!(hk.pair(0x88, 0x62), Some('\u{ca}'));
        assert_eq!(hk.next(&hex("8862")), Some((Some('\u{ca}'), 2)));
        // Code page 950 leaves the HKSCS pairs unmapped.
        assert_eq!(MultiByte::Cp950.decode(&hex("8862")), "\u{fffd}b");
        // A lead at the end waits; an ASCII byte after a lead is kept.
        let mut out = String::new();
        assert_eq!(hk.decode_partial(&hex("886288"), &mut out), 2);
        assert_eq!(hk.decode(b"\x88 "), "\u{fffd} ");
    }

    #[test]
    fn malformed_input_follows_whatwg() {
        let sjis = MultiByte::Cp932;
        // An ASCII byte after a lead is kept; a lead at the end is U+FFFD.
        assert_eq!(sjis.decode(b"\x819"), "\u{fffd}9");
        assert_eq!(sjis.decode(b"\x82\xa0a\x82"), "あa\u{fffd}");
        let mut out = String::new();
        assert_eq!(sjis.decode_partial(b"\x82\xa0\x82", &mut out), 2);
        assert_eq!(out, "あ");
        // Bytes no code page uses.
        assert_eq!(MultiByte::Cp936.decode(b"\xff"), "\u{fffd}");
        assert_eq!(MultiByte::Cp950.decode(b"\x80"), "\u{fffd}");
    }

    /// Every table maps as many pairs as the generator reported.
    #[test]
    fn tables_are_complete() {
        for (cs, expected) in [
            (MultiByte::Cp932, 9604),
            (MultiByte::Cp936, 21791),
            (MultiByte::Cp949, 17048),
            (MultiByte::Cp950, 13752),
            (MultiByte::Big5Hkscs, 18403),
        ] {
            let mut n = 0;
            for lead in 0x80..=0xffu8 {
                if cs.is_lead(lead) {
                    n += (0..=0xffu8).filter(|&t| cs.pair(lead, t).is_some()).count();
                }
            }
            assert_eq!(n, expected, "{cs:?}");
        }
    }
}
