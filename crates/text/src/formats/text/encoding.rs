//! Character encodings: byte order marks, sniffing, decoding, and
//! transcoding wide encodings into UTF-8 for the structured dissectors.

use std::borrow::Cow;

use crate::bytes::{to_u64, to_usize};
use crate::codec::charset::{self, Charset, Label, MultiByte};
use crate::cx::Cx;
use crate::error::Result;
use crate::formats::Input;
use crate::node::Node;
use crate::span::{Origin, Span};
use crate::value::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Encoding {
    Utf8,
    /// 8-bit text that is not UTF-8: decoded as Windows-1252, the usual
    /// superset of ISO 8859-1.
    Windows1252,
    /// A single-byte code page named by a declaration (XML `encoding=`,
    /// HTML `<meta charset>`, a coding cookie, MIME `charset=`).
    Single(Charset),
    /// A double-byte East Asian code page (Shift_JIS, GBK, EUC-KR, Big5),
    /// declared or recognised. Line breaks are single bytes, but other
    /// ASCII bytes can be the second half of a character, so structured
    /// parsers get it transcoded.
    Multi(MultiByte),
    Utf16Le,
    Utf16Be,
    Utf32Le,
    Utf32Be,
}

impl Encoding {
    pub fn name(self) -> &'static str {
        match self {
            Encoding::Utf8 => "UTF-8",
            Encoding::Windows1252 => "Windows-1252",
            Encoding::Single(c) => c.name(),
            Encoding::Multi(m) => m.name(),
            Encoding::Utf16Le => "UTF-16LE",
            Encoding::Utf16Be => "UTF-16BE",
            Encoding::Utf32Le => "UTF-32LE",
            Encoding::Utf32Be => "UTF-32BE",
        }
    }

    /// Bytes per code unit.
    pub fn unit(self) -> u64 {
        match self {
            Encoding::Utf8 | Encoding::Windows1252 | Encoding::Single(_) | Encoding::Multi(_) => 1,
            Encoding::Utf16Le | Encoding::Utf16Be => 2,
            Encoding::Utf32Le | Encoding::Utf32Be => 4,
        }
    }

    /// Whether ASCII bytes are always ASCII characters (so byte-oriented
    /// parsers work directly on the source).
    pub fn ascii_compatible(self) -> bool {
        self.unit() == 1 && !matches!(self, Encoding::Multi(_))
    }

    /// The transform name of a source transcoded from this encoding into
    /// UTF-8 (see [`Origin`]).
    pub fn transform(self) -> &'static str {
        match self {
            Encoding::Utf8 => "utf-8",
            Encoding::Windows1252 => Charset::Windows1252.transform(),
            Encoding::Single(c) => c.transform(),
            Encoding::Multi(m) => m.transform(),
            Encoding::Utf16Le => "utf-16le",
            Encoding::Utf16Be => "utf-16be",
            Encoding::Utf32Le => "utf-32le",
            Encoding::Utf32Be => "utf-32be",
        }
    }

    /// The code unit at the start of `bytes`.
    pub fn code_unit(self, bytes: &[u8]) -> Option<u32> {
        use crate::bytes::{u16_be, u16_le, u32_be, u32_le};
        match self {
            Encoding::Utf8 | Encoding::Windows1252 | Encoding::Single(_) | Encoding::Multi(_) => {
                bytes.first().map(|&b| u32::from(b))
            }
            Encoding::Utf16Le => u16_le(bytes, 0).map(u32::from),
            Encoding::Utf16Be => u16_be(bytes, 0).map(u32::from),
            Encoding::Utf32Le => u32_le(bytes, 0),
            Encoding::Utf32Be => u32_be(bytes, 0),
        }
    }

    pub fn decode(self, bytes: &[u8]) -> String {
        match self {
            Encoding::Utf8 => decode_8bit(bytes),
            Encoding::Windows1252 => windows_1252(bytes),
            Encoding::Single(c) => c.decode(bytes),
            Encoding::Multi(m) => m.decode(bytes),
            Encoding::Utf16Le => crate::text::utf16(bytes, crate::fields::Endian::Little),
            Encoding::Utf16Be => crate::text::utf16(bytes, crate::fields::Endian::Big),
            Encoding::Utf32Le | Encoding::Utf32Be => bytes
                .as_chunks::<4>()
                .0
                .iter()
                .map(|&b| {
                    let v = if self == Encoding::Utf32Le {
                        u32::from_le_bytes(b)
                    } else {
                        u32::from_be_bytes(b)
                    };
                    char::from_u32(v).unwrap_or(char::REPLACEMENT_CHARACTER)
                })
                .collect(),
        }
    }
}

/// The encoding announced by a byte order mark, and the mark's length.
pub fn bom(data: &[u8]) -> Option<(Encoding, u64)> {
    if data.starts_with(b"\xef\xbb\xbf") {
        Some((Encoding::Utf8, 3))
    } else if data.starts_with(b"\xff\xfe\0\0") {
        Some((Encoding::Utf32Le, 4))
    } else if data.starts_with(b"\0\0\xfe\xff") {
        Some((Encoding::Utf32Be, 4))
    } else if data.starts_with(b"\xff\xfe") {
        Some((Encoding::Utf16Le, 2))
    } else if data.starts_with(b"\xfe\xff") {
        Some((Encoding::Utf16Be, 2))
    } else {
        None
    }
}

/// UTF-16 without a byte order mark, recognised by mostly-ASCII text having
/// a zero byte in every other position.
pub fn sniff_utf16(data: &[u8]) -> Option<Encoding> {
    let sample = data.get(..data.len().min(512)).unwrap_or_default();
    let pairs = sample.as_chunks::<2>().0;
    if pairs.len() < 4 {
        return None;
    }
    let zero_hi = pairs.iter().filter(|p| p[1] == 0 && p[0] != 0).count();
    let zero_lo = pairs.iter().filter(|p| p[0] == 0 && p[1] != 0).count();
    let n = pairs.len();
    let mostly = |k: usize| k.saturating_mul(10) >= n.saturating_mul(9);
    let encoding = if mostly(zero_hi) {
        Encoding::Utf16Le
    } else if mostly(zero_lo) {
        Encoding::Utf16Be
    } else {
        return None;
    };
    let text = encoding.decode(sample);
    plausible_chars(&text).then_some(encoding)
}

fn plausible_chars(text: &str) -> bool {
    let control = text
        .chars()
        .filter(|&c| c.is_control() && !matches!(c, '\t' | '\n' | '\r' | '\x0c'))
        .count();
    control.saturating_mul(100) <= text.chars().count()
}

/// Inputs at least this long have their classification remembered.
const MEMO_MIN: usize = 4096;

thread_local! {
    /// The last large input classified on this thread and the answer.
    /// Identification runs dozens of text-based probes over the same head,
    /// each asking; the copy is compared in full, so a hit is exact.
    static MEMO: std::cell::RefCell<(Vec<u8>, Option<Encoding>)> =
        const { std::cell::RefCell::new((Vec::new(), None)) };
}

/// The encoding of text-like data, or `None` if it looks binary.
pub fn classify(data: &[u8]) -> Option<Encoding> {
    if data.len() < MEMO_MIN {
        return classify_once(data);
    }
    if let Some(found) = MEMO.with(|m| {
        let m = m.borrow();
        (m.0 == data).then_some(m.1)
    }) {
        return found;
    }
    let found = classify_once(data);
    MEMO.with(|m| {
        let mut m = m.borrow_mut();
        m.0.clear();
        m.0.extend_from_slice(data);
        m.1 = found;
    });
    found
}

fn classify_once(data: &[u8]) -> Option<Encoding> {
    if let Some((encoding, len)) = bom(data) {
        let rest = data.get(to_usize(len)..).unwrap_or_default();
        return (rest.is_empty() || plausible_chars(&encoding.decode(rest))).then_some(encoding);
    }
    if let Some(encoding) = sniff_utf16(data) {
        return Some(encoding);
    }
    if data.is_empty() {
        return None;
    }
    // Control characters other than layout ones. A terminal escape
    // (`ESC[32m` colours) and nroff overstrike (`N\bN`, `_\bx`) are text.
    // Counting stops once there are too many: binary data gets there fast.
    let limit = data.len() / 100;
    let control = data
        .iter()
        .enumerate()
        .filter(|&(i, &b)| {
            let next = data.get(i.saturating_add(1)).copied();
            let escape = b == 0x1b && matches!(next, Some(b'[' | b']' | b'(' | b')'));
            let overstrike = b == 0x08
                && i.checked_sub(1)
                    .and_then(|p| data.get(p))
                    .zip(next)
                    .is_some_and(|(&p, n)| p > 0x20 && p < 0x7f && (p == n || p == b'_'));
            let layout = matches!(b, 0 | b'\t' | b'\n' | b'\r' | 0x0c);
            b < 0x20 && !layout && !escape && !overstrike
        })
        .take(limit.saturating_add(1))
        .count();
    if control > limit {
        return None;
    }
    let utf8 = is_utf8(data);
    // DEL counts as a control character outside UTF-8.
    let control = if utf8 {
        control
    } else {
        control.saturating_add(data.iter().filter(|&&b| b == 0x7f).count())
    };
    if control.saturating_mul(100) > data.len() {
        return None;
    }
    // 8-bit text rarely contains NUL bytes; binary data usually does. A
    // few stray ones well inside otherwise clean text (a log written
    // across a crash) are tolerated.
    let nul = data.iter().filter(|&&b| b == 0).count();
    if nul > 0
        && (control > 0
            || nul.saturating_mul(1000) > data.len()
            || data.iter().take(256).any(|&b| b == 0))
    {
        return None;
    }
    if utf8 {
        return Some(Encoding::Utf8);
    }
    if let Some(m) = guess_multi(data) {
        return Some(Encoding::Multi(m));
    }
    // 8-bit legacy text: mostly ASCII, or words in a non-Latin script.
    let high = data.iter().filter(|&&b| b >= 0x80).count();
    if high.saturating_mul(4) <= data.len() {
        return Some(guess_single(data));
    }
    // Words first: they are cheap, and scoring code pages over a binary
    // head (all 0xff) is not.
    if !words(data) {
        return None;
    }
    let script = guess_single(data);
    matches!(script, Encoding::Single(_)).then_some(script)
}

/// Whether mostly-high-byte data reads as words: separated by spaces or
/// line breaks, and drawing on many different letters (not a few repeated
/// byte values).
fn words(data: &[u8]) -> bool {
    let mut seen = [false; 128];
    for &b in data {
        if let Some(s) = b
            .checked_sub(0x80)
            .and_then(|i| seen.get_mut(usize::from(i)))
        {
            *s = true;
        }
    }
    let distinct = seen.iter().filter(|&&s| s).count();
    let gaps = data.iter().filter(|b| matches!(b, b' ' | b'\n')).count();
    data.len() >= 32 && distinct >= 12 && gaps.saturating_mul(25) >= data.len()
}

/// The code page of 8-bit text, guessed from its letters: Windows-1252
/// unless most letters are high bytes that read as lower-case Cyrillic
/// (Windows-1251, KOI8-R) or Greek (Windows-1253) words.
fn guess_single(data: &[u8]) -> Encoding {
    let high = data.iter().filter(|&&b| b >= 0x80).count();
    let latin = data.iter().filter(|b| b.is_ascii_alphabetic()).count();
    if high.saturating_mul(2) < latin {
        return Encoding::Windows1252;
    }
    // Lower-case letters score; capitals inside a word and non-letters
    // count against a reading.
    let score = |c: Charset| {
        let mut score = 0i64;
        let mut prev_letter = false;
        for (i, &b) in data.iter().enumerate() {
            let ch = c.char(b);
            // Greek final sigma inside a word reads Cyrillic `т` (common
            // anywhere) as Greek.
            let medial_final = ch == 'ς'
                && data
                    .get(i.saturating_add(1))
                    .is_some_and(|&n| c.char(n).is_alphabetic());
            if b >= 0x80 {
                score = score.saturating_add(if medial_final {
                    -4
                } else if ch.is_lowercase() {
                    2
                } else if ch.is_uppercase() {
                    if prev_letter { -3 } else { 1 }
                } else {
                    -2
                });
            }
            prev_letter = ch.is_alphabetic();
        }
        score
    };
    let mut best = (0i64, Encoding::Windows1252);
    for c in [Charset::Windows1251, Charset::Koi8R, Charset::Windows1253] {
        let s = score(c);
        if s > best.0 {
            best = (s, Encoding::Single(c));
        }
    }
    best.1
}

/// Most bytes of a double-byte code page that [`guess_multi`] looks at.
const MULTI_SAMPLE: usize = 16 * 1024;

/// Text in a double-byte East Asian code page, recognised conservatively:
/// the sample must decode without a single invalid sequence, have at least
/// a few double-byte characters, and nine in ten of them must be the
/// common characters of the language the code page is for, as the code
/// pages order them: the 2965 level-1 kanji, kana and punctuation of
/// Shift_JIS and EUC-JP (with at least some kana), the 3755 level-1 hanzi of GBK
/// (GB 2312's first level), the 5401 frequent characters of Big5, and the
/// 2350 hangul syllables of EUC-KR (with spaces between words, which
/// Chinese lacks: Korean hangul bytes are also common GBK and Big5 hanzi).
/// The best-scoring code page wins.
fn guess_multi(data: &[u8]) -> Option<MultiByte> {
    let sample = data.get(..data.len().min(MULTI_SAMPLE)).unwrap_or_default();
    if !sample.iter().any(|&b| b >= 0x80) {
        return None;
    }
    let mut best: Option<(u64, MultiByte)> = None;
    for &m in MultiByte::ALL {
        if let Some(score) = multi_score(m, sample)
            && best.is_none_or(|(s, _)| score > s)
        {
            best = Some((score, m));
        }
    }
    best.map(|(_, m)| m)
}

/// How well `data` reads as `m` (per mille of its non-ASCII characters
/// that are common ones), or `None` if it does not.
fn multi_score(m: MultiByte, data: &[u8]) -> Option<u64> {
    let in_range = |code: u16, lead: (u8, u8), trail: (u8, u8)| {
        let [l, t] = code.to_be_bytes();
        (lead.0..=lead.1).contains(&l) && (trail.0..=trail.1).contains(&t)
    };
    let mut chars = 0u64;
    let mut common = 0u64;
    let mut kana = 0u64;
    let mut hangul = 0u64;
    // A space between two double-byte characters (a word break in Korean).
    let mut spaced = 0u64;
    let mut prev_wide = false;
    let mut space_after_wide = false;
    let mut pos = 0usize;
    while let Some((c, n)) = m.next(data.get(pos..).unwrap_or_default()) {
        let b0 = data.get(pos).copied().unwrap_or(0);
        if b0 < 0x80 {
            space_after_wide = b0 == b' ' && (prev_wide || space_after_wide);
            prev_wide = false;
            pos = pos.saturating_add(n);
            continue;
        }
        c?;
        chars = chars.saturating_add(1);
        if n == 2 {
            if space_after_wide {
                spaced = spaced.saturating_add(1);
            }
            let code =
                u16::from_be_bytes([b0, data.get(pos.saturating_add(1)).copied().unwrap_or(0)]);
            let good = match m {
                MultiByte::Cp932 => {
                    let is_kana =
                        (0x829f..=0x82f1).contains(&code) || (0x8340..=0x8396).contains(&code);
                    if is_kana {
                        kana = kana.saturating_add(1);
                    }
                    // Kana, punctuation and full-width letters, level-1 kanji.
                    is_kana
                        || (0x8140..=0x82f1).contains(&code)
                        || (0x889f..=0x9872).contains(&code)
                }
                MultiByte::Cp936 => {
                    in_range(code, (0xb0, 0xd7), (0xa1, 0xfe))
                        || in_range(code, (0xa1, 0xa3), (0xa1, 0xfe))
                }
                MultiByte::Cp950 => {
                    (0xa140..=0xa3bf).contains(&code) || (0xa440..=0xc67e).contains(&code)
                }
                MultiByte::Cp949 => {
                    let is_hangul = in_range(code, (0xb0, 0xc8), (0xa1, 0xfe));
                    if is_hangul {
                        hangul = hangul.saturating_add(1);
                    }
                    is_hangul || in_range(code, (0xa1, 0xa3), (0xa1, 0xfe))
                }
                MultiByte::EucJp => {
                    let is_kana = (0xa4a1..=0xa4f3).contains(&code)
                        || (0xa5a1..=0xa5f6).contains(&code)
                        || b0 == 0x8e;
                    if is_kana {
                        kana = kana.saturating_add(1);
                    }
                    // Kana, punctuation and full-width letters, level-1 kanji.
                    is_kana
                        || in_range(code, (0xa1, 0xa3), (0xa1, 0xfe))
                        || in_range(code, (0xb0, 0xcf), (0xa1, 0xfe))
                }
            };
            if good {
                common = common.saturating_add(1);
            }
        }
        prev_wide = n == 2;
        space_after_wide = false;
        pos = pos.saturating_add(n);
    }
    if chars < 8 || common.saturating_mul(10) < chars.saturating_mul(9) {
        return None;
    }
    let spaced_out = spaced.saturating_mul(12) >= chars;
    let plausible = match m {
        MultiByte::Cp932 | MultiByte::EucJp => kana.saturating_mul(10) >= chars,
        MultiByte::Cp949 => hangul.saturating_mul(2) >= chars && spaced_out,
        MultiByte::Cp936 | MultiByte::Cp950 => !spaced_out,
    };
    plausible.then(|| common.saturating_mul(1000).checked_div(chars).unwrap_or(0))
}

/// Bytes as UTF-8 when valid, otherwise as Windows-1252 (so legacy text
/// keeps its accented letters instead of turning into replacement marks).
pub fn decode_8bit(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_owned(),
        // A character cut off at the end (a capped read) is still UTF-8.
        Err(e) if e.error_len().is_none() => {
            String::from_utf8_lossy(bytes.get(..e.valid_up_to()).unwrap_or_default()).into_owned()
        }
        Err(_) => windows_1252(bytes),
    }
}

/// Windows code page 1252.
pub fn windows_1252(bytes: &[u8]) -> String {
    Charset::Windows1252.decode(bytes)
}

/// A text input made ready for byte-oriented (ASCII-compatible) parsing.
#[derive(Clone, Copy, Debug)]
pub struct Prepared {
    /// The text after any byte order mark, in UTF-8 or another
    /// ASCII-compatible encoding. For UTF-16/32 input this is a derived,
    /// transcoded source.
    pub span: Span,
    pub encoding: Encoding,
    pub bom: Option<Span>,
}

impl Prepared {
    /// The prepared text as an input (for embedding).
    pub fn input(&self, input: Input) -> Input {
        if self.span.source == input.span.source {
            Input {
                span: self.span,
                ..input
            }
        } else {
            input.nested(self.span)
        }
    }

    /// A short note for annotations, e.g. `" (UTF-16LE)"`, empty for UTF-8.
    pub fn note(&self) -> String {
        match self.encoding {
            Encoding::Utf8 => String::new(),
            e => format!(" ({})", e.name()),
        }
    }
}

/// Detects the encoding of `input`, emits a node for its byte order mark,
/// and transcodes UTF-16/32 text into a derived UTF-8 source.
pub async fn prepare(cx: &Cx, input: Input) -> Result<Prepared> {
    prepare_declared(cx, input, None).await
}

/// [`prepare`] for a walker that records resume marks (see `Cx::mark`):
/// takes the resume key before anything is emitted, and on a resumed run
/// does not emit the byte order mark again (the next child must be the one
/// the mark was taken before).
pub async fn prepare_resuming<K: std::any::Any + Send + Sync + Clone>(
    cx: &Cx,
    input: Input,
) -> Result<(Prepared, Option<K>)> {
    let resumed = cx.resume::<K>();
    let prepared = prepare_with(cx, input, None, resumed.is_none()).await?;
    Ok((prepared, resumed))
}

/// Whether `data` is UTF-8 (allowing a character cut off at the end).
fn is_utf8(data: &[u8]) -> bool {
    match std::str::from_utf8(data) {
        Ok(_) => true,
        Err(e) => e.error_len().is_none(),
    }
}

/// The legacy encoding (a single-byte or double-byte code page) a
/// declaration names, if the head of the text needs it: a byte order mark
/// or UTF-16 wins, and text that is valid UTF-8 is taken as UTF-8 whatever
/// it claims (mislabelled UTF-8 is far more common than legacy text that
/// happens to be valid UTF-8). Declared but undecodable encodings are
/// reported on `cx`.
fn declared_legacy(cx: Option<&Cx>, head: &[u8], declared: Option<Label>) -> Option<Encoding> {
    let declared = declared?;
    if bom(head).is_some() || sniff_utf16(head).is_some() || is_utf8(head) {
        return None;
    }
    match declared {
        Label::Single(c) => Some(Encoding::Single(c)),
        Label::Multi(m) => Some(Encoding::Multi(m)),
        Label::Unsupported(name) => {
            if let Some(cx) = cx {
                cx.diag(crate::error::Diagnostic::unsupported(format!(
                    "declared encoding {name} is not decoded (shown as Windows-1252)"
                )));
            }
            None
        }
        _ => None,
    }
}

/// Like [`prepare`], for text whose encoding is also declared inside it (an
/// XML declaration, an HTML `<meta charset>`) or by its container (MIME
/// `charset=`): a declared single-byte code page is transcoded into a
/// derived UTF-8 source, so that parsers see the right characters.
///
/// The decision is made from the head of the text: if that is plain ASCII
/// (or valid UTF-8), the text is used as it is.
pub async fn prepare_declared(cx: &Cx, input: Input, declared: Option<Label>) -> Result<Prepared> {
    prepare_with(cx, input, declared, true).await
}

async fn prepare_with(
    cx: &Cx,
    input: Input,
    declared: Option<Label>,
    emit_bom: bool,
) -> Result<Prepared> {
    let span = input.span;
    let head = cx.read_avail(span.sub(0, 512)).await?;
    let (encoding, bom_len) = match bom(&head) {
        Some(found) => found,
        None => match sniff_utf16(&head) {
            Some(e) => (e, 0),
            None => (Encoding::Utf8, 0),
        },
    };
    if encoding == Encoding::Utf8 && bom_len == 0 {
        let legacy = matches!(
            declared,
            Some(Label::Single(_) | Label::Multi(_) | Label::Unsupported(_))
        );
        let head = cx.read_avail(span.sub(0, crate::formats::HEAD_LEN)).await?;
        // A declared code page, or else a recognised double-byte one.
        // Windows-1252 is what 8-bit text falls back to anyway: keeping
        // the original source keeps spans in the file.
        let found = if legacy {
            declared_legacy(Some(cx), &head, declared)
        } else if declared.is_none() && !is_utf8(&head) {
            guess_multi(&head).map(Encoding::Multi)
        } else {
            None
        };
        if let Some(e) = found
            && e != Encoding::Single(Charset::Windows1252)
        {
            return transcode(cx, span, e, e.transform(), None).await;
        }
    }
    let bom = (bom_len > 0).then(|| span.sub(0, bom_len));
    if let Some(b) = bom.filter(|_| emit_bom) {
        cx.emit(
            Node::new("Byte order mark")
                .span(b)
                .value(Value::Text(encoding.name().to_owned())),
        );
    }
    let body = span.tail(bom_len);
    if encoding.ascii_compatible() {
        return Ok(Prepared {
            span: body,
            encoding,
            bom,
        });
    }
    transcode(cx, body, encoding, encoding.transform(), bom).await
}

/// Transcodes `body` from `encoding` into a derived UTF-8 source.
async fn transcode(
    cx: &Cx,
    body: Span,
    encoding: Encoding,
    transform: &'static str,
    bom: Option<Span>,
) -> Result<Prepared> {
    let origin = Origin {
        parent: body,
        transform,
    };
    let decoded = match cx.derived(origin) {
        Some(found) => found,
        None => {
            let data = crate::codec::read_all(cx, body).await?;
            let text = decode_stepped(cx, encoding, &data).await;
            let consumed = to_u64(data.len());
            cx.add_derived(origin, text.into_bytes(), consumed, None)?
        }
    };
    Ok(Prepared {
        span: decoded.span,
        encoding,
        bom,
    })
}

/// [`Encoding::decode`] of a whole (up to `max_derived`-sized) body, a
/// chunk at a time with a checkpoint in between. Chunks end on code unit
/// boundaries and never between the halves of a UTF-16 surrogate pair, so
/// the result is the same as decoding everything at once.
pub(super) async fn decode_stepped(cx: &Cx, encoding: Encoding, data: &[u8]) -> String {
    const CHUNK: usize = 64 * 1024; // a multiple of every code unit size
    if encoding == Encoding::Utf8 {
        // Not chunked: a cut could fall inside a multi-byte sequence (and
        // UTF-8 bodies are never transcoded, see `prepare_declared`).
        return encoding.decode(data);
    }
    let mut out = String::with_capacity(data.len());
    let mut rest = data;
    if let Encoding::Multi(m) = encoding {
        // A chunk ends before a lead byte whose trail is in the next one.
        while !rest.is_empty() {
            let chunk = rest.get(..CHUNK.min(rest.len())).unwrap_or_default();
            let mut used = m.decode_partial(chunk, &mut out);
            if used == 0 || chunk.len() == rest.len() {
                // A lone lead byte at the very end.
                out.push_str(&m.decode(chunk.get(used..).unwrap_or_default()));
                used = chunk.len();
            }
            rest = rest.get(used..).unwrap_or_default();
            cx.checkpoint().await;
        }
        return out;
    }
    while !rest.is_empty() {
        let mut n = CHUNK.min(rest.len());
        if n < rest.len() {
            let last = encoding.code_unit(rest.get(n.saturating_sub(2)..n).unwrap_or_default());
            let utf16 = matches!(encoding, Encoding::Utf16Le | Encoding::Utf16Be);
            if utf16 && last.is_some_and(|u| (0xd800..0xdc00).contains(&u)) {
                n = n.saturating_sub(2);
            }
        }
        let (chunk, tail) = rest.split_at_checked(n).unwrap_or((rest, &[]));
        out.push_str(&encoding.decode(chunk));
        rest = tail;
        cx.checkpoint().await;
    }
    out
}

/// The value of `name="..."` (or `'...'`, or unquoted) in `text`, matched
/// ASCII case-insensitively, as a charset label.
fn attribute(text: &[u8], name: &[u8]) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    lower
        .windows(name.len())
        .enumerate()
        .filter(|(_, w)| *w == name)
        .find_map(|(at, _)| attribute_value(text.get(at.saturating_add(name.len())..)?))
}

fn attribute_value(rest: &[u8]) -> Option<String> {
    let rest = super::probe::trim_start(rest);
    let rest = super::probe::trim_start(rest.strip_prefix(b"=")?);
    let rest = rest
        .strip_prefix(b"\"")
        .or_else(|| rest.strip_prefix(b"'"))
        .unwrap_or(rest);
    let end = rest
        .iter()
        .position(|&b| !(b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':')))
        .unwrap_or(rest.len());
    let label = rest.get(..end)?;
    (!label.is_empty()).then(|| String::from_utf8_lossy(label).into_owned())
}

/// The encoding named by an XML declaration at the start of `head`
/// (`<?xml version="1.0" encoding="ISO-8859-2"?>`).
pub fn xml_declared(head: &[u8]) -> Option<String> {
    let head = probe_text(head);
    let decl = head.strip_prefix(b"<?xml")?;
    let end = decl.windows(2).position(|w| w == b"?>")?;
    attribute(decl.get(..end)?, b"encoding")
}

/// The charset of an HTML `<meta charset=...>` or `<meta http-equiv=
/// "Content-Type" content="text/html; charset=...">` in `head`.
pub fn meta_charset(head: &[u8]) -> Option<String> {
    let head = head.get(..head.len().min(4096)).unwrap_or_default();
    attribute(head, b"charset")
}

/// A coding cookie in the first two lines of `head`: Emacs
/// (`-*- coding: latin-1 -*-`), Python (PEP 263) or Vim
/// (`vim: set fileencoding=koi8-r :`).
pub fn coding_cookie(head: &[u8]) -> Option<String> {
    crate::formats::util::lines::split_lines(head)
        .take(2)
        .find_map(|line| {
            let line = line.get(..line.len().min(256))?;
            let lower = line.to_ascii_lowercase();
            let at = lower.windows(6).position(|w| w == b"coding")?;
            let rest = line.get(at.saturating_add(6)..)?;
            let rest = rest
                .strip_prefix(b":")
                .or_else(|| rest.strip_prefix(b"="))?;
            let rest = super::probe::trim_start(rest);
            let end = rest
                .iter()
                .position(|&b| !(b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')))
                .unwrap_or(rest.len());
            let label = rest.get(..end)?;
            (!label.is_empty()).then(|| String::from_utf8_lossy(label).into_owned())
        })
}

/// The legacy encoding that `declared` names for text starting with
/// `head` (see [`prepare_declared`]), for code that decodes strings itself.
pub fn declared_charset(head: &[u8], declared: Option<&str>) -> Option<Encoding> {
    declared_legacy(None, head, declared.and_then(charset::lookup))
}

/// [`declared_charset`] for an already looked-up label.
pub fn declared_charset_label(head: &[u8], declared: Label) -> Option<Encoding> {
    declared_legacy(None, head, Some(declared))
}

/// The head of a probe as UTF-8-compatible bytes: without a byte order
/// mark, and transcoded if it is UTF-16/32.
pub fn probe_text<'a>(data: &'a [u8]) -> Cow<'a, [u8]> {
    match bom(data) {
        Some((Encoding::Utf8, n)) => Cow::Borrowed(data.get(to_usize(n)..).unwrap_or_default()),
        Some((e, n)) => Cow::Owned(
            e.decode(data.get(to_usize(n)..).unwrap_or_default())
                .into_bytes(),
        ),
        None => match sniff_utf16(data) {
            Some(e) => Cow::Owned(e.decode(data).into_bytes()),
            None => Cow::Borrowed(data),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_code_pages_are_text() {
        // "Привет, мир. Это проверка текста." in Windows-1251 and KOI8-R.
        let cp1251 = b"\xcf\xf0\xe8\xe2\xe5\xf2, \xec\xe8\xf0. \xdd\xf2\xee \xef\xf0\xee\xe2\xe5\xf0\xea\xe0 \xf2\xe5\xea\xf1\xf2\xe0 \xed\xe0 \xf0\xf3\xf1\xf1\xea\xee\xec \xff\xe7\xfb\xea\xe5.\n";
        assert_eq!(
            classify(cp1251),
            Some(Encoding::Single(Charset::Windows1251))
        );
        let koi8 = b"\xf0\xd2\xc9\xd7\xc5\xd4, \xcd\xc9\xd2. \xfc\xd4\xcf \xd0\xd2\xcf\xd7\xc5\xd2\xcb\xc1 \xd4\xc5\xcb\xd3\xd4\xc1 \xce\xc1 \xd2\xd5\xd3\xd3\xcb\xcf\xcd \xd1\xda\xd9\xcb\xc5.\n";
        assert_eq!(classify(koi8), Some(Encoding::Single(Charset::Koi8R)));
        assert_eq!(
            classify(b"Caf\xe9 cr\xe8me br\xfbl\xe9e\n"),
            Some(Encoding::Windows1252)
        );
    }

    /// `tests/data/text/cjk.py`.
    const SJIS: &[u8] =
        include_bytes!("../../../../../tests/fixtures/synthetic/text/shift_jis.txt");
    const GBK: &[u8] = include_bytes!("../../../../../tests/fixtures/synthetic/text/gbk.txt");
    const BIG5: &[u8] = include_bytes!("../../../../../tests/fixtures/synthetic/text/big5.txt");
    const EUC_KR: &[u8] = include_bytes!("../../../../../tests/fixtures/synthetic/text/euc-kr.txt");
    const EUC_JP: &[u8] = include_bytes!("../../../../../tests/fixtures/synthetic/text/euc-jp.txt");

    #[test]
    fn double_byte_code_pages_are_recognised() {
        use MultiByte::*;
        for (data, m) in [
            (SJIS, Cp932),
            (GBK, Cp936),
            (BIG5, Cp950),
            (EUC_KR, Cp949),
            (EUC_JP, EucJp),
        ] {
            assert_eq!(classify(data), Some(Encoding::Multi(m)), "{m:?}");
            // Each reads as some other code page too, but not well.
            for &other in MultiByte::ALL.iter().filter(|&&o| o != m) {
                assert_eq!(multi_score(other, data), None, "{m:?} as {other:?}");
            }
        }
        // Korean without its word spaces could be GBK or Big5 hanzi; with
        // them it is not Chinese.
        let unspaced: Vec<u8> = EUC_KR.iter().copied().filter(|&b| b != b' ').collect();
        assert_eq!(multi_score(Cp949, &unspaced), None);
        // Too few characters to tell.
        assert_eq!(guess_multi(b"file \x93\xfa\x96\x7b\n"), None);
        assert_eq!(guess_multi(SJIS.get(..12).unwrap_or_default()), None);
        // A lead byte cut off at the end of the sample is fine.
        assert_eq!(
            guess_multi(SJIS.get(..SJIS.len().saturating_sub(2)).unwrap_or_default()),
            Some(Cp932)
        );
    }

    #[test]
    fn single_byte_text_is_not_double_byte() {
        let french = "Les élèves étudièrent à Genève pendant l'été; où était-ce? Déjà là-bas, \
                      ils créèrent des chansons françaises très célèbres.\n";
        let french = encode_1252(french);
        assert_eq!(guess_multi(&french), None);
        assert_eq!(classify(&french), Some(Encoding::Windows1252));
        let cp1251 = b"\xcf\xf0\xe8\xe2\xe5\xf2, \xec\xe8\xf0. \xdd\xf2\xee \xef\xf0\xee\xe2\xe5\xf0\xea\xe0 \xf2\xe5\xea\xf1\xf2\xe0.\n";
        assert_eq!(guess_multi(cp1251), None);
        // Pseudo-random high bytes without controls or NULs (a compressed
        // or encrypted run) decode in GBK and Big5, but not as common text.
        let mut x = 0x1234_5678u32;
        let noise: Vec<u8> = (0..4096)
            .map(|_| {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
                0x80 | (x >> 24) as u8
            })
            .collect();
        assert_eq!(guess_multi(&noise), None);
        // Private-use and half-width singles of CP932 (0xA0..=0xFF).
        assert_eq!(guess_multi(&[0xfd, 0xfe, 0xff, 0xa0].repeat(64)), None);
    }

    fn encode_1252(s: &str) -> Vec<u8> {
        s.chars()
            .map(|c| {
                let u = c as u32;
                if u < 0x80 {
                    u as u8
                } else {
                    let high = Charset::Windows1252.high();
                    (0..128u8)
                        .find(|&i| high.get(usize::from(i)).map(|&h| u32::from(h)) == Some(u))
                        .map_or(b'?', |i| i | 0x80)
                }
            })
            .collect()
    }

    #[test]
    fn colours_overstrike_and_stray_nuls_are_text() {
        let colour = b"\x1b[32mINFO\x1b[0m compiling\n".repeat(20);
        assert_eq!(classify(&colour), Some(Encoding::Utf8));
        let man = b"N\x08NA\x08AM\x08ME\x08E\n     l\x08ls\x08s - list\n".repeat(4);
        assert_eq!(classify(&man), Some(Encoding::Utf8));
        let mut log = b"log line before the crash\n".repeat(20);
        log.extend_from_slice(&[0; 4]);
        log.extend_from_slice(&b"log line after the crash\n".repeat(200));
        assert_eq!(classify(&log), Some(Encoding::Utf8));
    }

    #[test]
    fn binary_stays_binary() {
        // A NUL near the start (a binary header), a few high bytes, a few
        // repeated byte values, and binary bytes before long runs of text.
        let mut icc = b"\0\0\x010".to_vec();
        icc.extend_from_slice(&[b'x'; 300]);
        assert_eq!(classify(&icc), None);
        assert_eq!(classify(b"\xec\xeb\xeb="), None);
        let res = b"\xff\xff\xff\xff @\x80\xff\xff\xff\xff\xff @\x80\xff".repeat(4);
        assert_eq!(classify(&res), None);
        let mut runs = b"\x19f\x02\x7f/\x90BKEy\x9d\x17g\x0f\0\x81)\x05\x06\x10zC".to_vec();
        runs.extend_from_slice(&[b'a'; 4000]);
        assert_eq!(classify(&runs), None);
    }
}
