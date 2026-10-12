//! The TempleOS AutoComplete dictionary: `ACWords.DATA` and `ACDefs.DATA`.
//!
//! Both are written by `ACDGen` in `Adam/AutoComplete/ACDictGen.HC` from
//! the Project Gutenberg edition of Webster's 1913 dictionary, and read by
//! `ACDDefGet` and the word filler (`Adam/AutoComplete/ACFill.HC`):
//!
//! - the **definitions** file is a stream of fields, each a marker byte
//!   (`ACD_WORD_CHAR` 1, `ACD_DEF_CHAR` 2, `ACD_PRONUNCIATION_CHAR` 3,
//!   `ACD_POS_CHAR` 4, `ACD_EXTRA_CHAR` 5) and a NUL-terminated string,
//!   ended by `ACD_END_CHAR` (0); a word field starts each entry;
//! - the **word list** holds the same words, sorted case-insensitively,
//!   each `ACD_WORD_CHAR`, the word, a NUL and the 16-bit number of the
//!   16 KiB block (`ACD_BLK_SIZE`) of the definitions file its entry starts
//!   in; it ends with `ACD_END_CHAR` too.
//!
//! Strings are in TempleOS's character set, CP437 above 0x7f.
//!
//! Ported from the public-domain TempleOS V5.03 source.

use crate::bytes::{find_byte, to_u64, to_usize, u16_le};
use crate::codec::charset::Charset;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::fmt::{clip, plural};
use crate::formats::util::val::uint;
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::Value;

pub static WORDS: Format = Format {
    name: "templeos-ac-words",
    title: "TempleOS AutoComplete word list",
    extensions: &["data"],
    mime: "application/x-templeos-ac-words",
    probe: Probe::Custom(words_probe),
    dissect: crate::expander!(words: Input),
};

pub static DEFS: Format = Format {
    name: "templeos-ac-defs",
    title: "TempleOS AutoComplete dictionary",
    extensions: &["data"],
    mime: "application/x-templeos-ac-defs",
    probe: Probe::Custom(defs_probe),
    dissect: crate::expander!(defs: Input),
};

const END: u8 = 0;
const WORD: u8 = 1;
/// `ACD_BLK_SIZE`.
const BLOCK: u64 = 0x4000;
/// Words longer than this are not believed.
const MAX_WORD: usize = 256;
/// Records the probes want to see (fewer only if the file ends first).
const PROBE_RECORDS: u32 = 8;
const WINDOW: u64 = 64 * 1024;

fn printable(b: &[u8]) -> bool {
    b.iter().all(|&c| c >= 0x20 && c != 0x7f)
}

fn field_text(b: &[u8]) -> bool {
    b.iter()
        .all(|&c| (c >= 0x20 && c != 0x7f) || matches!(c, b'\n' | b'\r' | b'\t'))
}

/// Word records from the start: `01`, a word, NUL, a 16-bit block.
fn words_probe(h: &Head<'_>) -> bool {
    let d = h.data;
    let mut pos = 0usize;
    let mut records = 0u32;
    while records < PROBE_RECORDS {
        match d.get(pos) {
            Some(&WORD) => {}
            Some(&END) => {
                return records >= 2 && h.len_known && to_u64(pos).saturating_add(1) == h.len;
            }
            _ => return false,
        }
        let start = pos.saturating_add(1);
        let Some(n) = d.get(start..).and_then(|r| find_byte(r, 0)) else {
            return false;
        };
        let word = d.get(start..start.saturating_add(n)).unwrap_or_default();
        if word.is_empty() || n > MAX_WORD || !printable(word) {
            return false;
        }
        pos = start.saturating_add(n).saturating_add(3);
        records = records.saturating_add(1);
    }
    true
}

/// Fields from the start: a word first, markers 1 to 5, text, NUL.
fn defs_probe(h: &Head<'_>) -> bool {
    let d = h.data;
    if d.first() != Some(&WORD) {
        return false;
    }
    let mut pos = 0usize;
    let mut records = 0u32;
    let mut other = false;
    while records < PROBE_RECORDS {
        match d.get(pos) {
            Some(&END) => {
                return records >= 3
                    && other
                    && h.len_known
                    && to_u64(pos).saturating_add(1) == h.len;
            }
            Some(&m @ 1..=5) => other |= m != WORD,
            _ => return false,
        }
        let start = pos.saturating_add(1);
        let Some(n) = d.get(start..).and_then(|r| find_byte(r, 0)) else {
            // A long definition may run past the head.
            return records >= 3 && other;
        };
        let body = d.get(start..start.saturating_add(n)).unwrap_or_default();
        if !field_text(body) || (d.get(pos) == Some(&WORD) && (body.is_empty() || n > MAX_WORD)) {
            return false;
        }
        pos = start.saturating_add(n).saturating_add(1);
        records = records.saturating_add(1);
    }
    other
}

/// A window of the input, refilled as the walkers move through it.
struct Window {
    span: Span,
    start: u64,
    data: Vec<u8>,
}

impl Window {
    fn new(span: Span) -> Self {
        Window {
            span,
            start: 0,
            data: Vec::new(),
        }
    }

    /// The bytes from `pos` to the end of the window, refilled so that at
    /// least `want` bytes are there unless the input ends first.
    async fn at(&mut self, cx: &Cx, pos: u64, want: u64) -> Result<&[u8]> {
        let end = self.start.saturating_add(to_u64(self.data.len()));
        let have_end = end >= self.span.len;
        if pos < self.start || (pos.saturating_add(want) > end && !have_end) || pos > end {
            self.start = pos;
            self.data = cx.read_avail(self.span.sub(pos, WINDOW.max(want))).await?;
        }
        Ok(self
            .data
            .get(to_usize(pos.saturating_sub(self.start))..)
            .unwrap_or_default())
    }

    /// The length of the NUL-terminated string at `pos`, without the NUL;
    /// `None` if the input ends first.
    async fn strlen(&mut self, cx: &Cx, pos: u64) -> Result<Option<u64>> {
        let mut at = pos;
        loop {
            let data = self.at(cx, at, 1).await?;
            if data.is_empty() {
                return Ok(None);
            }
            if let Some(n) = find_byte(data, 0) {
                return Ok(Some(at.saturating_add(to_u64(n)).saturating_sub(pos)));
            }
            at = at.saturating_add(to_u64(data.len()));
            cx.checkpoint().await;
        }
    }
}

fn decode(bytes: &[u8]) -> String {
    Charset::Cp437.decode(bytes)
}

async fn words(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut win = Window::new(file);
    let (mut pos, mut index) = cx.resume::<(u64, u64)>().unwrap_or((0, 0));
    loop {
        cx.progress_in(file, pos);
        let at = (pos, index);
        cx.mark(move || at);
        let head = win.at(&cx, pos, to_u64(MAX_WORD).saturating_add(4)).await?;
        match head.first() {
            None => {
                cx.diag(Diagnostic::malformed("no end marker").at(file.sub(pos, 0)));
                break;
            }
            Some(&END) => {
                cx.push(Node::new("End").span(file.sub(pos, 1))).await;
                pos = pos.saturating_add(1);
                break;
            }
            Some(&WORD) => {}
            Some(&m) => {
                cx.push(Node::new(format!("[{index}]")).span(file.tail(pos)).diag(
                    Diagnostic::malformed(format!("record marker {m}, not 1")).at(file.sub(pos, 1)),
                ))
                .await;
                return Ok(());
            }
        }
        let n = head.get(1..).and_then(|r| find_byte(r, 0));
        let Some(n) = n.filter(|&n| n <= MAX_WORD) else {
            cx.push(
                Node::new(format!("[{index}]"))
                    .span(file.tail(pos))
                    .diag(Diagnostic::malformed("word not terminated").at(file.sub(pos, 1))),
            )
            .await;
            return Ok(());
        };
        let word = decode(head.get(1..n.saturating_add(1)).unwrap_or_default());
        let block = u16_le(head, n.saturating_add(2));
        let len = to_u64(n).saturating_add(4);
        let span = file.sub(pos, len);
        let mut node = Node::new(word).span(span);
        match block {
            Some(b) => {
                node = node.value(uint(b, 16)).summary(format!(
                    "block {b}, definitions from {:#x}",
                    u64::from(b).saturating_mul(BLOCK)
                ));
            }
            None => {
                node = node.diag(Diagnostic::truncated(
                    Span::new(span.source, span.offset, len),
                    span.len,
                ))
            }
        }
        cx.push(node).await;
        pos = pos.saturating_add(len);
        index = index.saturating_add(1);
    }
    if pos < file.len {
        cx.push(
            Node::new("Trailing data")
                .span(file.tail(pos))
                .summary(plural(file.len.saturating_sub(pos), "byte")),
        )
        .await;
    }
    cx.annotate(format!(
        "TempleOS AutoComplete word list, {}",
        plural(index, "word")
    ));
    Ok(())
}

const FIELDS: [&str; 6] = [
    "End",
    "Word",
    "Definition",
    "Pronunciation",
    "Part of speech",
    "Extra",
];

/// Bytes of a definition shown in an entry's summary.
const PREVIEW: usize = 80;

async fn defs(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut win = Window::new(file);
    let (mut pos, mut index) = cx.resume::<(u64, u64)>().unwrap_or((0, 0));
    loop {
        cx.progress_in(file, pos);
        let at = (pos, index);
        cx.mark(move || at);
        let marker = win.at(&cx, pos, 1).await?.first().copied();
        match marker {
            None => {
                cx.diag(Diagnostic::malformed("no end marker").at(file.sub(pos, 0)));
                break;
            }
            Some(END) => {
                cx.push(Node::new("End").span(file.sub(pos, 1))).await;
                pos = pos.saturating_add(1);
                break;
            }
            Some(_) => {}
        }
        // An entry: its first field (a word, unless the file is damaged)
        // and the fields up to the next word or the end.
        let start = pos;
        let mut word = None;
        let mut preview = None;
        let mut first = true;
        let mut broken = None;
        loop {
            let m = win.at(&cx, pos, 1).await?.first().copied();
            let Some(m @ 1..=5) = m else {
                if let Some(m) = m.filter(|&m| m != END) {
                    broken = Some(
                        Diagnostic::malformed(format!("field marker {m}")).at(file.sub(pos, 1)),
                    );
                }
                break;
            };
            if m == WORD && !first {
                break;
            }
            first = false;
            let Some(n) = win.strlen(&cx, pos.saturating_add(1)).await? else {
                broken = Some(Diagnostic::malformed("field not terminated").at(file.tail(pos)));
                pos = file.len;
                break;
            };
            if (m == WORD && word.is_none()) || (m == 2 && preview.is_none()) {
                let shown = to_u64(PREVIEW.max(MAX_WORD)).min(n);
                let bytes = win.at(&cx, pos.saturating_add(1), shown).await?;
                let text = decode(bytes.get(..to_usize(shown)).unwrap_or_default());
                if m == WORD {
                    word = Some(text);
                } else {
                    preview = Some(text);
                }
            }
            pos = pos.saturating_add(n).saturating_add(2);
        }
        let span = file.sub(start, pos.saturating_sub(start));
        let mut node = Node::new(word.unwrap_or_else(|| format!("[{index}]")))
            .span(span)
            .lazy(entry_fields, span);
        if let Some(p) = preview {
            node = node.summary(clip(p.trim(), PREVIEW));
        }
        if let Some(d) = broken {
            node = node.diag(d);
            cx.push(node).await;
            index = index.saturating_add(1);
            cx.annotate(format!(
                "TempleOS AutoComplete dictionary, {}",
                plural(index, "entry")
            ));
            return Ok(());
        }
        cx.push(node).await;
        index = index.saturating_add(1);
        if span.len == 0 {
            break;
        }
    }
    if pos < file.len {
        cx.push(
            Node::new("Trailing data")
                .span(file.tail(pos))
                .summary(plural(file.len.saturating_sub(pos), "byte")),
        )
        .await;
    }
    cx.annotate(format!(
        "TempleOS AutoComplete dictionary, {}",
        crate::formats::util::fmt::count(index, "entry", "entries")
    ));
    Ok(())
}

/// Text kept per field value; the field's span covers all of it.
const VALUE_CAP: u64 = 4096;

async fn entry_fields(cx: Cx, span: Span) -> Result<()> {
    let mut win = Window::new(span);
    let mut pos = 0u64;
    while pos < span.len {
        let m = win.at(&cx, pos, 1).await?.first().copied().unwrap_or(END);
        let Some(n) = win.strlen(&cx, pos.saturating_add(1)).await? else {
            cx.diag(Diagnostic::malformed("field not terminated").at(span.tail(pos)));
            break;
        };
        let shown = n.min(VALUE_CAP);
        let bytes = win.at(&cx, pos.saturating_add(1), shown).await?;
        let mut text = decode(bytes.get(..to_usize(shown)).unwrap_or_default());
        if n > VALUE_CAP {
            text.push('…');
        }
        let name = FIELDS.get(usize::from(m)).copied().unwrap_or("Field");
        cx.push(
            Node::new(name)
                .span(span.sub(pos, n.saturating_add(2)))
                .value(Value::Text(text)),
        )
        .await;
        pos = pos.saturating_add(n).saturating_add(2);
    }
    Ok(())
}
