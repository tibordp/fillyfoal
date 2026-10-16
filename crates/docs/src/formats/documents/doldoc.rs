//! TempleOS DolDoc documents, and HolyC source, which is DolDoc too.
//!
//! A DolDoc file (`DocSave`/`DocLoad` in `Adam/DolDoc/DocFile.HC`) is text
//! with commands bracketed by dollar signs, `$LK,"Text",A="MN:Print"$`:
//! a two-letter code (`ST_DOC_CMDS` in `Adam/DolDoc/DocInit.HC`) or a color
//! name, `+`/`-` flags, then comma-separated arguments, each `KEY=value` or
//! positional (`PrsDollarCmd` in `Adam/DolDoc/DocPlain.HC`; the grammar is
//! in `Doc/DolDocOverview.DD`). A command runs to the next dollar sign
//! (`DocPutS`), so it never contains one; `$$` is a literal dollar sign.
//! Byte 5 (`CH_CURSOR`) marks where the cursor was. If the document has
//! binary data (sprites), the text ends with a NUL and the bins follow:
//! each a `CDocBin` from `start` to `end` (32-bit `num`, `flags`, `size`,
//! `use_cnt`) and `size` bytes, which commands refer to with `BI=num`.
//! Sprites are dissected by the image crate (`image::templeos`).
//!
//! HolyC source files (`.HC`, `.HH`, `.IN`, `.PRJ`) are DolDoc documents
//! the compiler reads, so links, colors and sprites appear in code; a file
//! without commands is plain text with HolyC's types (`U0`, `I64`) or its
//! `#help_index` directive.
//!
//! The plain text child follows `Doc2TXT` (`Adam/Opt/Utils/ToTXT.HC`):
//! text, with `$$` as one dollar sign, plus the tags of the commands that
//! show one (links, buttons, macros...; not sprites or HTML), without
//! the layout `Doc2TXT` adds (margins, indentation, cursor movement).
//! It is assembled from the file's own bytes, so it keeps their
//! provenance; tags are taken as written, with backslash escapes dropped.
//! TempleOS's character set is CP437 above 0x7f: text with such bytes is
//! transcoded to UTF-8 (a derived source) before the text dissector sees
//! it, as is text with shift-spaces (0x1f), which `Doc2TXT` makes spaces;
//! other ASCII text keeps the file's own bytes.
//!
//! In map files (`Kernel.MAP`, `Compiler.MAP`) each line is a link to a
//! function whose bin is a `CDbgInfo` (its source lines' code addresses)
//! rather than a sprite; bins that links refer to are read as such.
//!
//! Ported from the public-domain TempleOS V5.03 source.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::bytes::{find_byte, to_u64, to_usize, u32_le};
use crate::codec::charset::Charset;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::image::templeos::SPRITE;
use crate::formats::util::fmt::{clip, plural};
use crate::formats::{Format, Head, Input, Probe, dissect_named, embedded_as};
use crate::node::{Count, Node};
use crate::span::{Origin, Span};
use crate::value::Value;

pub static DOLDOC: Format = Format {
    name: "doldoc",
    title: "TempleOS DolDoc document",
    extensions: &["dd", "map"],
    mime: "text/x-doldoc",
    probe: Probe::Custom(|h| classify(h) == Some(Kind::DolDoc)),
    dissect: crate::expander!(doldoc: Input),
};

pub static HOLYC: Format = Format {
    name: "holyc",
    title: "HolyC source (DolDoc)",
    extensions: &["hc", "hh", "in", "prj"],
    mime: "text/x-holyc",
    probe: Probe::Custom(|h| classify(h) == Some(Kind::HolyC)),
    dissect: crate::expander!(holyc: Input),
};

// ---------------------------------------------------------------------------
// Commands

/// `ST_DOC_CMDS`, indexed by `DOCT_*`, with descriptions.
const COMMANDS: [(&[u8; 2], &str); 43] = [
    (b"TX", "Text"),
    (b"CR", "New line"),
    (b"SR", "Soft new line"),
    (b"TB", "Tab"),
    (b"PB", "Page break"),
    (b"CU", "Cursor"),
    (b"MK", "Marker"),
    (b"PT", "Prompt"),
    (b"CL", "Clear"),
    (b"PL", "Page length"),
    (b"LM", "Left margin"),
    (b"RM", "Right margin"),
    (b"HD", "Header"),
    (b"FO", "Footer"),
    (b"ID", "Indent"),
    (b"FG", "Foreground color"),
    (b"BG", "Background color"),
    (b"FD", "Default foreground color"),
    (b"BD", "Default background color"),
    (b"WW", "Word wrap"),
    (b"HL", "Highlight"),
    (b"BK", "Blink"),
    (b"IV", "Invert"),
    (b"UL", "Underline"),
    (b"SX", "Shift X"),
    (b"SY", "Shift Y"),
    (b"CM", "Cursor movement"),
    (b"AN", "Anchor"),
    (b"LK", "Link"),
    (b"BT", "Button"),
    (b"DA", "Data"),
    (b"CB", "Check box"),
    (b"LS", "List"),
    (b"MA", "Macro"),
    (b"MU", "Menu value"),
    (b"HX", "Hex editor"),
    (b"TR", "Tree"),
    (b"SP", "Sprite"),
    (b"IB", "Insert binary"),
    (b"IS", "Insert binary size"),
    (b"SO", "Song"),
    (b"HC", "HTML code"),
    (b"ER", "Error"),
];

/// `ST_COLORS`: a color name alone is a foreground color command.
const COLOR_NAMES: [&[u8]; 16] = [
    b"BLACK",
    b"BLUE",
    b"GREEN",
    b"CYAN",
    b"RED",
    b"PURPLE",
    b"BROWN",
    b"LTGRAY",
    b"DKGRAY",
    b"LTBLUE",
    b"LTGREEN",
    b"LTCYAN",
    b"LTRED",
    b"LTPURPLE",
    b"YELLOW",
    b"WHITE",
];

const FG: u8 = 15;
const LK: u8 = 28;
const CM: u8 = 26;
const HX: u8 = 35;
const SP: u8 = 37;
const HC: u8 = 41;
/// Not a command DolDoc knows (shown as an error entry in TempleOS).
const UNKNOWN: u8 = 43;
const KINDS: usize = 44;

/// Commands that carry a tag by default (`+T` in `DocInit`'s defaults).
fn has_tag(kind: u8) -> bool {
    matches!(kind, 0 | 27..=34 | 36..=41)
}

/// Commands whose first positional argument is a number (`attr`).
fn has_attr(kind: u8) -> bool {
    (9..=25).contains(&kind)
}

fn code(kind: u8) -> &'static str {
    match COMMANDS.get(usize::from(kind)) {
        Some((c, _)) => std::str::from_utf8(*c).unwrap_or("??"),
        None => "??",
    }
}

fn describe(kind: u8) -> &'static str {
    COMMANDS
        .get(usize::from(kind))
        .map_or("Unknown command", |c| c.1)
}

/// `ST_LINK_TYPES` (`LK_*` in `Adam/DolDoc/DocLink.HC`).
const LINK_TYPES: [(&[u8; 2], &str); 16] = [
    (b"FI", "File"),
    (b"FA", "File anchor"),
    (b"FF", "File find"),
    (b"FL", "File line"),
    (b"MN", "Manual page"),
    (b"PI", "Plain-text file"),
    (b"PF", "Plain-text find"),
    (b"PL", "Plain-text line"),
    (b"BF", "Bible find"),
    (b"DN", "Dictionary definition"),
    (b"HI", "Help index"),
    (b"AD", "Address"),
    (b"AI", "Document in memory"),
    (b"AA", "Document anchor"),
    (b"AF", "Document find"),
    (b"AL", "Document line"),
];

fn link_type(target: &str) -> &'static str {
    let t = target.as_bytes();
    if t.get(2) == Some(&b':') {
        for (c, name) in LINK_TYPES {
            if t.get(..2) == Some(c.as_slice()) {
                return name;
            }
        }
    }
    "File"
}

/// The command code at the start of a command body: its kind, or `None`
/// if it is not one.
fn kind_of(body: &[u8]) -> Option<u8> {
    let end = body
        .iter()
        .position(|b| !b.is_ascii_alphanumeric() && *b != b'_')
        .unwrap_or(body.len());
    let word = body.get(..end)?;
    if let Some(i) = COMMANDS.iter().position(|(c, _)| word == c.as_slice()) {
        return u8::try_from(i).ok();
    }
    COLOR_NAMES.contains(&word).then_some(FG)
}

/// A byte range of a command body.
type Range = (usize, usize);

/// One argument: `key=value` or positional; strings without their quotes.
#[derive(Debug)]
struct Arg {
    key: Option<Range>,
    value: Range,
    string: bool,
}

/// A command body taken apart.
#[derive(Debug)]
struct Command {
    code: Range,
    kind: u8,
    flags: Vec<(u8, Range)>,
    args: Vec<Arg>,
}

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn skip_space(body: &[u8], mut i: usize) -> usize {
    while body.get(i).is_some_and(|b| matches!(b, b' ' | b'\t' | 5)) {
        i = i.saturating_add(1);
    }
    i
}

fn ident_end(body: &[u8], mut i: usize) -> usize {
    while body.get(i).copied().is_some_and(is_ident) {
        i = i.saturating_add(1);
    }
    i
}

/// A quoted string starting at `i` (the quote): its content and the
/// position after the closing quote.
fn string_at(body: &[u8], i: usize) -> (Range, usize) {
    let start = i.saturating_add(1);
    let mut j = start;
    while let Some(&b) = body.get(j) {
        match b {
            b'\\' => j = j.saturating_add(2),
            b'"' => return ((start, j), j.saturating_add(1)),
            _ => j = j.saturating_add(1),
        }
    }
    let end = j.min(body.len());
    ((start, end), end)
}

/// An expression starting at `i`: up to a comma outside quotes and
/// brackets.
fn expression_at(body: &[u8], i: usize) -> (Range, usize) {
    let mut depth = 0u32;
    let mut j = i;
    while let Some(&b) = body.get(j) {
        match b {
            b'"' | b'\'' => {
                let mut k = j.saturating_add(1);
                while let Some(&c) = body.get(k) {
                    k = k.saturating_add(if c == b'\\' { 2 } else { 1 });
                    if c == b {
                        break;
                    }
                }
                j = k;
                continue;
            }
            b'(' | b'[' | b'{' => depth = depth.saturating_add(1),
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => break,
            _ => {}
        }
        j = j.saturating_add(1);
    }
    let end = j.min(body.len());
    let mut e = end;
    while e > i
        && body
            .get(e.saturating_sub(1))
            .is_some_and(|b| b.is_ascii_whitespace())
    {
        e = e.saturating_sub(1);
    }
    ((i, e), end)
}

/// Takes a command body apart as `PrsDollarCmd` does, leniently.
fn parse_command(body: &[u8]) -> Command {
    let mut i = skip_space(body, 0);
    let code_end = ident_end(body, i);
    let code = (i, code_end);
    let kind = body.get(i..code_end).and_then(kind_of).unwrap_or(UNKNOWN);
    i = code_end;
    let mut flags = Vec::new();
    loop {
        i = skip_space(body, i);
        match body.get(i) {
            Some(&sign @ (b'+' | b'-')) => {
                let s = skip_space(body, i.saturating_add(1));
                let e = ident_end(body, s);
                flags.push((sign, (s, e)));
                i = e.max(s.saturating_add(usize::from(e == s)));
            }
            _ => break,
        }
    }
    let mut args = Vec::new();
    loop {
        while body
            .get(i)
            .is_some_and(|b| matches!(b, b',' | b' ' | b'\t' | b'\r' | b'\n' | 5))
        {
            i = i.saturating_add(1);
        }
        if i >= body.len() {
            break;
        }
        if body.get(i) == Some(&b'"') {
            let (value, next) = string_at(body, i);
            args.push(Arg {
                key: None,
                value,
                string: true,
            });
            i = next;
            continue;
        }
        let key_end = ident_end(body, i);
        let eq = skip_space(body, key_end);
        if key_end > i && body.get(eq) == Some(&b'=') {
            let v = skip_space(body, eq.saturating_add(1));
            let (value, next, string) = if body.get(v) == Some(&b'"') {
                let (value, next) = string_at(body, v);
                (value, next, true)
            } else {
                let (value, next) = expression_at(body, v);
                (value, next, false)
            };
            args.push(Arg {
                key: Some((i, key_end)),
                value,
                string,
            });
            i = next.max(i.saturating_add(1));
        } else {
            let (value, next) = expression_at(body, i);
            args.push(Arg {
                key: None,
                value,
                string: false,
            });
            i = next.max(i.saturating_add(1));
        }
    }
    Command {
        code,
        kind,
        flags,
        args,
    }
}

fn slice(body: &[u8], (s, e): Range) -> &[u8] {
    body.get(s..e).unwrap_or_default()
}

/// A string argument without its escapes (`\"`, `\\`, `\n`, `\t`).
fn unescape(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut it = raw.iter();
    while let Some(&b) = it.next() {
        if b == b'\\' {
            match it.next() {
                Some(b'n') => out.push(b'\n'),
                Some(b't') => out.push(b'\t'),
                Some(&c) => out.push(c),
                None => {}
            }
        } else {
            out.push(b);
        }
    }
    out
}

fn text(raw: &[u8]) -> String {
    Charset::Cp437.decode(raw)
}

/// The meaning of each argument: its key, or what a positional argument
/// stands for (`PrsDollarCmd` gives positional arguments to the command's
/// default fields in order).
fn arg_names(cmd: &Command, body: &[u8]) -> Vec<String> {
    let mut positional: Vec<&str> = Vec::new();
    match cmd.kind {
        k if has_attr(k) => positional.push("Value"),
        HX => positional.extend(["Length", "Width"]),
        CM => positional.extend(["Left expression (LE)", "Right expression (RE)"]),
        k if has_tag(k) => positional.push("Tag"),
        _ => {}
    }
    let mut next = positional.into_iter();
    cmd.args
        .iter()
        .map(|a| match a.key {
            Some(k) => key_name(slice(body, k)),
            None => next.next().unwrap_or("Argument").to_owned(),
        })
        .collect()
}

/// `ST_DOC_FLAGS` keys that take a value.
fn key_name(key: &[u8]) -> String {
    let what = match key {
        b"T" => "Tag",
        b"LEN" => "Length",
        b"A" => "Aux",
        b"D" => "Define list",
        b"HTML" => "HTML link",
        b"LE" => "Left expression",
        b"LM" => "Left macro",
        b"RE" => "Right expression",
        b"RM" => "Right macro",
        b"BI" => "Bin",
        b"BP" => "Bin pointer link",
        b"RT" => "Raw type",
        b"SX" => "Shift X",
        b"SY" => "Shift Y",
        b"SCX" => "Scroll X",
        b"U" => "User data",
        _ => return text(key),
    };
    format!("{what} ({})", text(key))
}

/// The argument `key=` or, for `Tag`, the first positional string of a
/// tag-bearing command.
fn find_arg<'a>(cmd: &'a Command, body: &[u8], key: &[u8]) -> Option<&'a Arg> {
    if let Some(a) = cmd
        .args
        .iter()
        .find(|a| a.key.is_some_and(|k| slice(body, k) == key))
    {
        return Some(a);
    }
    (key == b"T" && has_tag(cmd.kind))
        .then(|| cmd.args.iter().find(|a| a.key.is_none() && a.string))
        .flatten()
}

fn arg_text(arg: &Arg, body: &[u8]) -> String {
    let raw = slice(body, arg.value);
    if arg.string {
        text(&unescape(raw))
    } else {
        text(raw)
    }
}

/// A number as HolyC writes one (decimal or `0x` hex).
fn number(raw: &[u8]) -> Option<u32> {
    let s = std::str::from_utf8(raw).ok()?.trim();
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16).ok(),
        None => s.parse().ok(),
    }
}

// ---------------------------------------------------------------------------
// Probe

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    DolDoc,
    HolyC,
}

/// Valid and invalid command bodies (`$...$` pairs) in `text`.
fn command_counts(text: &[u8]) -> (u32, u32) {
    let (mut good, mut bad) = (0u32, 0u32);
    let mut i = 0usize;
    while let Some(open) = text.get(i..).and_then(|t| find_byte(t, b'$')) {
        let start = i.saturating_add(open).saturating_add(1);
        let Some(close) = text.get(start..).and_then(|t| find_byte(t, b'$')) else {
            break;
        };
        let body = text
            .get(start..start.saturating_add(close))
            .unwrap_or_default();
        i = start.saturating_add(close).saturating_add(1);
        if body.is_empty() {
            continue;
        }
        let code_end = body
            .iter()
            .position(|b| !b.is_ascii_alphanumeric() && *b != b'_')
            .unwrap_or(body.len());
        let after = body.get(code_end).copied();
        if kind_of(body).is_some() && matches!(after, None | Some(b',' | b'+' | b'-')) {
            good = good.saturating_add(1);
        } else {
            bad = bad.saturating_add(1);
        }
    }
    (good, bad)
}

/// Whether `word` occurs in `text` as a whole identifier.
fn has_word(text: &[u8], word: &[u8]) -> bool {
    let mut from = 0usize;
    while let Some(at) = crate::bytes::find(text, word, from) {
        let before = at.checked_sub(1).and_then(|p| text.get(p)).copied();
        let after = text.get(at.saturating_add(word.len())).copied();
        if !before.is_some_and(is_ident) && !after.is_some_and(is_ident) {
            return true;
        }
        from = at.saturating_add(1);
    }
    false
}

/// Whether the lines look like code: at least 40% end with `;`, `{` or
/// `}` or start with `//` or `#`.
fn code_like(text: &[u8]) -> bool {
    let (mut lines, mut code) = (0u32, 0u32);
    for line in text.split(|&b| b == b'\n').take(400) {
        let t = line.trim_ascii();
        if t.is_empty() {
            continue;
        }
        lines = lines.saturating_add(1);
        if t.ends_with(b";")
            || t.ends_with(b"{")
            || t.ends_with(b"}")
            || t.starts_with(b"//")
            || t.starts_with(b"#")
        {
            code = code.saturating_add(1);
        }
    }
    lines > 0 && u64::from(code).saturating_mul(10) >= u64::from(lines).saturating_mul(4)
}

/// Whether a `CDocBin` header that fits follows the text.
fn bin_follows(h: &Head<'_>, text_len: usize) -> bool {
    let at = text_len.saturating_add(1);
    let Some(size) = u32_le(h.data, at.saturating_add(8)) else {
        return false;
    };
    h.within(to_u64(at).saturating_add(16).saturating_add(size.into()))
}

/// DolDoc commands in text (two or more, or one and a bin after the
/// text), and HolyC: `#help_index` first, or code with DolDoc commands
/// and HolyC's types, or code with `U0` and `I64` and no stray dollars.
fn classify(h: &Head<'_>) -> Option<Kind> {
    let nul = find_byte(h.data, 0);
    let text = h.data.get(..nul.unwrap_or(h.data.len()))?;
    if text.len() < 4
        || !text
            .iter()
            .all(|&b| b >= 0x20 || matches!(b, b'\t' | b'\n' | b'\r' | 5 | 0x1f))
    {
        return None;
    }
    if text.trim_ascii_start().starts_with(b"#help_index \"") {
        return Some(Kind::HolyC);
    }
    let (good, bad) = command_counts(text);
    if code_like(text) {
        let types = ["U0", "I64", "U8", "I32", "F64"]
            .iter()
            .any(|w| has_word(text, w.as_bytes()));
        let holyc = has_word(text, b"U0") && has_word(text, b"I64");
        if (good >= 1 && bad == 0 && types) || (holyc && bad.saturating_mul(4) <= good) {
            return Some(Kind::HolyC);
        }
    }
    if good >= 2 && bad.saturating_mul(8) <= good {
        return Some(Kind::DolDoc);
    }
    if good >= 1 && bad == 0 && nul.is_some_and(|n| bin_follows(h, n)) {
        return Some(Kind::DolDoc);
    }
    None
}

// ---------------------------------------------------------------------------
// Scanning

/// A command: its span (both dollar signs included) and kind.
#[derive(Clone, Copy, Debug)]
struct Cmd {
    span: Span,
    kind: u8,
}

/// A `CDocBin` and its data.
#[derive(Clone, Copy, Debug)]
struct Bin {
    num: u32,
    span: Span,
    data: Span,
    wanted: u64,
}

/// What one pass over the file finds.
#[derive(Debug, Default)]
struct Doc {
    text: u64,
    terminated: bool,
    cmds: Vec<Cmd>,
    total: u64,
    counts: Vec<u64>,
    links: Vec<u32>,
    /// Commands with `BI=`: index and bin number.
    refs: Vec<(u32, u32)>,
    uses: BTreeMap<u32, u32>,
    /// The kind of the first command referring to each bin.
    users: BTreeMap<u32, u8>,
    pieces: Vec<Span>,
    capped: bool,
    unclosed: Option<Span>,
    bins: Vec<Bin>,
    leftover: Option<Span>,
}

/// Commands, plain-text pieces and bins kept at most.
const MAX_ITEMS: usize = 1 << 18;
/// Command bodies longer than this are cut for parsing.
const BODY_CAP: usize = 4096;
const WINDOW: u64 = 64 * 1024;
const BIN_HEADER: u64 = 16;

impl Doc {
    fn piece(&mut self, span: Span) {
        if span.len == 0 {
            return;
        }
        if let Some(last) = self.pieces.last_mut()
            && last.source == span.source
            && last.end() == span.offset
        {
            last.len = last.len.saturating_add(span.len);
            return;
        }
        if self.pieces.len() >= MAX_ITEMS {
            self.capped = true;
            return;
        }
        self.pieces.push(span);
    }

    fn command(&mut self, file: Span, start: u64, end: u64, body: &[u8]) {
        let span = file.sub(start, end.saturating_sub(start));
        let cmd = parse_command(body);
        self.total = self.total.saturating_add(1);
        if let Some(c) = self.counts.get_mut(usize::from(cmd.kind)) {
            *c = c.saturating_add(1);
        }
        // The tag shown in the text (`Doc2TXT`).
        if has_tag(cmd.kind)
            && cmd.kind != SP
            && cmd.kind != HC
            && let Some(tag) = find_arg(&cmd, body, b"T")
            && tag.string
        {
            let base = start.saturating_add(1);
            let (s, e) = tag.value;
            let mut run = s;
            let mut i = s;
            while i < e {
                if body.get(i) == Some(&b'\\') {
                    self.piece(file.sub(
                        base.saturating_add(to_u64(run)),
                        to_u64(i.saturating_sub(run)),
                    ));
                    run = i.saturating_add(1);
                    i = i.saturating_add(2);
                } else {
                    i = i.saturating_add(1);
                }
            }
            self.piece(file.sub(
                base.saturating_add(to_u64(run)),
                to_u64(e.saturating_sub(run)),
            ));
        }
        if self.cmds.len() >= MAX_ITEMS {
            self.capped = true;
            return;
        }
        let index = u32::try_from(self.cmds.len()).unwrap_or(u32::MAX);
        if cmd.kind == LK {
            self.links.push(index);
        }
        if let Some(bin) = find_arg(&cmd, body, b"BI").and_then(|a| number(slice(body, a.value))) {
            self.refs.push((index, bin));
            self.users.entry(bin).or_insert(cmd.kind);
            let n = self.uses.entry(bin).or_insert(0);
            *n = n.saturating_add(1);
        }
        self.cmds.push(Cmd {
            span,
            kind: cmd.kind,
        });
    }
}

async fn scan(cx: &Cx, file: Span) -> Result<Arc<Doc>> {
    if let Some(doc) = cx.cached::<Doc>(file, "doldoc") {
        return Ok(doc);
    }
    let mut doc = Doc {
        counts: vec![0; KINDS],
        ..Doc::default()
    };
    let mut open: Option<u64> = None;
    let mut body: Vec<u8> = Vec::new();
    let mut run = 0u64;
    let mut pos = 0u64;
    let mut charged = 0u64;
    let mut end = file.len;
    'text: while pos < file.len {
        let data = cx.read_avail(file.sub(pos, WINDOW)).await?;
        if data.is_empty() {
            break;
        }
        for (i, &b) in data.iter().enumerate() {
            let at = pos.saturating_add(to_u64(i));
            match open {
                None => match b {
                    0 => {
                        end = at;
                        doc.terminated = true;
                        break 'text;
                    }
                    b'$' => {
                        doc.piece(file.sub(run, at.saturating_sub(run)));
                        open = Some(at);
                        body.clear();
                    }
                    5 => {
                        doc.piece(file.sub(run, at.saturating_sub(run)));
                        run = at.saturating_add(1);
                    }
                    _ => {}
                },
                Some(start) => match b {
                    b'$' => {
                        if at == start.saturating_add(1) {
                            // `$$`: one literal dollar sign.
                            doc.piece(file.sub(start, 1));
                        } else {
                            doc.command(file, start, at.saturating_add(1), &body);
                        }
                        open = None;
                        run = at.saturating_add(1);
                    }
                    0 => {
                        end = at;
                        doc.terminated = true;
                        break 'text;
                    }
                    _ => {
                        if body.len() < BODY_CAP {
                            body.push(b);
                        }
                    }
                },
            }
        }
        pos = pos.saturating_add(to_u64(data.len()));
        // Parsing a command costs about a unit; the byte loop a unit per KiB.
        cx.charge((to_u64(data.len()) / 1024).saturating_add(doc.total.saturating_sub(charged)))
            .await;
        charged = doc.total;
    }
    cx.charge(doc.total.saturating_sub(charged)).await;
    match open {
        Some(start) => doc.unclosed = Some(file.sub(start, end.saturating_sub(start))),
        None => doc.piece(file.sub(run, end.saturating_sub(run))),
    }
    doc.text = end;
    if doc.terminated {
        bins(cx, file, &mut doc).await?;
    }
    let doc = Arc::new(doc);
    cx.cache(file, "doldoc", doc.clone());
    Ok(doc)
}

/// `DocLoad`: a bin wherever at least a header's worth of bytes is left.
async fn bins(cx: &Cx, file: Span, doc: &mut Doc) -> Result<()> {
    let mut pos = doc.text.saturating_add(1);
    while file.len.saturating_sub(pos) >= BIN_HEADER {
        let header = cx.read(file.sub(pos, BIN_HEADER)).await?;
        let num = u32_le(&header, 0).unwrap_or(0);
        let size = u64::from(u32_le(&header, 8).unwrap_or(0));
        let data = file.sub(pos.saturating_add(BIN_HEADER), size);
        if doc.bins.len() >= MAX_ITEMS {
            doc.capped = true;
            return Ok(());
        }
        doc.bins.push(Bin {
            num,
            span: file.sub(pos, BIN_HEADER.saturating_add(data.len)),
            data,
            wanted: size,
        });
        pos = pos.saturating_add(BIN_HEADER).saturating_add(size);
    }
    if pos < file.len {
        doc.leftover = Some(file.tail(pos));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Dissection

async fn doldoc(cx: Cx, input: Input) -> Result<()> {
    dissect(cx, input, Kind::DolDoc).await
}

async fn holyc(cx: Cx, input: Input) -> Result<()> {
    dissect(cx, input, Kind::HolyC).await
}

/// The most frequent command kinds, for summaries.
fn top_kinds(doc: &Doc, n: usize) -> String {
    let mut kinds: Vec<(u64, u8)> = doc
        .counts
        .iter()
        .enumerate()
        .filter(|(_, c)| **c > 0)
        .map(|(k, &c)| (c, u8::try_from(k).unwrap_or(UNKNOWN)))
        .collect();
    kinds.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    let mut parts: Vec<String> = kinds
        .iter()
        .take(n)
        .map(|&(c, k)| format!("{c} {}", if k == UNKNOWN { "unknown" } else { code(k) }))
        .collect();
    if kinds.len() > n {
        parts.push("…".to_owned());
    }
    parts.join(", ")
}

async fn dissect(cx: Cx, input: Input, kind: Kind) -> Result<()> {
    let file = input.span;
    let doc = scan(&cx, file).await?;
    let text = file.sub(0, doc.text);
    cx.emit(Node::new("Text").span(text).summary(format!(
        "{}, {}",
        plural(doc.text, "byte"),
        plural(doc.total, "command")
    )));
    if doc.total > 0 {
        cx.emit(
            Node::new("Commands")
                .span(text)
                .summary(top_kinds(&doc, 6))
                .lazy(commands, input),
        );
    }
    if !doc.links.is_empty() {
        cx.emit(
            Node::new("Links")
                .span(text)
                .summary(plural(doc.links.len(), "link"))
                .lazy(links, input),
        );
    }
    if !doc.refs.is_empty() {
        cx.emit(
            Node::new("Bin references")
                .span(text)
                .summary(plural(doc.refs.len(), "command"))
                .desc("Commands with BI=, such as sprites ($SP$) and inserted binaries ($IB$)")
                .lazy(references, input),
        );
    }
    cx.emit(
        Node::new("Plain text")
            .span(text)
            .desc("The text and the tags it shows, as Doc2TXT has it, without its layout; CP437 beyond ASCII is transcoded to UTF-8")
            .lazy(plain_text, input),
    );
    if doc.terminated {
        cx.emit(
            Node::new("Terminator")
                .span(file.sub(doc.text, 1))
                .desc("The NUL that ends the text when bins follow"),
        );
    }
    if !doc.bins.is_empty() {
        cx.emit(
            Node::new("Bins")
                .span(file.tail(doc.text.saturating_add(1)))
                .summary(plural(doc.bins.len(), "bin"))
                .lazy(bin_list, input),
        );
    }
    if let Some(span) = doc.leftover {
        cx.emit(
            Node::new("Trailing data")
                .span(span)
                .summary(plural(span.len, "byte"))
                .diag(Diagnostic::malformed("too short for a bin header").at(span)),
        );
    }
    if let Some(span) = doc.unclosed {
        cx.diag(
            Diagnostic::malformed("a command is not closed; TempleOS drops the rest of the text")
                .at(span),
        );
    }
    if doc.capped {
        cx.diag(Diagnostic::limit(format!(
            "only the first {MAX_ITEMS} commands, text pieces and bins are listed"
        )));
    }
    let what = match kind {
        Kind::DolDoc => "DolDoc document",
        Kind::HolyC => "HolyC source (DolDoc)",
    };
    let mut parts = vec![plural(doc.total, "command")];
    if !doc.links.is_empty() {
        parts.push(plural(doc.links.len(), "link"));
    }
    if !doc.bins.is_empty() {
        parts.push(plural(doc.bins.len(), "bin"));
    }
    cx.annotate(format!("{what}, {}", parts.join(", ")));
    Ok(())
}

/// One node per kind of command present.
async fn commands(cx: Cx, input: Input) -> Result<()> {
    let doc = scan(&cx, input.span).await?;
    for (k, &n) in doc.counts.iter().enumerate() {
        if n == 0 {
            continue;
        }
        let kind = u8::try_from(k).unwrap_or(UNKNOWN);
        let name = if kind == UNKNOWN { "??" } else { code(kind) };
        let mut node = Node::new(name)
            .span(input.span.sub(0, doc.text))
            .summary(format!("{}: {n}", describe(kind)))
            .lazy(kind_list, (input, kind));
        if kind == UNKNOWN {
            node = node.desc("Commands DolDoc does not know; TempleOS shows them as errors");
        }
        cx.emit(node);
    }
    Ok(())
}

/// Commands listed between checkpoints when filtering.
const FILTER_STEP: usize = 4096;

async fn kind_list(cx: Cx, (input, kind): (Input, u8)) -> Result<()> {
    let doc = scan(&cx, input.span).await?;
    let stored = doc.cmds.iter().filter(|c| c.kind == kind).count();
    cx.set_count(Count::Exact(to_u64(stored)));
    let mut n = 0u64;
    for (i, c) in doc.cmds.iter().enumerate() {
        if i % FILTER_STEP == FILTER_STEP - 1 {
            cx.checkpoint().await;
        }
        if c.kind != kind {
            continue;
        }
        if cx.skipping() {
            cx.push(Node::new(format!("[{n}]")).span(c.span)).await;
        } else {
            cx.push(command_node(&cx, format!("[{n}]"), c.span).await?)
                .await;
        }
        n = n.saturating_add(1);
    }
    Ok(())
}

/// The body of the command at `span`, without its dollar signs.
async fn body_of(cx: &Cx, span: Span) -> Result<Vec<u8>> {
    let inner = span.sub(1, span.len.saturating_sub(2).min(to_u64(BODY_CAP)));
    cx.read(inner).await
}

async fn command_node(cx: &Cx, name: String, span: Span) -> Result<Node> {
    let body = body_of(cx, span).await?;
    Ok(Node::new(name)
        .span(span)
        .value(Value::Text(clip(&text(&body), 200)))
        .lazy(command_fields, span))
}

async fn command_fields(cx: Cx, span: Span) -> Result<()> {
    let body = body_of(&cx, span).await?;
    let cmd = parse_command(&body);
    let at = |(s, e): Range| span.sub(1u64.saturating_add(to_u64(s)), to_u64(e.saturating_sub(s)));
    cx.emit(
        Node::new("Code")
            .span(at(cmd.code))
            .value(Value::Text(text(slice(&body, cmd.code))))
            .summary(describe(cmd.kind)),
    );
    for &(sign, flag) in &cmd.flags {
        let on = if sign == b'+' { "set" } else { "cleared" };
        cx.emit(
            Node::new("Flag")
                .span(at((flag.0.saturating_sub(1), flag.1)))
                .value(Value::Text(format!(
                    "{}{}",
                    char::from(sign),
                    text(slice(&body, flag))
                )))
                .summary(on),
        );
    }
    let names = arg_names(&cmd, &body);
    for (arg, name) in cmd.args.iter().zip(names) {
        let mut node = Node::new(name)
            .span(at(arg.value))
            .value(Value::Text(arg_text(arg, &body)));
        if arg.key.is_some_and(|k| slice(&body, k) == b"A") && cmd.kind == LK {
            node = node.summary(link_type(&arg_text(arg, &body)));
        }
        cx.emit(node);
    }
    if span.len.saturating_sub(2) > to_u64(BODY_CAP) {
        cx.diag(Diagnostic::limit(format!(
            "only the first {BODY_CAP} bytes of the command are parsed"
        )));
    }
    Ok(())
}

/// A link's text and target: `A=` if given, else the tag.
fn link_parts(body: &[u8]) -> (String, String) {
    let cmd = parse_command(body);
    let tag = find_arg(&cmd, body, b"T").map(|a| arg_text(a, body));
    let aux = find_arg(&cmd, body, b"A").map(|a| arg_text(a, body));
    let target = aux.clone().or_else(|| tag.clone()).unwrap_or_default();
    (tag.unwrap_or_default(), target)
}

async fn links(cx: Cx, input: Input) -> Result<()> {
    let doc = scan(&cx, input.span).await?;
    cx.set_count(Count::Exact(to_u64(doc.links.len())));
    for &i in &doc.links {
        let Some(c) = doc.cmds.get(to_usize(i.into())) else {
            continue;
        };
        let body = body_of(&cx, c.span).await?;
        let (tag, target) = link_parts(&body);
        cx.push(
            Node::new(clip(&tag, 60))
                .span(c.span)
                .value(Value::Text(target.clone()))
                .summary(link_type(&target))
                .lazy(command_fields, c.span),
        )
        .await;
    }
    Ok(())
}

async fn references(cx: Cx, input: Input) -> Result<()> {
    let doc = scan(&cx, input.span).await?;
    let by_num: BTreeMap<u32, Span> = doc.bins.iter().map(|b| (b.num, b.span)).collect();
    cx.set_count(Count::Exact(to_u64(doc.refs.len())));
    for &(i, num) in &doc.refs {
        let Some(c) = doc.cmds.get(to_usize(i.into())) else {
            continue;
        };
        let body = body_of(&cx, c.span).await?;
        let cmd = parse_command(&body);
        let tag = find_arg(&cmd, &body, b"T")
            .map(|a| arg_text(a, &body))
            .unwrap_or_default();
        let name = if tag.is_empty() {
            code(cmd.kind).to_owned()
        } else {
            format!("{} {}", code(cmd.kind), clip(&tag, 40))
        };
        let mut node = Node::new(name)
            .span(c.span)
            .value(Value::Text(format!("bin {num}")))
            .summary(describe(cmd.kind))
            .lazy(command_fields, c.span);
        node = match by_num.get(&num) {
            Some(&bin) => node.target(bin),
            None => node.diag(Diagnostic::malformed(format!("there is no bin {num}"))),
        };
        cx.push(node).await;
    }
    Ok(())
}

/// `CH_SHIFT_SPACE`: a space the editor will not break a line at.
const CH_SHIFT_SPACE: u8 = 0x1f;

async fn plain_text(cx: Cx, input: Input) -> Result<()> {
    let doc = scan(&cx, input.span).await?;
    if doc.pieces.is_empty() {
        cx.diag(Diagnostic::note("no text"));
        return Ok(());
    }
    let span = cx
        .add_pieces_stepped(
            Origin {
                parent: input.span.sub(0, doc.text),
                transform: "doldoc-text",
            },
            &doc.pieces,
        )
        .await?;
    let span = cp437_to_utf8(&cx, span).await?;
    // As plain text: the text may well show dollar-sign commands it quotes.
    dissect_named(cx, (input.nested(span), "text")).await
}

/// `span` transcoded from CP437 to UTF-8 as a derived source, with
/// `CH_SHIFT_SPACE` (0x1f) as the space `Doc2TXT` makes of it; or `span`
/// itself if it is ASCII without those (or too large to transcode).
async fn cp437_to_utf8(cx: &Cx, span: Span) -> Result<Span> {
    const CHUNK: usize = 64 * 1024;
    let origin = Origin {
        parent: span,
        transform: "cp437",
    };
    if let Some(found) = cx.derived(origin) {
        return Ok(found.span);
    }
    if span.len > cx.limits().max_derived {
        return Ok(span);
    }
    let data = crate::codec::read_all(cx, span).await?;
    if data.is_ascii() && find_byte(&data, CH_SHIFT_SPACE).is_none() {
        return Ok(span);
    }
    let mut text = String::with_capacity(data.len());
    for chunk in data.chunks(CHUNK) {
        let chunk: Vec<u8> = chunk
            .iter()
            .map(|&b| if b == CH_SHIFT_SPACE { b' ' } else { b })
            .collect();
        text.push_str(&Charset::Cp437.decode(&chunk));
        cx.checkpoint().await;
    }
    Ok(cx
        .add_derived(origin, text.into_bytes(), to_u64(data.len()), None)?
        .span)
}

async fn bin_list(cx: Cx, input: Input) -> Result<()> {
    let doc = scan(&cx, input.span).await?;
    cx.set_count(Count::Exact(to_u64(doc.bins.len())));
    for b in &doc.bins {
        let uses = doc.uses.get(&b.num).copied().unwrap_or(0);
        let mut summary = plural(b.wanted, "byte");
        summary.push_str(&match uses {
            0 => ", not referenced".to_owned(),
            n => format!(", {}", plural(n, "reference")),
        });
        let mut node = Node::new(format!("Bin {}", b.num))
            .span(b.span)
            .summary(summary);
        if b.data.len < b.wanted {
            node = node.diag(Diagnostic::truncated(
                Span::new(b.data.source, b.data.offset, b.wanted),
                b.data.len,
            ));
        }
        let dbg = doc.users.get(&b.num) == Some(&LK);
        if dbg {
            node = node.desc("Line addresses of the function the link names (CDbgInfo)");
        }
        cx.push(node.lazy(bin_fields, (input, *b, dbg))).await;
    }
    Ok(())
}

fn bin_header(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("Number").desc("num: what BI= refers to").emit()?;
    f.u32("Flags").hex().emit()?;
    f.u32("Size").emit()?;
    f.u32("Use count")
        .desc("use_cnt: commands referring to the bin when saved")
        .emit()?;
    Ok(())
}

/// A bin a link refers to is a `CDbgInfo` (map files, `Compiler/CHash.HC`);
/// any other is a sprite.
async fn bin_fields(cx: Cx, (input, b, dbg): (Input, Bin, bool)) -> Result<()> {
    let header = b.span.sub(0, BIN_HEADER);
    cx.emit(struct_node(
        "Header",
        header,
        Endian::Little,
        (),
        bin_header,
    ));
    if dbg {
        dbg_info(&cx, b.data).await?;
    } else {
        cx.emit(embedded_as("Sprite", input.nested(b.data), &SPRITE));
    }
    Ok(())
}

/// `CDbgInfo`: the first and last source line of a function, then the
/// 32-bit code address of each line from `min_line` to `max_line + 1` (the
/// last is the end of the function), as the compiler's map writer
/// (`MapFileWrite` in `Compiler/CHash.HC`) and `FunSeg.HC` use it.
async fn dbg_info(cx: &Cx, data: Span) -> Result<()> {
    let head = cx.read(data.sub_exact(0, 8)?).await?;
    let min = u32_le(&head, 0).unwrap_or(0);
    let max = u32_le(&head, 4).unwrap_or(0);
    cx.emit(
        Node::new("First line")
            .span(data.sub(0, 4))
            .value(Value::UInt {
                value: min.into(),
                bits: 32,
                radix: crate::value::Radix::Dec,
            }),
    );
    cx.emit(
        Node::new("Last line")
            .span(data.sub(4, 4))
            .value(Value::UInt {
                value: max.into(),
                bits: 32,
                radix: crate::value::Radix::Dec,
            }),
    );
    let wanted = u64::from(max)
        .saturating_add(2)
        .saturating_sub(min.into())
        .saturating_mul(4);
    let body = data.sub(8, wanted);
    let mut node = Node::new("Line addresses")
        .span(body)
        .summary(plural(body.len / 4, "address"));
    if max < min {
        node = node.diag(Diagnostic::malformed("the last line is before the first"));
    } else if body.len < wanted {
        node = node.diag(Diagnostic::truncated(
            Span::new(body.source, body.offset, wanted),
            body.len,
        ));
    }
    cx.emit(node.lazy(line_addresses, (body, min)));
    Ok(())
}

async fn line_addresses(cx: Cx, (body, min): (Span, u32)) -> Result<()> {
    const BATCH: u64 = 1024;
    let n = body.len / 4;
    cx.set_count(Count::Exact(n));
    let mut i = 0u64;
    while i < n {
        let take = BATCH.min(n.saturating_sub(i));
        let chunk = body.sub(i.saturating_mul(4), take.saturating_mul(4));
        let data = cx.read(chunk).await?;
        for (k, a) in data.as_chunks::<4>().0.iter().enumerate() {
            let index = i.saturating_add(to_u64(k));
            let line = u64::from(min).saturating_add(index);
            let name = if index.saturating_add(1) == n {
                format!("End ({line})")
            } else {
                format!("Line {line}")
            };
            cx.push(
                Node::new(name)
                    .span(chunk.sub(to_u64(k).saturating_mul(4), 4))
                    .value(Value::UInt {
                        value: u32::from_le_bytes(*a).into(),
                        bits: 32,
                        radix: crate::value::Radix::Hex,
                    }),
            )
            .await;
        }
        i = i.saturating_add(take);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_parse() {
        let body = br#"LK-UL+X,"Some \"text\"",A="MN:Print",BI=0x10"#;
        let cmd = parse_command(body);
        assert_eq!(cmd.kind, LK);
        assert_eq!(cmd.flags.len(), 2);
        let names = arg_names(&cmd, body);
        assert_eq!(names.first().map(String::as_str), Some("Tag"));
        let tag = find_arg(&cmd, body, b"T").map(|a| arg_text(a, body));
        assert_eq!(tag.as_deref(), Some("Some \"text\""));
        let bin = find_arg(&cmd, body, b"BI").and_then(|a| number(slice(body, a.value)));
        assert_eq!(bin, Some(16));
        assert_eq!(kind_of(b"RED"), Some(FG));
        assert_eq!(parse_command(b"ID,-2").args.len(), 1);
    }

    fn kind(data: &[u8]) -> Option<Kind> {
        classify(&Head {
            data,
            tail: data,
            len: to_u64(data.len()),
            len_known: true,
        })
    }

    #[test]
    fn probe_kinds() {
        let holyc = b"I64 x;\nU0 Main()\n{\n  x=1;\n}\n";
        assert_eq!(kind(holyc), Some(Kind::HolyC));
        let c = b"typedef int I64;\nstatic U8 b;\nI64 f(void)\n{\n  return 0;\n}\n";
        assert_eq!(kind(c), None);
        assert_eq!(kind(b"$WW,1$Some $FG,2$text$FG$.\n"), Some(Kind::DolDoc));
        assert_eq!(kind(b"Costs $5 or $10, says $FG$.\n"), None);
        let mut sprite = b"$SP,\"\",BI=1$\n\0".to_vec();
        sprite.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0]);
        assert_eq!(kind(&sprite), Some(Kind::DolDoc));
    }

    #[test]
    fn bin_needs_a_known_length_or_the_head() {
        // One command and a bin whose size runs past the data: with the
        // length only an upper bound, that it "fits" proves nothing.
        let mut data = b"$FG$hello world\0".to_vec();
        data.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0, 0xa0, 0x86, 1, 0, 0, 0, 0, 0]);
        let head = |len_known| Head {
            data: &data,
            tail: &data,
            len: 1 << 20,
            len_known,
        };
        assert_eq!(classify(&head(false)), None);
        assert_eq!(classify(&head(true)), Some(Kind::DolDoc));
    }

    #[test]
    fn probe_counts() {
        assert_eq!(command_counts(b"$WW,1$$FG,2$x$$y$FG$ $5 and $10"), (3, 1));
        assert!(has_word(b"U0 Main()", b"U0"));
        assert!(!has_word(b"U01", b"U0"));
    }
}
