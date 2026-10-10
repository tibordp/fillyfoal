//! Rich Text Format: the group tree with control words, the font and color
//! tables, document information, embedded pictures (hex-encoded `\pict`
//! data decoded and dissected), and the document's plain text.

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::error::{DiagKind, Diagnostic, Result};
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::Value;

use super::decode::{Transform, decoded_node, preview};
use super::encoding::windows_1252;
use super::scan::Scanner;
use super::{plural, text_node};

pub static FORMAT: Format = Format {
    name: "rtf",
    title: "Rich Text Format",
    extensions: &["rtf"],
    mime: "application/rtf",
    probe: Probe::Magic(&[(0, b"{\\rtf")]),
    dissect: crate::expander!(dissect: Input),
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Open,
    Close,
    /// `\word` or `\word-123`.
    Word,
    /// `\` followed by a non-letter (`\*`, `\~`, `\{` ...).
    Symbol,
    /// `\'hh`.
    Hex,
    Text,
    /// `\binN` and its N raw bytes.
    Bin,
    Eof,
}

#[derive(Clone, Copy, Debug)]
struct Tok {
    kind: Kind,
    start: u64,
    end: u64,
    param: Option<i64>,
    /// The word's name (`start+1 .. name_end`).
    name_end: u64,
}

struct Lexer<'a> {
    scan: Scanner<'a>,
    pos: u64,
}

impl<'a> Lexer<'a> {
    fn new(cx: &'a Cx, span: Span) -> Self {
        Lexer {
            scan: Scanner::new(cx, span),
            pos: 0,
        }
    }

    fn tok(kind: Kind, start: u64, end: u64) -> Tok {
        Tok {
            kind,
            start,
            end,
            param: None,
            name_end: start,
        }
    }

    async fn next(&mut self) -> Result<Tok> {
        loop {
            let start = self.pos;
            let Some(b) = self.scan.byte(start).await? else {
                return Ok(Self::tok(Kind::Eof, start, start));
            };
            let one = start.saturating_add(1);
            let tok = match b {
                b'\r' | b'\n' => {
                    self.pos = one;
                    continue;
                }
                b'{' => Self::tok(Kind::Open, start, one),
                b'}' => Self::tok(Kind::Close, start, one),
                b'\\' => self.control(start).await?,
                _ => {
                    let end = self
                        .scan
                        .find(one, |c| matches!(c, b'\\' | b'{' | b'}' | b'\r' | b'\n'))
                        .await?
                        .unwrap_or(self.scan.len());
                    Self::tok(Kind::Text, start, end)
                }
            };
            self.pos = tok.end.max(one);
            return Ok(tok);
        }
    }

    async fn control(&mut self, start: u64) -> Result<Tok> {
        let at = start.saturating_add(1);
        let Some(c) = self.scan.byte(at).await? else {
            return Ok(Self::tok(Kind::Symbol, start, at));
        };
        if c == b'\'' {
            let hex = self
                .scan
                .bytes(at.saturating_add(1), at.saturating_add(3), 2)
                .await?;
            let value = u8::from_str_radix(&String::from_utf8_lossy(&hex), 16).ok();
            let mut t = Self::tok(Kind::Hex, start, at.saturating_add(3));
            t.param = value.map(i64::from);
            return Ok(t);
        }
        if !c.is_ascii_alphabetic() {
            return Ok(Self::tok(Kind::Symbol, start, at.saturating_add(1)));
        }
        let name_end = self
            .scan
            .find(at, |b| !b.is_ascii_alphabetic())
            .await?
            .unwrap_or(self.scan.len())
            .min(at.saturating_add(32));
        let mut end = name_end;
        let mut digits = Vec::new();
        if self.scan.byte(end).await? == Some(b'-') {
            digits.push(b'-');
            end = end.saturating_add(1);
        }
        while let Some(d) = self.scan.byte(end).await? {
            if !d.is_ascii_digit() || digits.len() > 11 {
                break;
            }
            digits.push(d);
            end = end.saturating_add(1);
        }
        let param = String::from_utf8_lossy(&digits).parse::<i64>().ok();
        if digits.len() == 1 && digits.first() == Some(&b'-') {
            end = end.saturating_sub(1);
        }
        if self.scan.byte(end).await? == Some(b' ') {
            end = end.saturating_add(1);
        }
        let name = self.scan.bytes(at, name_end, 32).await?;
        let mut tok = Tok {
            kind: Kind::Word,
            start,
            end,
            param,
            name_end,
        };
        if name == b"bin" {
            let n = u64::try_from(param.unwrap_or(0)).unwrap_or(0);
            tok.kind = Kind::Bin;
            tok.end = end.saturating_add(n).min(self.scan.len());
        }
        Ok(tok)
    }

    async fn name(&mut self, t: &Tok) -> Result<String> {
        let raw = self
            .scan
            .bytes(t.start.saturating_add(1), t.name_end, 32)
            .await?;
        Ok(String::from_utf8_lossy(&raw).into_owned())
    }

    fn span(&self, t: &Tok) -> Span {
        self.scan.span(t.start, t.end)
    }
}

/// What skipping a group learned about it.
#[derive(Default)]
struct GroupInfo {
    end: u64,
    closed: bool,
    /// The destination: the first control word (after `\*`).
    dest: String,
    dest_param: Option<i64>,
    /// The first control words.
    words: Vec<String>,
    /// Text directly inside the group (capped).
    text: Vec<u8>,
    /// The first control words' parameters (for dates).
    params: Vec<(String, i64)>,
    groups: u64,
}

/// Skips the group whose `{` was just read.
async fn skip_group(lex: &mut Lexer<'_>, open: &Tok) -> Result<GroupInfo> {
    let mut info = GroupInfo {
        end: open.end,
        ..GroupInfo::default()
    };
    let mut depth = 1u32;
    let mut first = true;
    loop {
        lex.scan.tick().await;
        let t = lex.next().await?;
        let top = depth == 1;
        match t.kind {
            Kind::Eof => {
                info.end = t.start;
                return Ok(info);
            }
            Kind::Open => {
                if top {
                    info.groups = info.groups.saturating_add(1);
                }
                depth = depth.saturating_add(1);
            }
            Kind::Close => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    info.end = t.end;
                    info.closed = true;
                    return Ok(info);
                }
            }
            Kind::Word if top => {
                let name = lex.name(&t).await?;
                if first {
                    info.dest = name.clone();
                    info.dest_param = t.param;
                }
                if info.words.len() < 16 {
                    info.words.push(name.clone());
                }
                if info.params.len() < 16
                    && let Some(p) = t.param
                {
                    info.params.push((name, p));
                }
            }
            Kind::Symbol if top && first => {
                // `\*` marks an optional destination; the next word names it.
                continue;
            }
            Kind::Text if top && info.text.len() < 400 => {
                let bytes = lex.scan.bytes(t.start, t.end, 400).await?;
                info.text.extend_from_slice(&bytes);
            }
            Kind::Hex if top && info.text.len() < 400 => {
                info.text.extend(t.param.and_then(|p| u8::try_from(p).ok()));
            }
            _ => {}
        }
        if !matches!(t.kind, Kind::Symbol) {
            first = false;
        }
    }
}

/// Destinations whose content is not document text.
const NON_TEXT: &[&str] = &[
    "fonttbl",
    "colortbl",
    "stylesheet",
    "info",
    "pict",
    "object",
    "objdata",
    "listtable",
    "listoverridetable",
    "rsidtbl",
    "generator",
    "themedata",
    "colorschememapping",
    "datastore",
    "latentstyles",
    "header",
    "footer",
    "headerl",
    "headerr",
    "footerl",
    "footerr",
    "fldinst",
    "xmlnstbl",
    "mmathPr",
    "pgdsctbl",
    "filetbl",
    "revtbl",
    "bkmkstart",
    "bkmkend",
    "shpinst",
    "nonshppict",
    "blipuid",
    "userprops",
    "docvar",
    "wgrffmtfilter",
    "pnseclvl",
    "listtext",
    "panose",
    "falt",
    "leveltext",
    "levelnumbers",
    "fname",
];

/// A date from `\yrN\moN\dyN\hrN\minN` parameters.
fn date(params: &[(String, i64)]) -> Option<String> {
    let get = |n: &str| params.iter().find(|(k, _)| k == n).map(|(_, v)| *v);
    let (y, m, d) = (get("yr")?, get("mo")?, get("dy")?);
    Some(format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}",
        get("hr").unwrap_or(0),
        get("min").unwrap_or(0)
    ))
}

#[derive(Clone, Debug)]
struct Group {
    input: Input,
    span: Span,
}

fn group_node(info: &GroupInfo, span: Span, input: Input) -> Node {
    let name = match (info.dest.as_str(), info.dest_param) {
        ("", _) => "{group}".to_owned(),
        (d, Some(p)) => format!("\\{d}{p}"),
        (d, None) => format!("\\{d}"),
    };
    let text = windows_1252(&info.text);
    let text = preview(text.trim_end_matches(';'), 60);
    let param = |n: &str| info.params.iter().find(|(k, _)| k == n).map(|(_, v)| *v);
    let mut summary = match date(&info.params) {
        Some(d) if info.dest.ends_with("tim") => d,
        _ if info.dest == "pict" => {
            let kind = info
                .words
                .iter()
                .find_map(|w| picture_kind(w))
                .unwrap_or("picture");
            match (param("picw"), param("pich")) {
                (Some(w), Some(h)) => format!("{kind}, {w}×{h}"),
                _ => kind.to_owned(),
            }
        }
        _ => text,
    };
    if info.groups > 0 {
        let groups = plural(info.groups, "group", "groups");
        summary = if summary.is_empty() {
            groups
        } else {
            format!("{summary} ({groups})")
        };
    }
    let mut node = Node::new(name)
        .span(span)
        .lazy(crate::expander!(self::group: Group), Group { input, span });
    if !summary.is_empty() {
        node = node.summary(summary);
    }
    if !info.closed {
        node = node.diag(Diagnostic::new(DiagKind::Truncated, "group not closed"));
    }
    node
}

/// Expands a group: its control words, text runs and subgroups.
async fn group(cx: Cx, g: Group) -> Result<()> {
    let mut lex = Lexer::new(&cx, g.span);
    let open = lex.next().await?;
    if open.kind != Kind::Open {
        return Err(Diagnostic::malformed("expected '{'").at(lex.span(&open)));
    }
    content(&cx, &mut lex, g.input).await
}

/// Pushes tokens until the group's closing brace (or the end).
async fn content(cx: &Cx, lex: &mut Lexer<'_>, input: Input) -> Result<()> {
    // Text runs (with \'hh escapes) merge into one node. Only the first
    // RUN_CAP bytes are kept (the rest are counted), and none where the
    // text is not shown.
    let mut run: Option<(u64, u64, Run)> = None;
    let mut dest = String::new();
    let mut colors = 0u64;
    let mut color = (None, None, None);
    let mut data: Option<(u64, u64)> = None;
    let mut first = true;
    loop {
        lex.scan.tick().await;
        let t = lex.next().await?;
        let textual = matches!(t.kind, Kind::Text | Kind::Hex)
            || (t.kind == Kind::Symbol && !matches!(dest.as_str(), "pict" | "objdata"));
        if !textual && let Some((a, b, text)) = run.take() {
            flush(cx, lex, (a, b), &text, &dest, &mut data).await;
        }
        match t.kind {
            Kind::Eof | Kind::Close => break,
            Kind::Open => {
                let info = skip_group(lex, &t).await?;
                let span = lex.scan.span(t.start, info.end);
                cx.push(group_node(&info, span, input)).await;
            }
            Kind::Text | Kind::Hex | Kind::Symbol if textual => {
                let r = run.get_or_insert((t.start, t.end, Run::default()));
                r.1 = t.end;
                if matches!(dest.as_str(), "pict" | "objdata" | "colortbl") {
                    // `flush` keeps only the range.
                } else {
                    match t.kind {
                        Kind::Text => {
                            let bytes = lex.scan.bytes(t.start, t.end, super::VALUE_CAP).await?;
                            r.2.extend(&bytes);
                        }
                        Kind::Hex => {
                            if let Some(b) = t.param.and_then(|p| u8::try_from(p).ok()) {
                                r.2.extend(&[b]);
                            }
                        }
                        _ => {
                            let sym = lex
                                .scan
                                .byte(t.start.saturating_add(1))
                                .await?
                                .unwrap_or(b' ');
                            r.2.extend(&[match sym {
                                b'~' => b' ',
                                b'-' | b'*' => continue,
                                other => other,
                            }]);
                        }
                    }
                }
            }
            Kind::Symbol => {
                let sym = lex
                    .scan
                    .byte(t.start.saturating_add(1))
                    .await?
                    .unwrap_or(b' ');
                cx.push(Node::new(format!("\\{}", char::from(sym))).span(lex.span(&t)))
                    .await;
            }
            Kind::Bin => {
                let data_span = lex.scan.span(
                    t.end
                        .saturating_sub(u64::try_from(t.param.unwrap_or(0)).unwrap_or(0)),
                    t.end,
                );
                cx.push(crate::formats::embedded(
                    "\\bin data",
                    input.nested(data_span),
                ))
                .await;
            }
            Kind::Word => {
                let name = lex.name(&t).await?;
                if first {
                    dest = name.clone();
                }
                if dest == "colortbl" {
                    match name.as_str() {
                        "red" => color.0 = t.param,
                        "green" => color.1 = t.param,
                        "blue" => color.2 = t.param,
                        _ => {}
                    }
                }
                let mut node = Node::new(format!("\\{name}")).span(lex.span(&t));
                if let Some(p) = t.param {
                    node = node.value(Value::Int { value: p, bits: 32 });
                }
                if let Some(desc) = describe(&name) {
                    node = node.desc(desc);
                }
                cx.push(node).await;
            }
            _ => {}
        }
        first = false;
        // Color table entries end at ';' (inside text runs).
        if dest == "colortbl"
            && t.kind == Kind::Text
            && let (Some(r), Some(g), Some(b)) = color
        {
            colors = colors.saturating_add(1);
            cx.push(
                Node::new(format!("Color {colors}"))
                    .span(lex.span(&t))
                    .value(Value::Text(format!("#{r:02x}{g:02x}{b:02x}")))
                    .summary(format!("rgb({r}, {g}, {b})")),
            )
            .await;
            color = (None, None, None);
        }
    }
    if let Some((a, b, text)) = run.take() {
        flush(cx, lex, (a, b), &text, &dest, &mut data).await;
    }
    if let Some((a, b)) = data {
        let span = lex.scan.span(a, b);
        let name = if dest == "pict" {
            "Picture data"
        } else {
            "Object data"
        };
        cx.push(
            decoded_node(name, input, span, Transform::Hex)
                .summary(format!("hex, {:#x} bytes decoded", span.len / 2)),
        )
        .await;
    }
    Ok(())
}

/// The most of one text run kept in memory; the node shows less.
const RUN_CAP: usize = super::VALUE_CAP.saturating_mul(4);

/// The bytes of a text run: the first [`RUN_CAP`], then a count.
#[derive(Default)]
struct Run {
    bytes: Vec<u8>,
    /// Bytes past the cap.
    more: u64,
    /// Whether any of those is not whitespace.
    more_text: bool,
}

impl Run {
    fn extend(&mut self, bytes: &[u8]) {
        let room = RUN_CAP.saturating_sub(self.bytes.len());
        let (keep, rest) = bytes.split_at(room.min(bytes.len()));
        self.bytes.extend_from_slice(keep);
        self.more = self.more.saturating_add(to_u64(rest.len()));
        self.more_text |= windows_1252(rest).chars().any(|c| !c.is_whitespace());
    }
}

/// Pushes a text run (relative `start..end`), or, in `\pict` and
/// `\objdata`, extends the range of hex data instead.
async fn flush(
    cx: &Cx,
    lex: &Lexer<'_>,
    (start, end): (u64, u64),
    run: &Run,
    dest: &str,
    data: &mut Option<(u64, u64)>,
) {
    if dest == "colortbl" {
        return;
    }
    if matches!(dest, "pict" | "objdata") {
        let d = data.get_or_insert((start, end));
        d.0 = d.0.min(start);
        d.1 = d.1.max(end);
        return;
    }
    let text = windows_1252(&run.bytes);
    if text.trim().is_empty() && !run.more_text {
        return;
    }
    let mut node = text_node("Text", lex.scan.span(start, end), &text);
    if run.more > 0 {
        // One character per Windows-1252 byte.
        let chars = to_u64(text.chars().count()).saturating_add(run.more);
        node = node.summary(format!("{chars} characters, truncated"));
    }
    cx.push(node).await;
}

/// The picture format named by a `\pict` control word.
fn picture_kind(word: &str) -> Option<&'static str> {
    Some(match word {
        "pngblip" => "PNG",
        "jpegblip" => "JPEG",
        "emfblip" => "EMF",
        "wmetafile" => "WMF",
        "macpict" => "QuickDraw PICT",
        "dibitmap" => "DIB",
        "wbitmap" => "bitmap",
        _ => return None,
    })
}

/// Short descriptions of common control words.
fn describe(word: &str) -> Option<&'static str> {
    Some(match word {
        "rtf" => "RTF version",
        "ansi" => "ANSI character set",
        "mac" => "Macintosh character set",
        "pc" => "IBM PC code page 437",
        "ansicpg" => "ANSI code page",
        "deff" => "Default font",
        "deflang" => "Default language",
        "par" => "End of paragraph",
        "pard" => "Reset paragraph properties",
        "plain" => "Reset character properties",
        "b" => "Bold",
        "i" => "Italic",
        "ul" => "Underline",
        "f" => "Font",
        "fs" => "Font size (half-points)",
        "cf" => "Foreground color",
        "cb" => "Background color",
        "uc" => "Fallback characters after \\u",
        "u" => "Unicode character",
        "tab" => "Tab",
        "line" => "Line break",
        "page" => "Page break",
        "sect" => "End of section",
        "picw" => "Picture width",
        "pich" => "Picture height",
        "picwgoal" => "Desired width (twips)",
        "pichgoal" => "Desired height (twips)",
        "pngblip" => "PNG picture",
        "jpegblip" => "JPEG picture",
        "emfblip" => "EMF picture",
        "wmetafile" => "Windows metafile",
        "paperw" => "Paper width (twips)",
        "paperh" => "Paper height (twips)",
        "margl" => "Left margin (twips)",
        "margr" => "Right margin (twips)",
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Plain text

#[derive(Clone, Debug)]
struct Doc {
    span: Span,
}

/// Paragraphs of document text, skipping non-text destinations.
async fn paragraphs(cx: Cx, d: Doc) -> Result<()> {
    let mut lex = Lexer::new(&cx, d.span);
    // Per group: whether its content is skipped, and \uc.
    let mut stack: Vec<(bool, i64)> = vec![(false, 1)];
    let mut text = String::new();
    let mut start: Option<u64> = None;
    let mut end = 0u64;
    let mut pending_skip = 0i64;
    let mut number = 0u64;
    let mut just_opened = false;
    let mut star = false;
    loop {
        lex.scan.tick().await;
        let t = lex.next().await?;
        let (skipping, uc) = stack.last().copied().unwrap_or((false, 1));
        let mut emit = |ch: &str, t: &Tok, text: &mut String| {
            if pending_skip > 0 {
                pending_skip = pending_skip.saturating_sub(1);
                return;
            }
            if !skipping {
                if text.len() < super::VALUE_CAP.saturating_mul(4) {
                    text.push_str(ch);
                }
                start.get_or_insert(t.start);
                end = t.end;
            }
        };
        match t.kind {
            Kind::Eof => break,
            Kind::Open => {
                stack.push((skipping, uc));
                just_opened = true;
                star = false;
                if stack.len() > 512 {
                    stack.truncate(512);
                }
                continue;
            }
            Kind::Close => {
                stack.pop();
                if stack.is_empty() {
                    break;
                }
            }
            Kind::Symbol => {
                let sym = lex
                    .scan
                    .byte(t.start.saturating_add(1))
                    .await?
                    .unwrap_or(b' ');
                match sym {
                    b'*' if just_opened => {
                        star = true;
                        continue;
                    }
                    b'~' => emit("\u{a0}", &t, &mut text),
                    b'_' => emit("-", &t, &mut text),
                    b'\\' | b'{' | b'}' => emit(&char::from(sym).to_string(), &t, &mut text),
                    b'\n' | b'\r' => emit("\n", &t, &mut text),
                    _ => {}
                }
            }
            Kind::Hex => {
                let byte = t.param.and_then(|p| u8::try_from(p).ok()).unwrap_or(b'?');
                emit(&windows_1252(&[byte]), &t, &mut text);
            }
            Kind::Text => {
                let bytes = lex.scan.bytes(t.start, t.end, 4096).await?;
                for ch in windows_1252(&bytes).chars() {
                    emit(&ch.to_string(), &t, &mut text);
                }
            }
            Kind::Word => {
                let name = lex.name(&t).await?;
                if just_opened
                    && (star || NON_TEXT.contains(&name.as_str()))
                    && let Some(top) = stack.last_mut()
                {
                    top.0 = true;
                }
                match name.as_str() {
                    "par" | "line" | "sect" | "page" if !skipping => {
                        if let Some(s) = start.take() {
                            number = number.saturating_add(1);
                            let span = lex.scan.span(s, end);
                            cx.push(text_node(
                                format!("Paragraph {number}"),
                                span,
                                text.trim_end(),
                            ))
                            .await;
                        }
                        text.clear();
                    }
                    "tab" => emit("\t", &t, &mut text),
                    "emdash" => emit("—", &t, &mut text),
                    "endash" => emit("–", &t, &mut text),
                    "lquote" => emit("‘", &t, &mut text),
                    "rquote" => emit("’", &t, &mut text),
                    "ldblquote" => emit("“", &t, &mut text),
                    "rdblquote" => emit("”", &t, &mut text),
                    "bullet" => emit("•", &t, &mut text),
                    "uc" => {
                        if let Some(top) = stack.last_mut() {
                            top.1 = t.param.unwrap_or(1);
                        }
                    }
                    "u" => {
                        let v = t.param.unwrap_or(0);
                        let code = if v < 0 { v.saturating_add(65_536) } else { v };
                        let c = u32::try_from(code)
                            .ok()
                            .and_then(char::from_u32)
                            .unwrap_or(char::REPLACEMENT_CHARACTER);
                        emit(&c.to_string(), &t, &mut text);
                        pending_skip = uc;
                    }
                    _ => {}
                }
            }
            Kind::Bin => {}
        }
        just_opened = false;
        star = false;
    }
    if let Some(s) = start {
        number = number.saturating_add(1);
        let span = lex.scan.span(s, end);
        cx.push(text_node(
            format!("Paragraph {number}"),
            span,
            text.trim_end(),
        ))
        .await;
    }
    Ok(())
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let head = cx.read_avail(input.span.sub(0, 64 * 1024)).await?;
    let find = |tag: &[u8]| {
        let at = super::probe::find(&head, tag)?;
        let rest = head.get(at.saturating_add(tag.len())..)?;
        let end = rest.iter().position(|&b| b == b'}' || b == b'\\')?;
        let text = windows_1252(rest.get(..end)?);
        let text = text.trim().trim_end_matches(';').to_owned();
        (!text.is_empty()).then_some(text)
    };
    let mut summary = String::from("RTF document");
    if let Some(t) = find(b"{\\title ") {
        summary = format!("{summary}: {}", preview(&t, 60));
    }
    if let Some(a) = find(b"{\\author ") {
        summary = format!("{summary}, by {}", preview(&a, 40));
    }
    if let Some(g) = find(b"{\\*\\generator ") {
        summary = format!("{summary} ({})", preview(&g, 40));
    }
    cx.annotate(summary);
    cx.emit(
        Node::new("Document text")
            .span(input.span)
            .desc("The text of the document, by paragraph")
            .lazy(paragraphs, Doc { span: input.span }),
    );
    // The outer group's content is the top level.
    let mut lex = Lexer::new(&cx, input.span);
    let open = lex.next().await?;
    if open.kind != Kind::Open {
        return Err(Diagnostic::malformed("expected '{\\rtf'").at(lex.span(&open)));
    }
    content(&cx, &mut lex, input).await?;
    let rest = lex.next().await?;
    if rest.kind == Kind::Eof && lex.pos < lex.scan.len() {
        return Ok(());
    }
    if rest.kind != Kind::Eof {
        cx.emit(Node::new("Trailing data").span(lex.scan.span(rest.start, lex.scan.len())));
    }
    Ok(())
}
