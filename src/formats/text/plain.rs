//! Plain text (the fallback for anything that looks like text) and scripts
//! identified by a `#!` line.
//!
//! The top level reports the encoding, line endings and a line count
//! (estimated from the head for large files); the lines themselves are a
//! paged collection, each with its number, span and content.

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::Result;
use crate::formats::{Format, HEAD_LEN, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::Value;

use super::encoding::{self, Encoding};
use super::scan::{LINE_CAP, Lines, Scanner};
use super::{count, plural, text_node};

pub static FORMAT: Format = Format {
    name: "text",
    title: "Plain text",
    extensions: &["txt", "text", "log", "nfo", "me", "readme"],
    mime: "text/plain",
    probe: Probe::Custom(probe_text),
    dissect: crate::expander!(dissect: Input),
};

pub static SCRIPT: Format = Format {
    name: "script",
    title: "Script with interpreter line",
    extensions: &[
        "sh", "bash", "zsh", "py", "pl", "rb", "js", "mjs", "php", "lua", "tcl",
    ],
    mime: "text/x-script",
    probe: Probe::Custom(probe_script),
    dissect: crate::expander!(dissect_script: Input),
};

/// Anything that looks like text. A few bytes are too little evidence (a
/// truncated binary header is often printable), unless they end a line.
fn probe_text(h: &Head<'_>) -> bool {
    let tiny = h.len < 4 && !h.data.ends_with(b"\n");
    !tiny && encoding::classify(h.data).is_some()
}

/// How lines end in a sample.
#[derive(Clone, Copy, Debug, Default)]
struct Endings {
    lf: u64,
    crlf: u64,
    cr: u64,
}

impl Endings {
    fn count(units: impl Iterator<Item = u32>) -> Endings {
        let mut e = Endings::default();
        let mut prev_cr = false;
        for u in units {
            match u {
                0x0a if prev_cr => e.crlf = e.crlf.saturating_add(1),
                0x0a => e.lf = e.lf.saturating_add(1),
                0x0d if prev_cr => e.cr = e.cr.saturating_add(1),
                _ if prev_cr => e.cr = e.cr.saturating_add(1),
                _ => {}
            }
            prev_cr = u == 0x0d;
        }
        if prev_cr {
            e.cr = e.cr.saturating_add(1);
        }
        e
    }

    fn total(&self) -> u64 {
        self.lf.saturating_add(self.crlf).saturating_add(self.cr)
    }

    fn describe(&self) -> &'static str {
        match (self.lf > 0, self.crlf > 0, self.cr > 0) {
            (false, false, false) => "none",
            (true, false, false) => "LF",
            (false, true, false) => "CRLF",
            (false, false, true) => "CR",
            _ => "mixed",
        }
    }
}

fn units(data: &[u8], encoding: Encoding) -> impl Iterator<Item = u32> + '_ {
    let step = to_usize(encoding.unit());
    data.chunks(step).filter_map(move |c| encoding.code_unit(c))
}

/// What the top level shows about a text body.
struct Overview {
    encoding: Encoding,
    bom: u64,
    endings: Endings,
    /// Exact line count if the sample covers everything, else an estimate.
    lines: u64,
    exact: bool,
}

async fn overview(cx: &Cx, span: Span) -> Result<Overview> {
    let head = cx.read_avail(span.sub(0, HEAD_LEN)).await?;
    let (encoding, bom) = match encoding::bom(&head) {
        Some(found) => found,
        None => {
            // A coding cookie names the code page of legacy 8-bit text.
            let cookie = encoding::coding_cookie(&head);
            match encoding::declared_charset(&head, cookie.as_deref()) {
                Some(c) => (Encoding::Single(c), 0),
                None => (encoding::classify(&head).unwrap_or(Encoding::Utf8), 0),
            }
        }
    };
    let body = head.get(to_usize(bom)..).unwrap_or_default();
    let endings = Endings::count(units(body, encoding));
    let exact = to_u64(head.len()) >= span.len;
    let ends_with_eol = units(body, encoding)
        .last()
        .is_some_and(|u| u == 0x0a || u == 0x0d);
    let mut lines = endings.total();
    if exact {
        if !body.is_empty() && !ends_with_eol {
            lines = lines.saturating_add(1);
        }
    } else if !body.is_empty() {
        // Extrapolate from the sample's density.
        let per = to_u64(body.len())
            .checked_div(lines.max(1))
            .unwrap_or(1)
            .max(1);
        lines = span.len.saturating_sub(bom).checked_div(per).unwrap_or(0);
    }
    Ok(Overview {
        encoding,
        bom,
        endings,
        lines,
        exact,
    })
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let o = overview(&cx, input.span).await?;
    let mut summary = format!("{} text", o.encoding.name());
    if o.endings.total() > 0 {
        summary = format!("{summary}, {} line endings", o.endings.describe());
    }
    cx.annotate(format!("{summary}, {}", line_count(&o)));
    emit_overview(&cx, input.span, &o);
    Ok(())
}

fn line_count(o: &Overview) -> String {
    if o.exact {
        plural(o.lines, "line", "lines")
    } else {
        format!("~{} lines", count(o.lines))
    }
}

fn emit_overview(cx: &Cx, span: Span, o: &Overview) {
    let mut encoding = Node::new("Encoding").value(Value::Text(o.encoding.name().to_owned()));
    if o.bom > 0 {
        encoding = encoding.span(span.sub(0, o.bom)).summary("byte order mark");
    } else if matches!(o.encoding, Encoding::Single(_)) {
        encoding = encoding.summary("declared by a coding comment");
    }
    cx.emit(encoding);
    let e = &o.endings;
    cx.emit(
        Node::new("Line endings")
            .value(Value::Text(e.describe().to_owned()))
            .summary(format!("{} LF, {} CRLF, {} CR", e.lf, e.crlf, e.cr)),
    );
    let body = span.tail(o.bom);
    let summary = if o.exact {
        line_count(o)
    } else {
        format!(
            "{} (estimated from the first {HEAD_LEN:#x} bytes)",
            line_count(o)
        )
    };
    cx.emit(
        Node::new("Lines")
            .span(body)
            .summary(summary)
            .lazy(lines, (body, o.encoding, 0u64)),
    );
}

/// Pushes the lines of `span` as a paged collection, numbering from
/// `first + 1`.
pub async fn lines(cx: Cx, (span, encoding, first): (Span, Encoding, u64)) -> Result<()> {
    if encoding.ascii_compatible() {
        let mut lines = Lines::new(&cx, span);
        lines.seek(0, first);
        while let Some(line) = lines.next().await? {
            cx.push(line_node(
                line.number,
                line.span,
                &encoding.decode(&line.bytes),
            ))
            .await;
        }
        cx.set_count(Count::Exact(lines.number().saturating_sub(first)));
        return Ok(());
    }
    // Wide encodings: find line breaks code unit by code unit.
    let unit = encoding.unit();
    let mut scan = Scanner::new(&cx, span);
    let mut pos = 0u64;
    let mut number = first;
    while pos < scan.len() {
        cx.checkpoint().await;
        let start = pos;
        let (end, next) = loop {
            let bytes = scan.bytes(pos, pos.saturating_add(unit), 4).await?;
            match encoding.code_unit(&bytes) {
                None => break (pos, scan.len()),
                Some(0x0a) => break (pos, pos.saturating_add(unit)),
                Some(0x0d) => {
                    let after = pos.saturating_add(unit);
                    let more = scan.bytes(after, after.saturating_add(unit), 4).await?;
                    let skip = if encoding.code_unit(&more) == Some(0x0a) {
                        after.saturating_add(unit)
                    } else {
                        after
                    };
                    break (pos, skip);
                }
                Some(_) => pos = pos.saturating_add(unit),
            }
        };
        number = number.saturating_add(1);
        let content = scan.bytes(start, end, LINE_CAP).await?;
        cx.push(line_node(
            number,
            scan.span(start, end),
            &encoding.decode(&content),
        ))
        .await;
        pos = next.max(start.saturating_add(unit));
    }
    cx.set_count(Count::Exact(number.saturating_sub(first)));
    Ok(())
}

fn line_node(number: u64, span: Span, text: &str) -> Node {
    text_node(format!("Line {number}"), span, text)
}

// ---------------------------------------------------------------------------
// Scripts

/// Interpreters by program name, with the language they run.
const INTERPRETERS: &[(&str, &str)] = &[
    ("sh", "Shell"),
    ("bash", "Bash"),
    ("dash", "Shell"),
    ("ash", "Shell"),
    ("ksh", "Korn shell"),
    ("mksh", "Korn shell"),
    ("zsh", "Zsh"),
    ("fish", "fish"),
    ("csh", "C shell"),
    ("tcsh", "C shell"),
    ("python", "Python"),
    ("pypy", "Python"),
    ("perl", "Perl"),
    ("ruby", "Ruby"),
    ("node", "JavaScript (Node.js)"),
    ("nodejs", "JavaScript (Node.js)"),
    ("deno", "JavaScript/TypeScript (Deno)"),
    ("bun", "JavaScript (Bun)"),
    ("ts-node", "TypeScript"),
    ("php", "PHP"),
    ("lua", "Lua"),
    ("luajit", "Lua"),
    ("tclsh", "Tcl"),
    ("wish", "Tcl/Tk"),
    ("awk", "AWK"),
    ("gawk", "AWK"),
    ("mawk", "AWK"),
    ("sed", "sed"),
    ("Rscript", "R"),
    ("pwsh", "PowerShell"),
    ("osascript", "AppleScript"),
    ("groovy", "Groovy"),
    ("swift", "Swift"),
    ("julia", "Julia"),
    ("make", "Makefile"),
    ("runghc", "Haskell"),
    ("stack", "Haskell"),
    ("guile", "Scheme"),
    ("racket", "Racket"),
    ("sbcl", "Common Lisp"),
    ("elixir", "Elixir"),
    ("escript", "Erlang"),
    ("kotlin", "Kotlin"),
    ("dart", "Dart"),
    ("expect", "Expect"),
    ("nix-shell", "Nix shell"),
    ("crystal", "Crystal"),
    ("nim", "Nim"),
    ("scala", "Scala"),
    ("jshell", "Java"),
];

fn probe_script(h: &Head<'_>) -> bool {
    let data = super::probe::head(h);
    let Some(rest) = data.strip_prefix(b"#!") else {
        return false;
    };
    let line = rest.split(|&b| b == b'\n').next().unwrap_or_default();
    line.len() < 512
        && line.iter().all(|&b| b >= 0x20 || b == b'\t' || b == b'\r')
        && super::probe::trim_start(line).first() == Some(&b'/')
}

/// The interpreter program and its arguments from a `#!` line.
struct Shebang {
    path: String,
    program: String,
}

fn parse_shebang(line: &str) -> Shebang {
    let mut words = line.split_whitespace().map(str::to_owned);
    let path = words.next().unwrap_or_default();
    let args: Vec<String> = words.collect();
    let base = |p: &str| p.rsplit('/').next().unwrap_or(p).to_owned();
    let mut program = base(&path);
    if program == "env" {
        // `env [-S] [-i] [NAME=value ...] program args...`
        let at = args
            .iter()
            .position(|a| !a.starts_with('-') && !a.contains('='));
        if let Some(at) = at {
            program = base(args.get(at).map_or("", String::as_str));
        }
    }
    Shebang { path, program }
}

/// The language of an interpreter, matching versioned names (`python3.12`).
fn language(program: &str) -> Option<&'static str> {
    let stem = program.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.' || c == '-');
    INTERPRETERS
        .iter()
        .find(|(name, _)| *name == program || *name == stem)
        .map(|(_, lang)| *lang)
}

pub async fn dissect_script(cx: Cx, input: Input) -> Result<()> {
    let o = overview(&cx, input.span).await?;
    let body = input.span.tail(o.bom);
    let mut scan = Scanner::new(&cx, body);
    let Some(first) = scan.line(0).await? else {
        return dissect(cx, input).await;
    };
    let line = scan.owned(first.start, first.end, 1024).await?;
    let piece = line.piece();
    let command = piece.from(2).trim();
    let shebang = parse_shebang(&command.text());
    let lang = language(&shebang.program);
    let what = lang.map_or_else(|| "Script".to_owned(), |l| format!("{l} script"));
    cx.annotate(format!("{what} ({}), {}", command.text(), line_count(&o)));
    cx.emit(
        Node::new("Interpreter line")
            .span(scan.span(first.start, first.end))
            .value(Value::Text(piece.text()))
            .lazy(shebang_fields, scan.span(first.start, first.end)),
    );
    emit_overview(&cx, input.span, &o);
    Ok(())
}

async fn shebang_fields(cx: Cx, span: Span) -> Result<()> {
    let line = Scanner::new(&cx, span).owned(0, span.len, 1024).await?;
    let command = line.piece().from(2).trim();
    let mut words = command.words();
    if let Some(path) = words.next() {
        cx.emit(
            Node::new("Interpreter")
                .span(path.span())
                .value(Value::Text(path.text())),
        );
    }
    let shebang = parse_shebang(&command.text());
    if shebang.program != shebang.path.rsplit('/').next().unwrap_or_default() {
        cx.emit(Node::new("Program").value(Value::Text(shebang.program.clone())));
    }
    if let Some(lang) = language(&shebang.program) {
        cx.emit(Node::new("Language").value(Value::Text(lang.to_owned())));
    }
    let rest: Vec<_> = words.collect();
    if let (Some(a), Some(b)) = (rest.first(), rest.last()) {
        let args = command.slice(
            to_usize(a.span().offset.saturating_sub(command.span().offset)),
            to_usize(b.span().end().saturating_sub(command.span().offset)),
        );
        cx.emit(
            Node::new("Arguments")
                .span(args.span())
                .value(Value::Text(args.text())),
        );
    }
    Ok(())
}
