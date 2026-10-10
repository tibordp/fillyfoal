//! Machine-control programs for digital fabrication: G-code text as written
//! by 3D-printer slicers and CNC CAM software (`gcode`), and Prusa binary
//! G-code (`bgcode`).
//!
//! # G-code text
//!
//! G-code has no signature, and `.nc` is also NetCDF's extension, so it is
//! identified by content only, conservatively: a known slicer's header
//! comment (PrusaSlicer, SuperSlicer, OrcaSlicer, Bambu Studio, Slic3r,
//! Cura, Simplify3D, ideaMaker, KISSlicer, Kiri:Moto), or a head made
//! mostly of well-formed command lines (`G`/`M`/`T` words with numeric
//! parameters) including motion commands. Lines ending in `*` (Gerber) are
//! never G-code here.
//!
//! The top level shows what slicers record in their header and footer
//! comments (slicer, estimated time, filament, layer height, temperatures;
//! PrusaSlicer `; key = value`, Cura `;KEY:value` and Simplify3D
//! `;   key,value` styles, from the first 128 KiB and the last 64 KiB),
//! temperatures from the first `M104`/`M109`/`M140`/`M190` commands
//! otherwise, the full set of header/footer settings, embedded thumbnails
//! (`; thumbnail[_PNG|_JPG|_QOI] begin WxH len` base64 blocks, decoded and
//! dissected as images), layers (`;LAYER_CHANGE`, `;LAYER:n`,
//! `; CHANGE_LAYER`, `; layer n, Z = ...` markers) as a paged collection
//! with Z and move counts, and the lines, each with a description of its
//! command and its words on expansion. CNC programs (no slicer comments)
//! show as lines with command summaries.
//!
//! # Binary G-code
//!
//! The layout is libbgcode's `doc/specifications.md`: a 10-byte header
//! (`GCDE`, version 1, checksum type), then blocks of a 8- or 12-byte
//! header (type, compression, sizes), type-specific parameters, data and an
//! optional CRC-32 over all three. Compression 1 is zlib (libbgcode calls
//! `deflateInit`), 2 and 3 Heatshrink 11/4 and 12/4; G-code blocks may be
//! MeatPack-encoded. Metadata blocks are INI-like `key=value` lines (JSON
//! for encoding 1). Checked against libbgcode itself (pybgcode built from
//! the libbgcode repository): every compression, encoding and checksum
//! type in the fixtures, with the decoded G-code compared to libbgcode's
//! `from_binary_to_ascii`.

use std::sync::Arc;

use crate::bytes::{to_u64, u16_le, u32_le};
use crate::codec::{Codec, decode_span};
use crate::cx::Cx;
use crate::declare_format;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::text::decode::{Decoded, base64, derive};
use crate::formats::text::probe;
use crate::formats::text::scan::{LINE_CAP, Lines};
use crate::formats::text::text_node;
use crate::formats::util::datakit::{hex, text};
use crate::formats::{Head, Input, Probe, content, dissect_or_data};
use crate::node::{Count, Node};
use crate::span::{Origin, Span};
use crate::value::{EnumTable, Value};

// ---------------------------------------------------------------------------
// G-code lines

/// A word of a line: a letter and its number (offsets in the line).
#[derive(Clone, Copy, Debug)]
struct Word {
    letter: u8,
    start: usize,
    /// Where the number starts (after the letter).
    number: usize,
    end: usize,
}

impl Word {
    fn number<'a>(&self, line: &'a [u8]) -> &'a [u8] {
        line.get(self.number..self.end).unwrap_or_default()
    }

    fn value(&self, line: &[u8]) -> Option<f64> {
        std::str::from_utf8(self.number(line)).ok()?.parse().ok()
    }
}

/// A line split into words, an argument (free text after the command), a
/// checksum and a comment.
#[derive(Debug, Default)]
struct Parsed {
    words: Vec<Word>,
    /// Text after the words that is not a word (message argument, quoted
    /// string, extended syntax).
    rest: Option<(usize, usize)>,
    /// `*NN` checksum (offset of `*`).
    checksum: Option<usize>,
    /// Offset of the comment (`;` or a whole-line or trailing `(...)`).
    comment: Option<usize>,
    /// Every token was a word.
    clean: bool,
}

/// Commands whose argument is free text.
const TEXT_ARGUMENT: &[&str] = &["M23", "M28", "M30", "M32", "M33", "M117", "M118", "M928"];

fn parse_line(line: &[u8]) -> Parsed {
    let mut p = Parsed {
        clean: true,
        ..Parsed::default()
    };
    let mut i = 0usize;
    while let Some(&c) = line.get(i) {
        match c {
            b' ' | b'\t' | b'\r' => i = i.saturating_add(1),
            b';' => {
                p.comment = Some(i);
                break;
            }
            b'(' => {
                // Inline comment (CNC); a leading one is the whole line's.
                match line
                    .get(i..)
                    .and_then(|r| r.iter().position(|&b| b == b')'))
                {
                    Some(close) if !p.words.is_empty() => {
                        i = i.saturating_add(close).saturating_add(1)
                    }
                    _ => {
                        p.comment = Some(i);
                        break;
                    }
                }
            }
            b'*' if !p.words.is_empty() => {
                p.checksum = Some(i);
                p.comment = line
                    .get(i..)
                    .and_then(|r| r.iter().position(|&b| b == b';'))
                    .map(|n| i.saturating_add(n));
                break;
            }
            c if c.is_ascii_alphabetic() && p.rest.is_none() => {
                let start = i;
                let number = i.saturating_add(1);
                let mut j = number;
                if matches!(line.get(j), Some(b'-' | b'+')) {
                    j = j.saturating_add(1);
                }
                while line
                    .get(j)
                    .is_some_and(|b| b.is_ascii_digit() || *b == b'.')
                {
                    j = j.saturating_add(1);
                }
                let next = line.get(j).copied();
                let separated = next
                    .is_none_or(|b| matches!(b, b' ' | b'\t' | b'\r' | b';' | b'(' | b'*'))
                    || (j > number && next.is_some_and(|b| b.is_ascii_alphabetic()));
                if !separated {
                    p.clean = false;
                    p.rest = Some((start, rest_end(line, start)));
                    break;
                }
                p.words.push(Word {
                    letter: c.to_ascii_uppercase(),
                    start,
                    number,
                    end: j,
                });
                i = j;
                if p.words.len() == 1 && TEXT_ARGUMENT.contains(&command(&p, line).as_str()) {
                    let arg = skip_blank(line, i);
                    if arg < line.len() {
                        p.rest = Some((arg, rest_end(line, arg)));
                    }
                    break;
                }
            }
            _ => {
                p.clean = false;
                p.rest = Some((i, rest_end(line, i)));
                break;
            }
        }
    }
    if p.comment.is_none()
        && let Some((_, end)) = p.rest
        && line.get(end) == Some(&b';')
    {
        p.comment = Some(end);
    }
    p
}

fn skip_blank(line: &[u8], mut i: usize) -> usize {
    while line.get(i).is_some_and(|b| *b == b' ' || *b == b'\t') {
        i = i.saturating_add(1);
    }
    i
}

/// End of free text: a `;` comment, or the end of the line.
fn rest_end(line: &[u8], from: usize) -> usize {
    let tail = line.get(from..).unwrap_or_default();
    let end = tail.iter().position(|&b| b == b';').unwrap_or(tail.len());
    let mut end = from.saturating_add(end);
    while end > from
        && line
            .get(end.saturating_sub(1))
            .is_some_and(|b| b.is_ascii_whitespace())
    {
        end = end.saturating_sub(1);
    }
    end
}

/// The command of a line (`G1`, `M862.3`, `T0`): its first `G` or `M`
/// word, else its `T` word, with leading zeros removed (`G01` is `G1`);
/// empty if none.
fn command(p: &Parsed, line: &[u8]) -> String {
    let w = p
        .words
        .iter()
        .find(|w| matches!(w.letter, b'G' | b'M') && w.end > w.number)
        .or_else(|| {
            p.words
                .iter()
                .find(|w| w.letter == b'T' && w.end > w.number)
        });
    let Some(w) = w else {
        return String::new();
    };
    let num = String::from_utf8_lossy(w.number(line)).into_owned();
    let (int, frac) = num.split_once('.').unwrap_or((num.as_str(), ""));
    let int = int.trim_start_matches('0');
    let int = if int.is_empty() { "0" } else { int };
    if frac.is_empty() {
        format!("{}{int}", char::from(w.letter))
    } else {
        format!("{}{int}.{frac}", char::from(w.letter))
    }
}

/// What common commands do (Marlin/Prusa/Klipper for printers, Fanuc-style
/// for CNC; where they differ, the CNC meaning is given for `M3`-`M9` and
/// `M30`).
const COMMANDS: &[(&str, &str)] = &[
    ("G0", "rapid move"),
    ("G1", "linear move"),
    ("G2", "clockwise arc"),
    ("G3", "counter-clockwise arc"),
    ("G4", "dwell"),
    ("G5", "Bézier move"),
    ("G10", "retract / set offsets"),
    ("G11", "unretract"),
    ("G17", "select XY plane"),
    ("G18", "select ZX plane"),
    ("G19", "select YZ plane"),
    ("G20", "units: inches"),
    ("G21", "units: millimetres"),
    ("G28", "home axes"),
    ("G29", "bed levelling"),
    ("G30", "probe / return to secondary home"),
    ("G40", "cutter compensation off"),
    ("G41", "cutter compensation left"),
    ("G42", "cutter compensation right"),
    ("G43", "tool length offset"),
    ("G49", "cancel tool length offset"),
    ("G53", "machine coordinates"),
    ("G54", "work offset 1"),
    ("G55", "work offset 2"),
    ("G56", "work offset 3"),
    ("G57", "work offset 4"),
    ("G58", "work offset 5"),
    ("G59", "work offset 6"),
    ("G60", "save position"),
    ("G61", "exact stop mode / restore position"),
    ("G64", "path blending"),
    ("G73", "peck drilling cycle"),
    ("G80", "cancel canned cycle"),
    ("G81", "drilling cycle"),
    ("G82", "drilling cycle with dwell"),
    ("G83", "peck drilling cycle"),
    ("G84", "tapping cycle"),
    ("G85", "boring cycle"),
    ("G90", "absolute positioning"),
    ("G91", "relative positioning"),
    ("G92", "set position"),
    ("G93", "inverse-time feed"),
    ("G94", "feed per minute"),
    ("G95", "feed per revolution"),
    ("G98", "canned cycle: return to initial level"),
    ("G99", "canned cycle: return to R level"),
    ("M0", "program stop"),
    ("M1", "optional stop"),
    ("M2", "program end"),
    ("M3", "spindle on, clockwise"),
    ("M4", "spindle on, counter-clockwise"),
    ("M5", "spindle stop"),
    ("M6", "tool change"),
    ("M7", "mist coolant on"),
    ("M8", "flood coolant on"),
    ("M9", "coolant off"),
    ("M17", "enable steppers"),
    ("M18", "disable steppers"),
    ("M20", "list SD card"),
    ("M23", "select SD file"),
    ("M24", "start/resume SD print"),
    ("M25", "pause SD print"),
    ("M30", "program end and rewind"),
    ("M73", "set print progress"),
    ("M82", "extruder absolute mode"),
    ("M83", "extruder relative mode"),
    ("M84", "disable steppers"),
    ("M104", "set hotend temperature"),
    ("M105", "report temperatures"),
    ("M106", "fan on"),
    ("M107", "fan off"),
    ("M109", "wait for hotend temperature"),
    ("M114", "report position"),
    ("M115", "firmware info"),
    ("M117", "display message"),
    ("M118", "serial message"),
    ("M140", "set bed temperature"),
    ("M141", "set chamber temperature"),
    ("M190", "wait for bed temperature"),
    ("M191", "wait for chamber temperature"),
    ("M200", "set filament diameter"),
    ("M201", "set maximum acceleration"),
    ("M203", "set maximum feed rate"),
    ("M204", "set acceleration"),
    ("M205", "set jerk / advanced settings"),
    ("M206", "set home offsets"),
    ("M207", "set retraction"),
    ("M220", "set speed factor"),
    ("M221", "set flow factor"),
    ("M400", "wait for moves to finish"),
    ("M486", "object cancellation"),
    ("M500", "save settings"),
    ("M572", "set pressure advance"),
    ("M600", "filament change"),
    ("M862.1", "check nozzle diameter"),
    ("M862.2", "check printer type"),
    ("M862.3", "check printer model"),
    ("M862.5", "check G-code level"),
    ("M862.6", "check firmware feature"),
    ("M900", "set linear advance"),
];

fn describe(cmd: &str) -> Option<String> {
    if let Some((_, d)) = COMMANDS.iter().find(|(c, _)| *c == cmd) {
        return Some((*d).to_owned());
    }
    if let Some(n) = cmd.strip_prefix('T')
        && n.bytes().all(|b| b.is_ascii_digit())
    {
        return Some(format!("select tool {n}"));
    }
    None
}

fn is_motion(cmd: &str) -> bool {
    matches!(cmd, "G0" | "G1" | "G2" | "G3" | "G5")
}

/// Text of a `;` comment line (after the `;`), if the line is one.
fn comment_text(trimmed: &[u8]) -> Option<&[u8]> {
    trimmed.strip_prefix(b";")
}

// ---------------------------------------------------------------------------
// Slicer conventions

/// Comments that start a layer.
fn is_layer_marker(comment: &[u8]) -> bool {
    let c = probe::trim(comment);
    c == b"LAYER_CHANGE"
        || c == b"CHANGE_LAYER"
        || c.starts_with(b"LAYER:")
        || c.starts_with(b"BEGIN_LAYER_OBJECT")
        || (probe::starts_with_nocase(c, b"layer ") && c.get(6).is_some_and(u8::is_ascii_digit))
}

/// A Z height recorded in a comment (`;Z:0.2`, `; Z_HEIGHT: 0.2`,
/// `; layer 3, Z = 0.6`, `; BEGIN_LAYER_OBJECT z=0.2`).
fn comment_z(comment: &[u8]) -> Option<f64> {
    let c = probe::trim(comment);
    let value = if let Some(v) = c.strip_prefix(b"Z:") {
        v
    } else if let Some(v) = c.strip_prefix(b"Z_HEIGHT:") {
        v
    } else if probe::starts_with_nocase(c, b"layer ") || c.starts_with(b"BEGIN_LAYER_OBJECT") {
        let at = probe::find_nocase(c, b"z")?;
        let rest = c.get(at.saturating_add(1)..)?;
        let rest = probe::trim_start(rest);
        rest.strip_prefix(b"=").unwrap_or(rest)
    } else {
        return None;
    };
    let v = probe::trim(value);
    let n = v
        .iter()
        .take_while(|b| b.is_ascii_digit() || matches!(b, b'.' | b'-'))
        .count();
    std::str::from_utf8(v.get(..n)?).ok()?.parse().ok()
}

/// Known slicers' header comments: the producer named in it.
fn slicer_name(comment: &[u8]) -> Option<String> {
    let c = probe::trim(comment);
    let s = String::from_utf8_lossy(c);
    let lower = s.to_ascii_lowercase();
    for marker in ["generated by ", "generated with ", "sliced by "] {
        if let Some(at) = lower.find(marker) {
            let rest = s
                .get(at.saturating_add(marker.len())..)
                .unwrap_or_default()
                .trim();
            let rest = rest.split(" on ").next().unwrap_or(rest).trim();
            if !rest.is_empty() && rest.len() <= 80 {
                return Some(rest.to_owned());
            }
        }
    }
    if s.starts_with("KISSlicer") {
        return Some("KISSlicer".to_owned());
    }
    None
}

const KNOWN_SLICERS: &[&str] = &[
    "prusaslicer",
    "superslicer",
    "orcaslicer",
    "bambustudio",
    "bambu studio",
    "slic3r",
    "cura",
    "simplify3d",
    "ideamaker",
    "kissslicer",
    "kiri:moto",
    "crealityprint",
    "creality print",
    "flashprint",
];

fn known_slicer(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    KNOWN_SLICERS.iter().any(|k| lower.contains(k))
}

/// A `key = value`, `KEY:value` or `key,value` setting in comment text:
/// the key and value as ranges of `comment`.
fn setting(comment: &[u8]) -> Option<((usize, usize), (usize, usize))> {
    let lead = comment
        .len()
        .saturating_sub(probe::trim_start(comment).len());
    let body = probe::trim(comment);
    let end_of = |start: usize, part: &[u8]| -> (usize, usize) {
        let skip = part.len().saturating_sub(probe::trim_start(part).len());
        let s = start.saturating_add(skip);
        (s, s.saturating_add(probe::trim(part).len()))
    };
    let (sep, allowed): (usize, fn(u8) -> bool) =
        if let Some(eq) = body.iter().position(|&b| b == b'=') {
            (eq, |b| {
                b.is_ascii_alphanumeric() || b" _-[]().%/#".contains(&b)
            })
        } else if let Some(colon) = body.iter().position(|&b| b == b':') {
            if body
                .get(..colon)
                .is_some_and(|k| k.iter().filter(|&&b| b == b' ').count() > 2)
            {
                return None;
            }
            (colon, |b| b.is_ascii_alphanumeric() || b" _.-".contains(&b))
        } else {
            let comma = body.iter().position(|&b| b == b',')?;
            (comma, |b| b.is_ascii_alphanumeric() || b == b'_')
        };
    let key = body.get(..sep)?;
    let tkey = probe::trim(key);
    if tkey.is_empty() || tkey.len() > 64 || !tkey.iter().all(|&b| allowed(b)) {
        return None;
    }
    if !tkey.first().is_some_and(u8::is_ascii_alphabetic) {
        return None;
    }
    let value = body.get(sep.saturating_add(1)..).unwrap_or_default();
    Some((
        end_of(lead, key),
        end_of(lead.saturating_add(sep).saturating_add(1), value),
    ))
}

/// Thumbnail block start: image format, width, height.
fn thumbnail_begin(comment: &[u8]) -> Option<(&'static str, String)> {
    let c = probe::trim(comment);
    let (format, rest) = if let Some(r) = c.strip_prefix(b"thumbnail begin") {
        ("PNG", r)
    } else if let Some(r) = c.strip_prefix(b"thumbnail_PNG begin") {
        ("PNG", r)
    } else if let Some(r) = c.strip_prefix(b"thumbnail_JPG begin") {
        ("JPEG", r)
    } else {
        ("QOI", c.strip_prefix(b"thumbnail_QOI begin")?)
    };
    let dims = String::from_utf8_lossy(probe::trim(rest))
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .replace('x', "×");
    Some((format, dims))
}

fn thumbnail_end(comment: &[u8]) -> bool {
    let c = probe::trim(comment);
    c.starts_with(b"thumbnail") && c.ends_with(b" end")
}

// ---------------------------------------------------------------------------
// Probe

fn probe_gcode(h: &Head<'_>) -> bool {
    if !probe::is_text(h) {
        return false;
    }
    let data = probe::head(h);
    let mut slicer: Option<String> = None;
    let mut marker = false;
    let mut commands = 0u32;
    let mut motions = 0u32;
    let mut other = 0u32;
    let mut in_thumbnail = false;
    for (n, line) in probe::lines(&data).enumerate().take(4000) {
        let t = probe::trim(line);
        if t.is_empty() {
            continue;
        }
        if let Some(c) = comment_text(t) {
            if thumbnail_begin(c).is_some() {
                in_thumbnail = true;
            } else if thumbnail_end(c) {
                in_thumbnail = false;
            } else if !in_thumbnail && n < 40 {
                if let Some(name) = slicer_name(c) {
                    slicer.get_or_insert(name);
                }
                let tc = probe::trim(c);
                marker |= tc.starts_with(b"FLAVOR:") || tc == b"HEADER_BLOCK_START";
            }
            continue;
        }
        if t.ends_with(b"*") {
            // Gerber data blocks end in `*`.
            return false;
        }
        if t == b"%" || (t.first() == Some(&b'(') && t.last() == Some(&b')')) {
            continue;
        }
        if t.first() == Some(&b'O') && t.get(1).is_some_and(u8::is_ascii_digit) && n < 5 {
            continue;
        }
        let p = parse_line(t);
        let cmd = command(&p, t);
        let axis_only = !p.words.is_empty()
            && p.clean
            && p.words
                .iter()
                .all(|w| b"XYZIJKABCEF".contains(&w.letter) && w.end > w.number);
        let good =
            (!cmd.is_empty() && (p.clean || TEXT_ARGUMENT.contains(&cmd.as_str()))) || axis_only;
        if good {
            commands = commands.saturating_add(1);
            let moving = p
                .words
                .iter()
                .any(|w| b"XYZ".contains(&w.letter) && w.end > w.number);
            if (is_motion(&cmd) || axis_only) && moving {
                motions = motions.saturating_add(1);
            }
        } else {
            other = other.saturating_add(1);
        }
    }
    if let Some(name) = &slicer {
        // A known slicer's header: the body may lie beyond large thumbnails.
        if known_slicer(name) && (commands > 0 || to_u64(data.len()) >= h.len.min(0x8000)) {
            return true;
        }
        if commands >= 3 && motions >= 1 {
            return true;
        }
    }
    if marker && commands >= 3 && motions >= 1 {
        return true;
    }
    commands >= 8 && motions >= 3 && other.saturating_mul(4) <= commands
}

declare_format!(pub GCODE = "gcode", "G-code program", ["gcode", "gco", "g", "nc", "ngc"], "text/x-gcode",
    Probe::Custom(probe_gcode), dissect_gcode);

// ---------------------------------------------------------------------------
// Survey: header and footer comments

/// Bytes at the start and end of a file searched for header and footer
/// comments.
const HEAD_SCAN: u64 = 128 * 1024;
const TAIL_SCAN: u64 = 64 * 1024;

#[derive(Clone, Debug)]
struct Setting {
    key: String,
    value: String,
    span: Span,
    value_span: Span,
}

#[derive(Debug, Default)]
struct Survey {
    slicer: Option<(String, Span)>,
    settings: Vec<Setting>,
    /// First nonzero hotend and bed temperatures set by commands.
    nozzle: Option<(f64, Span)>,
    bed: Option<(f64, Span)>,
    thumbnails: bool,
    layers: bool,
    extrusion: bool,
    spindle: bool,
}

impl Survey {
    fn get(&self, keys: &[&str]) -> Option<&Setting> {
        keys.iter()
            .find_map(|k| self.settings.iter().find(|s| s.key.eq_ignore_ascii_case(k)))
    }

    fn note_command(&mut self, p: &Parsed, line: &[u8], span: Span) {
        let cmd = command(p, line);
        let s_value = || {
            p.words
                .iter()
                .find(|w| w.letter == b'S')
                .and_then(|w| w.value(line))
                .filter(|v| *v > 0.0)
        };
        match cmd.as_str() {
            "M104" | "M109" if self.nozzle.is_none() => self.nozzle = s_value().map(|v| (v, span)),
            "M140" | "M190" if self.bed.is_none() => self.bed = s_value().map(|v| (v, span)),
            "M3" | "M4" | "M6" => self.spindle = true,
            _ => {}
        }
        if is_motion(&cmd) && p.words.iter().any(|w| w.letter == b'E') {
            self.extrusion = true;
        }
    }
}

fn make_setting(line: &crate::formats::text::scan::LineBuf, offset: usize) -> Option<Setting> {
    let comment = line.bytes.get(offset..)?;
    if slicer_name(comment).is_some() {
        return None;
    }
    let ((ks, ke), (vs, ve)) = setting(comment)?;
    let at = |a: usize| to_u64(offset.saturating_add(a));
    let key = String::from_utf8_lossy(comment.get(ks..ke)?).into_owned();
    let value =
        crate::formats::text::encoding::decode_8bit(comment.get(vs..ve).unwrap_or_default());
    Some(Setting {
        key,
        value,
        span: line.span,
        value_span: line.span.sub(at(vs), to_u64(ve.saturating_sub(vs))),
    })
}

/// Offset of the comment text (after `;`) in a comment line.
fn comment_offset(bytes: &[u8]) -> Option<usize> {
    let lead = bytes.len().saturating_sub(probe::trim_start(bytes).len());
    (bytes.get(lead) == Some(&b';')).then_some(lead.saturating_add(1))
}

async fn survey(cx: &Cx, span: Span) -> Result<Arc<Survey>> {
    if let Some(s) = cx.cached::<Survey>(span, "gcode-survey") {
        return Ok(s);
    }
    let mut s = Survey::default();
    let head_len = HEAD_SCAN.min(span.len);
    let mut lines = Lines::new(cx, span.sub(0, head_len));
    let mut leading = true;
    let mut in_thumbnail = false;
    let mut trailing: Vec<Setting> = Vec::new();
    let mut count = 0u64;
    while let Some(line) = lines.next().await? {
        count = count.saturating_add(1);
        let t = probe::trim(&line.bytes);
        if t.is_empty() {
            continue;
        }
        if let Some(off) = comment_offset(&line.bytes) {
            let c = line.bytes.get(off..).unwrap_or_default();
            if thumbnail_begin(c).is_some() {
                s.thumbnails = true;
                in_thumbnail = true;
                continue;
            }
            if thumbnail_end(c) {
                in_thumbnail = false;
                continue;
            }
            if in_thumbnail {
                continue;
            }
            if is_layer_marker(c) {
                s.layers = true;
            }
            if s.slicer.is_none()
                && count <= 60
                && let Some(name) = slicer_name(c)
            {
                s.slicer = Some((name, line.span));
            }
            if let Some(setting) = make_setting(&line, off) {
                if leading {
                    s.settings.push(setting);
                } else {
                    trailing.push(setting);
                }
            }
            continue;
        }
        if t.first() == Some(&b'(') || t == b"%" {
            continue;
        }
        leading = false;
        trailing.clear();
        let p = parse_line(&line.bytes);
        s.note_command(&p, &line.bytes, line.span);
    }
    if head_len >= span.len {
        s.settings.append(&mut trailing);
    } else {
        let start = head_len.max(span.len.saturating_sub(TAIL_SCAN));
        let region = span.tail(start);
        let mut lines = Lines::new(cx, region);
        // Start at a line boundary.
        let before = cx.read(span.sub(start.saturating_sub(1), 1)).await?;
        if before.first() != Some(&b'\n') {
            lines.next_bounds().await?;
        }
        let mut block: Vec<Setting> = Vec::new();
        while let Some(line) = lines.next().await? {
            let t = probe::trim(&line.bytes);
            if t.is_empty() {
                continue;
            }
            if let Some(off) = comment_offset(&line.bytes) {
                let c = line.bytes.get(off..).unwrap_or_default();
                if is_layer_marker(c) {
                    s.layers = true;
                }
                if let Some(setting) = make_setting(&line, off) {
                    block.push(setting);
                }
                continue;
            }
            block.clear();
            let p = parse_line(&line.bytes);
            s.note_command(&p, &line.bytes, line.span);
        }
        s.settings.append(&mut block);
    }
    let s = Arc::new(s);
    cx.cache(span, "gcode-survey", s.clone());
    Ok(s)
}

/// `6646` seconds as `1h 50m 46s`.
fn duration(seconds: u64) -> String {
    let (h, m, s) = (seconds / 3600, seconds / 60 % 60, seconds % 60);
    match (h, m) {
        (0, 0) => format!("{s}s"),
        (0, _) => format!("{m}m {s}s"),
        _ => format!("{h}h {m}m {s}s"),
    }
}

// ---------------------------------------------------------------------------
// Dissection

pub async fn dissect_gcode(cx: Cx, input: Input) -> Result<()> {
    let span = input.span;
    let s = survey(&cx, span).await?;
    let mut summary: Vec<String> = Vec::new();
    let kind = if s.slicer.is_some() || s.extrusion || s.nozzle.is_some() {
        "3D printer G-code"
    } else if s.spindle {
        "CNC G-code"
    } else {
        "G-code"
    };
    summary.push(kind.to_owned());

    if let Some((name, line)) = &s.slicer {
        cx.emit(Node::new("Slicer").span(*line).value(text(name.clone())));
        summary.push(name.clone());
    }
    let show =
        |name: &'static str, keys: &[&str], unit: &str, summary: &mut Vec<String>, add: bool| {
            if let Some(st) = s.get(keys) {
                let unit = if st.key.ends_with("[g]") {
                    " g"
                } else if st.key.ends_with("[mm]") {
                    " mm"
                } else {
                    unit
                };
                let shown = if unit.is_empty() || st.value.ends_with(unit.trim()) {
                    st.value.clone()
                } else {
                    format!("{}{unit}", st.value)
                };
                let mut node = text_node(name, st.value_span, &st.value);
                if name == "Estimated time"
                    && st.key.eq_ignore_ascii_case("TIME")
                    && let Ok(secs) = st.value.trim().parse::<u64>()
                {
                    node = node.summary(duration(secs));
                    if add {
                        summary.push(duration(secs));
                    }
                } else if add {
                    summary.push(shown);
                }
                cx.emit(node.desc(format!("`{}` comment", st.key)));
                true
            } else {
                false
            }
        };
    show(
        "Printer",
        &[
            "printer_model",
            "TARGET_MACHINE.NAME",
            "printer_settings_id",
        ],
        "",
        &mut summary,
        true,
    );
    show(
        "Flavor",
        &["FLAVOR", "gcode_flavor"],
        "",
        &mut summary,
        false,
    );
    show(
        "Estimated time",
        &[
            "estimated printing time (normal mode)",
            "TIME",
            "estimated printing time",
            "total estimated time",
            "Build time",
        ],
        "",
        &mut summary,
        true,
    );
    show(
        "Filament used",
        &[
            "filament used [g]",
            "filament used [mm]",
            "Filament used",
            "Filament length",
            "total filament weight [g]",
        ],
        "",
        &mut summary,
        true,
    );
    show(
        "Filament type",
        &["filament_type", "Filament type"],
        "",
        &mut summary,
        true,
    );
    show(
        "Layer height",
        &["layer_height", "Layer height", "layerHeight"],
        " mm",
        &mut summary,
        false,
    );
    show(
        "Layer count",
        &["LAYER_COUNT", "total layer number", "total layers count"],
        "",
        &mut summary,
        false,
    );
    if !show(
        "Nozzle temperature",
        &["temperature", "nozzle_temperature"],
        " °C",
        &mut summary,
        false,
    ) && let Some((v, line)) = s.nozzle
    {
        cx.emit(
            Node::new("Nozzle temperature")
                .span(line)
                .value(Value::Float(v))
                .summary("°C, first M104/M109"),
        );
    }
    if !show(
        "Bed temperature",
        &["bed_temperature", "hot_plate_temp"],
        " °C",
        &mut summary,
        false,
    ) && let Some((v, line)) = s.bed
    {
        cx.emit(
            Node::new("Bed temperature")
                .span(line)
                .value(Value::Float(v))
                .summary("°C, first M140/M190"),
        );
    }
    cx.annotate(summary.join(", "));

    if !s.settings.is_empty() {
        cx.emit(
            Node::new("Settings")
                .summary(format!("{} header and footer comments", s.settings.len()))
                .lazy(settings, span),
        );
    }
    if s.thumbnails {
        cx.emit(Node::new("Thumbnails").lazy(thumbnails, input));
    }
    if s.layers {
        cx.emit(Node::new("Layers").span(span).lazy(layers, span));
    }
    cx.emit(Node::new("Lines").span(span).lazy(lines, (span, 0u64)));
    Ok(())
}

async fn settings(cx: Cx, span: Span) -> Result<()> {
    let s = survey(&cx, span).await?;
    for st in &s.settings {
        cx.push(text_node(st.key.clone(), st.value_span, &st.value).span(st.span))
            .await;
    }
    Ok(())
}

/// Thumbnails lie in the leading comments; scanning stops at the first
/// command or after this many bytes.
const THUMBNAIL_SCAN: u64 = 8 << 20;

async fn thumbnails(cx: Cx, input: Input) -> Result<()> {
    let span = input.span;
    let mut lines = Lines::new(&cx, span.sub(0, THUMBNAIL_SCAN));
    let mut open: Option<(&'static str, String, u64, u64)> = None;
    while let Some(line) = lines.next_bounds().await? {
        let bytes = lines
            .scanner()
            .bytes(
                line.start,
                line.end.min(line.start.saturating_add(256)),
                256,
            )
            .await?;
        let t = probe::trim(&bytes);
        if t.is_empty() {
            continue;
        }
        let Some(c) = comment_text(t) else {
            if t.first() == Some(&b'(') || t == b"%" {
                continue;
            }
            break;
        };
        if let Some((format, dims)) = thumbnail_begin(c) {
            open = Some((format, dims, line.start, line.next));
        } else if thumbnail_end(c)
            && let Some((format, dims, begin, data)) = open.take()
        {
            let data_span = span.sub(data, line.start.saturating_sub(data));
            let whole = lines.scanner().span(begin, line.end);
            cx.push(
                Node::new("Thumbnail")
                    .span(whole)
                    .value(text(format!("{format} {dims}")))
                    .summary(format!("{:#x} bytes of base64", data_span.len))
                    .lazy(thumbnail, (input, data_span)),
            )
            .await;
        }
    }
    Ok(())
}

fn unbase64_comments(data: &[u8]) -> Decoded {
    let cleaned: Vec<u8> = data.iter().copied().filter(|&b| b != b';').collect();
    base64(&cleaned)
}

async fn thumbnail(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    let (decoded, error) = derive(&cx, span, "gcode-thumbnail", unbase64_comments).await?;
    if let Some(e) = error {
        cx.diag(e);
    }
    cx.annotate(format!("{:#x} bytes decoded", decoded.len));
    dissect_or_data(cx, input.nested(decoded)).await
}

/// Walker state for layers: position, lines so far, layers so far, the
/// current Z, segments pushed so far.
type LayerMark = (u64, u64, u64, Option<f64>, u64);

#[derive(Default)]
struct Segment {
    start: u64,
    first_line: u64,
    layer: bool,
    commands: u64,
    moves: u64,
    extruding: u64,
    marker_z: Option<f64>,
    move_z: Option<f64>,
}

async fn layers(cx: Cx, span: Span) -> Result<()> {
    let mut lines = Lines::new(&cx, span);
    let (pos, number, mut index, mut z, mut pushed) =
        cx.resume::<LayerMark>().unwrap_or((0, 0, 0, None, 0));
    lines.seek(pos, number);
    let mut mark: LayerMark = (pos, number, index, z, pushed);
    let mut seg = Segment {
        start: pos,
        first_line: number,
        ..Segment::default()
    };
    loop {
        let line = lines.next().await?;
        let marker = line.as_ref().and_then(|l| {
            let off = comment_offset(&l.bytes)?;
            let c = l.bytes.get(off..)?;
            Some((is_layer_marker(c), comment_z(c)))
        });
        let ends = match (&line, marker) {
            (None, _) => seg.commands > 0 || seg.layer,
            (Some(_), Some((true, _))) => seg.commands > 0,
            _ => false,
        };
        if ends {
            let (end, last) = line.as_ref().map_or((lines.pos(), lines.number()), |l| {
                (l.start, l.number.saturating_sub(1))
            });
            if seg.layer {
                index = index.saturating_add(1);
            }
            let seg_z = seg.marker_z.or(seg.move_z).or(z);
            let node = segment_node(span, &seg, end, index, seg_z, last);
            let at = mark;
            cx.mark(move || at);
            cx.progress_in(span, span.offset.saturating_add(lines.pos()));
            cx.push(node).await;
            pushed = pushed.saturating_add(1);
            z = seg.move_z.or(seg.marker_z).or(z);
            if let Some(l) = &line {
                // The next segment starts at this marker.
                mark = (l.start, l.number.saturating_sub(1), index, z, pushed);
                seg = Segment {
                    start: l.start,
                    first_line: l.number.saturating_sub(1),
                    ..Segment::default()
                };
            }
        }
        let Some(line) = line else {
            break;
        };
        match marker {
            Some((true, mz)) => {
                seg.layer = true;
                if mz.is_some() {
                    seg.marker_z = mz;
                }
            }
            Some((false, Some(mz))) if seg.layer && seg.marker_z.is_none() => {
                seg.marker_z = Some(mz)
            }
            Some(_) => {}
            None => {
                let p = parse_line(&line.bytes);
                if p.words.is_empty() {
                    continue;
                }
                let cmd = command(&p, &line.bytes);
                seg.commands = seg.commands.saturating_add(1);
                if is_motion(&cmd) {
                    seg.moves = seg.moves.saturating_add(1);
                    let extrudes = p
                        .words
                        .iter()
                        .any(|w| w.letter == b'E' && w.value(&line.bytes).is_some_and(|v| v > 0.0));
                    if extrudes && p.words.iter().any(|w| b"XYIJ".contains(&w.letter)) {
                        seg.extruding = seg.extruding.saturating_add(1);
                    }
                    if seg.move_z.is_none()
                        && let Some(v) = p
                            .words
                            .iter()
                            .find(|w| w.letter == b'Z')
                            .and_then(|w| w.value(&line.bytes))
                    {
                        seg.move_z = Some(v);
                    }
                }
            }
        }
    }
    cx.set_count(Count::Exact(pushed));
    Ok(())
}

fn segment_node(
    span: Span,
    seg: &Segment,
    end: u64,
    index: u64,
    z: Option<f64>,
    last_line: u64,
) -> Node {
    let sub = span.sub(seg.start, end.saturating_sub(seg.start));
    let name = if seg.layer {
        format!("Layer {index}")
    } else {
        "Start".to_owned()
    };
    let mut parts = Vec::new();
    parts.push(format!(
        "{} move{} ({} extruding)",
        seg.moves,
        if seg.moves == 1 { "" } else { "s" },
        seg.extruding
    ));
    parts.push(format!(
        "lines {}–{}",
        seg.first_line.saturating_add(1),
        last_line.max(seg.first_line.saturating_add(1))
    ));
    let mut node = Node::new(name)
        .span(sub)
        .summary(parts.join(", "))
        .lazy(lines, (sub, seg.first_line));
    if let Some(z) = z.filter(|_| seg.layer) {
        node = node.value(Value::Float(z)).desc("Z height (mm)");
    }
    node
}

/// The lines of `span` as a paged collection, numbered from `first + 1`.
async fn lines(cx: Cx, (span, first): (Span, u64)) -> Result<()> {
    let mut lines = Lines::new(&cx, span);
    let (pos, number) = cx.resume::<(u64, u64)>().unwrap_or((0, first));
    lines.seek(pos, number);
    loop {
        let at = (lines.pos(), lines.number());
        cx.mark(move || at);
        cx.progress_in(span, span.offset.saturating_add(lines.pos()));
        let Some(line) = lines.next().await? else {
            break;
        };
        let content = line.text();
        let mut node = text_node(format!("Line {}", line.number), line.span, &content);
        let trimmed = probe::trim(&line.bytes);
        if let Some(c) = comment_text(trimmed) {
            node = node.summary(if is_layer_marker(c) {
                "layer change"
            } else if thumbnail_begin(c).is_some() {
                "thumbnail"
            } else {
                "comment"
            });
        } else if trimmed.first() == Some(&b'(') && trimmed.last() == Some(&b')') {
            node = node.summary("comment");
        } else if trimmed == b"%" {
            node = node.summary("tape start/end marker");
        } else if !trimmed.is_empty() {
            let p = parse_line(&line.bytes);
            let cmd = command(&p, &line.bytes);
            if !cmd.is_empty() {
                node = node.summary(match describe(&cmd) {
                    Some(d) => format!("{cmd}: {d}"),
                    None => cmd,
                });
            }
            if !p.words.is_empty() && !line.truncated() {
                node = node.lazy(words, line.span);
            }
        }
        cx.push(node).await;
    }
    cx.set_count(Count::Exact(lines.number().saturating_sub(first)));
    Ok(())
}

fn letter_meaning(letter: u8) -> Option<&'static str> {
    Some(match letter {
        b'G' => "preparatory command",
        b'M' => "machine command",
        b'O' => "program number",
        b'X' | b'Y' | b'Z' => "axis position",
        b'A' | b'B' | b'C' => "rotary axis position",
        b'U' | b'V' | b'W' => "secondary axis position",
        b'E' => "extrusion",
        b'F' => "feed rate",
        b'S' => "speed / temperature / parameter",
        b'P' => "parameter",
        b'T' => "tool",
        b'N' => "line number",
        b'I' | b'J' | b'K' => "arc centre offset",
        b'R' => "radius / retract level",
        b'H' => "tool length offset",
        b'D' => "diameter / offset",
        b'L' => "loop count",
        b'Q' => "peck depth",
        _ => return None,
    })
}

async fn words(cx: Cx, span: Span) -> Result<()> {
    let bytes = cx.read(span.sub(0, to_u64(LINE_CAP))).await?;
    let p = parse_line(&bytes);
    let at = |s: usize, e: usize| span.sub(to_u64(s), to_u64(e.saturating_sub(s)));
    for w in &p.words {
        let number = String::from_utf8_lossy(w.number(&bytes)).into_owned();
        let mut node = Node::new(char::from(w.letter).to_string()).span(at(w.start, w.end));
        node = match (number.parse::<i64>(), w.value(&bytes)) {
            (Ok(i), _) if !number.contains('.') => node.value(Value::Int { value: i, bits: 64 }),
            (_, Some(v)) => node.value(Value::Float(v)),
            _ => node,
        };
        if let Some(m) = letter_meaning(w.letter) {
            node = node.summary(m);
        }
        cx.emit(node);
    }
    if let Some((s, e)) = p.rest {
        cx.emit(text_node(
            "Argument",
            at(s, e),
            &String::from_utf8_lossy(bytes.get(s..e).unwrap_or_default()),
        ));
    }
    if let Some(s) = p.checksum {
        let end = rest_end(&bytes, s);
        cx.emit(text_node(
            "Checksum",
            at(s, end),
            &String::from_utf8_lossy(bytes.get(s..end).unwrap_or_default()),
        ));
    }
    if let Some(s) = p.comment {
        let c = bytes.get(s..).unwrap_or_default();
        let c = c.strip_prefix(b";").unwrap_or(c);
        cx.emit(text_node(
            "Comment",
            at(s, bytes.len()),
            &String::from_utf8_lossy(probe::trim(c)),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Binary G-code

const LE: Endian = Endian::Little;

const CHECKSUM_TYPES: EnumTable = &[(0, "None"), (1, "CRC32")];
const BLOCK_TYPES: EnumTable = &[
    (0, "File metadata"),
    (1, "G-code"),
    (2, "Slicer metadata"),
    (3, "Printer metadata"),
    (4, "Print metadata"),
    (5, "Thumbnail"),
];
const COMPRESSION: EnumTable = &[
    (0, "None"),
    (1, "Deflate (zlib)"),
    (2, "Heatshrink 11/4"),
    (3, "Heatshrink 12/4"),
];
const METADATA_ENCODING: EnumTable = &[(0, "INI"), (1, "JSON")];
const GCODE_ENCODING: EnumTable = &[(0, "None"), (1, "MeatPack"), (2, "MeatPack with comments")];
const IMAGE_FORMATS: EnumTable = &[(0, "PNG"), (1, "JPEG"), (2, "QOI")];

fn probe_bgcode(h: &Head<'_>) -> bool {
    h.starts_with(b"GCDE")
        && u32_le(h.data, 4).is_some_and(|v| (1..=255).contains(&v))
        && u16_le(h.data, 8).is_some_and(|c| c <= 1)
}

declare_format!(pub BGCODE = "bgcode", "Prusa binary G-code", ["bgcode"], "application/x-bgcode",
    Probe::Custom(probe_bgcode), dissect_bgcode);

fn file_header(f: &mut Fields<'_>, _: &()) -> Result<u16> {
    f.ascii("Magic", 4).emit()?;
    f.u32("Version").emit()?;
    f.u16("Checksum type").enumeration(CHECKSUM_TYPES).emit()
}

#[derive(Clone, Copy, Debug)]
struct BlockHeader {
    kind: u16,
    compression: u16,
    uncompressed: u32,
    compressed: u32,
}

impl BlockHeader {
    fn size(&self) -> u64 {
        if self.compression == 0 { 8 } else { 12 }
    }

    fn data_size(&self) -> u64 {
        u64::from(if self.compression == 0 {
            self.uncompressed
        } else {
            self.compressed
        })
    }

    fn params_size(&self) -> Option<u64> {
        match self.kind {
            0..=4 => Some(2),
            5 => Some(6),
            _ => None,
        }
    }
}

fn block_header(f: &mut Fields<'_>, _: &()) -> Result<BlockHeader> {
    let kind = f.u16("Type").enumeration(BLOCK_TYPES).emit()?;
    let compression = f.u16("Compression").enumeration(COMPRESSION).emit()?;
    let uncompressed = f.u32("Uncompressed size").hex().emit()?;
    let compressed = if compression == 0 {
        uncompressed
    } else {
        f.u32("Compressed size").hex().emit()?
    };
    Ok(BlockHeader {
        kind,
        compression,
        uncompressed,
        compressed,
    })
}

fn block_params(f: &mut Fields<'_>, kind: &u16) -> Result<()> {
    match kind {
        1 => {
            f.u16("Encoding").enumeration(GCODE_ENCODING).emit()?;
        }
        5 => {
            f.u16("Format").enumeration(IMAGE_FORMATS).emit()?;
            f.u16("Width").emit()?;
            f.u16("Height").emit()?;
        }
        _ => {
            f.u16("Encoding").enumeration(METADATA_ENCODING).emit()?;
        }
    }
    Ok(())
}

/// The codec for a block's data, `None` for an unknown compression.
fn block_codec(compression: u16, meatpack: bool) -> Option<Codec> {
    let base = match compression {
        0 => Codec::Stored,
        1 => Codec::Zlib,
        2 => Codec::Heatshrink {
            window: 11,
            lookahead: 4,
        },
        3 => Codec::Heatshrink {
            window: 12,
            lookahead: 4,
        },
        _ => return None,
    };
    if !meatpack {
        return Some(base);
    }
    Some(match compression {
        0 => Codec::MeatPack,
        1 => Codec::chain(
            "zlib+meatpack",
            "zlib+meatpack (lazy)",
            [base, Codec::MeatPack],
        ),
        2 => Codec::chain(
            "heatshrink-11+meatpack",
            "heatshrink-11+meatpack (lazy)",
            [base, Codec::MeatPack],
        ),
        _ => Codec::chain(
            "heatshrink-12+meatpack",
            "heatshrink-12+meatpack (lazy)",
            [base, Codec::MeatPack],
        ),
    })
}

/// A block as found by the walker.
#[derive(Clone, Copy, Debug)]
struct Block {
    header: BlockHeader,
    /// Parameter value (encoding or image format) and, for thumbnails,
    /// the size.
    param: u16,
    width: u16,
    height: u16,
    span: Span,
    params: Span,
    data: Span,
    checksum: Option<Span>,
}

/// Reads the block at `pos` (relative to `file`).
async fn read_block(cx: &Cx, file: Span, pos: u64, checksummed: bool) -> Result<Block> {
    let head = cx.read(file.sub(pos, 18)).await?;
    let kind = u16_le(&head, 0)
        .ok_or_else(|| Diagnostic::truncated(file.sub(pos, 8), to_u64(head.len())))?;
    let compression = u16_le(&head, 2).unwrap_or(0);
    let uncompressed = u32_le(&head, 4)
        .ok_or_else(|| Diagnostic::truncated(file.sub(pos, 8), to_u64(head.len())))?;
    let compressed = if compression == 0 {
        uncompressed
    } else {
        u32_le(&head, 8)
            .ok_or_else(|| Diagnostic::truncated(file.sub(pos, 12), to_u64(head.len())))?
    };
    let header = BlockHeader {
        kind,
        compression,
        uncompressed,
        compressed,
    };
    let params_size = header.params_size().ok_or_else(|| {
        Diagnostic::malformed(format!("unknown block type {kind}")).at(file.sub(pos, 2))
    })?;
    let hs = header.size();
    let p = usize::try_from(hs).unwrap_or(0);
    let param = u16_le(&head, p).unwrap_or(0);
    let width = u16_le(&head, p.saturating_add(2)).unwrap_or(0);
    let height = u16_le(&head, p.saturating_add(4)).unwrap_or(0);
    let data_at = pos.saturating_add(hs).saturating_add(params_size);
    let csize = if checksummed { 4 } else { 0 };
    let total = hs
        .saturating_add(params_size)
        .saturating_add(header.data_size())
        .saturating_add(csize);
    let span = file.sub(pos, total);
    let data = file.sub(data_at, header.data_size());
    Ok(Block {
        header,
        param,
        width,
        height,
        span,
        params: file.sub(pos.saturating_add(hs), params_size),
        data,
        checksum: checksummed.then(|| file.sub(data.end().saturating_sub(file.offset), csize)),
    })
}

fn block_name(b: &Block) -> String {
    let base = crate::value::lookup(BLOCK_TYPES, b.header.kind.into()).unwrap_or("Block");
    base.to_owned()
}

fn block_summary(b: &Block) -> String {
    let compression = match b.header.compression {
        0 => String::new(),
        c => format!(
            "{}, ",
            crate::value::lookup(COMPRESSION, c.into()).unwrap_or("unknown compression")
        ),
    };
    let what = match b.header.kind {
        5 => format!(
            "{} {}×{}, ",
            crate::value::lookup(IMAGE_FORMATS, b.param.into()).unwrap_or("image"),
            b.width,
            b.height
        ),
        1 if b.param != 0 => format!(
            "{}, ",
            crate::value::lookup(GCODE_ENCODING, b.param.into()).unwrap_or("encoded")
        ),
        _ => String::new(),
    };
    if b.header.compression == 0 {
        format!("{what}{:#x} bytes", b.header.uncompressed)
    } else {
        format!(
            "{what}{compression}{:#x} → {:#x} bytes",
            b.header.compressed, b.header.uncompressed
        )
    }
}

/// Metadata of a block's INI text: `(key, value, line span)`.
async fn metadata_entries(cx: &Cx, b: &Block) -> Result<(Span, Vec<(String, String, Span)>)> {
    let codec = block_codec(b.header.compression, false)
        .ok_or_else(|| Diagnostic::unsupported("unknown compression").at(b.data))?;
    let decoded = match codec {
        Codec::Stored => b.data,
        codec => {
            let d = decode_span(cx, b.data, &codec, Some(u64::from(b.header.uncompressed))).await?;
            if let Some(e) = d.error {
                cx.diag(e);
            }
            d.span
        }
    };
    let mut lines = Lines::new(cx, decoded);
    let mut out = Vec::new();
    while let Some(line) = lines.next().await? {
        let t = line.text();
        if let Some((k, v)) = t.split_once('=') {
            out.push((k.trim().to_owned(), v.trim().to_owned(), line.span));
        } else if !t.trim().is_empty() {
            out.push((String::new(), t, line.span));
        }
    }
    Ok((decoded, out))
}

pub async fn dissect_bgcode(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let header_span = file.sub(0, 10);
    let checksum_type = parse(&cx, header_span, LE, &(), file_header).await?;
    cx.emit(struct_node("File header", header_span, LE, (), file_header));
    let checksummed = checksum_type == 1;

    // Metadata at the front, for the summary.
    let mut summary = vec!["Prusa binary G-code".to_owned()];
    let mut pos = 10u64;
    let mut thumbnails = 0u32;
    let mut facts: Vec<(String, String)> = Vec::new();
    for _ in 0..64 {
        if pos >= file.len {
            break;
        }
        let Ok(b) = read_block(&cx, file, pos, checksummed).await else {
            break;
        };
        match b.header.kind {
            0 | 3 if b.param == 0 => {
                if let Ok((_, entries)) = metadata_entries(&cx, &b).await {
                    facts.extend(entries.into_iter().map(|(k, v, _)| (k, v)));
                }
            }
            5 => thumbnails = thumbnails.saturating_add(1),
            1 => break,
            _ => {}
        }
        if b.span.len == 0 {
            break;
        }
        pos = pos.saturating_add(b.span.len);
    }
    let fact = |key: &str| facts.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone());
    for key in [
        "Producer",
        "printer_model",
        "filament_type",
        "estimated printing time (normal mode)",
        "filament used [g]",
    ] {
        if let Some(v) = fact(key).filter(|v| !v.is_empty()) {
            summary.push(if key == "filament used [g]" {
                format!("{v} g")
            } else {
                v
            });
        }
    }
    if thumbnails > 0 {
        summary.push(format!(
            "{thumbnails} thumbnail{}",
            if thumbnails == 1 { "" } else { "s" }
        ));
    }
    cx.annotate(summary.join(", "));
    cx.emit(
        Node::new("Blocks")
            .span(file.tail(10))
            .lazy(blocks, (input, checksummed)),
    );
    cx.emit(
        Node::new("G-code")
            .span(file.tail(10))
            .desc("All G-code blocks decoded and joined, as text G-code")
            .lazy(gcode, (input, checksummed)),
    );
    Ok(())
}

async fn blocks(cx: Cx, (input, checksummed): (Input, bool)) -> Result<()> {
    let file = input.span;
    let (mut pos, mut index) = cx.resume::<(u64, u64)>().unwrap_or((10, 0));
    while pos < file.len {
        let at = (pos, index);
        cx.mark(move || at);
        cx.progress_in(file, file.offset.saturating_add(pos));
        let b = read_block(&cx, file, pos, checksummed).await?;
        let mut node = Node::new(block_name(&b))
            .span(b.span)
            .summary(block_summary(&b))
            .lazy(
                block,
                (
                    input,
                    b.span.offset.saturating_sub(file.offset),
                    checksummed,
                ),
            );
        let want = b
            .header
            .size()
            .saturating_add(b.header.params_size().unwrap_or(0))
            .saturating_add(b.header.data_size())
            .saturating_add(if checksummed { 4 } else { 0 });
        let short = b.span.len < want;
        if short {
            node = node.diag(Diagnostic::truncated(
                Span::new(b.span.source, b.span.offset, want),
                b.span.len,
            ));
        }
        cx.push(node).await;
        index = index.saturating_add(1);
        if short || b.span.len == 0 {
            break;
        }
        pos = pos.saturating_add(b.span.len);
    }
    cx.set_count(Count::Exact(index));
    Ok(())
}

async fn block(cx: Cx, (input, pos, checksummed): (Input, u64, bool)) -> Result<()> {
    let file = input.span;
    let b = read_block(&cx, file, pos, checksummed).await?;
    let hspan = file.sub(pos, b.header.size());
    cx.emit(struct_node("Block header", hspan, LE, (), block_header));
    cx.emit(struct_node(
        "Parameters",
        b.params,
        LE,
        b.header.kind,
        block_params,
    ));
    let mut checksum = None;
    if let Some(cs) = b.checksum {
        let stored = cx.read(cs).await?;
        let covered = cx.read(file.sub(pos, b.span.len.saturating_sub(4))).await?;
        let mut node = Node::new("Checksum").span(cs);
        match u32_le(&stored, 0) {
            Some(v) => {
                node = node.value(hex(v, 32));
                let computed = crate::formats::util::datakit::crc32_paced(&cx, &covered).await;
                node = if to_u64(covered.len()) < b.span.len.saturating_sub(4) {
                    node.summary("CRC-32 (block truncated)")
                } else if computed == v {
                    node.summary("CRC-32, valid")
                } else {
                    node.diag(Diagnostic::warning(format!(
                        "CRC-32 mismatch: computed {computed:#010x}"
                    )))
                };
            }
            None => node = node.diag(Diagnostic::truncated(cs, to_u64(stored.len()))),
        }
        checksum = Some(node);
    }
    let expected = Some(u64::from(b.header.uncompressed));
    match b.header.kind {
        5 => {
            let Some(codec) = block_codec(b.header.compression, false) else {
                cx.emit(
                    Node::new("Image")
                        .span(b.data)
                        .diag(Diagnostic::unsupported("unknown compression")),
                );
                return Ok(());
            };
            cx.emit(content("Image", input, b.data, codec, expected));
        }
        1 => {
            let meatpack = matches!(b.param, 1 | 2);
            match block_codec(b.header.compression, meatpack) {
                Some(codec) => cx.emit(Node::new("G-code").span(b.data).lazy(
                    gcode_block,
                    (input, b.data, codec, b.header.uncompressed, meatpack),
                )),
                None => cx.emit(
                    Node::new("G-code")
                        .span(b.data)
                        .diag(Diagnostic::unsupported("unknown compression")),
                ),
            }
            if b.param > 2 {
                cx.diag(
                    Diagnostic::unsupported(format!("G-code encoding {}", b.param)).at(b.params),
                );
            }
        }
        _ if b.param == 1 => {
            // JSON (libbgcode's "Slicer3" metadata).
            if let Some(codec) = block_codec(b.header.compression, false) {
                cx.emit(content("JSON", input, b.data, codec, expected));
            }
        }
        _ => {
            let (decoded, entries) = metadata_entries(&cx, &b).await?;
            let mut node = Node::new("Entries")
                .span(decoded)
                .summary(format!("{} entries", entries.len()));
            if decoded.source != b.data.source {
                node = node.desc("Decompressed metadata (INI)");
            }
            cx.emit(node.lazy(entries_node, (input, pos, checksummed)));
        }
    }
    if let Some(node) = checksum {
        cx.emit(node);
    }
    Ok(())
}

async fn entries_node(cx: Cx, (input, pos, checksummed): (Input, u64, bool)) -> Result<()> {
    let b = read_block(&cx, input.span, pos, checksummed).await?;
    let (_, entries) = metadata_entries(&cx, &b).await?;
    for (k, v, span) in entries {
        let name = if k.is_empty() { "Line".to_owned() } else { k };
        cx.push(text_node(name, span, &v)).await;
    }
    Ok(())
}

async fn decode_gcode(
    cx: &Cx,
    data: Span,
    codec: &Codec,
    uncompressed: u32,
    meatpack: bool,
) -> Result<Span> {
    if *codec == Codec::Stored {
        return Ok(data);
    }
    // With MeatPack the recorded size is that of the packed data.
    let expected = (!meatpack).then_some(u64::from(uncompressed));
    let d = decode_span(cx, data, codec, expected).await?;
    if let Some(e) = d.error {
        cx.diag(e);
    }
    Ok(d.span)
}

async fn gcode_block(
    cx: Cx,
    (input, data, codec, uncompressed, meatpack): (Input, Span, Codec, u32, bool),
) -> Result<()> {
    let decoded = decode_gcode(&cx, data, &codec, uncompressed, meatpack).await?;
    cx.annotate(format!("{:#x} bytes of G-code", decoded.len));
    dissect_gcode(cx, input.nested(decoded)).await
}

async fn gcode(cx: Cx, (input, checksummed): (Input, bool)) -> Result<()> {
    let file = input.span;
    let mut pos = 10u64;
    let mut pieces = Vec::new();
    let mut blocks = 0u64;
    while pos < file.len {
        cx.checkpoint().await;
        let b = match read_block(&cx, file, pos, checksummed).await {
            Ok(b) => b,
            Err(e) => {
                cx.diag(e);
                break;
            }
        };
        if b.header.kind == 1 {
            let meatpack = matches!(b.param, 1 | 2);
            match block_codec(b.header.compression, meatpack) {
                Some(codec) => {
                    match decode_gcode(&cx, b.data, &codec, b.header.uncompressed, meatpack).await {
                        Ok(span) => pieces.push(span),
                        Err(e) => {
                            cx.diag(e);
                            break;
                        }
                    }
                }
                None => {
                    cx.diag(Diagnostic::unsupported("unknown compression").at(b.data));
                    break;
                }
            }
            blocks = blocks.saturating_add(1);
        }
        if b.span.len == 0 {
            break;
        }
        pos = pos.saturating_add(b.span.len);
    }
    if pieces.is_empty() {
        return Err(Diagnostic::note("no G-code blocks").at(file));
    }
    let joined = cx
        .add_pieces_stepped(
            Origin {
                parent: file,
                transform: "bgcode-gcode",
            },
            &pieces,
        )
        .await?;

    cx.annotate(format!(
        "{:#x} bytes of G-code from {blocks} block{}",
        joined.len,
        if blocks == 1 { "" } else { "s" }
    ));
    dissect_gcode(cx, input.nested(joined)).await
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn words_and_commands() {
        let line = b"N12 G01 X10.5 Y-3 E.02 F1200*71 ; move";
        let p = parse_line(line);
        assert_eq!(command(&p, line), "G1");
        assert_eq!(p.words.len(), 6);
        assert!(p.checksum.is_some());
        assert!(p.comment.is_some());
        let line = b"M117 Printing layer 3";
        let p = parse_line(line);
        assert_eq!(command(&p, line), "M117");
        assert!(p.rest.is_some());
        let line = b"G1X10Y20Z.3";
        assert_eq!(parse_line(line).words.len(), 4);
        let line = b"M862.3 P \"MK4S\" ; printer model check";
        let p = parse_line(line);
        assert_eq!(command(&p, line), "M862.3");
        assert!(!p.clean);
        let line = b"(contour) G0 X1";
        assert!(parse_line(line).comment == Some(0));
    }

    #[test]
    fn settings() {
        let c = b" filament used [mm] = 12.04";
        let ((ks, ke), (vs, ve)) = setting(c).unwrap();
        assert_eq!(&c[ks..ke], b"filament used [mm]");
        assert_eq!(&c[vs..ve], b"12.04");
        let c = b"FLAVOR:Marlin";
        let ((ks, ke), (vs, ve)) = setting(c).unwrap();
        assert_eq!((&c[ks..ke], &c[vs..ve]), (&b"FLAVOR"[..], &b"Marlin"[..]));
        assert!(setting(b" Move the head up, slowly").is_none());
        assert_eq!(comment_z(b"Z:0.4"), Some(0.4));
        assert_eq!(comment_z(b" layer 3, Z = 0.600"), Some(0.6));
        assert!(is_layer_marker(b"LAYER:-2"));
        assert!(!is_layer_marker(b" layer_height = 0.2"));
        assert_eq!(
            slicer_name(b" generated by PrusaSlicer 2.8.1 on 2025-03-14").as_deref(),
            Some("PrusaSlicer 2.8.1")
        );
    }

    fn claims(text: &str) -> bool {
        let data = text.as_bytes();
        probe_gcode(&Head {
            data,
            tail: data,
            len: to_u64(data.len()),
            len_known: true,
        })
    }

    #[test]
    fn probe_is_conservative() {
        // Ordinary text, INI-style comments, Gerber and short snippets.
        assert!(!claims("Hello world.\nThis is a note about G1 and M104.\n"));
        assert!(!claims("; generated by Notepad\n[section]\nkey=value\n"));
        assert!(!claims(
            "G04 Gerber*\n%FSLAX24Y24*%\nG01*\nX0Y0D02*\nX100Y0D01*\nX100Y100D01*\nM02*\n"
        ));
        assert!(!claims("G1 X1\nG1 X2\nM2\n"));
        let mut prose = String::new();
        for i in 0..20 {
            prose.push_str(&format!("Step {i}: move the part by hand\n"));
        }
        prose.push_str("G1 X1 Y1\nG1 X2 Y2\nG1 X3 Y3\n");
        assert!(!claims(&prose));
        // CNC programs and slicer output are claimed.
        let mut cnc = String::from("%\nO1000\n(PART)\nG21 G90\n");
        for i in 0..10 {
            cnc.push_str(&format!("G1 X{i} Y{i} F100\n"));
        }
        cnc.push_str("M30\n%\n");
        assert!(claims(&cnc));
        assert!(claims(
            "; generated by PrusaSlicer 2.8.1 on 2025-03-14\nG28\nG1 Z.2\n"
        ));
        assert!(claims(
            ";FLAVOR:Marlin\n;Generated with Cura_SteamEngine 5.4.0\nM104 S200\nG28\nG0 X1 Y1\n"
        ));
    }
}
