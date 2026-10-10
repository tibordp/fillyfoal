//! Printer languages and printer descriptions: HP PJL job wrappers, PCL 5
//! escape sequences, PCL XL (PCL 6) binary streams, HP-GL/2 plots, Epson
//! ESC/P, Zebra ZPL labels, PostScript Printer Descriptions (PPD), Windows
//! generic printer descriptions (GPD), and CUPS/PWG and Apple (URF) raster.

use crate::bytes::{to_u64, u32_be};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record};
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::text::probe;
use crate::formats::text::scan::{Lines, Scanner};
use crate::formats::util::val::{text, uint};
use crate::formats::{Head, Input, Probe, embedded};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::Value;

/// Universal Exit Language: ends a job language and returns to PJL.
const UEL: &[u8] = b"\x1b%-12345X";
/// Longest command or text run shown as one node's value.
const CAP: usize = 256;

fn printable(b: &[u8]) -> String {
    b.iter()
        .map(|&c| match c {
            0x1b => "<ESC>".to_owned(),
            0x20..=0x7e => char::from(c).to_string(),
            b'\r' => "\\r".to_owned(),
            b'\n' => "\\n".to_owned(),
            0x0c => "\\f".to_owned(),
            _ => format!("\\x{c:02x}"),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// PJL

declare_format!(pub PJL = "pjl", "HP Printer Job Language job", ["pjl", "prn"], "application/vnd.hp-pjl",
    Probe::Custom(|h| h.starts_with(UEL) && probe::trim_start(h.data.get(UEL.len()..).unwrap_or_default()).starts_with(b"@PJL")), pjl);

async fn pjl(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut scan = Scanner::new(&cx, file);
    let mut pos = 0u64;
    let mut language = String::new();
    let mut job = String::new();
    while pos < scan.len() {
        scan.tick().await;
        cx.progress_in(scan.region(), scan.region().offset.saturating_add(pos));
        if scan.matches(pos, UEL).await? {
            let end = pos.saturating_add(to_u64(UEL.len()));
            cx.push(Node::new("Universal Exit Language").span(scan.span(pos, end)))
                .await;
            pos = end;
            continue;
        }
        if scan.matches(pos, b"@PJL").await? {
            let eol = scan
                .find(pos, |b| b == b'\n')
                .await?
                .map_or(scan.len(), |p| p.saturating_add(1));
            let line = String::from_utf8_lossy(&scan.bytes(pos, eol, CAP).await?)
                .trim()
                .to_owned();
            let body = line.get(4..).unwrap_or_default().trim();
            let (cmd, args) = body.split_once(' ').unwrap_or((body, ""));
            let node = Node::new(if cmd.is_empty() {
                "@PJL".to_owned()
            } else {
                cmd.to_ascii_uppercase()
            })
            .span(scan.span(pos, eol));
            cx.push(if args.is_empty() {
                node
            } else {
                node.value(text(args.trim()))
            })
            .await;
            let upper = body.to_ascii_uppercase();
            if upper.starts_with("JOB") && job.is_empty() {
                job = args.trim().to_owned();
            }
            pos = eol;
            if let Some(lang) = upper.strip_prefix("ENTER LANGUAGE") {
                language = lang.trim_start_matches([' ', '=']).trim().to_owned();
                let end = scan.find_seq(pos, UEL).await?.unwrap_or(scan.len());
                let span = scan.span(pos, end);
                if span.len > 0 {
                    cx.push(embedded(format!("{language} data"), input.nested(span)))
                        .await;
                }
                pos = end;
            }
            continue;
        }
        // Anything else up to the next UEL or @PJL line: job data.
        let end = scan
            .find_seq(pos, UEL)
            .await?
            .unwrap_or(scan.len())
            .max(pos.saturating_add(1));
        let span = scan.span(pos, end);
        let blank = scan
            .bytes(pos, end, 64)
            .await?
            .iter()
            .all(u8::is_ascii_whitespace);
        if !blank {
            cx.push(embedded("Job data", input.nested(span))).await;
        }
        pos = end;
    }
    cx.annotate(format!(
        "PJL job{}{}",
        if job.is_empty() {
            String::new()
        } else {
            format!(" {job}")
        },
        if language.is_empty() {
            String::new()
        } else {
            format!(", {language}")
        }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// PCL 5

declare_format!(pub PCL = "pcl", "HP Printer Command Language (PCL 5)", ["pcl", "prn"], "application/vnd.hp-pcl",
    Probe::Custom(|h| h.starts_with(b"\x1bE\x1b") || (h.starts_with(b"\x1bE\r\n\x1b"))), pcl);

/// Names of parameterized commands by group character and terminator
/// (upper-cased); the parameter character is the first byte.
const PCL_COMMANDS: &[(&[u8; 3], &str)] = &[
    (b"&lO", "Orientation"),
    (b"&lA", "Page size"),
    (b"&lH", "Paper source"),
    (b"&lE", "Top margin"),
    (b"&lF", "Text length"),
    (b"&lX", "Copies"),
    (b"&lS", "Simplex/duplex"),
    (b"&lC", "Vertical motion index"),
    (b"&lD", "Line spacing"),
    (b"&lL", "Perforation skip"),
    (b"&lM", "Media type"),
    (b"&lG", "Output bin"),
    (b"&lU", "Left registration"),
    (b"&lZ", "Top registration"),
    (b"&lP", "Page length"),
    (b"&aL", "Left margin"),
    (b"&aM", "Right margin"),
    (b"&aR", "Vertical position (rows)"),
    (b"&aC", "Horizontal position (columns)"),
    (b"&aH", "Horizontal position (decipoints)"),
    (b"&aV", "Vertical position (decipoints)"),
    (b"&aG", "Duplex page side"),
    (b"&aP", "Print direction"),
    (b"&uD", "Unit of measure"),
    (b"&kH", "Horizontal motion index"),
    (b"&kG", "Line termination"),
    (b"&kS", "Pitch mode"),
    (b"&dD", "Underline on"),
    (b"&d@", "Underline off"),
    (b"&fS", "Push/pop cursor"),
    (b"&fY", "Macro ID"),
    (b"&fX", "Macro control"),
    (b"&pX", "Transparent print data"),
    (b"&sC", "End-of-line wrap"),
    (b"&rF", "Flush pages"),
    (b"&tP", "Text parsing method"),
    (b"&nW", "Alphanumeric ID"),
    (b"*pX", "Horizontal position (dots)"),
    (b"*pY", "Vertical position (dots)"),
    (b"*pR", "Set pattern reference point"),
    (b"*tR", "Raster resolution"),
    (b"*rA", "Start raster graphics"),
    (b"*rB", "End raster graphics"),
    (b"*rC", "End raster graphics"),
    (b"*rS", "Raster width"),
    (b"*rT", "Raster height"),
    (b"*rF", "Raster presentation"),
    (b"*rU", "Simple colour"),
    (b"*bM", "Compression method"),
    (b"*bW", "Raster data"),
    (b"*bV", "Raster data (plane)"),
    (b"*bY", "Raster Y offset"),
    (b"*vW", "Configure image data"),
    (b"*vA", "Colour component 1"),
    (b"*vB", "Colour component 2"),
    (b"*vC", "Colour component 3"),
    (b"*vI", "Assign colour index"),
    (b"*vS", "Foreground colour"),
    (b"*vT", "Pattern type"),
    (b"*vN", "Source transparency"),
    (b"*vO", "Pattern transparency"),
    (b"*cA", "Rectangle width (dots)"),
    (b"*cB", "Rectangle height (dots)"),
    (b"*cH", "Rectangle width (decipoints)"),
    (b"*cV", "Rectangle height (decipoints)"),
    (b"*cP", "Fill rectangle"),
    (b"*cG", "Pattern ID"),
    (b"*cW", "User-defined pattern"),
    (b"*cQ", "Pattern control"),
    (b"*cD", "Font ID"),
    (b"*cE", "Character code"),
    (b"*cF", "Font control"),
    (b"*cR", "Symbol set ID code"),
    (b"*cS", "Symbol set control"),
    (b"*gW", "Configure raster data"),
    (b"*oM", "Print quality"),
    (b"*oW", "Driver configuration"),
    (b"*lO", "Logical operation"),
    (b"*lR", "Pixel placement"),
    (b"*mW", "Download dither matrix"),
    (b"*iW", "Viewing illuminant"),
    (b"*tI", "Gamma correction"),
    (b"*tJ", "Render algorithm"),
    (b"(sP", "Primary spacing"),
    (b"(sH", "Primary pitch"),
    (b"(sV", "Primary height"),
    (b"(sS", "Primary style"),
    (b"(sB", "Primary stroke weight"),
    (b"(sT", "Primary typeface"),
    (b"(sW", "Character/font data"),
    (b")sP", "Secondary spacing"),
    (b")sH", "Secondary pitch"),
    (b")sV", "Secondary height"),
    (b")sS", "Secondary style"),
    (b")sB", "Secondary stroke weight"),
    (b")sT", "Secondary typeface"),
    (b")sW", "Font header"),
    (b"(fW", "Define symbol set"),
    (b"%-X", "Universal Exit Language"),
];

fn pcl_name(param: u8, group: u8, term: u8) -> Option<&'static str> {
    let key = [param, group, term.to_ascii_uppercase()];
    match (param, group, term.to_ascii_uppercase()) {
        (b'%', _, b'B') => return Some("Enter HP-GL/2"),
        (b'%', _, b'A') => return Some("Enter PCL"),
        (b'(' | b')', 0, b'X') => return Some("Select font by ID"),
        (b'(' | b')', 0, b'@') => return Some("Default font"),
        (b'(', 0, _) => return Some("Primary symbol set"),
        (b')', 0, _) => return Some("Secondary symbol set"),
        _ => {}
    }
    PCL_COMMANDS
        .iter()
        .find(|(k, _)| **k == key)
        .map(|(_, v)| *v)
}

const PCL_SIMPLE: &[(u8, &str)] = &[
    (b'E', "Reset"),
    (b'9', "Clear horizontal margins"),
    (b'=', "Half line feed"),
    (b'Y', "Display functions on"),
    (b'Z', "Display functions off"),
    (b'z', "Self test"),
];

/// Reads a parameterized PCL command at `pos` (just after ESC). Returns the
/// end of the command (and its data) and a description.
async fn pcl_command(scan: &mut Scanner<'_>, pos: u64) -> Result<(u64, String, Vec<String>)> {
    let param = scan.byte(pos).await?.unwrap_or(0);
    let mut at = pos.saturating_add(1);
    let mut group = 0u8;
    if let Some(g) = scan.byte(at).await?.filter(|b| (0x60..=0x7e).contains(b)) {
        group = g;
        at = at.saturating_add(1);
    }
    let mut parts = Vec::new();
    let mut names = Vec::new();
    loop {
        scan.tick().await;
        let start = at;
        while let Some(b) = scan.byte(at).await? {
            if b.is_ascii_digit() || matches!(b, b'+' | b'-' | b'.') {
                at = at.saturating_add(1);
                if at.saturating_sub(start) > 32 {
                    break;
                }
            } else {
                break;
            }
        }
        let value = String::from_utf8_lossy(&scan.bytes(start, at, 32).await?).into_owned();
        let Some(term) = scan.byte(at).await? else {
            parts.push(value);
            return Ok((at, String::new(), parts));
        };
        at = at.saturating_add(1);
        if !(0x40..=0x7e).contains(&term) {
            // Not a valid terminator: stop before it.
            return Ok((at.saturating_sub(1), String::new(), parts));
        }
        let up = term.to_ascii_uppercase();
        names.push(pcl_name(param, group, term).map_or_else(
            || {
                format!(
                    "{}{}{}",
                    char::from(param),
                    if group == 0 {
                        String::new()
                    } else {
                        char::from(group).to_string()
                    },
                    char::from(up)
                )
            },
            str::to_owned,
        ));
        parts.push(format!("{value}{}", char::from(term)));
        // Commands that carry binary data: W terminators and &p#X.
        if up == b'W' || (param == b'&' && group == b'p' && up == b'X') {
            let n: u64 = value.trim_start_matches('+').parse().unwrap_or(0);
            at = at.saturating_add(n).min(scan.len());
        }
        if term.is_ascii_uppercase() || !(0x60..=0x7e).contains(&term) {
            break;
        }
    }
    Ok((at, names.join(", "), parts))
}

async fn pcl(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut scan = Scanner::new(&cx, file);
    let mut pos = 0u64;
    let (mut pages, mut commands) = (0u32, 0u32);
    while pos < scan.len() {
        scan.tick().await;
        cx.progress_in(scan.region(), scan.region().offset.saturating_add(pos));
        let Some(b) = scan.byte(pos).await? else {
            break;
        };
        if b != 0x1b {
            let end = scan.find(pos, |c| c == 0x1b).await?.unwrap_or(scan.len());
            let data = scan.bytes(pos, end, CAP).await?;
            let ff = data.iter().filter(|&&c| c == 0x0c).count();
            pages = pages.saturating_add(u32::try_from(ff).unwrap_or(0));
            cx.push(
                Node::new("Text")
                    .span(scan.span(pos, end))
                    .value(text(printable(&data))),
            )
            .await;
            pos = end;
            continue;
        }
        let c1 = scan.byte(pos.saturating_add(1)).await?.unwrap_or(0);
        commands = commands.saturating_add(1);
        if (0x21..=0x2f).contains(&c1) {
            let (end, name, parts) = pcl_command(&mut scan, pos.saturating_add(1)).await?;
            let end = end.max(pos.saturating_add(2));
            let head = format!(
                "ESC {}",
                printable(
                    &scan
                        .bytes(pos.saturating_add(1), end.min(pos.saturating_add(3)), 2)
                        .await?
                )
            );
            let node = Node::new(if name.is_empty() { head } else { name })
                .span(scan.span(pos, end))
                .value(text(parts.join(" ")));
            cx.push(node).await;
            pos = end;
        } else {
            let name = PCL_SIMPLE.iter().find(|(k, _)| *k == c1).map_or_else(
                || format!("ESC {}", printable(&[c1])),
                |(_, v)| (*v).to_owned(),
            );
            let end = pos.saturating_add(2).min(scan.len());
            cx.push(Node::new(name).span(scan.span(pos, end))).await;
            pos = end;
        }
    }
    cx.annotate(format!(
        "PCL 5 print job, {commands} commands, {} pages",
        pages.max(1)
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// PCL XL (PCL 6)

fn pclxl_probe(h: &Head<'_>) -> bool {
    matches!(h.data.first(), Some(b'(' | b')')) && h.at(1, b" HP-PCL XL;")
}

declare_format!(pub PCLXL = "pcl-xl", "HP PCL XL (PCL 6) print stream", ["pxl", "pcl"], "application/vnd.hp-pclxl",
    Probe::Custom(pclxl_probe), pclxl);

const XL_OPERATORS: &[(u8, &str)] = &[
    (0x41, "BeginSession"),
    (0x42, "EndSession"),
    (0x43, "BeginPage"),
    (0x44, "EndPage"),
    (0x46, "VendorUnique"),
    (0x47, "Comment"),
    (0x48, "OpenDataSource"),
    (0x49, "CloseDataSource"),
    (0x4f, "BeginFontHeader"),
    (0x50, "ReadFontHeader"),
    (0x51, "EndFontHeader"),
    (0x52, "BeginChar"),
    (0x53, "ReadChar"),
    (0x54, "EndChar"),
    (0x55, "RemoveFont"),
    (0x56, "SetCharAttributes"),
    (0x5b, "BeginStream"),
    (0x5c, "ReadStream"),
    (0x5d, "EndStream"),
    (0x5e, "ExecStream"),
    (0x60, "PopGS"),
    (0x61, "PushGS"),
    (0x6a, "SetColorSpace"),
    (0x6b, "SetCursor"),
    (0x6d, "SetFont"),
    (0x6e, "SetLineDash"),
    (0x6f, "SetLineCap"),
    (0x70, "SetLineJoin"),
    (0x71, "SetMiterLimit"),
    (0x74, "SetPageDefaultCTM"),
    (0x75, "SetPageOrigin"),
    (0x76, "SetPageRotation"),
    (0x77, "SetPageScale"),
    (0x78, "SetPaintTxMode"),
    (0x79, "SetPenWidth"),
    (0x7a, "SetROP"),
    (0x7b, "SetSourceTxMode"),
    (0x7c, "SetCharBoldValue"),
    (0x7e, "SetClipMode"),
    (0x7f, "SetPathToClip"),
    (0x80, "SetCharShear"),
    (0x81, "SetCharScale"),
    (0x82, "SetCharAngle"),
    (0x84, "NewPath"),
    (0x85, "PaintPath"),
    (0x86, "ArcPath"),
    (0x88, "BezierPath"),
    (0x8a, "BezierRelPath"),
    (0x8b, "Chord"),
    (0x8c, "ChordPath"),
    (0x8d, "Ellipse"),
    (0x8e, "EllipsePath"),
    (0x91, "LinePath"),
    (0x93, "LineRelPath"),
    (0x94, "Pie"),
    (0x95, "PiePath"),
    (0x96, "Rectangle"),
    (0x97, "RectanglePath"),
    (0x98, "RoundRectangle"),
    (0x99, "RoundRectanglePath"),
    (0xa8, "Text"),
    (0xa9, "TextPath"),
    (0xb0, "BeginImage"),
    (0xb1, "ReadImage"),
    (0xb2, "EndImage"),
    (0xb3, "BeginRastPattern"),
    (0xb4, "ReadRastPattern"),
    (0xb5, "EndRastPattern"),
    (0xb6, "BeginScan"),
    (0xb8, "EndScan"),
    (0xb9, "ScanLineRel"),
];

/// Element size of a PCL XL data type, and how many elements a scalar,
/// xy pair or box holds; arrays are marked with `None`.
fn xl_type(t: u8) -> Option<(u64, Option<u64>, &'static str)> {
    let size = match t & 0x07 {
        0 => 1,
        1 | 3 => 2,
        2 | 4 | 5 => 4,
        _ => return None,
    };
    let name = ["ubyte", "uint16", "uint32", "sint16", "sint32", "real32"]
        .get(usize::from(t & 7))
        .copied()
        .unwrap_or("?");
    match t & 0xf8 {
        0xc0 => Some((size, Some(1), name)),
        0xc8 => Some((size, None, name)),
        0xd0 => Some((size, Some(2), name)),
        0xe0 => Some((size, Some(4), name)),
        _ => None,
    }
}

fn xl_number(b: &[u8], t: u8, little: bool) -> String {
    let mut a = [0u8; 4];
    for (i, &x) in b.iter().take(4).enumerate() {
        if let Some(slot) = a.get_mut(if little {
            i
        } else {
            4usize.saturating_sub(b.len().min(4)).saturating_add(i)
        }) {
            *slot = x;
        }
    }
    let v = if little {
        u32::from_le_bytes(a)
    } else {
        u32::from_be_bytes(a)
    };
    match t & 7 {
        3 => i16::from_ne_bytes(u16::try_from(v & 0xffff).unwrap_or(0).to_ne_bytes()).to_string(),
        4 => i32::from_ne_bytes(v.to_ne_bytes()).to_string(),
        5 => f32::from_bits(v).to_string(),
        _ => v.to_string(),
    }
}

async fn pclxl(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut scan = Scanner::new(&cx, file);
    let little = scan.byte(0).await? == Some(b')');
    let eol = scan
        .find(0, |b| b == b'\n')
        .await?
        .map_or(scan.len(), |p| p.saturating_add(1));
    let header = String::from_utf8_lossy(&scan.bytes(0, eol, CAP).await?)
        .trim()
        .to_owned();
    cx.emit(
        Node::new("Stream header")
            .span(scan.span(0, eol))
            .value(text(header.clone()))
            .summary(if little {
                "little-endian binding"
            } else {
                "big-endian binding"
            }),
    );
    let mut pos = eol;
    let mut group = pos;
    let mut attrs: Vec<String> = Vec::new();
    let mut last: Option<String> = None;
    let (mut ops, mut pages) = (0u32, 0u32);
    let short = |at: u64| Diagnostic::malformed("element runs past the end").at(file.tail(at));
    while pos < scan.len() {
        scan.tick().await;
        cx.progress_in(scan.region(), scan.region().offset.saturating_add(pos));
        let Some(tag) = scan.byte(pos).await? else {
            break;
        };
        let start = pos;
        pos = pos.saturating_add(1);
        if let Some((size, count, tname)) = xl_type(tag) {
            let (n, prefix) = match count {
                Some(n) => (n, 0u64),
                None => {
                    let lt = scan.byte(pos).await?.ok_or_else(|| short(pos))?;
                    let lsize: u64 = if lt == 0xc1 { 2 } else { 1 };
                    let lb = scan
                        .bytes(
                            pos.saturating_add(1),
                            pos.saturating_add(1).saturating_add(lsize),
                            2,
                        )
                        .await?;
                    (
                        xl_number(&lb, if lt == 0xc1 { 1 } else { 0 }, little)
                            .parse()
                            .unwrap_or(0),
                        lsize.saturating_add(1),
                    )
                }
            };
            let data_at = pos.saturating_add(prefix);
            let end = data_at.saturating_add(n.saturating_mul(size));
            if end > scan.len() {
                return Err(short(start));
            }
            let raw = scan.bytes(data_at, end, 64).await?;
            let vals: Vec<String> = raw
                .chunks(usize::try_from(size).unwrap_or(1))
                .take(16)
                .map(|c| xl_number(c, tag, little))
                .collect();
            let shown = if count.is_none()
                && tag == 0xc8
                && raw.iter().all(|b| b.is_ascii_graphic() || *b == b' ')
            {
                format!("{:?}", String::from_utf8_lossy(&raw))
            } else if vals.len() == 1 {
                vals.join("")
            } else {
                format!("({})", vals.join(", "))
            };
            last = Some(format!("{tname} {shown}"));
            pos = end;
            continue;
        }
        match tag {
            0xf8 | 0xf9 => {
                let n: u64 = if tag == 0xf9 { 2 } else { 1 };
                let b = scan.bytes(pos, pos.saturating_add(n), 2).await?;
                let id = xl_number(&b, if tag == 0xf9 { 1 } else { 0 }, little);
                attrs.push(format!("{id}={}", last.take().unwrap_or_default()));
                pos = pos.saturating_add(n);
            }
            0xfa | 0xfb => {
                let n: u64 = if tag == 0xfa { 4 } else { 1 };
                let b = scan.bytes(pos, pos.saturating_add(n), 4).await?;
                let len: u64 = xl_number(&b, if tag == 0xfa { 2 } else { 0 }, little)
                    .parse()
                    .unwrap_or(0);
                let end = pos.saturating_add(n).saturating_add(len);
                if end > scan.len() {
                    return Err(short(start));
                }
                cx.push(
                    Node::new("Embedded data")
                        .span(scan.span(start, end))
                        .summary(format!("{len} bytes")),
                )
                .await;
                pos = end;
                group = pos;
            }
            0x00 | 0x09 | 0x0a | 0x0d | 0x20 => {
                if group == start {
                    group = pos;
                }
            }
            _ => {
                ops = ops.saturating_add(1);
                let name = XL_OPERATORS
                    .iter()
                    .find(|(k, _)| *k == tag)
                    .map_or_else(|| format!("Operator {tag:#04x}"), |(_, v)| (*v).to_owned());
                if tag == 0x43 {
                    pages = pages.saturating_add(1);
                }
                let node = Node::new(name).span(scan.span(group, pos));
                let node = if attrs.is_empty() {
                    node
                } else {
                    node.value(text(attrs.join(", ")))
                        .summary(format!("{} attributes", attrs.len()))
                };
                cx.push(node).await;
                attrs.clear();
                last = None;
                group = pos;
            }
        }
    }
    cx.annotate(format!(
        "PCL XL stream ({}), {ops} operators, {pages} pages",
        header.get(2..).unwrap_or_default()
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// HP-GL / HP-GL/2

fn hpgl_probe(h: &Head<'_>) -> bool {
    let d = probe::trim_start(h.data);
    let d = d
        .strip_prefix(b"\x1b%-1B")
        .or_else(|| d.strip_prefix(b"\x1b%0B"))
        .unwrap_or(d);
    (d.starts_with(b"IN;")
        || d.starts_with(b"BPIN;")
        || d.starts_with(b"BP;IN;")
        || d.starts_with(b"IN\n"))
        && d.iter()
            .take(64)
            .all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace() || b == 0x03)
}

declare_format!(pub HPGL = "hpgl", "HP-GL/2 plot", ["hpgl", "hgl", "plt", "hp2"], "application/vnd.hp-hpgl",
    Probe::Custom(hpgl_probe), hpgl);

const HPGL_NAMES: &[(&[u8; 2], &str)] = &[
    (b"IN", "Initialize"),
    (b"DF", "Default values"),
    (b"BP", "Begin plot"),
    (b"PG", "Advance page"),
    (b"SP", "Select pen"),
    (b"PU", "Pen up"),
    (b"PD", "Pen down"),
    (b"PA", "Plot absolute"),
    (b"PR", "Plot relative"),
    (b"PE", "Polyline encoded"),
    (b"LB", "Label"),
    (b"SI", "Character size"),
    (b"SR", "Relative character size"),
    (b"DI", "Absolute direction"),
    (b"DR", "Relative direction"),
    (b"CI", "Circle"),
    (b"AA", "Arc absolute"),
    (b"AR", "Arc relative"),
    (b"AT", "Three-point arc"),
    (b"EA", "Edge rectangle absolute"),
    (b"ER", "Edge rectangle relative"),
    (b"RA", "Fill rectangle absolute"),
    (b"RR", "Fill rectangle relative"),
    (b"WG", "Fill wedge"),
    (b"EW", "Edge wedge"),
    (b"EP", "Edge polygon"),
    (b"FP", "Fill polygon"),
    (b"PM", "Polygon mode"),
    (b"FT", "Fill type"),
    (b"LT", "Line type"),
    (b"PW", "Pen width"),
    (b"WU", "Pen width unit"),
    (b"SC", "Scale"),
    (b"IP", "Input P1 and P2"),
    (b"IR", "Input P1 and P2 relative"),
    (b"IW", "Input window"),
    (b"RO", "Rotate coordinate system"),
    (b"PS", "Plot size"),
    (b"NP", "Number of pens"),
    (b"PC", "Pen colour"),
    (b"TR", "Transparency mode"),
    (b"MC", "Merge control"),
    (b"CO", "Comment"),
    (b"SA", "Select alternate font"),
    (b"SS", "Select standard font"),
    (b"SD", "Standard font definition"),
    (b"AD", "Alternate font definition"),
    (b"LO", "Label origin"),
    (b"ES", "Extra space"),
    (b"DT", "Define label terminator"),
    (b"VS", "Velocity select"),
    (b"LA", "Line attributes"),
    (b"BR", "Bezier relative"),
    (b"BZ", "Bezier absolute"),
    (b"CT", "Chord tolerance"),
    (b"UL", "User-defined line type"),
];

async fn hpgl(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut scan = Scanner::new(&cx, file);
    let mut pos = 0u64;
    let mut terminator = 0x03u8;
    let (mut count, mut pens, mut pages) = (0u32, 0u32, 1u32);
    while pos < scan.len() {
        scan.tick().await;
        cx.progress_in(scan.region(), scan.region().offset.saturating_add(pos));
        let Some(b) = scan.byte(pos).await? else {
            break;
        };
        if b.is_ascii_whitespace() || b == b';' {
            pos = pos.saturating_add(1);
            continue;
        }
        if b == 0x1b {
            // An embedded PCL escape (e.g. ESC%-1B or ESC.( device control).
            let end = scan
                .find(pos.saturating_add(1), |c| {
                    c.is_ascii_uppercase() || c == b':'
                })
                .await?
                .map_or(scan.len(), |p| p.saturating_add(1));
            let raw = scan.bytes(pos, end, 32).await?;
            cx.push(
                Node::new("Escape sequence")
                    .span(scan.span(pos, end))
                    .value(text(printable(&raw))),
            )
            .await;
            pos = end;
            continue;
        }
        let m2 = scan.byte(pos.saturating_add(1)).await?.unwrap_or(0);
        if !b.is_ascii_alphabetic() || !m2.is_ascii_alphabetic() {
            let end = scan
                .find(pos.saturating_add(1), |c| {
                    c == b';' || c.is_ascii_alphabetic()
                })
                .await?
                .unwrap_or(scan.len());
            cx.push(
                Node::new("Unknown")
                    .span(scan.span(pos, end))
                    .diag(Diagnostic::malformed("not an HP-GL mnemonic")),
            )
            .await;
            pos = end;
            continue;
        }
        let mn = [b.to_ascii_uppercase(), m2.to_ascii_uppercase()];
        let args_at = pos.saturating_add(2);
        let end = match &mn {
            b"LB" => scan
                .find(args_at, |c| c == terminator)
                .await?
                .map_or(scan.len(), |p| p.saturating_add(1)),
            b"PE" | b"CO" => scan
                .find(args_at, |c| c == b';')
                .await?
                .map_or(scan.len(), |p| p.saturating_add(1)),
            _ => scan
                .find(args_at, |c| {
                    c == b';' || c.is_ascii_alphabetic() || c == 0x1b
                })
                .await?
                .unwrap_or(scan.len()),
        };
        let args = scan.bytes(args_at, end, CAP).await?;
        let args = String::from_utf8_lossy(&args)
            .trim_end_matches([';', '\x03'])
            .trim()
            .to_owned();
        if mn == *b"DT" {
            terminator = args.bytes().next().unwrap_or(0x03);
        }
        if mn == *b"SP" {
            pens = pens.max(args.parse().unwrap_or(0));
        }
        if mn == *b"PG" {
            pages = pages.saturating_add(1);
        }
        let name = HPGL_NAMES.iter().find(|(k, _)| **k == mn).map_or_else(
            || String::from_utf8_lossy(&mn).into_owned(),
            |(k, v)| format!("{} {v}", String::from_utf8_lossy(*k)),
        );
        let node = Node::new(name).span(scan.span(pos, end.max(args_at)));
        cx.push(if args.is_empty() {
            node
        } else {
            node.value(text(args))
        })
        .await;
        count = count.saturating_add(1);
        pos = end.max(args_at);
    }
    cx.annotate(format!(
        "HP-GL/2 plot, {count} instructions, up to pen {pens}, {pages} pages"
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Epson ESC/P

fn escp_probe(h: &Head<'_>) -> bool {
    let head = h.data.get(..512).unwrap_or(h.data);
    h.starts_with(b"\x1b@")
        && head.iter().filter(|&&b| b == 0x1b).count() >= 4
        && !h.at(2, b"\x1b@\x1b@")
}

declare_format!(pub ESCP = "escp", "Epson ESC/P printer data", ["prn", "escp"], "application/vnd.epson.escp",
    Probe::Custom(escp_probe), escp);

/// ESC/P commands: (code, name, fixed argument bytes).
const ESCP_COMMANDS: &[(u8, &str, u64)] = &[
    (b'@', "Initialize", 0),
    (b'E', "Bold on", 0),
    (b'F', "Bold off", 0),
    (b'4', "Italic on", 0),
    (b'5', "Italic off", 0),
    (b'0', "1/8-inch line spacing", 0),
    (b'2', "1/6-inch line spacing", 0),
    (b'M', "12 cpi", 0),
    (b'P', "10 cpi", 0),
    (b'g', "15 cpi", 0),
    (b'G', "Double-strike on", 0),
    (b'H', "Double-strike off", 0),
    (b'x', "Print quality", 1),
    (b'k', "Typeface", 1),
    (b't', "Character table", 1),
    (b'R', "International character set", 1),
    (b'r', "Colour", 1),
    (b'U', "Unidirectional", 1),
    (b'!', "Master select", 1),
    (b'-', "Underline", 1),
    (b'w', "Double height", 1),
    (b'W', "Double width", 1),
    (b'J', "Advance paper", 1),
    (b'A', "n/60-inch line spacing", 1),
    (b'3', "n/180-inch line spacing", 1),
    (b'+', "n/360-inch line spacing", 1),
    (b'l', "Left margin", 1),
    (b'Q', "Right margin", 1),
    (b'$', "Absolute horizontal position", 2),
    (b'\\', "Relative horizontal position", 2),
    (b'U', "Unidirectional", 1),
    (b'p', "Proportional", 1),
    (b'S', "Super/subscript", 1),
    (b'T', "Super/subscript off", 0),
    (b'N', "Bottom margin", 1),
    (b'O', "Cancel bottom margin", 0),
    (b'i', "Incremental mode", 1),
    (b'c', "Horizontal motion index", 2),
    (b'a', "Justification", 1),
    (b'q', "Character style", 1),
    (b'X', "Font size", 3),
    (b'8', "Paper-out detection off", 0),
    (b'9', "Paper-out detection on", 0),
    (b'<', "Unidirectional (one line)", 0),
    (b'f', "Skip", 2),
    (b'j', "Reverse feed", 1),
];

async fn escp(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut scan = Scanner::new(&cx, file);
    let mut pos = 0u64;
    let (mut commands, mut graphics) = (0u32, 0u32);
    while pos < scan.len() {
        scan.tick().await;
        cx.progress_in(scan.region(), scan.region().offset.saturating_add(pos));
        let Some(b) = scan.byte(pos).await? else {
            break;
        };
        if b != 0x1b {
            let end = scan.find(pos, |c| c == 0x1b).await?.unwrap_or(scan.len());
            let data = scan.bytes(pos, end, CAP).await?;
            cx.push(
                Node::new("Text")
                    .span(scan.span(pos, end))
                    .value(text(printable(&data))),
            )
            .await;
            pos = end;
            continue;
        }
        commands = commands.saturating_add(1);
        let c = scan.byte(pos.saturating_add(1)).await?.unwrap_or(0);
        let args = scan
            .bytes(pos.saturating_add(2), pos.saturating_add(10), 8)
            .await?;
        let arg = |i: usize| u64::from(args.get(i).copied().unwrap_or(0));
        let (name, end): (String, u64) = match c {
            b'(' => {
                let cmd = arg(0);
                let n = arg(1).saturating_add(arg(2).saturating_mul(256));
                (
                    format!(
                        "Extended command ESC ( {}",
                        char::from(u8::try_from(cmd).unwrap_or(b'?'))
                    ),
                    pos.saturating_add(5).saturating_add(n),
                )
            }
            b'*' => {
                let m = arg(0);
                let n = arg(1).saturating_add(arg(2).saturating_mul(256));
                let per = match m {
                    32..=40 => 3,
                    71..=73 => 6,
                    _ => 1,
                };
                graphics = graphics.saturating_add(1);
                (
                    format!("Bit image (mode {m}, {n} columns)"),
                    pos.saturating_add(5).saturating_add(n.saturating_mul(per)),
                )
            }
            b'K' | b'L' | b'Y' | b'Z' => {
                let n = arg(0).saturating_add(arg(1).saturating_mul(256));
                graphics = graphics.saturating_add(1);
                (
                    format!("Bit image ESC {} ({n} columns)", char::from(c)),
                    pos.saturating_add(4).saturating_add(n),
                )
            }
            b'.' => {
                // ESC . c v h m nL nH: raster graphics, m rows of n dots.
                let comp = arg(0);
                let rows = arg(3);
                let dots = arg(4).saturating_add(arg(5).saturating_mul(256));
                let bytes = rows.saturating_mul(dots.div_ceil(8));
                let data = pos.saturating_add(8);
                graphics = graphics.saturating_add(1);
                let end = if comp == 1 {
                    packbits_end(&mut scan, data, bytes).await?
                } else {
                    data.saturating_add(bytes)
                };
                (
                    format!(
                        "Raster graphics ({rows}×{dots}{})",
                        if comp == 1 { ", RLE" } else { "" }
                    ),
                    end,
                )
            }
            b'C' => {
                let n = arg(0);
                (
                    if n == 0 {
                        "Page length (inches)".to_owned()
                    } else {
                        "Page length (lines)".to_owned()
                    },
                    pos.saturating_add(if n == 0 { 4 } else { 3 }),
                )
            }
            b'D' | b'B' => {
                let end = scan
                    .find(pos.saturating_add(2), |b| b == 0)
                    .await?
                    .map_or(scan.len(), |p| p.saturating_add(1));
                (
                    if c == b'D' {
                        "Horizontal tabs"
                    } else {
                        "Vertical tabs"
                    }
                    .to_owned(),
                    end,
                )
            }
            _ => match ESCP_COMMANDS.iter().find(|(k, _, _)| *k == c) {
                Some((_, n, args)) => {
                    ((*n).to_owned(), pos.saturating_add(2).saturating_add(*args))
                }
                None => (format!("ESC {}", printable(&[c])), pos.saturating_add(2)),
            },
        };
        let end = end.min(scan.len()).max(pos.saturating_add(1));
        let raw = scan.bytes(pos, end.min(pos.saturating_add(8)), 8).await?;
        cx.push(
            Node::new(name)
                .span(scan.span(pos, end))
                .value(text(printable(&raw))),
        )
        .await;
        pos = end;
    }
    cx.annotate(format!(
        "Epson ESC/P print data, {commands} commands, {graphics} graphics blocks"
    ));
    Ok(())
}

/// The end of PackBits/TIFF run-length data that decodes to `bytes` bytes.
async fn packbits_end(scan: &mut Scanner<'_>, mut pos: u64, bytes: u64) -> Result<u64> {
    let mut out = 0u64;
    while out < bytes && pos < scan.len() {
        scan.tick().await;
        let n = scan.byte(pos).await?.unwrap_or(0);
        if n < 128 {
            let len = u64::from(n).saturating_add(1);
            out = out.saturating_add(len);
            pos = pos.saturating_add(1).saturating_add(len);
        } else {
            out = out.saturating_add(257u64.saturating_sub(n.into()));
            pos = pos.saturating_add(2);
        }
    }
    Ok(pos.min(scan.len()))
}

// ---------------------------------------------------------------------------
// Zebra ZPL

fn zpl_probe(h: &Head<'_>) -> bool {
    let d = probe::trim_start(h.data);
    (d.starts_with(b"^XA")
        || (d.starts_with(b"~") && probe::contains(d.get(..256).unwrap_or(d), b"^XA")))
        && probe::contains(d, b"^XZ")
        && probe::is_text(h)
}

declare_format!(pub ZPL = "zpl", "Zebra Programming Language label", ["zpl", "zpl2"], "application/x-zpl",
    Probe::Custom(zpl_probe), zpl);

const ZPL_NAMES: &[(&str, &str)] = &[
    ("XA", "Start format"),
    ("XZ", "End format"),
    ("FO", "Field origin"),
    ("FT", "Field typeset"),
    ("FD", "Field data"),
    ("FS", "Field separator"),
    ("FB", "Field block"),
    ("FR", "Field reverse"),
    ("FH", "Field hexadecimal indicator"),
    ("FN", "Field number"),
    ("FX", "Comment"),
    ("FV", "Field variable"),
    ("A0", "Scalable font"),
    ("CF", "Change default font"),
    ("CI", "Character set"),
    ("BY", "Bar code defaults"),
    ("BC", "Code 128"),
    ("B3", "Code 39"),
    ("BE", "EAN-13"),
    ("BU", "UPC-A"),
    ("BQ", "QR code"),
    ("BX", "Data Matrix"),
    ("B7", "PDF417"),
    ("BI", "Industrial 2 of 5"),
    ("GB", "Graphic box"),
    ("GC", "Graphic circle"),
    ("GD", "Graphic diagonal line"),
    ("GE", "Graphic ellipse"),
    ("GF", "Graphic field"),
    ("PW", "Print width"),
    ("LL", "Label length"),
    ("LH", "Label home"),
    ("LS", "Label shift"),
    ("LT", "Label top"),
    ("PQ", "Print quantity"),
    ("PR", "Print rate"),
    ("MD", "Media darkness"),
    ("MM", "Print mode"),
    ("MN", "Media tracking"),
    ("MT", "Media type"),
    ("PO", "Print orientation"),
    ("PM", "Mirror image"),
    ("SD", "Set darkness"),
    ("DG", "Download graphic"),
    ("XG", "Recall graphic"),
    ("IM", "Image move"),
    ("JA", "Cancel all"),
    ("JM", "Set dots per millimetre"),
    ("SN", "Serialization data"),
    ("DF", "Download format"),
    ("XF", "Recall format"),
    ("CW", "Font identifier"),
    ("TO", "Transfer object"),
    ("ID", "Object delete"),
];

async fn zpl(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut scan = Scanner::new(&cx, file);
    let mut pos = 0u64;
    let mut labels = 0u32;
    while pos < scan.len() {
        scan.tick().await;
        cx.progress_in(scan.region(), scan.region().offset.saturating_add(pos));
        let Some(start) = scan.find(pos, |b| b == b'^' || b == b'~').await? else {
            break;
        };
        if scan.matches_nocase(start, b"^XA").await? {
            let end = scan
                .find_seq_nocase(start, b"^XZ")
                .await?
                .map_or(scan.len(), |p| p.saturating_add(3));
            let span = scan.span(start, end);
            labels = labels.saturating_add(1);
            cx.push(
                Node::new(format!("Label {labels}"))
                    .span(span)
                    .lazy(zpl_commands, span),
            )
            .await;
            pos = end;
        } else {
            let end = zpl_command_end(&mut scan, start).await?;
            cx.push(zpl_node(&mut scan, start, end).await?).await;
            pos = end;
        }
    }
    cx.annotate(format!("Zebra ZPL, {labels} labels"));
    Ok(())
}

async fn zpl_command_end(scan: &mut Scanner<'_>, start: u64) -> Result<u64> {
    Ok(scan
        .find(start.saturating_add(1), |b| b == b'^' || b == b'~')
        .await?
        .unwrap_or(scan.len()))
}

async fn zpl_node(scan: &mut Scanner<'_>, start: u64, end: u64) -> Result<Node> {
    let raw = scan.bytes(start, end, CAP).await?;
    let s = String::from_utf8_lossy(&raw).trim_end().to_owned();
    let code: String = s
        .chars()
        .skip(1)
        .take(2)
        .collect::<String>()
        .to_ascii_uppercase();
    let args: String = s.chars().skip(3).collect();
    let name = ZPL_NAMES
        .iter()
        .find(|(k, _)| *k == code)
        .map(|(_, v)| *v)
        .map_or_else(
            || {
                if code.starts_with('A') {
                    format!("{} Font", s.get(..2).unwrap_or("^A"))
                } else {
                    s.chars().take(3).collect()
                }
            },
            |n| format!("{} {n}", s.chars().take(3).collect::<String>()),
        );
    let node = Node::new(name).span(scan.span(start, end));
    Ok(if args.trim().is_empty() {
        node
    } else {
        node.value(text(args.trim()))
    })
}

async fn zpl_commands(cx: Cx, span: Span) -> Result<()> {
    let mut scan = Scanner::new(&cx, span);
    let mut pos = scan
        .find(0, |b| b == b'^' || b == b'~')
        .await?
        .unwrap_or(scan.len());
    while pos < scan.len() {
        scan.tick().await;
        cx.progress_in(scan.region(), scan.region().offset.saturating_add(pos));
        let end = zpl_command_end(&mut scan, pos).await?;
        cx.push(zpl_node(&mut scan, pos, end).await?).await;
        pos = end;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// PPD and GPD: `*Keyword option/translation: value` lines

declare_format!(pub PPD = "ppd", "PostScript Printer Description", ["ppd"], "application/vnd.cups-ppd",
    Probe::Custom(|h| h.starts_with(b"*PPD-Adobe:")), ppd);

fn gpd_probe(h: &Head<'_>) -> bool {
    let head = h.data.get(..4096).unwrap_or(h.data);
    probe::trim_start(head).starts_with(b"*")
        && probe::contains(head, b"*GPDFileVersionNum:")
        && probe::is_text(h)
}

declare_format!(pub GPD = "gpd", "Windows Generic Printer Description", ["gpd"], "application/x-gpd",
    Probe::Custom(gpd_probe), gpd);

async fn ppd(cx: Cx, input: Input) -> Result<()> {
    let head = crate::formats::text::scan::head_lines(&cx, input.span, 16384).await?;
    let find = |k: &str| {
        head.iter().find_map(|(l, _)| {
            l.strip_prefix(k)
                .map(|v| v.trim().trim_matches('"').to_owned())
        })
    };
    let name = find("*NickName:")
        .or_else(|| find("*ModelName:"))
        .unwrap_or_default();
    let version = find("*PPD-Adobe:").unwrap_or_default();
    cx.annotate(format!("PostScript Printer Description {version}: {name}"));
    star_entries(cx, input.span).await
}

async fn gpd(cx: Cx, input: Input) -> Result<()> {
    let head = crate::formats::text::scan::head_lines(&cx, input.span, 16384).await?;
    let find = |k: &str| {
        head.iter().find_map(|(l, _)| {
            l.trim()
                .strip_prefix(k)
                .map(|v| v.trim().trim_matches('"').to_owned())
        })
    };
    let name = find("*ModelName:").unwrap_or_default();
    let version = find("*GPDFileVersionNum:").unwrap_or_default();
    cx.annotate(format!("Generic Printer Description {version}: {name}"));
    star_entries(cx, input.span).await
}

/// Whether a PPD line opens a block, and the keyword that closes it.
fn block_close(key: &str) -> Option<&'static str> {
    match key {
        "*OpenUI" => Some("*CloseUI"),
        "*JCLOpenUI" => Some("*JCLCloseUI"),
        "*OpenGroup" => Some("*CloseGroup"),
        "*OpenSubGroup" => Some("*CloseSubGroup"),
        _ => None,
    }
}

fn braces(s: &str) -> i64 {
    let mut quoted = false;
    let mut n = 0i64;
    for c in s.chars() {
        match c {
            '"' => quoted = !quoted,
            '{' if !quoted => n = n.saturating_add(1),
            '}' if !quoted => n = n.saturating_sub(1),
            _ => {}
        }
    }
    n
}

/// Lists keyword entries; UI groups and brace blocks become lazy nodes and
/// multi-line quoted values are kept together.
async fn star_entries(cx: Cx, region: Span) -> Result<()> {
    let mut lines = Lines::new(&cx, region);
    while let Some(line) = lines.next().await? {
        let t = line.text();
        let trimmed = t.trim();
        if trimmed.is_empty()
            || trimmed.starts_with("*%")
            || !trimmed.starts_with('*') && trimmed != "}" && !trimmed.contains(':')
        {
            continue;
        }
        let start = line.start;
        let (head, value) = trimmed
            .split_once(':')
            .map_or((trimmed, ""), |(k, v)| (k.trim(), v.trim()));
        let key = head.split([' ', '\t']).next().unwrap_or(head);
        let option = head.get(key.len()..).unwrap_or_default().trim();
        let name = if option.is_empty() {
            key.trim_start_matches('*').to_owned()
        } else {
            format!("{} {}", key.trim_start_matches('*'), option)
        };
        if let Some(close) = block_close(key) {
            let mut depth = 0u32;
            while let Some(l) = lines.next().await? {
                let lt = l.text();
                let k = lt.trim().split([':', ' ']).next().unwrap_or("").to_owned();
                if block_close(&k).is_some() {
                    depth = depth.saturating_add(1);
                } else if k == close && depth == 0 {
                    break;
                } else if k.starts_with("*Close") {
                    depth = depth.saturating_sub(1);
                }
            }
            let span = lines.since(start);
            cx.push(
                Node::new(name)
                    .span(span)
                    .value(text(value))
                    .lazy(crate::expander!(self::star_block: Span), span),
            )
            .await;
            continue;
        }
        let mut depth = braces(trimmed);
        let next_opens = depth == 0 && lines.peek().await?.is_some_and(|l| l.text().trim() == "{");
        if depth > 0 || next_opens {
            while let Some(l) = lines.next().await? {
                depth = depth.saturating_add(braces(&l.text()));
                if depth <= 0 {
                    break;
                }
            }
            let span = lines.since(start);
            cx.push(
                Node::new(name)
                    .span(span)
                    .value(text(value.trim_end_matches('{').trim()))
                    .lazy(crate::expander!(self::star_block: Span), span),
            )
            .await;
            continue;
        }
        // A quoted value may continue over several lines, ending in *End.
        if value.matches('"').count() % 2 == 1 {
            while let Some(l) = lines.next().await? {
                if l.text().contains('"') {
                    break;
                }
            }
            if lines
                .peek()
                .await?
                .is_some_and(|l| l.text().trim() == "*End")
            {
                lines.next().await?;
            }
            let span = lines.since(start);
            cx.push(Node::new(name).span(span).summary("multi-line value"))
                .await;
            continue;
        }
        cx.push(
            Node::new(name)
                .span(line.span)
                .value(text(value.trim_matches('"'))),
        )
        .await;
    }
    Ok(())
}

/// The inside of a block: everything but its first and last line.
async fn star_block(cx: Cx, span: Span) -> Result<()> {
    let mut lines = Lines::new(&cx, span);
    let Some(first) = lines.next().await? else {
        return Ok(());
    };
    let mut start = first.next;
    if lines.peek().await?.is_some_and(|l| l.text().trim() == "{") {
        start = lines.next().await?.map_or(start, |l| l.next);
    }
    // Drop the closing line.
    let mut end = start;
    while let Some(l) = lines.next().await? {
        if l.next < span.len || !l.is_blank() {
            end = l.start;
        }
    }
    if end > start {
        star_entries(cx, span.sub(start, end.saturating_sub(start))).await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// CUPS / PWG raster

fn cups_probe(h: &Head<'_>) -> bool {
    matches!(
        h.data.get(..4),
        Some(b"RaSt" | b"tSaR" | b"RaS2" | b"2SaR" | b"RaS3" | b"3SaR")
    )
}

declare_format!(pub CUPS_RASTER = "cups-raster", "CUPS/PWG raster", ["ras", "pwg", "cups"], "application/vnd.cups-raster",
    Probe::Custom(cups_probe), cups_raster);

record! {
    pub struct CupsHeader {
        media_class: ascii[64] "MediaClass",
        media_color: ascii[64] "MediaColor",
        media_type: ascii[64] "MediaType",
        output_type: ascii[64] "OutputType",
        advance_distance: u32 "AdvanceDistance",
        advance_media: u32 "AdvanceMedia",
        collate: u32 "Collate",
        cut_media: u32 "CutMedia",
        duplex: u32 "Duplex",
        hw_res_x: u32 "HWResolution[0]",
        hw_res_y: u32 "HWResolution[1]",
        bbox_left: u32 "ImagingBoundingBox[0]",
        bbox_bottom: u32 "ImagingBoundingBox[1]",
        bbox_right: u32 "ImagingBoundingBox[2]",
        bbox_top: u32 "ImagingBoundingBox[3]",
        insert_sheet: u32 "InsertSheet",
        jog: u32 "Jog",
        leading_edge: u32 "LeadingEdge",
        margin_left: u32 "Margins[0]",
        margin_bottom: u32 "Margins[1]",
        manual_feed: u32 "ManualFeed",
        media_position: u32 "MediaPosition",
        media_weight: u32 "MediaWeight",
        mirror_print: u32 "MirrorPrint",
        negative_print: u32 "NegativePrint",
        num_copies: u32 "NumCopies",
        orientation: u32 "Orientation",
        output_face_up: u32 "OutputFaceUp",
        page_width: u32 "PageSize[0]" .desc("Points"),
        page_height: u32 "PageSize[1]" .desc("Points"),
        separations: u32 "Separations",
        tray_switch: u32 "TraySwitch",
        tumble: u32 "Tumble",
        width: u32 "cupsWidth",
        height: u32 "cupsHeight",
        media_type_num: u32 "cupsMediaType",
        bits_per_color: u32 "cupsBitsPerColor",
        bits_per_pixel: u32 "cupsBitsPerPixel",
        bytes_per_line: u32 "cupsBytesPerLine",
        color_order: u32 "cupsColorOrder" .enumeration(&[(0, "chunky"), (1, "banded"), (2, "planar")]),
        color_space: u32 "cupsColorSpace" .enumeration(CUPS_SPACES),
        compression: u32 "cupsCompression",
        row_count: u32 "cupsRowCount",
        row_feed: u32 "cupsRowFeed",
        row_step: u32 "cupsRowStep",
    }
}

const CUPS_SPACES: &[(u64, &str)] = &[
    (0, "gray"),
    (1, "RGB"),
    (2, "RGBA"),
    (3, "black"),
    (4, "CMY"),
    (5, "YMC"),
    (6, "CMYK"),
    (7, "YMCK"),
    (8, "KCMY"),
    (9, "KCMYcm"),
    (10, "GMCK"),
    (11, "GMCS"),
    (12, "white"),
    (13, "gold"),
    (14, "silver"),
    (15, "CIE XYZ"),
    (16, "CIE Lab"),
    (17, "RGBW"),
    (18, "sGray"),
    (19, "sRGB"),
    (20, "Adobe RGB"),
];

const CUPS_V2_EXTRA: u64 = 1376;

async fn cups_raster(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let sync = cx.read(file.sub(0, 4)).await?;
    let endian = if sync.first() == Some(&b'R') {
        Endian::Big
    } else {
        Endian::Little
    };
    let version = match sync.get(..4) {
        Some(b"RaSt" | b"tSaR") => 1,
        Some(b"RaS2" | b"2SaR") => 2,
        _ => 3,
    };
    cx.emit(
        Node::new("Sync word")
            .span(file.sub(0, 4))
            .value(text(String::from_utf8_lossy(&sync)))
            .summary(format!(
                "version {version}, {}",
                if endian == Endian::Big {
                    "big-endian"
                } else {
                    "little-endian"
                }
            )),
    );
    let header_len = CupsHeader::SIZE.saturating_add(if version == 1 { 0 } else { CUPS_V2_EXTRA });
    let mut cur = Cursor::new(&cx, file, endian);
    cur.seek(4);
    let mut pages = 0u32;
    let mut first = None;
    while !cur.at_end() {
        let start = cur.pos();
        let (h, _) = cur.record::<CupsHeader>().await?;
        cur.skip(header_len.saturating_sub(CupsHeader::SIZE));
        let data_len = u64::from(h.bytes_per_line).saturating_mul(h.height.into());
        let data_at = cur.pos();
        let end = if version == 2 {
            let bpp = u64::from(h.bits_per_pixel.max(8).div_ceil(8));
            run_length_end(
                &cx,
                file,
                data_at,
                h.bytes_per_line.into(),
                bpp,
                h.height.into(),
            )
            .await?
        } else {
            data_at.saturating_add(data_len)
        };
        if end > file.len {
            return Err(Diagnostic::truncated(
                file.sub(data_at, end.saturating_sub(data_at)),
                file.len.saturating_sub(data_at),
            ));
        }
        cur.seek(end);
        pages = pages.saturating_add(1);
        let summary = format!(
            "{}×{}, {} dpi, {}-bit {}",
            h.width,
            h.height,
            h.hw_res_x,
            h.bits_per_pixel,
            CUPS_SPACES
                .iter()
                .find(|(k, _)| *k == u64::from(h.color_space))
                .map_or("?", |(_, v)| v)
        );
        if first.is_none() {
            first = Some((summary.clone(), h.media_class.clone()));
        }
        let header = file.sub(start, header_len);
        cx.push(
            Node::new(format!("Page {pages}"))
                .span(cur.since(start))
                .summary(summary)
                .lazy(
                    cups_page,
                    (
                        header,
                        endian,
                        file.sub(data_at, end.saturating_sub(data_at)),
                        version,
                    ),
                ),
        )
        .await;
    }
    let (summary, class) = first.unwrap_or_default();
    let kind = if class.starts_with("PwgRaster") {
        "PWG raster"
    } else {
        "CUPS raster"
    };
    cx.annotate(format!("{kind} v{version}, {pages} pages, {summary}"));
    Ok(())
}

async fn cups_page(
    cx: Cx,
    (header, endian, data, version): (Span, Endian, Span, u8),
) -> Result<()> {
    cx.emit(CupsHeader::node(
        "Page header",
        header.sub(0, CupsHeader::SIZE),
        endian,
    ));
    if version >= 2 {
        cx.emit(Node::new("Version 2 fields").span(header.tail(CupsHeader::SIZE)).summary("colour count, scaling, cupsInteger/cupsReal/cupsString, marker type, rendering intent, page size name"));
    }
    cx.emit(
        Node::new("Raster data")
            .span(data)
            .summary(if version == 2 {
                "run-length encoded"
            } else {
                "uncompressed"
            }),
    );
    Ok(())
}

/// The end of CUPS v2 / URF run-length data: per line a repeat count, then
/// runs (`n < 128`: one pixel repeated `n + 1` times; `n > 128`: `257 - n`
/// literal pixels; 128: rest of the line blank).
async fn run_length_end(
    cx: &Cx,
    region: Span,
    at: u64,
    line_bytes: u64,
    pixel: u64,
    lines: u64,
) -> Result<u64> {
    let mut scan = Scanner::new(cx, region);
    let mut pos = at;
    let mut done = 0u64;
    let pixels_per_line = line_bytes.checked_div(pixel.max(1)).unwrap_or(0);
    while done < lines && pos < scan.len() {
        scan.tick().await;
        let repeat = u64::from(scan.byte(pos).await?.unwrap_or(0)).saturating_add(1);
        pos = pos.saturating_add(1);
        let mut filled = 0u64;
        while filled < pixels_per_line && pos < scan.len() {
            scan.tick().await;
            let n = scan.byte(pos).await?.unwrap_or(0);
            pos = pos.saturating_add(1);
            match n {
                0..=127 => {
                    filled = filled.saturating_add(u64::from(n).saturating_add(1));
                    pos = pos.saturating_add(pixel);
                }
                128 => filled = pixels_per_line,
                _ => {
                    let count = 257u64.saturating_sub(n.into());
                    filled = filled.saturating_add(count);
                    pos = pos.saturating_add(count.saturating_mul(pixel));
                }
            }
        }
        done = done.saturating_add(repeat);
    }
    Ok(pos)
}

// ---------------------------------------------------------------------------
// Apple raster (URF)

declare_format!(pub URF = "urf", "Apple raster (URF)", ["urf"], "image/urf",
    Probe::Custom(|h| h.starts_with(b"UNIRAST\0") && u32_be(h.data, 8).is_some_and(|n| n > 0 && n < 100_000)), urf);

const URF_SPACES: &[(u8, &str)] = &[
    (0, "sGray"),
    (1, "sRGB"),
    (2, "CIELab"),
    (3, "Adobe RGB"),
    (4, "Gray"),
    (5, "RGB"),
    (6, "CMYK"),
];

async fn urf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let count = u32_be(&cx.read(file.sub(8, 4)).await?, 0).unwrap_or(0);
    cx.emit(Node::new("Signature").span(file.sub(0, 8)));
    cx.emit(
        Node::new("Pages")
            .span(file.sub(8, 4))
            .value(uint(count, 32)),
    );
    let mut pos = 12u64;
    let mut first = String::new();
    for i in 0..count {
        if pos >= file.len {
            break;
        }
        let h = cx.read(file.sub_exact(pos, 32)?).await?;
        let bpp = h.first().copied().unwrap_or(0);
        let space = h.get(1).copied().unwrap_or(0);
        let width = u32_be(&h, 12).unwrap_or(0);
        let height = u32_be(&h, 16).unwrap_or(0);
        let dpi = u32_be(&h, 20).unwrap_or(0);
        let pixel = u64::from(bpp.max(8).div_ceil(8));
        let end = run_length_end(
            &cx,
            file,
            pos.saturating_add(32),
            u64::from(width).saturating_mul(pixel),
            pixel,
            height.into(),
        )
        .await?;
        let space_name = URF_SPACES
            .iter()
            .find(|(k, _)| *k == space)
            .map_or("?", |(_, v)| v);
        let summary = format!("{width}×{height}, {dpi} dpi, {bpp}-bit {space_name}");
        if first.is_empty() {
            first = summary.clone();
        }
        let header = file.sub(pos, 32);
        let data = file.sub(
            pos.saturating_add(32),
            end.saturating_sub(pos).saturating_sub(32),
        );
        cx.push(
            Node::new(format!("Page {}", i.saturating_add(1)))
                .span(file.sub(pos, end.saturating_sub(pos)))
                .summary(summary)
                .lazy(urf_page, (header, data)),
        )
        .await;
        pos = end;
    }
    cx.annotate(format!("Apple raster, {count} pages, {first}"));
    Ok(())
}

async fn urf_page(cx: Cx, (header, data): (Span, Span)) -> Result<()> {
    let h = cx.read(header).await?;
    let byte = |i: usize| u64::from(h.get(i).copied().unwrap_or(0));
    let word = |i: usize| u64::from(u32_be(&h, i).unwrap_or(0));
    let space = h.get(1).copied().unwrap_or(0);
    cx.emit(
        Node::new("Bits per pixel")
            .span(header.sub(0, 1))
            .value(uint(byte(0), 8)),
    );
    cx.emit(
        Node::new("Colour space")
            .span(header.sub(1, 1))
            .value(Value::Enum {
                raw: space.into(),
                bits: 8,
                name: URF_SPACES
                    .iter()
                    .find(|(k, _)| *k == space)
                    .map(|(_, v)| *v),
            }),
    );
    cx.emit(
        Node::new("Duplex")
            .span(header.sub(2, 1))
            .value(uint(byte(2), 8)),
    );
    cx.emit(
        Node::new("Quality")
            .span(header.sub(3, 1))
            .value(uint(byte(3), 8)),
    );
    cx.emit(
        Node::new("Width")
            .span(header.sub(12, 4))
            .value(uint(word(12), 32)),
    );
    cx.emit(
        Node::new("Height")
            .span(header.sub(16, 4))
            .value(uint(word(16), 32)),
    );
    cx.emit(
        Node::new("Resolution")
            .span(header.sub(20, 4))
            .value(uint(word(20), 32))
            .summary("dpi"),
    );
    cx.emit(
        Node::new("Raster data")
            .span(data)
            .summary("run-length encoded lines"),
    );
    Ok(())
}
