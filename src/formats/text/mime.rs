//! Internet messages: e-mail (`.eml`, RFC 5322 + MIME), mbox mailboxes and
//! MHTML web archives.
//!
//! An entity is a header block and a body. Headers are unfolded and their
//! encoded words (RFC 2047) decoded. Multipart bodies are split at their
//! boundary into parts, recursively; leaf bodies are decoded from base64 or
//! quoted-printable into a derived source and dissected (an attached PDF,
//! an HTML part, a nested message ...).

use crate::cx::Cx;
use crate::error::{DiagKind, Diagnostic, Result};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::Value;

use super::decode::{self, Transform, decoded_text_node, preview};
use super::encoding::{decode_8bit, prepare};
use super::scan::Lines;
use super::{parse_datetime, plural, probe, text_node};

pub static EML: Format = Format {
    name: "eml",
    title: "E-mail message",
    extensions: &["eml", "msg822", "mime", "emlx"],
    mime: "message/rfc822",
    probe: Probe::Custom(|h| probe_message(h) && !probe_mhtml(h)),
    dissect: crate::expander!(dissect_eml: Input),
};

pub static MHTML: Format = Format {
    name: "mhtml",
    title: "MHTML web archive",
    extensions: &["mht", "mhtml"],
    mime: "multipart/related",
    probe: Probe::Custom(|h| probe_message(h) && probe_mhtml(h)),
    dissect: crate::expander!(dissect_mhtml: Input),
};

pub static MBOX: Format = Format {
    name: "mbox",
    title: "Mailbox (mbox)",
    extensions: &["mbox", "mbx", "mbs"],
    mime: "application/mbox",
    probe: Probe::Custom(probe_mbox),
    dissect: crate::expander!(dissect_mbox: Input),
};

/// Header names that identify a message.
const KNOWN: &[&[u8]] = &[
    b"received",
    b"return-path",
    b"from",
    b"to",
    b"cc",
    b"subject",
    b"date",
    b"message-id",
    b"mime-version",
    b"delivered-to",
    b"content-type",
    b"reply-to",
    b"dkim-signature",
    b"x-mailer",
    b"user-agent",
    b"in-reply-to",
    b"references",
    b"sender",
    b"content-transfer-encoding",
    b"snapshot-content-location",
    b"authentication-results",
];

/// The name of a header field line, if it is one.
fn field_name(line: &[u8]) -> Option<&[u8]> {
    let colon = line.iter().position(|&b| b == b':')?;
    let name = line.get(..colon)?;
    (!name.is_empty() && name.len() < 80 && name.iter().all(|&b| b > 0x20 && b < 0x7f))
        .then_some(name)
}

/// Whether the head starts with a header block of a message.
fn probe_message(h: &Head<'_>) -> bool {
    let head = probe::head(h);
    let mut known = 0usize;
    for (i, line) in probe::lines(&head).take(60).enumerate() {
        if line.is_empty() {
            break;
        }
        if line.first().is_some_and(|b| *b == b' ' || *b == b'\t') && i > 0 {
            continue;
        }
        let Some(name) = field_name(line) else {
            return false;
        };
        if KNOWN.iter().any(|k| name.eq_ignore_ascii_case(k)) {
            known = known.saturating_add(1);
        }
    }
    known >= 2
}

fn probe_mhtml(h: &Head<'_>) -> bool {
    let head = probe::head(h);
    let end = probe::find(&head, b"\n\n")
        .or_else(|| probe::find(&head, b"\r\n\r\n"))
        .unwrap_or(head.len());
    let headers = head.get(..end).unwrap_or_default().to_ascii_lowercase();
    probe::contains(&headers, b"multipart/related") && !probe::contains(&headers, b"\nreceived:")
}

fn probe_mbox(h: &Head<'_>) -> bool {
    let head = probe::head(h);
    let mut lines = probe::lines(&head);
    let (Some(first), Some(second)) = (lines.next(), lines.next()) else {
        return false;
    };
    first.starts_with(b"From ")
        && first
            .split(|&b| b == b' ')
            .filter(|w| !w.is_empty())
            .count()
            >= 3
        && field_name(second).is_some()
}

// ---------------------------------------------------------------------------
// Headers

/// RFC 2047 encoded words (`=?charset?B|Q?text?=`) decoded.
pub fn decode_words(text: &str) -> String {
    if !text.contains("=?") {
        return text.to_owned();
    }
    // Adjacent encoded words in the same charset are joined as bytes before
    // decoding: encoders split multi-byte characters across words.
    let mut out = String::with_capacity(text.len());
    let mut pending: Option<(String, Vec<u8>)> = None;
    let flush = |out: &mut String, pending: &mut Option<(String, Vec<u8>)>| {
        if let Some((charset, bytes)) = pending.take() {
            out.push_str(&decode_charset(&charset, &bytes));
        }
    };
    let mut rest = text;
    while let Some(i) = rest.find("=?") {
        let before = rest.get(..i).unwrap_or_default();
        let word = rest.get(i.saturating_add(2)..).unwrap_or_default();
        match encoded_word(word) {
            Some((charset, bytes, used)) => {
                // Whitespace between adjacent encoded words disappears.
                let adjacent = pending.is_some() && before.trim().is_empty();
                let same = pending
                    .as_ref()
                    .is_some_and(|(c, _)| c.eq_ignore_ascii_case(charset));
                if adjacent && same {
                    if let Some((_, b)) = pending.as_mut() {
                        b.extend_from_slice(&bytes);
                    }
                } else {
                    flush(&mut out, &mut pending);
                    if !adjacent {
                        out.push_str(before);
                    }
                    pending = Some((charset.to_owned(), bytes));
                }
                rest = word.get(used..).unwrap_or_default();
            }
            None => {
                flush(&mut out, &mut pending);
                out.push_str(before);
                out.push_str("=?");
                rest = word;
            }
        }
    }
    flush(&mut out, &mut pending);
    out.push_str(rest);
    out
}

/// One encoded word after its `=?`: the charset (without an RFC 2231
/// `*language` suffix), the decoded bytes, and the length used up to and
/// including the closing `?=`.
fn encoded_word(word: &str) -> Option<(&str, Vec<u8>, usize)> {
    let (charset, r) = word.split_once('?')?;
    let (enc, r) = r.split_once('?')?;
    let end = r.find("?=")?;
    let payload = r.get(..end)?;
    if charset.is_empty() || charset.contains(char::is_whitespace) {
        return None;
    }
    let bytes = match enc {
        "B" | "b" => decode::base64(payload.as_bytes()).bytes,
        "Q" | "q" => decode::quoted_printable(payload.replace('_', " ").as_bytes()).bytes,
        _ => return None,
    };
    let used = charset
        .len()
        .saturating_add(enc.len())
        .saturating_add(end)
        .saturating_add(4);
    let charset = charset.split('*').next().unwrap_or_default();
    Some((charset, bytes, used))
}

/// Bytes in the charset `label` names; unknown and unsupported charsets
/// are read as UTF-8 if valid, else Windows-1252.
fn decode_charset(label: &str, bytes: &[u8]) -> String {
    crate::codec::charset::decode_label(label, bytes).unwrap_or_else(|| decode_8bit(bytes))
}

/// One header field.
#[derive(Clone, Debug)]
struct Field {
    name: String,
    /// Unfolded and decoded.
    value: String,
    span: Span,
}

/// The most header fields read from one header block.
const MAX_FIELDS: usize = 2000;

/// Reads the header block at the start of `span`. Returns the fields and
/// where the body starts (relative), if a blank line ends the headers.
async fn headers(cx: &Cx, span: Span) -> Result<(Vec<Field>, Option<u64>)> {
    let mut lines = Lines::new(cx, span);
    let mut fields: Vec<Field> = Vec::new();
    loop {
        let Some(line) = lines.next().await? else {
            return Ok((fields, None));
        };
        if line.bytes.is_empty() {
            return Ok((fields, Some(line.next)));
        }
        let p = line.piece();
        let folded = matches!(p.first(), Some(b' ' | b'\t'));
        if folded && let Some(last) = fields.last_mut() {
            let more = p.trim().text();
            if last.value.len() < super::VALUE_CAP.saturating_mul(4) {
                if !last.value.is_empty() {
                    last.value.push(' ');
                }
                last.value.push_str(&more);
            }
            last.span = Span::new(
                last.span.source,
                last.span.offset,
                line.span.end().saturating_sub(last.span.offset),
            );
            continue;
        }
        let Some((name, value)) = p
            .split_once(b':')
            .filter(|(n, _)| field_name(p.bytes()).is_some() && !n.is_empty())
        else {
            // Not a header: the body starts here (no blank line).
            return Ok((fields, Some(line.start)));
        };
        if fields.len() >= MAX_FIELDS {
            continue;
        }
        let value = value.trim();
        fields.push(Field {
            name: name.text(),
            value: value.text(),
            span: line.span,
        });
    }
}

fn get<'a>(fields: &'a [Field], name: &str) -> Option<&'a Field> {
    fields.iter().find(|f| f.name.eq_ignore_ascii_case(name))
}

/// `type/subtype` and parameters of a `Content-Type` (or similar) value.
struct Params {
    value: String,
    params: Vec<(String, String)>,
}

impl Params {
    fn parse(text: &str) -> Params {
        let mut parts = split_params(text).into_iter();
        let value = parts.next().unwrap_or_default().trim().to_ascii_lowercase();
        // RFC 2231: `name*=charset'lang'percent-encoded`, and values split
        // into sections `name*0`, `name*1*`, ... (sections ending in `*`
        // are percent-encoded; the first one names the charset).
        struct Piece {
            name: String,
            section: Option<u32>,
            extended: bool,
            value: String,
        }
        let pieces: Vec<Piece> = parts
            .filter_map(|p| {
                let (k, v) = p.split_once('=')?;
                let k = k.trim().to_ascii_lowercase();
                let v = v.trim();
                let v = v
                    .strip_prefix('"')
                    .and_then(|v| v.strip_suffix('"'))
                    .unwrap_or(v);
                let (k, extended) = match k.strip_suffix('*') {
                    Some(k) => (k.to_owned(), true),
                    None => (k, false),
                };
                let (name, section) = match k.rsplit_once('*') {
                    Some((n, s)) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => {
                        (n.to_owned(), s.parse().ok())
                    }
                    _ => (k, None),
                };
                Some(Piece {
                    name,
                    section,
                    extended,
                    value: v.to_owned(),
                })
            })
            .take(MAX_PARAMS)
            .collect();
        let mut params: Vec<(String, String)> = Vec::new();
        let mut done: Vec<&str> = Vec::new();
        for p in &pieces {
            if done.contains(&p.name.as_str()) {
                continue;
            }
            let mut same: Vec<&Piece> = pieces.iter().filter(|q| q.name == p.name).collect();
            let rfc2231 = same.iter().any(|q| q.extended || q.section.is_some());
            let decoded = if rfc2231 {
                // The RFC 2231 form wins over a plain one (RFC 6266).
                same.retain(|q| q.extended || q.section.is_some());
                same.sort_by_key(|q| q.section.unwrap_or(0));
                // Sections are joined before percent-decoding (plain ones
                // with `%` escaped), which also tolerates encoders that
                // split an escape between sections.
                let mut charset: Option<String> = None;
                let mut joined = String::new();
                for (i, q) in same.iter().enumerate() {
                    if q.extended {
                        let mut raw = q.value.as_str();
                        if i == 0 {
                            let mut it = raw.splitn(3, '\'');
                            if let (Some(c), Some(_), Some(r)) = (it.next(), it.next(), it.next()) {
                                charset = Some(c.to_owned());
                                raw = r;
                            }
                        }
                        joined.push_str(raw);
                    } else {
                        joined.push_str(&q.value.replace('%', "%25"));
                    }
                }
                let bytes = crate::text::url::percent_decode_bytes(joined.as_bytes());
                match charset.filter(|c| !c.is_empty()) {
                    Some(c) => decode_charset(&c, &bytes),
                    None => decode_8bit(&bytes),
                }
            } else {
                decode_words(&p.value)
            };
            done.push(&p.name);
            params.push((p.name.clone(), decoded));
        }
        Params { value, params }
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// Splits at `;` outside quotes.
fn split_params(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in text.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                cur.push(c);
            }
            ';' if !quoted => out.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out
}

/// The most parameters read from one header value.
const MAX_PARAMS: usize = 256;

/// Parses an RFC 5322 date (`Mon, 5 Oct 2026 10:00:00 +0200`).
fn mail_date(text: &str) -> Option<i64> {
    const MONTHS: [&str; 12] = [
        "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
    ];
    let text = text.split_once(',').map_or(text, |(_, rest)| rest);
    let mut words = text.split_whitespace();
    let day: u32 = words.next()?.parse().ok()?;
    let month = words.next()?.to_ascii_lowercase();
    let month = MONTHS
        .iter()
        .position(|m| month.starts_with(m))?
        .saturating_add(1);
    let mut year: u32 = words.next()?.parse().ok()?;
    if year < 100 {
        year = year.saturating_add(if year < 50 { 2000 } else { 1900 });
    }
    let time = words.next().unwrap_or("00:00:00");
    let zone = words.next().unwrap_or("+0000");
    let zone = match zone {
        "GMT" | "UT" | "UTC" | "Z" => "+0000",
        z if z.starts_with(['+', '-']) => z,
        _ => "+0000",
    };
    parse_datetime(&format!("{year:04}-{month:02}-{day:02}T{time}{zone}"))
}

// ---------------------------------------------------------------------------
// Entities

#[derive(Clone, Debug)]
struct Entity {
    input: Input,
    span: Span,
    depth: u32,
}

const MAX_DEPTH: u32 = 32;

/// Pushes the nodes of an entity: its headers, then its body.
async fn entity(cx: Cx, e: Entity) -> Result<()> {
    if e.depth > MAX_DEPTH {
        return Err(Diagnostic::limit("MIME parts nested too deeply").at(e.span));
    }
    let (fields, body_start) = headers(&cx, e.span).await?;
    let header_end = body_start.unwrap_or(e.span.len);
    let header_span = e.span.sub(0, header_end);
    cx.push(
        Node::new("Headers")
            .span(header_span)
            .summary(plural(
                crate::bytes::to_u64(fields.len()),
                "field",
                "fields",
            ))
            .lazy(header_nodes, header_span),
    )
    .await;
    let Some(body_start) = body_start else {
        return Ok(());
    };
    let body = e.span.tail(body_start);
    let ctype = get(&fields, "Content-Type")
        .map(|f| Params::parse(&f.value))
        .unwrap_or(Params {
            value: "text/plain".to_owned(),
            params: Vec::new(),
        });
    if ctype.value.starts_with("multipart/") {
        match ctype.get("boundary") {
            Some(b) => return parts(&cx, &e, body, b.as_bytes()).await,
            None => cx.diag(Diagnostic::malformed("multipart without a boundary")),
        }
    }
    cx.push(body_node(&fields, &ctype, e.input, body, e.depth))
        .await;
    Ok(())
}

/// The node for a leaf body (or an embedded message).
fn body_node(fields: &[Field], ctype: &Params, input: Input, body: Span, depth: u32) -> Node {
    let encoding = get(fields, "Content-Transfer-Encoding")
        .map(|f| f.value.trim().to_ascii_lowercase())
        .unwrap_or_default();
    let transform = match encoding.as_str() {
        "base64" => Transform::Base64,
        "quoted-printable" => Transform::QuotedPrintable,
        _ => Transform::Identity,
    };
    let disposition = get(fields, "Content-Disposition").map(|f| Params::parse(&f.value));
    let filename = disposition
        .as_ref()
        .and_then(|d| d.get("filename").map(str::to_owned))
        .or_else(|| ctype.get("name").map(str::to_owned));
    let name = filename.clone().unwrap_or_else(|| "Body".to_owned());
    let mut summary = ctype.value.clone();
    if transform != Transform::Identity {
        summary = format!("{summary}, {encoding}");
    }
    summary = format!("{summary}, {:#x} bytes", body.len);
    if ctype.value == "message/rfc822" && transform == Transform::Identity {
        return Node::new(name).span(body).summary(summary).lazy(
            crate::expander!(self::entity: Entity),
            Entity {
                input,
                span: body,
                depth: depth.saturating_add(1),
            },
        );
    }
    let charset = ctype.get("charset").and_then(crate::codec::charset::lookup);
    decoded_text_node(name, input, body, transform, charset).summary(summary)
}

/// Splits a multipart body at `--boundary` lines.
async fn parts(cx: &Cx, e: &Entity, body: Span, boundary: &[u8]) -> Result<()> {
    let mut delim = b"--".to_vec();
    delim.extend_from_slice(boundary);
    let mut lines = Lines::new(cx, body);
    // Start of the current part (after its delimiter line), and where the
    // content before the current line ends (excluding its line break).
    let mut part: Option<u64> = None;
    let mut preamble_end = None;
    let mut prev_end = 0u64;
    let mut index = 0u64;
    let mut closed = false;
    while let Some(line) = lines.next().await? {
        let is_delim = line.bytes.starts_with(&delim);
        if !is_delim {
            prev_end = line.start.saturating_add(line.span.len);
            continue;
        }
        let rest = line.bytes.get(delim.len()..).unwrap_or_default();
        let last = rest.starts_with(b"--");
        if !last && !probe::trim(rest).is_empty() {
            prev_end = line.start.saturating_add(line.span.len);
            continue;
        }
        // The line break before a delimiter belongs to the delimiter.
        let content_end = if line.start == 0 { 0 } else { prev_end };
        match part.take() {
            Some(start) => {
                index = index.saturating_add(1);
                push_part(
                    cx,
                    e,
                    body.sub(start, content_end.saturating_sub(start)),
                    index,
                )
                .await?;
            }
            None => {
                if content_end > 0 && preamble_end.is_none() {
                    cx.push(Node::new("Preamble").span(body.sub(0, content_end)))
                        .await;
                }
                preamble_end = Some(content_end);
            }
        }
        if last {
            closed = true;
            let epilogue = body.tail(line.next);
            if !epilogue.is_empty() {
                cx.push(Node::new("Epilogue").span(epilogue)).await;
            }
            break;
        }
        part = Some(line.next);
        prev_end = line.start.saturating_add(line.span.len);
    }
    if let Some(start) = part {
        index = index.saturating_add(1);
        push_part(cx, e, body.tail(start), index).await?;
    }
    if !closed {
        cx.diag(Diagnostic::new(
            DiagKind::Truncated,
            "closing boundary missing",
        ));
    }
    if index == 0 {
        cx.diag(Diagnostic::malformed("no parts found for the boundary"));
    }
    Ok(())
}

async fn push_part(cx: &Cx, e: &Entity, span: Span, index: u64) -> Result<()> {
    let (fields, _) = headers(cx, span).await?;
    let ctype = get(&fields, "Content-Type")
        .map(|f| Params::parse(&f.value).value)
        .unwrap_or_else(|| "text/plain".to_owned());
    let filename = get(&fields, "Content-Disposition")
        .and_then(|f| Params::parse(&f.value).get("filename").map(str::to_owned))
        .or_else(|| {
            get(&fields, "Content-Type")
                .and_then(|f| Params::parse(&f.value).get("name").map(str::to_owned))
        });
    let name = match &filename {
        Some(f) => format!("Part {index}: {f}"),
        None => format!("Part {index}"),
    };
    cx.push(
        Node::new(name)
            .span(span)
            .summary(format!("{ctype}, {:#x} bytes", span.len))
            .lazy(
                crate::expander!(self::entity: Entity),
                Entity {
                    input: e.input,
                    span,
                    depth: e.depth.saturating_add(1),
                },
            ),
    )
    .await;
    Ok(())
}

async fn header_nodes(cx: Cx, span: Span) -> Result<()> {
    let (fields, _) = headers(&cx, span).await?;
    for f in fields {
        let decoded = decode_words(&f.value);
        let mut node = text_node(f.name.clone(), f.span, &decoded);
        if let Some(unicode) = crate::text::url::hosts_to_unicode(&decoded) {
            node = node.summary(unicode);
        }
        if f.name.eq_ignore_ascii_case("Date")
            && let Some(t) = mail_date(&f.value)
        {
            node = Node::new(f.name)
                .span(f.span)
                .value(Value::Timestamp { unix_seconds: t })
                .summary(f.value);
        }
        cx.push(node).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Entry points

/// A one-line description of a message from its headers.
fn describe(fields: &[Field]) -> String {
    let subject = get(fields, "Subject").map(|f| preview(&decode_words(&f.value), 80));
    let from = get(fields, "From").map(|f| preview(&decode_words(&f.value), 60));
    match (subject, from) {
        (Some(s), Some(f)) => format!("{s} — from {f}"),
        (Some(s), None) => s,
        (None, Some(f)) => format!("from {f}"),
        (None, None) => "no subject".to_owned(),
    }
}

pub async fn dissect_eml(cx: Cx, input: Input) -> Result<()> {
    let prepared = prepare(&cx, input).await?;
    let span = prepared.span;
    let (fields, _) = headers(&cx, span.sub(0, 256 * 1024)).await?;
    cx.annotate(format!("E-mail: {}", describe(&fields)));
    entity(
        cx,
        Entity {
            input: prepared.input(input),
            span,
            depth: 0,
        },
    )
    .await
}

pub async fn dissect_mhtml(cx: Cx, input: Input) -> Result<()> {
    let prepared = prepare(&cx, input).await?;
    let span = prepared.span;
    let (fields, _) = headers(&cx, span.sub(0, 256 * 1024)).await?;
    let title = get(&fields, "Subject")
        .or_else(|| get(&fields, "Snapshot-Content-Location"))
        .map(|f| preview(&decode_words(&f.value), 80));
    cx.annotate(match title {
        Some(t) => format!("MHTML web archive: {t}"),
        None => "MHTML web archive".to_owned(),
    });
    entity(
        cx,
        Entity {
            input: prepared.input(input),
            span,
            depth: 0,
        },
    )
    .await
}

/// mbox: messages separated by `From ` lines.
pub async fn dissect_mbox(cx: Cx, input: Input) -> Result<()> {
    let prepared = prepare(&cx, input).await?;
    let input = prepared.input(input);
    let span = prepared.span;
    cx.annotate("Mailbox (mbox)");
    let mut lines = Lines::new(&cx, span);
    let mut current: Option<(u64, String, u64)> = None; // (separator start, envelope, message start)
    let mut prev_blank = true;
    let mut count = 0u64;
    loop {
        let before = lines.pos();
        let line = lines.next().await?;
        let separator = line
            .as_ref()
            .is_some_and(|l| prev_blank && l.bytes.starts_with(b"From "));
        if let Some(l) = &line {
            prev_blank = l.bytes.is_empty();
        }
        if line.is_some() && !separator {
            continue;
        }
        if let Some((sep, envelope, start)) = current.take() {
            count = count.saturating_add(1);
            let message = span.sub(start, before.saturating_sub(start));
            let (fields, _) = headers(&cx, message.sub(0, 256 * 1024)).await?;
            let mut node = Node::new(format!("Message {count}"))
                .span(span.sub(sep, before.saturating_sub(sep)))
                .summary(describe(&fields))
                .desc(envelope)
                .lazy(
                    crate::expander!(self::entity: Entity),
                    Entity {
                        input,
                        span: message,
                        depth: 0,
                    },
                );
            if let Some(t) = get(&fields, "Date").and_then(|f| mail_date(&f.value)) {
                node = node.value(Value::Timestamp { unix_seconds: t });
            }
            cx.push(node).await;
        }
        let Some(l) = line else {
            break;
        };
        current = Some((l.start, decode_8bit(&l.bytes), l.next));
    }
    cx.annotate(format!(
        "Mailbox (mbox), {}",
        plural(count, "message", "messages")
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Expected values from Python's `email.header.decode_header` /
    /// `make_header` and `Message.get_filename`.
    #[test]
    fn encoded_words() {
        assert_eq!(
            decode_words("=?iso-8859-2?q?Zo=EB_=AF=F3=B3=E6?= <zoe@example>"),
            "Zoë Żółć <zoe@example>"
        );
        assert_eq!(decode_words("=?koi8-r?b?6dfBziDwxdTSz9c=?="), "Иван Петров");
        assert_eq!(
            decode_words("a =?ISO-8859-1?Q?a?= =?ISO-8859-1?Q?b?= c"),
            "a ab c"
        );
        assert_eq!(
            decode_words("=?windows-1250?B?jmx1nW916Gv9IGv58g==?="),
            "Žluťoučký kůň"
        );
        // RFC 2231 language suffix; a character split between words.
        assert_eq!(decode_words("=?utf-8*en?q?caf=C3=A9?="), "café");
        assert_eq!(
            decode_words("=?UTF-8?B?xb1sdcU=?= =?UTF-8?B?pW91xI0=?="),
            "Žluťouč"
        );
        // Not encoded words.
        assert_eq!(decode_words("=?broken"), "=?broken");
        assert_eq!(decode_words("x =?utf-8?x?y?= z"), "x =?utf-8?x?y?= z");
    }

    #[test]
    fn rfc2231_parameters() {
        let p = Params::parse(
            "attachment; filename*0*=iso-8859-1''%A3%20rates; filename*1=\" for 2026.txt\"",
        );
        assert_eq!(p.get("filename"), Some("£ rates for 2026.txt"));
        let p = Params::parse("text/plain; name=\"plain.txt\"; name*=utf-8''%E2%82%AC.txt");
        assert_eq!(p.get("name"), Some("€.txt"));
        let p = Params::parse("text/plain; charset=\"iso-8859-2\"; format=flowed");
        assert_eq!(p.value, "text/plain");
        assert_eq!(p.get("charset"), Some("iso-8859-2"));
        assert_eq!(p.get("format"), Some("flowed"));
        // Sections out of order, and an escape split between sections.
        let p = Params::parse("a; f*1*=%A9; f*0*=utf-8''%C2");
        assert_eq!(p.get("f"), Some("©"));
    }
}
