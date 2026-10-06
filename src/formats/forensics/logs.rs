//! Text and record logs with forensic value: Windows SetupAPI device logs,
//! W3C extended logs (IIS, Windows Firewall), PowerShell transcripts, Linux
//! audit logs, BSD process accounting and Vim's viminfo.

use std::sync::Arc;

use crate::bytes::{to_u64, u16_le, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::error::Result;
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::util::datakit::{clip, text};
use crate::formats::{Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{FlagTable, Value, flag};

const LE: Endian = Endian::Little;

/// A text line: offset, length including the line break, and the text.
pub(crate) type Line = (u64, u64, String);
pub(crate) type Lines = Vec<Line>;
/// An audit event: serial, time, record types and lines.
type AuditEvent = (String, i64, Vec<String>, Lines);

/// Text lines with their offsets: `(offset, length including the line
/// break, text without it)`.
fn lines(data: &[u8]) -> Lines {
    let mut at = 0u64;
    data.split_inclusive(|&b| b == b'\n')
        .map(|line| {
            let start = at;
            at = at.saturating_add(to_u64(line.len()));
            let body = line.strip_suffix(b"\n").unwrap_or(line);
            let body = body.strip_suffix(b"\r").unwrap_or(body);
            (
                start,
                to_u64(line.len()),
                String::from_utf8_lossy(body).into_owned(),
            )
        })
        .collect()
}

pub(crate) fn strip_bom(data: &[u8]) -> &[u8] {
    data.strip_prefix(b"\xef\xbb\xbf").unwrap_or(data)
}

/// The text of a file, read up to the session limit, with its lines.
pub(crate) async fn text_lines(cx: &Cx, file: Span) -> Result<Lines> {
    let data = cx.read_avail(file.sub(0, cx.limits().max_read)).await?;
    let mut all = lines(&data);
    if let Some(first) = all.first_mut() {
        first.2 = first.2.trim_start_matches('\u{feff}').to_owned();
    }
    Ok(all)
}

/// A group node over a run of lines, expanding to one node per line.
pub(crate) fn line_group(name: String, file: Span, lines: Lines) -> Node {
    let start = lines.first().map_or(0, |l| l.0);
    let end = lines.last().map_or(start, |l| l.0.saturating_add(l.1));
    Node::new(name)
        .span(file.sub(start, end.saturating_sub(start)))
        .lazy(expand_lines, (file, Arc::new(lines)))
}

async fn expand_lines(cx: Cx, (file, lines): (Span, Arc<Lines>)) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(lines.len())));
    for (at, len, line) in lines.iter() {
        cx.push(
            Node::new("Line")
                .span(file.sub(*at, *len))
                .value(text(clip(line, 400))),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Windows SetupAPI device installation log (setupapi.dev.log)

fn setupapi_probe(h: &Head<'_>) -> bool {
    strip_bom(h.data).starts_with(b"[Device Install Log]")
}

declare_format!(pub SETUPAPI = "setupapi-log", "Windows SetupAPI device installation log", ["log"], "text/x-setupapi-log",
    Probe::Custom(setupapi_probe), setupapi);

async fn setupapi(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let all = text_lines(&cx, file).await?;
    let mut header = Vec::new();
    let mut i = 0usize;
    // Header lines until [BeginLog].
    while let Some(l) = all.get(i) {
        if l.2.starts_with("[BeginLog]") {
            break;
        }
        header.push(l.clone());
        i = i.saturating_add(1);
    }
    let os = header
        .iter()
        .find_map(|l| l.2.trim().strip_prefix("OS Version = ").map(str::to_owned))
        .unwrap_or_default();
    cx.emit(line_group("Header".to_owned(), file, header));
    let (mut sections, mut usb, mut boots) = (0u32, 0u32, 0u32);
    let mut current: Option<(String, Lines)> = None;
    for l in all.iter().skip(i) {
        let t = l.2.trim_start();
        if let Some(title) = t.strip_prefix(">>>  [").and_then(|r| r.strip_suffix(']')) {
            if let Some((name, list)) = current.take() {
                cx.push(setup_section(name, file, list)).await;
            }
            current = Some((title.to_owned(), vec![l.clone()]));
            sections = sections.saturating_add(1);
            if title.contains("USB\\VID_") || title.contains("USBSTOR\\") {
                usb = usb.saturating_add(1);
            }
            continue;
        }
        if let Some(boot) = t
            .strip_prefix("[Boot Session: ")
            .and_then(|r| r.strip_suffix(']'))
        {
            if let Some((name, list)) = current.take() {
                cx.push(setup_section(name, file, list)).await;
            }
            boots = boots.saturating_add(1);
            cx.push(
                Node::new("Boot session")
                    .span(file.sub(l.0, l.1))
                    .value(text(boot)),
            )
            .await;
            continue;
        }
        if let Some((_, list)) = current.as_mut() {
            list.push(l.clone());
            if t.starts_with("<<<  [Exit status")
                && let Some((name, list)) = current.take()
            {
                cx.push(setup_section(name, file, list)).await;
            }
        }
    }
    if let Some((name, list)) = current.take() {
        cx.push(setup_section(name, file, list)).await;
    }
    cx.annotate(format!(
        "SetupAPI device log{}, {boots} boot sessions, {sections} sections ({usb} USB devices)",
        if os.is_empty() {
            String::new()
        } else {
            format!(" (Windows {os})")
        }
    ));
    Ok(())
}

fn setup_section(title: String, file: Span, list: Lines) -> Node {
    let start = list.iter().find_map(|l| {
        l.2.trim_start()
            .strip_prefix(">>>  Section start ")
            .map(str::to_owned)
    });
    let status = list.iter().find_map(|l| {
        l.2.trim_start()
            .strip_prefix("<<<  [Exit status: ")
            .and_then(|r| r.strip_suffix(']'))
            .map(str::to_owned)
    });
    let mut node = line_group(title, file, list);
    if let Some(s) = start {
        node = node.value(text(s));
    }
    if let Some(s) = status {
        node = node.summary(s);
    }
    node
}

// ---------------------------------------------------------------------------
// W3C extended log files (IIS, Windows Firewall, proxies)

fn w3c_probe(h: &Head<'_>) -> bool {
    let d = strip_bom(h.data);
    (d.starts_with(b"#Software: ") || d.starts_with(b"#Version: "))
        && d.get(..1024)
            .unwrap_or(d)
            .windows(10)
            .any(|w| w == b"\n#Fields: ")
}

declare_format!(pub W3C = "w3c-log", "W3C extended log (IIS, Windows Firewall)", ["log"], "text/x-w3c-log",
    Probe::Custom(w3c_probe), w3c);

async fn w3c(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let all = text_lines(&cx, file).await?;
    let mut fields: Arc<Vec<String>> = Arc::new(Vec::new());
    let (mut software, mut entries) = (String::new(), 0u64);
    for (at, len, line) in &all {
        let span = file.sub(*at, *len);
        if let Some(directive) = line.strip_prefix('#') {
            let (k, v) = directive.split_once(':').unwrap_or((directive, ""));
            let v = v.trim();
            match k {
                "Fields" => fields = Arc::new(v.split_whitespace().map(str::to_owned).collect()),
                "Software" => software = v.to_owned(),
                _ => {}
            }
            cx.push(
                Node::new(format!("#{k}"))
                    .span(span)
                    .value(text(v))
                    .desc("Directive"),
            )
            .await;
            continue;
        }
        if line.trim().is_empty() {
            continue;
        }
        entries = entries.saturating_add(1);
        let values: Vec<&str> = line.split(' ').collect();
        let get = |name: &str| {
            fields
                .iter()
                .position(|f| f == name)
                .and_then(|i| values.get(i).copied())
                .unwrap_or("")
        };
        let when = format!("{} {}", get("date"), get("time")).trim().to_owned();
        let what = [
            get("action"),
            get("cs-method"),
            get("cs-uri-stem"),
            get("protocol"),
            get("src-ip"),
            get("dst-ip"),
            get("dst-port"),
            get("sc-status"),
        ]
        .iter()
        .filter(|s| !s.is_empty() && **s != "-")
        .copied()
        .collect::<Vec<_>>()
        .join(" ");
        let mut node = Node::new(if when.is_empty() {
            format!("Entry {entries}")
        } else {
            when
        })
        .span(span)
        .lazy(w3c_entry, (span, fields.clone()));
        if !what.is_empty() {
            node = node.summary(clip(&what, 160));
        }
        cx.push(node).await;
    }
    cx.annotate(format!(
        "W3C extended log{}, {entries} entries",
        if software.is_empty() {
            String::new()
        } else {
            format!(" from {software}")
        }
    ));
    Ok(())
}

async fn w3c_entry(cx: Cx, (span, fields): (Span, Arc<Vec<String>>)) -> Result<()> {
    let raw = cx.read(span).await?;
    let line = String::from_utf8_lossy(&raw);
    let line = line.trim_end_matches(['\r', '\n']);
    let mut at = 0u64;
    for (i, value) in line.split(' ').enumerate() {
        let name = fields
            .get(i)
            .cloned()
            .unwrap_or_else(|| format!("Field {i}"));
        cx.push(
            Node::new(name)
                .span(span.sub(at, to_u64(value.len())))
                .value(text(value)),
        )
        .await;
        at = at.saturating_add(to_u64(value.len())).saturating_add(1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// PowerShell transcripts

fn transcript_probe(h: &Head<'_>) -> bool {
    let d = strip_bom(h.data);
    let rest = d
        .strip_prefix(b"**********************")
        .unwrap_or_default();
    let rest = rest
        .strip_prefix(b"\r\n")
        .or_else(|| rest.strip_prefix(b"\n"))
        .unwrap_or_default();
    rest.starts_with(b"Windows PowerShell transcript start")
        || rest.starts_with(b"PowerShell transcript start")
}

declare_format!(pub TRANSCRIPT = "powershell-transcript", "PowerShell transcript", ["txt"], "text/x-powershell-transcript",
    Probe::Custom(transcript_probe), transcript);

/// `yyyyMMddHHmmss` as `yyyy-MM-dd HH:mm:ss`.
fn compact_time(s: &str) -> String {
    let p = |a: usize, b: usize| s.get(a..b).unwrap_or("");
    if s.len() == 14 && s.bytes().all(|b| b.is_ascii_digit()) {
        format!(
            "{}-{}-{} {}:{}:{}",
            p(0, 4),
            p(4, 6),
            p(6, 8),
            p(8, 10),
            p(10, 12),
            p(12, 14)
        )
    } else {
        s.to_owned()
    }
}

async fn transcript(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let all = text_lines(&cx, file).await?;
    let (mut user, mut machine, mut commands) = (String::new(), String::new(), 0u32);
    let mut command: Option<(String, Lines)> = None;
    let mut in_header = false;
    let mut header = Vec::new();
    for l in &all {
        let t = l.2.as_str();
        if t.starts_with("**********************") {
            if let Some((cmd, list)) = command.take() {
                cx.push(transcript_command(cmd, file, list)).await;
            }
            in_header = !in_header;
            if !in_header && !header.is_empty() {
                cx.push(header_node(file, std::mem::take(&mut header)))
                    .await;
            }
            continue;
        }
        if in_header {
            if let Some(u) = t.strip_prefix("Username: ") {
                user = u.to_owned();
            } else if let Some(m) = t.strip_prefix("Machine: ") {
                machine = m.split(" (").next().unwrap_or(m).to_owned();
            }
            header.push(l.clone());
            continue;
        }
        if let Some(prompt) = t.strip_prefix("PS ").and_then(|r| r.split_once("> ")) {
            if let Some((cmd, list)) = command.take() {
                cx.push(transcript_command(cmd, file, list)).await;
            }
            commands = commands.saturating_add(1);
            command = Some((prompt.1.to_owned(), vec![l.clone()]));
            continue;
        }
        match command.as_mut() {
            Some((_, list)) => list.push(l.clone()),
            None if !t.is_empty() => {
                cx.push(
                    Node::new("Line")
                        .span(file.sub(l.0, l.1))
                        .value(text(clip(t, 400))),
                )
                .await
            }
            None => {}
        }
    }
    if let Some((cmd, list)) = command.take() {
        cx.push(transcript_command(cmd, file, list)).await;
    }
    if !header.is_empty() {
        cx.push(header_node(file, header)).await;
    }
    cx.annotate(format!(
        "PowerShell transcript{}{}, {commands} commands",
        if user.is_empty() {
            String::new()
        } else {
            format!(" by {user}")
        },
        if machine.is_empty() {
            String::new()
        } else {
            format!(" on {machine}")
        }
    ));
    Ok(())
}

fn header_node(file: Span, lines: Lines) -> Node {
    let kind = lines.first().map(|l| l.2.clone()).unwrap_or_default();
    let time = lines.iter().find_map(|l| {
        l.2.strip_prefix("Start time: ")
            .or_else(|| l.2.strip_prefix("End time: "))
            .map(compact_time)
    });
    let start = lines.first().map_or(0, |l| l.0);
    let end = lines.last().map_or(start, |l| l.0.saturating_add(l.1));
    let mut node = Node::new(kind)
        .span(file.sub(start, end.saturating_sub(start)))
        .lazy(transcript_header, (file, Arc::new(lines)));
    if let Some(t) = time {
        node = node.value(text(t));
    }
    node
}

async fn transcript_header(cx: Cx, (file, lines): (Span, Arc<Lines>)) -> Result<()> {
    for (at, len, line) in lines.iter().skip(1) {
        let node = Node::new("Line").span(file.sub(*at, *len));
        cx.push(match line.split_once(": ") {
            Some((k, v)) if k.ends_with("time") => Node::new(k.to_owned())
                .span(file.sub(*at, *len))
                .value(text(compact_time(v))),
            Some((k, v)) => Node::new(k.to_owned())
                .span(file.sub(*at, *len))
                .value(text(v)),
            None => node.value(text(line.clone())),
        })
        .await;
    }
    Ok(())
}

fn transcript_command(cmd: String, file: Span, list: Lines) -> Node {
    let output = list.len().saturating_sub(1);
    line_group(format!("PS> {}", clip(&cmd, 120)), file, list)
        .summary(format!("{output} output lines"))
}

// ---------------------------------------------------------------------------
// Linux audit logs (auditd)

fn audit_probe(h: &Head<'_>) -> bool {
    let first = h.data.split(|&b| b == b'\n').next().unwrap_or_default();
    h.starts_with(b"type=") && first.windows(11).any(|w| w == b" msg=audit(")
}

declare_format!(pub AUDIT = "linux-audit-log", "Linux audit log (auditd)", ["log"], "text/x-audit-log",
    Probe::Custom(audit_probe), audit);

/// The `type=` and the `audit(seconds.millis:serial)` stamp of a record.
fn audit_stamp(line: &str) -> Option<(String, i64, String)> {
    let kind = line.strip_prefix("type=")?.split(' ').next()?.to_owned();
    let stamp = line.split_once("msg=audit(")?.1.split_once(')')?.0;
    let (time, serial) = stamp.split_once(':')?;
    let seconds = time.split('.').next()?.parse().ok()?;
    Some((kind, seconds, serial.to_owned()))
}

async fn audit(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let all = text_lines(&cx, file).await?;
    let mut events = 0u64;
    let mut kinds: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    let mut current: Option<AuditEvent> = None;
    for l in &all {
        let Some((kind, seconds, serial)) = audit_stamp(&l.2) else {
            continue;
        };
        let entry = kinds.entry(kind.clone()).or_insert(0);
        *entry = entry.saturating_add(1);
        match current.as_mut() {
            Some((s, _, types, list)) if *s == serial => {
                types.push(kind);
                list.push(l.clone());
            }
            _ => {
                if let Some(ev) = current.take() {
                    cx.push(audit_event(file, ev)).await;
                }
                events = events.saturating_add(1);
                current = Some((serial, seconds, vec![kind], vec![l.clone()]));
            }
        }
    }
    if let Some(ev) = current.take() {
        cx.push(audit_event(file, ev)).await;
    }
    let mut top: Vec<(String, u64)> = kinds.into_iter().collect();
    top.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let top: Vec<String> = top
        .iter()
        .take(4)
        .map(|(k, n)| format!("{n} {k}"))
        .collect();
    cx.annotate(format!(
        "Linux audit log, {events} events ({})",
        top.join(", ")
    ));
    Ok(())
}

fn audit_event(file: Span, (serial, seconds, types, list): AuditEvent) -> Node {
    let start = list.first().map_or(0, |l| l.0);
    let end = list.last().map_or(start, |l| l.0.saturating_add(l.1));
    let comm = list.iter().find_map(|l| {
        l.2.split_once(" exe=\"")
            .and_then(|(_, r)| r.split('"').next())
            .map(str::to_owned)
    });
    let mut node = Node::new(format!("Event {serial}"))
        .span(file.sub(start, end.saturating_sub(start)))
        .value(Value::Timestamp {
            unix_seconds: seconds,
        })
        .lazy(audit_records, (file, Arc::new(list)));
    let mut summary = types.join(", ");
    if let Some(c) = comm {
        summary.push_str(&format!(" — {c}"));
    }
    node = node.summary(clip(&summary, 160));
    node
}

async fn audit_records(cx: Cx, (file, list): (Span, Arc<Lines>)) -> Result<()> {
    for (at, len, line) in list.iter() {
        let kind = line
            .strip_prefix("type=")
            .and_then(|r| r.split(' ').next())
            .unwrap_or("record")
            .to_owned();
        let body = line.split_once("): ").map_or("", |(_, r)| r);
        cx.push(
            Node::new(kind)
                .span(file.sub(*at, *len))
                .value(text(clip(body, 400)))
                .lazy(audit_fields, (file.sub(*at, *len), body.to_owned())),
        )
        .await;
    }
    Ok(())
}

/// Splits `key=value` pairs (values may be double-quoted).
fn audit_pairs(body: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut rest = body.trim();
    while let Some((k, r)) = rest.split_once('=') {
        let key = k.trim().to_owned();
        let (value, tail) = if let Some(q) = r.strip_prefix('"') {
            let (v, t) = q.split_once('"').unwrap_or((q, ""));
            (v.to_owned(), t)
        } else if let Some(q) = r.strip_prefix('\'') {
            let (v, t) = q.split_once('\'').unwrap_or((q, ""));
            (v.to_owned(), t)
        } else {
            let (v, t) = r.split_once(' ').unwrap_or((r, ""));
            (v.to_owned(), t)
        };
        out.push((key, value));
        rest = tail.trim_start();
        if out.len() > 512 {
            break;
        }
    }
    out
}

async fn audit_fields(cx: Cx, (span, body): (Span, String)) -> Result<()> {
    for (k, v) in audit_pairs(&body) {
        // Hex-encoded strings (proctitle, untrusted names) are decoded when printable.
        let decoded = ((k == "proctitle" || v.len() >= 16)
            && v.len().is_multiple_of(2)
            && v.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| {
            (0..v.len() / 2)
                .filter_map(|i| {
                    v.get(i.saturating_mul(2)..i.saturating_mul(2).saturating_add(2))
                        .and_then(|h| u8::from_str_radix(h, 16).ok())
                })
                .map(|b| if b == 0 { b' ' } else { b })
                .collect::<Vec<u8>>()
        })
        .filter(|b| b.iter().all(|&c| (0x20..0x7f).contains(&c)));
        let mut node = Node::new(k).span(span).value(text(v));
        if let Some(d) = decoded {
            node = node.summary(String::from_utf8_lossy(&d).into_owned());
        }
        cx.push(node).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// BSD process accounting (Linux acct v3, /var/log/account/pacct)

const ACCT_RECORD: u64 = 64;

fn acct_plausible(r: &[u8]) -> bool {
    let comm = r.get(48..64).unwrap_or_default();
    let end = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
    r.get(1) == Some(&3)
        && r.first().is_some_and(|f| f & 0xe0 == 0)
        && end > 0
        && comm
            .get(..end)
            .is_some_and(|c| c.iter().all(|&b| (0x20..0x7f).contains(&b)))
        && comm.get(end..).is_some_and(|c| c.iter().all(|&b| b == 0))
        && u32_le(r, 24).is_some_and(|t| (100_000_000..0x8000_0000).contains(&t))
}

fn acct_probe(h: &Head<'_>) -> bool {
    h.len >= ACCT_RECORD
        && h.len.is_multiple_of(ACCT_RECORD)
        && h.data
            .as_chunks::<64>()
            .0
            .iter()
            .take(16)
            .all(|r| acct_plausible(r))
}

declare_format!(pub ACCT = "linux-acct", "Linux process accounting (acct v3)", ["pacct", "acct"], "application/x-acct",
    Probe::Custom(acct_probe), acct);

const ACCT_FLAGS: FlagTable = &[
    flag(1, "AFORK"),
    flag(2, "ASU"),
    flag(8, "ACORE"),
    flag(0x10, "AXSIG"),
];

/// A `comp_t`: 13-bit mantissa, 3-bit base-8 exponent, in clock ticks.
fn comp_t(v: u16) -> u64 {
    u64::from(v & 0x1fff) << (3 * u32::from(v >> 13))
}

fn acct_layout(f: &mut Fields<'_>, _: &()) -> Result<(String, u32, u32)> {
    f.u8("Flags").flags(ACCT_FLAGS).emit()?;
    f.u8("Version").emit()?;
    f.u16("Controlling terminal").hex().emit()?;
    f.u32("Exit code").emit()?;
    let uid = f.u32("UID").emit()?;
    f.u32("GID").emit()?;
    f.u32("PID").emit()?;
    f.u32("Parent PID").emit()?;
    let start = f.u32("Start time").timestamp().emit()?;
    f.f32("Elapsed time (ticks)").emit()?;
    for name in [
        "User time",
        "System time",
        "Average memory",
        "Characters transferred",
        "Blocks read or written",
        "Minor page faults",
        "Major page faults",
        "Swaps",
    ] {
        f.u16(name)
            .with(|&v, n| {
                if comp_t(v) == u64::from(v) {
                    n
                } else {
                    n.summary(format!("{} (decoded)", comp_t(v)))
                }
            })
            .emit()?;
    }
    let comm = f.ascii("Command", 16).emit()?;
    Ok((comm, uid, start))
}

async fn acct(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let count = file.len / ACCT_RECORD;
    cx.set_count(Count::Exact(count));
    let mut commands = std::collections::BTreeSet::new();
    for i in 0..count {
        let span = file.sub(i.saturating_mul(ACCT_RECORD), ACCT_RECORD);
        let block = cx.block(span).await?;
        let (comm, uid, start) = acct_layout(&mut Fields::new(&block, LE), &())?;
        let exit = u32_le(&block.data, 4).unwrap_or(0);
        let tty = u16_le(&block.data, 2).unwrap_or(0);
        commands.insert(comm.clone());
        cx.push(
            struct_node(comm, span, LE, (), acct_layout)
                .value(Value::Timestamp {
                    unix_seconds: start.into(),
                })
                .summary(format!(
                    "uid {uid}, exit {exit}{}",
                    if tty == 0 {
                        String::new()
                    } else {
                        format!(", tty {tty:#x}")
                    }
                )),
        )
        .await;
    }
    cx.annotate(format!(
        "process accounting, {count} records, {} distinct commands",
        commands.len()
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Vim viminfo

declare_format!(pub VIMINFO = "viminfo", "Vim viminfo history", ["viminfo"], "text/x-viminfo",
    Probe::Magic(&[(0, b"# This viminfo file was generated by Vim")]), viminfo);

async fn viminfo(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let all = text_lines(&cx, file).await?;
    let mut section: Option<(String, Lines)> = None;
    let mut commands = 0u64;
    let mut files = std::collections::BTreeSet::new();
    for l in &all {
        let t = l.2.as_str();
        // Every comment line titles the entries that follow it.
        if let Some(title) = t.strip_prefix("# ") {
            if let Some((name, list)) = section.take()
                && !list.is_empty()
            {
                cx.push(viminfo_section(name, file, list)).await;
            }
            section = Some((title.trim_end_matches(':').to_owned(), Vec::new()));
            continue;
        }
        if t.starts_with(':') {
            commands = commands.saturating_add(1);
        }
        if let Some(path) = t.strip_prefix("> ") {
            files.insert(path.to_owned());
        }
        if let Some((_, list)) = section.as_mut()
            && !t.is_empty()
        {
            list.push(l.clone());
        }
    }
    if let Some((name, list)) = section.take()
        && !list.is_empty()
    {
        cx.push(viminfo_section(name, file, list)).await;
    }
    cx.annotate(format!(
        "viminfo, {commands} command-line entries, {} files with marks",
        files.len()
    ));
    Ok(())
}

fn viminfo_section(name: String, file: Span, list: Lines) -> Node {
    let n = list
        .iter()
        .filter(|l| !l.2.starts_with('|') && !l.2.starts_with('\t'))
        .count();
    line_group(name, file, list).summary(format!("{n} entries"))
}
