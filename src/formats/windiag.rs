//! Windows crash and program artifacts: Windows Error Reporting reports
//! (`.wer`) and Program Information Files (`.pif`).

use crate::bytes::{to_u64, u16_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::datakit::{clip, size, text};
use crate::formats::{Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::Value;

const LE: Endian = Endian::Little;

// ---------------------------------------------------------------------------
// Windows Error Reporting (.wer)

declare_format!(pub WER = "wer-report", "Windows Error Reporting report (.wer)", ["wer"], "application/x-ms-wer",
    Probe::Magic(&[(0, b"\xff\xfeV\0e\0r\0s\0i\0o\0n\0=\0")]), wer);

async fn wer(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let raw = cx.read_avail(file.sub(2, 0x40000)).await?;
    let units: Vec<u16> = raw.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
    let mut at = 0usize;
    let mut entries: Vec<(String, String, Span)> = Vec::new();
    while at < units.len() {
        let end = units.get(at..).and_then(|r| r.iter().position(|&u| u == u16::from(b'\n'))).map_or(units.len(), |p| at.saturating_add(p).saturating_add(1));
        let line = String::from_utf16_lossy(units.get(at..end).unwrap_or_default());
        let span = file.sub(2u64.saturating_add(to_u64(at).saturating_mul(2)), to_u64(end.saturating_sub(at)).saturating_mul(2));
        if let Some((k, v)) = line.trim_end().split_once('=') {
            entries.push((k.to_owned(), v.to_owned(), span));
        }
        at = end;
        if entries.len() > 100_000 {
            break;
        }
    }
    let get = |key: &str| entries.iter().find(|(k, _, _)| k == key).map(|(_, v, _)| v.clone()).unwrap_or_default();
    let event = get("EventType");
    let app = get("AppName");
    let app = if app.is_empty() { get("Sig[0].Value") } else { app };
    cx.set_count(Count::Exact(to_u64(entries.len())));
    for (k, v, span) in &entries {
        let node = Node::new(k.clone()).span(*span);
        let node = if k.ends_with("Time") && let Ok(t) = v.parse::<u64>() {
            node.value(Value::Timestamp { unix_seconds: crate::text::filetime_to_unix(t) })
        } else {
            node.value(text(v.clone()))
        };
        cx.push(node).await;
    }
    let mut summary = format!("WER report: {}", if event.is_empty() { "event" } else { &event });
    if !app.is_empty() {
        summary.push_str(&format!(" in {app}"));
    }
    summary.push_str(&format!(", {} entries", entries.len()));
    cx.annotate(summary);
    Ok(())
}

// ---------------------------------------------------------------------------
// Program Information Files (.pif)

declare_format!(pub PIF = "pif", "Windows Program Information File (.pif)", ["pif"], "application/x-ms-pif",
    Probe::Magic(&[(0x171, b"MICROSOFT PIFEX\0")]), pif);

record! {
    pub struct PifBasic {
        _reserved: u8 "Reserved",
        checksum: u8 "Checksum" .hex(),
        title: ascii[30] "Window title",
        max_memory: u16 "Maximum memory (KiB)",
        min_memory: u16 "Minimum memory (KiB)",
        program: ascii[63] "Program filename",
        flags1: u8 "Flags" .hex(),
        _reserved2: u8 "Reserved",
        directory: ascii[64] "Startup directory",
        parameters: ascii[64] "Parameters",
        video: u8 "Video mode",
        pages: u8 "Text pages",
        first_irq: u8 "First interrupt",
        last_irq: u8 "Last interrupt",
        rows: u8 "Screen rows",
        columns: u8 "Screen columns",
        window_row: u8 "Window row",
        window_column: u8 "Window column",
        system_memory: u16 "System memory",
        shared_name: ascii[64] "Shared program name",
        shared_data: ascii[64] "Shared program data file",
        flags2: u8 "Flags 2" .hex(),
        flags3: u8 "Flags 3" .hex(),
    }
}

const PIF_SECTIONS: &[(&str, &str)] = &[
    ("MICROSOFT PIFEX", "Basic section"),
    ("WINDOWS 286 3.0", "Windows 286 settings"),
    ("WINDOWS 386 3.0", "Windows 386 enhanced-mode settings"),
    ("WINDOWS VMM 4.0", "Windows 95 settings"),
    ("WINDOWS NT  3.1", "Windows NT settings"),
    ("WINDOWS NT  4.0", "Windows NT 4 settings"),
    ("CONFIG  SYS 4.0", "CONFIG.SYS for MS-DOS mode"),
    ("AUTOEXECBAT 4.0", "AUTOEXEC.BAT for MS-DOS mode"),
];

async fn pif(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, PifBasic::SIZE);
    let basic: PifBasic = read_record(&cx, span, LE).await?;
    cx.emit(PifBasic::node("Basic section", span, LE));
    let mut at = 0x171u64;
    let mut seen = Vec::new();
    let mut names = Vec::new();
    while at != 0xffff && at.saturating_add(22) <= file.len {
        if seen.contains(&at) || seen.len() > 64 {
            cx.diag(Diagnostic::malformed("section headings loop").at(file.sub(at, 22)));
            break;
        }
        seen.push(at);
        let head = cx.read(file.sub(at, 22)).await?;
        let name = crate::text::until_nul(head.get(..16).unwrap_or_default());
        let next = u64::from(u16_le(&head, 16).unwrap_or(0xffff));
        let data_at = u64::from(u16_le(&head, 18).unwrap_or(0));
        let len = u64::from(u16_le(&head, 20).unwrap_or(0));
        let data = file.sub(data_at, len);
        let title = PIF_SECTIONS.iter().find(|(k, _)| *k == name).map(|(_, t)| *t);
        names.push(name.clone());
        let mut node = Node::new(name).span(file.sub(at, 22)).target(data).summary(size(len)).lazy(pif_section, (file.sub(at, 22), data));
        if let Some(t) = title {
            node = node.desc(t);
        }
        cx.push(node).await;
        at = next;
    }
    let program = basic.program.trim().to_owned();
    cx.annotate(format!(
        "PIF for {}{}, sections: {}",
        if program.is_empty() { "?" } else { &program },
        if basic.parameters.trim().is_empty() { String::new() } else { format!(" {}", basic.parameters.trim()) },
        clip(&names.join(", "), 120)
    ));
    Ok(())
}

fn pif_heading(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.ascii("Section name", 16).emit()?;
    f.u16("Next heading offset").hex().emit()?;
    f.u16("Data offset").hex().emit()?;
    f.u16("Data length").emit()?;
    Ok(())
}

async fn pif_section(cx: Cx, (heading, data): (Span, Span)) -> Result<()> {
    cx.emit(struct_node("Heading", heading, LE, (), pif_heading));
    let raw = cx.read_avail(data.sub(0, 0x1000)).await?;
    // NT sections name the CONFIG.NT / AUTOEXEC.NT replacements.
    let strings: Vec<String> = raw
        .split(|&b| b == 0)
        .filter(|s| s.len() >= 4 && s.iter().all(|&b| (0x20..0x7f).contains(&b)))
        .map(crate::text::latin1)
        .collect();
    let mut node = Node::new("Data").span(data);
    if !strings.is_empty() {
        node = node.summary(clip(&strings.join(", "), 120));
    }
    cx.emit(node);
    Ok(())
}
