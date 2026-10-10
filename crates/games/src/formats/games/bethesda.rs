//! Bethesda TES3 and TES4+ plugins (`.esm`, `.esp`, `.esl`).

use crate::bytes::{to_usize, u16_le, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::error::{Diagnostic, Result};
use crate::formats::{Head, Input, Probe};
use crate::node::Node;

/// NUL-terminated (or padded) Latin-1 text.
fn zstr(b: &[u8]) -> String {
    crate::text::until_nul(b)
}

// ---------------------------------------------------------------------------
// Bethesda: TES3 / TES4+ plugins

fn tes_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"TES3") && h.at(16, b"HEDR")
        || h.starts_with(b"TES4") && (h.at(20, b"HEDR") || h.at(24, b"HEDR"))
}

declare_format!(pub TES = "tes-plugin", "Bethesda game plugin (ESM/ESP)", ["esm", "esp", "esl", "omwaddon"], "application/x-tes-plugin",
    Probe::Custom(tes_probe), tes);

async fn tes(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 28)).await?;
    let tes3 = head.starts_with(b"TES3");
    // TES3 records: 16-byte header, 8-byte subrecord headers. TES4 and later:
    // 20 (Oblivion) or 24-byte record headers, 6-byte subrecord headers.
    let rec_head: u64 = if tes3 {
        16
    } else if head.get(20..24) == Some(b"HEDR") {
        20
    } else {
        24
    };
    let mut pos = 0u64;
    let mut n = 0u32;
    let mut summary = String::new();
    while pos.saturating_add(rec_head) <= file.len {
        let h = cx.read(file.sub(pos, rec_head)).await?;
        let kind = String::from_utf8_lossy(h.get(..4).unwrap_or_default()).into_owned();
        let size = u64::from(u32_le(&h, 4).unwrap_or(0));
        // GRUP sizes include their header; record sizes do not.
        let total = if kind == "GRUP" {
            size
        } else {
            size.saturating_add(rec_head)
        };
        if total < rec_head {
            return Err(Diagnostic::malformed("record size smaller than its header")
                .at(file.sub(pos, rec_head)));
        }
        let span = file.sub(pos, total);
        let mut node = Node::new(kind.clone()).span(span);
        if kind == "GRUP" {
            let label = h.get(8..12).unwrap_or_default();
            node = node.summary(format!(
                "{} — {} bytes",
                String::from_utf8_lossy(label),
                size
            ));
        } else if n == 0 {
            // The file header: HEDR, author, description, masters.
            let body = cx.read_avail(span.tail(rec_head).sub(0, 4096)).await?;
            let mut at = 0usize;
            let mut masters = Vec::new();
            while at.saturating_add(if tes3 { 8 } else { 6 }) <= body.len() {
                let id =
                    String::from_utf8_lossy(body.get(at..at.saturating_add(4)).unwrap_or_default())
                        .into_owned();
                let (len, hl) = if tes3 {
                    (
                        to_usize(u32_le(&body, at.saturating_add(4)).unwrap_or(0).into()),
                        8,
                    )
                } else {
                    (
                        usize::from(u16_le(&body, at.saturating_add(4)).unwrap_or(0)),
                        6,
                    )
                };
                let data = body
                    .get(at.saturating_add(hl)..at.saturating_add(hl).saturating_add(len))
                    .unwrap_or_default();
                match id.as_str() {
                    "HEDR" => {
                        let version = f32::from_le_bytes([
                            data.first().copied().unwrap_or(0),
                            data.get(1).copied().unwrap_or(0),
                            data.get(2).copied().unwrap_or(0),
                            data.get(3).copied().unwrap_or(0),
                        ]);
                        let records = if tes3 {
                            u32_le(data, 296)
                        } else {
                            u32_le(data, 4)
                        }
                        .unwrap_or(0);
                        if tes3 {
                            summary = format!("{} ", zstr(data.get(8..40).unwrap_or_default()));
                        }
                        summary.push_str(&format!("v{version:.2}, {records} records"));
                    }
                    "CNAM" => summary = format!("{} by {}", summary, zstr(data)),
                    "MAST" => masters.push(zstr(data)),
                    _ => {}
                }
                at = at.saturating_add(hl).saturating_add(len);
            }
            if !masters.is_empty() {
                summary.push_str(&format!(", masters: {}", masters.join(", ")));
            }
            node = node.summary(summary.clone());
        } else {
            node = node.summary(format!("{size} bytes"));
        }
        cx.progress_in(file, file.offset.saturating_add(pos));
        cx.push(node).await;
        n = n.saturating_add(1);
        pos = pos.saturating_add(total);
    }
    cx.annotate(format!(
        "{} plugin, {summary}",
        if tes3 {
            "Morrowind"
        } else {
            "Gamebryo/Creation engine"
        }
    ));
    Ok(())
}
